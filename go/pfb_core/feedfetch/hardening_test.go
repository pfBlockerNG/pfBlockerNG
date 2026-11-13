package feedfetch_test

// Hardening from the #3905 review (#3911) that the parity corpus cannot see: zero values that must be PHP's defaults,
// the self-hosted fetch pinned to the address it was classified at, and rsync's temporary file.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// The feed-host filter is on unless a caller turns it off, as PHP's pfb_feed_internal_filter defaults to On.
func TestAZeroFetcherRefusesAnInternalFeedHost(t *testing.T) {
	f := &feedfetch.Fetcher{Policy: feedfetch.Policy{
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		},
	}}
	feed := feedfetch.Feed{Dir: t.TempDir(), Name: "FEED"}
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://internal.example/list", Timeout: time.Second})
	if res.OK || res.Reason != "feed host resolves to a non-permitted address" {
		t.Fatalf("a zero Fetcher fetched an internal host: %+v", res)
	}
}

// A zero RetryDelay is pfb_download()'s 5 s pause: a run whose deadline falls inside the first pause makes one request.
func TestAZeroRetryDelayPausesBetweenAttempts(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close() // no answer: the attempt fails
	}))
	defer srv.Close()
	f, feed := fetcherFor(t)
	f.RetryDelay = 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := f.Ingest(ctx, feed, feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: time.Second})
	if res.OK || requests.Load() != 1 {
		t.Fatalf("with a zero RetryDelay a run ending inside the first pause made %d requests (%+v), want 1",
			requests.Load(), res)
	}
}

// A self-hosted URL is fetched from the address it was classified self at; the name is never resolved again, so a
// second answer (here a public address) cannot redirect the read.
func TestASelfHostedFeedIsReadFromTheAddressItWasClassifiedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("SELF\n")) }))
	defer srv.Close()
	f, feed := fetcherFor(t)
	var calls atomic.Int32
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "http://self.example:" + port(t, srv.URL) + "/list", Timeout: 5 * time.Second})
	if !res.OK || published(t, feed) != "SELF\n" {
		t.Fatalf("a self-hosted feed was not read from its classified address: %+v, published %q", res, published(t, feed))
	}
}

// rsync's temporary file (".NAME.raw.XXXXXX" beside the target) never outlives the call, also when rsync is killed at
// the deadline, and one left by an earlier killed run is removed by the next.
func TestRsyncsTemporaryFileNeverOutlivesTheCall(t *testing.T) {
	for name, tc := range map[string]struct {
		script string
		ok     bool
	}{
		"killed at the deadline": {"printf partial >\"${dir}/.${base}.Ab12Cd\"\nexec sleep 3600\n", false},
		"after an earlier kill":  {"printf full >\"${dst}\"\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			tools := t.TempDir()
			script := "#!/bin/sh\neval \"dst=\\${$#}\"\ndir=$(dirname \"${dst}\")\nbase=$(basename \"${dst}\")\n" + tc.script
			if err := os.WriteFile(filepath.Join(tools, "rsync"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			f, feed := fetcherFor(t)
			f.RsyncBin = filepath.Join(tools, "rsync")
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, ".FEED.raw.Zz99Yy"), []byte("earlier\n"), 0o600)
			res := f.Ingest(context.Background(), feed, feedfetch.Request{
				URL: "rsync://feed.example/feeds/list.txt", Rsync: true, Timeout: time.Second})
			if res.OK != tc.ok {
				t.Fatalf("ingest: %+v, want OK %v", res, tc.ok)
			}
			if left, _ := filepath.Glob(filepath.Join(feed.Dir, ".FEED.raw.*")); len(left) != 0 {
				t.Fatalf("rsync's temporary file outlived the call: %v", left)
			}
		})
	}
}
