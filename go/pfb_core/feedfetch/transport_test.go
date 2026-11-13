package feedfetch_test

// Transfer behaviour pinned beside the parity corpus. TLS Flex and the system proxy are corpus rows now (tls-*, proxy-*,
// proxy-credentials-*); what stays here is Core's own side of them: Flex over a pinned address, the proxy's
// credentials sent on the first request (PHP sends none, a documented divergence), a body over the ceiling without a
// declared length, and the rsync wall deadline (#2876).

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// fetcherFor resolves every name to loopback plus a public address, so it is neither refused nor self-hosted.
func fetcherFor(t *testing.T) (*feedfetch.Fetcher, feedfetch.Feed) {
	t.Helper()
	dir := t.TempDir()
	return &feedfetch.Fetcher{Policy: feedfetch.Policy{
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.5")}, nil
		},
	}, RetryDelay: time.Millisecond}, feedfetch.Feed{Dir: dir, Name: "FEED"}
}

func published(t *testing.T, feed feedfetch.Feed) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(feed.Dir, feed.Name+".orig"))
	if err != nil {
		return "<none>"
	}
	return string(b)
}

func port(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestAnUntrustedCertificateFailsUnlessFlexDowngrades(t *testing.T) {
	var mu sync.Mutex
	served := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		io.WriteString(w, "tls\n")
	}))
	defer srv.Close()
	target := "https://feed.example:" + port(t, srv.URL) + "/list"

	f, feed := fetcherFor(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: target, Timeout: 10 * time.Second})
	if res.OK || res.Reason != "curl_incomplete" || published(t, feed) != "<none>" || served != 0 {
		t.Fatalf("without flex an untrusted certificate must fail every attempt: %+v, published %q, served %d",
			res, published(t, feed), served)
	}

	res = f.Ingest(context.Background(), feed, feedfetch.Request{URL: target, Timeout: 10 * time.Second, Flex: true})
	if !res.OK || published(t, feed) != "tls\n" {
		t.Fatalf("flex must downgrade verification after the first failure: %+v, published %q", res, published(t, feed))
	}

	trusted, feed2 := fetcherFor(t)
	trusted.RootCAs = x509.NewCertPool()
	trusted.RootCAs.AddCert(srv.Certificate())
	// The test certificate names example.com; a verified connection checks the URL's name, not the pinned address.
	res = trusted.Ingest(context.Background(), feed2, feedfetch.Request{
		URL: "https://example.com:" + port(t, srv.URL) + "/list", Timeout: 10 * time.Second})
	if !res.OK || published(t, feed2) != "tls\n" {
		t.Fatalf("a trusted certificate for the URL's name must verify over the pinned address: %+v", res)
	}
}

func TestTheSystemProxyCarriesTheRequestAndItsCredentials(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String()+" "+r.Header.Get("Proxy-Authorization"))
		mu.Unlock()
		io.WriteString(w, "via proxy\n")
	}))
	defer proxy.Close()

	f, feed := fetcherFor(t)
	f.Proxy, _ = url.Parse(proxy.URL)
	f.Proxy.User = url.UserPassword("puser", "ppass")
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:8081/list", Timeout: 10 * time.Second})
	want := "http://feed.example:8081/list Basic " + base64.StdEncoding.EncodeToString([]byte("puser:ppass"))
	if !res.OK || published(t, feed) != "via proxy\n" || len(seen) != 1 || seen[0] != want {
		t.Fatalf("the request must go through the proxy with its credentials: %+v, published %q, proxy saw %q, want %q",
			res, published(t, feed), seen, want)
	}
}

func TestAnUndeclaredBodyOverTheCeilingIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // chunked: no Content-Length is declared
		io.WriteString(w, strings.Repeat("x", 64))
	}))
	defer srv.Close()
	f, feed := fetcherFor(t)
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "http://feed.example:" + port(t, srv.URL) + "/big", Timeout: 10 * time.Second, MaxBytes: 16})
	if res.OK || res.Reason != "download_too_large" || published(t, feed) != "old\n" {
		t.Fatalf("an undeclared body over the ceiling must be refused, keeping the published copy: %+v, published %q",
			res, published(t, feed))
	}
	if entries, _ := os.ReadDir(feed.Dir); len(entries) != 1 {
		t.Fatalf("nothing but the published copy may remain: %v", entries)
	}
}

func TestAnRsyncTransferPastItsDeadlineIsKilledAndDiscarded(t *testing.T) {
	tools := t.TempDir()
	// The descendant keeps the output pipe open: unless the whole process group dies at the deadline, the call
	// hangs until the test binary's own timeout.
	script := "#!/bin/sh\n" +
		"eval \"dst=\\${$#}\"\n" +
		"printf partial >\"${dst}\"\n" +
		"sleep 3600 &\n" +
		"wait\n"
	if err := os.WriteFile(filepath.Join(tools, "rsync"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	f, feed := fetcherFor(t)
	f.RsyncBin = filepath.Join(tools, "rsync")
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "rsync://feed.example/feeds/list.txt", Rsync: true, Timeout: time.Second})
	if res.OK || res.Reason != "rsync transfer timed out" || published(t, feed) != "old\n" {
		t.Fatalf("an rsync past its deadline must fail and keep the published copy: %+v, published %q", res, published(t, feed))
	}
	if entries, _ := os.ReadDir(feed.Dir); len(entries) != 1 {
		t.Fatalf("the killed transfer's output must be discarded: %v", entries)
	}
}
