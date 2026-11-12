package feedfetch_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// #3914: the published copy's raw-byte digest is SHA-1, recorded hex in ".orig.sha1".
func TestThePublishedDigestIsTheSHA1OfTheRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "abc") }))
	defer srv.Close()
	f, feed := fetcherFor(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second})
	b, _ := os.ReadFile(filepath.Join(feed.Dir, "FEED.orig.sha1"))
	// SHA-1("abc"), FIPS 180-2 appendix A; the digest is of the bytes before the trailing newline is added.
	if !res.OK || string(b) != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("ingest %+v recorded %q, want the SHA-1 of the raw body", res, b)
	}
}

// A previous Core version recorded the SHA-256 of the same bytes, as ".orig.sha256" and as a 64-hex value. Neither
// may read as unchanged, and neither may fail the feed: it re-ingests.
func TestAPreviousVersionsSHA256DigestReIngests(t *testing.T) {
	const body = "same\n"
	// SHA-256("same\n")
	const old = "a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6"
	seed := func(feed feedfetch.Feed) {
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte(body), 0o600)
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.sha256"), []byte(old), 0o600)
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.sha1"), []byte(old), 0o600)
	}

	t.Run("remote", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		defer srv.Close()
		f, feed := fetcherFor(t)
		seed(feed)
		req := feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second}
		if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
			t.Fatalf("probe over an old-length digest: %+v, want OK and changed", res)
		}
		if res := f.Ingest(context.Background(), feed, req); !res.OK {
			t.Fatalf("ingest over an old-length digest: %+v", res)
		}
		if b, _ := os.ReadFile(filepath.Join(feed.Dir, "FEED.orig.sha1")); len(b) != 40 {
			t.Fatalf("the re-ingest recorded %q, want a SHA-1", b)
		}
	})

	t.Run("local", func(t *testing.T) {
		src := t.TempDir()
		os.WriteFile(filepath.Join(src, "list.txt"), []byte(body), 0o600)
		f, feed := fetcherFor(t)
		f.Policy.LocalDirs = []string{src}
		seed(feed)
		req := feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")}
		if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
			t.Fatalf("probe over an old-length digest: %+v, want OK and changed", res)
		}
		if res := f.Ingest(context.Background(), feed, req); !res.OK {
			t.Fatalf("ingest over an old-length digest: %+v", res)
		}
	})
}
