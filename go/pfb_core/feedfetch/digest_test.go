package feedfetch_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// #3925: the published copy's raw-byte digest is the xxh128 PHP writes, recorded as ".orig.xxhash128".
func TestThePublishedDigestIsTheXXH128OfTheRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pfBlockerNG") }))
	defer srv.Close()
	f, feed := fetcherFor(t)
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.md5"), []byte("edd79a4a2824e07a01a70285409d6bca"), 0o600)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second})
	b, _ := os.ReadFile(filepath.Join(feed.Dir, "FEED.orig.xxhash128"))
	// xxh128("pfBlockerNG"), the vector tests/php/FeedChangeHashHelpersTest.php pins for PHP; the digest is of the bytes
	// before the trailing newline is added.
	if !res.OK || string(b) != "4a2690170244f2e853151c59fbcb2105" {
		t.Fatalf("ingest %+v recorded %q, want the xxh128 of the raw body", res, b)
	}
	// PHP's write replaces a legacy md5 sidecar (pfb_hash_write).
	if _, err := os.Stat(filepath.Join(feed.Dir, "FEED.orig.md5")); !os.IsNotExist(err) {
		t.Fatalf("the legacy md5 sidecar outlived the ingest: %v", err)
	}
}

// A baseline PHP wrote (pfb_hash_write: 32 lowercase hex, no newline; pfb_hash_read trims) reads as unchanged: a remote
// feed that answers 200 with the same bytes keeps no probe body, so the next ingest has nothing to publish and nothing
// is downloaded again; a local feed with the same bytes is unchanged.
func TestABaselinePHPWroteReadsAsUnchanged(t *testing.T) {
	const body = "same\n"
	for kind, sidecar := range map[string]string{ // xxh128("same\n")
		"as PHP writes it": "7e1402559176eb98e66aa82c39de3587",
		"with a newline":   "7e1402559176eb98e66aa82c39de3587\n",
	} {
		seed := func(feed feedfetch.Feed) {
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte(body), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.xxhash128"), []byte(sidecar), 0o600)
		}

		t.Run("remote "+kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			f, feed := fetcherFor(t)
			seed(feed)
			req := feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
				t.Fatalf("probe over PHP's baseline %q: %+v, want OK and unchanged", sidecar, res)
			}
			if _, err := os.Stat(filepath.Join(feed.Dir, "FEED.probe")); !os.IsNotExist(err) {
				t.Fatalf("an unchanged probe kept its body: %v", err)
			}
		})

		t.Run("local "+kind, func(t *testing.T) {
			src := t.TempDir()
			os.WriteFile(filepath.Join(src, "list.txt"), []byte(body), 0o600)
			f, feed := fetcherFor(t)
			f.Policy.LocalDirs = []string{src}
			seed(feed)
			// Not the published bytes: only the sidecar can say unchanged.
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("published copy\n"), 0o600)
			req := feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
				t.Fatalf("probe over PHP's baseline %q: %+v, want OK and unchanged", sidecar, res)
			}
		})
	}
}

// pfb_hash_read's legacy rule: with no ".orig.xxhash128", a valid ".orig.md5" is the baseline. A local feed compares
// its md5; a remote 200 cannot confirm unchanged against it (pfb_update_check collapses it to no baseline), so it
// re-ingests once and the ingest replaces the md5 with an xxh128.
func TestALegacyMD5BaselineIsReadTheWayPHPReadsIt(t *testing.T) {
	const body = "same\n"
	const md5 = "847676261680bff61c72961c8198abc0" // md5("same\n")
	seed := func(feed feedfetch.Feed) {
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("published copy\n"), 0o600)
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.md5"), []byte(md5+"\n"), 0o600)
	}

	t.Run("local", func(t *testing.T) {
		src := t.TempDir()
		os.WriteFile(filepath.Join(src, "list.txt"), []byte(body), 0o600)
		f, feed := fetcherFor(t)
		f.Policy.LocalDirs = []string{src}
		seed(feed)
		req := feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")}
		if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
			t.Fatalf("probe over a matching md5: %+v, want OK and unchanged", res)
		}
		os.WriteFile(filepath.Join(src, "list.txt"), []byte("new\n"), 0o600)
		if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
			t.Fatalf("probe over a different md5: %+v, want OK and changed", res)
		}
		if res := f.Ingest(context.Background(), feed, req); !res.OK {
			t.Fatalf("ingest: %+v", res)
		}
		b, _ := os.ReadFile(filepath.Join(feed.Dir, "FEED.orig.xxhash128"))
		if string(b) != "07baf267a0c0ef53ec95a82711cc4758" { // xxh128("new\n")
			t.Fatalf("the ingest recorded %q, want the xxh128 of the source", b)
		}
		if _, err := os.Stat(filepath.Join(feed.Dir, "FEED.orig.md5")); !os.IsNotExist(err) {
			t.Fatalf("the legacy md5 sidecar outlived the ingest: %v", err)
		}
	})

	t.Run("remote", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		defer srv.Close()
		f, feed := fetcherFor(t)
		seed(feed)
		req := feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second}
		if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
			t.Fatalf("remote probe over an md5 baseline: %+v, want OK and changed", res)
		}
	})
}

// pfb_hash_read fails safe: an ".orig.xxhash128" that is not 32 lowercase hex is no baseline, even beside a valid
// ".orig.md5" (it is not consulted). A local feed then hashes the published copy; a remote 200 is changed.
func TestAnUnreadableXXH128SidecarIsNoBaseline(t *testing.T) {
	const body = "same\n"
	for i, bad := range []string{
		"",
		"7E1402559176EB98E66AA82C39DE3587",         // uppercase
		"7e1402559176eb98e66aa82c39de358",          // 31 digits
		"7e1402559176eb98e66aa82c39de3587 x",       // trailing word
		"a9993e364706816aba3e25717850c26c9cd0d89d", // a 40-hex SHA-1
	} {
		seed := func(feed feedfetch.Feed, published string) {
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte(published), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.xxhash128"), []byte(bad), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.md5"), []byte("847676261680bff61c72961c8198abc0"), 0o600)
		}

		t.Run("remote "+strconv.Itoa(i), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			f, feed := fetcherFor(t)
			seed(feed, body)
			req := feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
				t.Fatalf("probe over sidecar %q: %+v, want OK and changed", bad, res)
			}
		})

		t.Run("local "+strconv.Itoa(i), func(t *testing.T) {
			src := t.TempDir()
			os.WriteFile(filepath.Join(src, "list.txt"), []byte(body), 0o600)
			f, feed := fetcherFor(t)
			f.Policy.LocalDirs = []string{src}
			req := feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")}
			seed(feed, "published copy\n")
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
				t.Fatalf("probe over sidecar %q and a different published copy: %+v, want OK and changed", bad, res)
			}
			seed(feed, body)
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
				t.Fatalf("probe over sidecar %q and the same published copy: %+v, want OK and unchanged", bad, res)
			}
		})
	}
}
