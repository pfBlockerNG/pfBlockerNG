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

// The files a previous Core version left: the published copy, a stored ETag and the SHA-256 of the same bytes, with
// no SHA-1 baseline (or, in sidecar, a 64-hex value in ".orig.sha1"). The probe must read the feed as changed even when
// the server would answer the ETag with 304 and a local source holds the same bytes; the ingest then records the SHA-1
// and drops the legacy file, so the next probe is unchanged again.
func TestAPreviousVersionsFilesReIngestDespiteA304OrIdenticalBytes(t *testing.T) {
	const body = "same\n"
	const old = "a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6" // SHA-256("same\n")
	for _, sidecar := range []string{"FEED.orig.sha256", "FEED.orig.sha1"} {
		seed := func(feed feedfetch.Feed) {
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte(body), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, "FEED.orig.etag"), []byte(`"v1"`), 0o600)
			os.WriteFile(filepath.Join(feed.Dir, sidecar), []byte(old), 0o600)
		}
		cycle := func(t *testing.T, f *feedfetch.Fetcher, feed feedfetch.Feed, req feedfetch.Request) {
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
				t.Fatalf("probe over %s: %+v, want OK and changed", sidecar, res)
			}
			if res := f.Ingest(context.Background(), feed, req); !res.OK {
				t.Fatalf("ingest over %s: %+v", sidecar, res)
			}
			if b, _ := os.ReadFile(filepath.Join(feed.Dir, "FEED.orig.sha1")); len(b) != 40 {
				t.Fatalf("the re-ingest recorded %q, want a SHA-1", b)
			}
			if _, err := os.Stat(filepath.Join(feed.Dir, "FEED.orig.sha256")); !os.IsNotExist(err) {
				t.Fatalf("the legacy digest outlived the re-ingest: %v", err)
			}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
				t.Fatalf("probe after the re-ingest: %+v, want OK and unchanged", res)
			}
		}

		t.Run("remote 304 "+sidecar, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				if r.Header.Get("If-None-Match") == `"v1"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				io.WriteString(w, body)
			}))
			defer srv.Close()
			f, feed := fetcherFor(t)
			seed(feed)
			cycle(t, f, feed, feedfetch.Request{URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 30 * time.Second})
		})

		t.Run("local "+sidecar, func(t *testing.T) {
			src := t.TempDir()
			os.WriteFile(filepath.Join(src, "list.txt"), []byte(body), 0o600)
			f, feed := fetcherFor(t)
			f.Policy.LocalDirs = []string{src}
			seed(feed)
			cycle(t, f, feed, feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")})
		})
	}
}
