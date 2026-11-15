package feedfetch_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

type etReprocessor interface {
	ReprocessET(context.Context, feedfetch.Feed, feedfetch.Request) feedfetch.Result
}

func TestETReprocessRetainedGzipAndMissingRaw(t *testing.T) {
	var requests atomic.Int32
	var raw bytes.Buffer
	z := gzip.NewWriter(&raw)
	_, _ = z.Write([]byte("198.51.100.1,1,90\n198.51.100.2,2,80\n"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(raw.Bytes())
	}))
	defer server.Close()
	f := &feedfetch.Fetcher{Policy: feedfetch.Policy{NoFilter: true}, ETDir: t.TempDir(), ETMatchFile: filepath.Join(t.TempDir(), "match.txt"), ETBlock: []string{"ET_Cnc"}, ETMatch: []string{"ET_Bot"}}
	feed := feedfetch.Feed{Dir: t.TempDir(), Name: "ET"}
	req := feedfetch.Request{URL: server.URL + "/iprepdata.txt"}
	if got := f.Ingest(context.Background(), feed, req); !got.OK {
		t.Fatalf("seed: %+v", got)
	}
	// Loopback transfer is the self-hosted source path; seed its validator to prove reuse preserves it too.
	if err := os.WriteFile(filepath.Join(feed.Dir, "ET.orig.etag"), []byte(`"v1"`), 0600); err != nil {
		t.Fatal(err)
	}
	api, ok := any(f).(etReprocessor)
	if !ok {
		t.Fatal("Fetcher lacks ReprocessET")
	}
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	orig := filepath.Join(feed.Dir, "ET.orig")
	digest, etag := read(orig+".xxhash128"), read(orig+".etag")
	f.ETBlock, f.ETMatch = []string{"ET_Bot"}, []string{"ET_Cnc"}
	got := api.ReprocessET(context.Background(), feed, req)
	if !got.OK || got.Decision != feedfetch.Changed || read(orig) != "198.51.100.2\n" || read(f.ETMatchFile) != "198.51.100.1\n" || requests.Load() != 1 {
		t.Fatalf("reselection: %+v, requests %d, orig %q, match %q", got, requests.Load(), read(orig), read(f.ETMatchFile))
	}
	if read(orig+".xxhash128") != digest || read(orig+".etag") != etag {
		t.Fatal("reuse changed wire metadata")
	}
	if err := os.Remove(filepath.Join(feed.Dir, "ET.raw")); err != nil {
		t.Fatal(err)
	}
	f.ETBlock = []string{"ET_Cnc"}
	got = api.ReprocessET(context.Background(), feed, req)
	if !got.OK || got.Decision != feedfetch.Unchanged || read(orig) != "198.51.100.2\n" || requests.Load() != 1 {
		t.Fatalf("no raw must keep existing selection without download: %+v", got)
	}
}

func TestETReprocessErrorsKeepOriginalAndCleanStages(t *testing.T) {
	for _, mode := range []string{"bad gzip", "cancelled", "split error"} {
		t.Run(mode, func(t *testing.T) {
			f := &feedfetch.Fetcher{ETDir: t.TempDir(), ETBlock: []string{"ET_Cnc"}}
			api, ok := any(f).(etReprocessor)
			if !ok {
				t.Fatal("Fetcher lacks ReprocessET")
			}
			feed := feedfetch.Feed{Dir: t.TempDir(), Name: "ET"}
			orig := filepath.Join(feed.Dir, "ET.orig")
			if err := os.WriteFile(orig, []byte("last good\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var raw bytes.Buffer
			z := gzip.NewWriter(&raw)
			_, _ = z.Write([]byte("198.51.100.1,1,90\n"))
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "bad gzip" {
				raw.Reset()
				raw.WriteString("not gzip")
			}
			if mode == "split error" {
				f.ETDir = filepath.Join(t.TempDir(), "missing")
			}
			if err := os.WriteFile(filepath.Join(feed.Dir, "ET.raw"), raw.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got := api.ReprocessET(ctx, feed, feedfetch.Request{URL: "https://invalid.example/iprepdata.txt"})
			b, err := os.ReadFile(orig)
			if got.OK || got.Reason == "" || err != nil || string(b) != "last good\n" {
				t.Fatalf("%s: %+v; orig %q, %v", mode, got, b, err)
			}
			entries, err := os.ReadDir(feed.Dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".pfbstage_") {
					t.Fatalf("leaked stage %s", entry.Name())
				}
			}
		})
	}
}
