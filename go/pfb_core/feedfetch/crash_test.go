package feedfetch_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// A process killed in the middle of a probe leaves whatever the probe had written. The next Ingest must fetch the feed
// again, never publish that partial body as if the probe had finished.
func TestAProbeKilledMidBodyLeavesNothingTheIngestPublishes(t *testing.T) {
	var hits atomic.Int32
	midBody := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Content-Length", "16")
			io.WriteString(w, "PARTIAL")
			w.(http.Flusher).Flush()
			close(midBody)
			<-release
			return
		}
		io.WriteString(w, "complete\n")
	}))
	defer srv.Close()
	defer close(release)

	f, feed := fetcherFor(t)
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
	url := "http://feed.example:" + port(t, srv.URL) + "/list"
	go f.Probe(context.Background(), feed, feedfetch.Request{URL: url, Timeout: 30 * time.Second})
	<-midBody
	// The "crash": the files as they are while the probe is still receiving its body.
	crashed := feedfetch.Feed{Dir: t.TempDir(), Name: "FEED"}
	entries, err := os.ReadDir(feed.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(feed.Dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(crashed.Dir, e.Name()), b, 0o600)
	}

	res := f.Ingest(context.Background(), crashed, feedfetch.Request{URL: url, Timeout: 30 * time.Second})
	if !res.OK || published(t, crashed) != "complete\n" || hits.Load() != 2 {
		t.Fatalf("the ingest after a killed probe must fetch again: %+v, published %q, requests %d",
			res, published(t, crashed), hits.Load())
	}
}
