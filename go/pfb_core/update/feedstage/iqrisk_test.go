package feedstage

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// issue #4256: WHEN the ET IQRisk categories change and a Reload (force parse) runs with the source unchanged THEN the new
// split is published, as today's Reload re-runs processet() on the kept .raw; nothing is transferred again.
func TestAReloadPublishesTheSplitOfTheCategoriesNowSelected(t *testing.T) {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	zw.Write([]byte("192.0.2.10,1,127\n198.51.100.20,2,88\n198.51.100.40,15,2\n"))
	zw.Close()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write(body.Bytes())
	}))
	defer srv.Close()
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt.gz")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}
	parsed := filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")
	if got := readFile(t, parsed); !strings.Contains(got, "192.0.2.10") {
		t.Fatalf("the first run's list %q, want ET_Cnc's address", got)
	}

	stage.Fetcher.ETBlock = []string{"ET_P2P"}
	r := run(stage, feed, "parse")

	if r.Disposition != "reparsed" {
		t.Fatalf("the Reload = %+v", r)
	}
	got := readFile(t, parsed)
	if !strings.Contains(got, "198.51.100.40") || strings.Contains(got, "192.0.2.10") {
		t.Errorf("the Reload's list %q, want ET_P2P's address alone", got)
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("%d requests, want the first run's alone", n)
	}
}
