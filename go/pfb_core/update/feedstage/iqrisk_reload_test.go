package feedstage

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// etServer serves body at every path and counts the requests.
func etServer(t *testing.T, body []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

const etCSV = "192.0.2.10,1,127\n198.51.100.20,2,88\n198.51.100.40,15,2\n"

// issue #4256: an uncompressed ET IQRisk source keeps no download to split again, so its Reload downloads it: the
// categories now selected take effect, where today's Reload splits the published split and publishes an empty list.
func TestAReloadOfAnUncompressedETFeedDownloadsAndSplitsWithTheCategoriesNowSelected(t *testing.T) {
	srv, requests := etServer(t, []byte(etCSV))
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}

	stage.Fetcher.ETBlock = []string{"ET_P2P"}
	r := run(stage, feed, "parse")

	if r.Disposition == "failed" {
		t.Fatalf("the Reload = %+v", r)
	}
	got := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip"))
	if !strings.Contains(got, "198.51.100.40") || strings.Contains(got, "192.0.2.10") {
		t.Errorf("the Reload's list %q, want ET_P2P's address alone", got)
	}
	if n := requests.Load(); n != 2 {
		t.Errorf("%d requests, want the Reload's download too", n)
	}
}

// A Hold feed whose script asks for its download to be parsed again never downloads for it: Hold is download once.
func TestAHeldETFeedWithAScriptDoesNotDownloadAgain(t *testing.T) {
	srv, requests := etServer(t, []byte(etCSV))
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	scriptDir := t.TempDir()
	stage.Paths.ScriptDirs = []string{scriptDir}
	if err := os.WriteFile(filepath.Join(scriptDir, "post.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed := testFeed("ipv4", "hold", "auto", srv.URL+"/iprepdata.txt")
	feed.PostScript = "post.sh"
	if r := run(stage, feed, "none"); r.Disposition == "failed" {
		t.Fatalf("the first run = %+v", r)
	}

	before := requests.Load()

	// stage 6 does not probe it again here: its verdict stands for what the run itself transfers
	if r := stage.Run(context.Background(), feed, Change{Verdict: VerdictUnchanged, Force: "none"}); r.Disposition == "failed" {
		t.Fatalf("the held run = %+v", r)
	}

	if n := requests.Load(); n != before {
		t.Errorf("%d requests, want %d: the held run transfers nothing", n, before)
	}
}

// A Reload whose kept download does not split fails the feed and publishes nothing: the lists stand.
func TestAReloadWhoseKeptDownloadDoesNotSplitPublishesNothing(t *testing.T) {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	io.WriteString(zw, etCSV)
	zw.Close()
	srv, _ := etServer(t, body.Bytes())
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt.gz")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}
	dir := stage.Paths.FeedDir
	parsed, orig := filepath.Join(dir, "feed_v4.parsed.ip"), filepath.Join(dir, "feed_v4.orig")
	listBefore, origBefore := readFile(t, parsed), readFile(t, orig)
	writeFile(t, filepath.Join(dir, "feed_v4.raw"), "no gzip\n")

	stage.Fetcher.ETBlock = []string{"ET_P2P"}
	r := run(stage, feed, "parse")

	if r.Disposition != "failed" {
		t.Errorf("the Reload = %+v, want failed", r)
	}
	if got := readFile(t, parsed); got != listBefore {
		t.Errorf("the list %q, want %q kept", got, listBefore)
	}
	if got := readFile(t, orig); got != origBefore {
		t.Errorf("the published copy %q, want %q kept", got, origBefore)
	}
}
