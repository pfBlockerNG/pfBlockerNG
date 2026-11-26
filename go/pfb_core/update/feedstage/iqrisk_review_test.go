package feedstage

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gzipped(t *testing.T, text string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	io.WriteString(zw, text)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// issue #4256: today a configured script makes every pass of an unchanged feed parse its download again through the reuse
// arm (pfb_list_script_reparse_active(), on Hold or not), which re-runs processet() with the categories now selected.
func TestAnUnchangedETFeedWithAScriptSplitsItsKeptDownloadAgain(t *testing.T) {
	srv, requests := etServer(t, gzipped(t, etCSV))
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	scriptDir := t.TempDir()
	stage.Paths.ScriptDirs = []string{scriptDir}
	if err := os.WriteFile(filepath.Join(scriptDir, "post.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt.gz")
	feed.PostScript = "post.sh"
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}
	before := requests.Load()

	stage.Fetcher.ETBlock = []string{"ET_P2P"}
	r := stage.Run(context.Background(), feed, Change{Verdict: VerdictUnchanged, Force: "none"})

	if r.Disposition == "failed" {
		t.Fatalf("the unchanged run = %+v", r)
	}
	got := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip"))
	if !strings.Contains(got, "198.51.100.40") || strings.Contains(got, "192.0.2.10") {
		t.Errorf("the unchanged run's list %q, want ET_P2P's address alone", got)
	}
	if n := requests.Load(); n != before {
		t.Errorf("%d requests, want %d: an unchanged run transfers nothing", n, before)
	}
}

// globCtx is cancelled from the moment a file matches its pattern, and stays cancelled, as a context does.
type globCtx struct {
	context.Context
	pattern   string
	cancelled *bool
}

func (c globCtx) Err() error {
	if m, _ := filepath.Glob(c.pattern); len(m) > 0 {
		*c.cancelled = true
	}
	if *c.cancelled {
		return context.Canceled
	}
	return nil
}

// A Reload cancelled while it splits the kept download again is cancelled, not a failed feed: it counts against no retry cap.
func TestAReloadCancelledDuringTheETSplitIsCancelled(t *testing.T) {
	srv, _ := etServer(t, gzipped(t, etCSV))
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt.gz")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}
	ctx := globCtx{context.Background(), filepath.Join(stage.Paths.FeedDir, runPrefix+feed.Name, ".pfbstage_*"), new(bool)}

	r := stage.Run(ctx, feed, Change{Force: "parse"})

	if r.Disposition != "failed" || r.Reason != "cancelled" {
		t.Errorf("the cancelled Reload = %+v, want failed, cancelled", r)
	}
}

// A Reload whose kept download does not split is no failed transfer: today's reuse arm logs no FAIL line for it, so it
// never counts against the retry cap (pfb_failures()).
func TestAReloadWhoseKeptDownloadDoesNotSplitIsNoFailedTransfer(t *testing.T) {
	srv, _ := etServer(t, gzipped(t, etCSV))
	stage := testStage(t)
	stage.Fetcher.ETDir = t.TempDir()
	stage.Fetcher.ETBlock = []string{"ET_Cnc"}
	feed := testFeed("ipv4", "enabled", "auto", srv.URL+"/iprepdata.txt.gz")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the first run = %+v", r)
	}
	writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.raw"), "no gzip\n")

	r := run(stage, feed, "parse")

	if r.Disposition != "failed" || r.Stage == "fetch" {
		t.Errorf("the Reload = %+v, want failed at a stage other than fetch", r)
	}
}
