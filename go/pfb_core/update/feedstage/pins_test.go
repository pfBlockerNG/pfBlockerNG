package feedstage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// A caller's cancellation while the IP post-script runs fails the feed as cancelled and publishes nothing.
func TestCancelDuringTheIPPostScriptIsReportedCancelled(t *testing.T) {
	ctx, script := cancelWhenScriptStarts(t)
	stage, feed, source := localStage(t)
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "blocks.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "203.0.113.1\n")
	feed.PostScript = "blocks.sh"
	got := stage.Run(ctx, feed, Change{Force: "download"})
	if got.Disposition != "failed" || got.Stage != "post-script" || got.Reason != "cancelled" {
		t.Fatalf("a run cancelled in its IP post-script = %+v, want failed/post-script/cancelled", got)
	}
	if regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")) {
		t.Fatal("a cancelled run published its list")
	}
}

// Reuse needs the published list: a matching record without its list parses the download again.
func TestReuseNeedsThePublishedList(t *testing.T) {
	stage, feed, source := localStage(t)
	writeFile(t, source, "203.0.113.1\n")
	if got := run(stage, feed, "none"); got.Disposition != "changed" {
		t.Fatalf("the first run = %+v", got)
	}
	list := filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")
	if err := os.Remove(list); err != nil {
		t.Fatal(err)
	}
	if got := run(stage, feed, "none"); got.Disposition != "reparsed" {
		t.Fatalf("the run whose list is gone = %+v, want reparsed", got)
	}
	if got := readFile(t, list); got != "203.0.113.1\n" {
		t.Fatalf("the list = %q, want the download's entry", got)
	}
}

// Force both drops the digest of the last transfer, force download keeps it: a transfer answered 304 writes none.
func TestForceBothDropsTheTransferDigest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	for force, kept := range map[string]bool{"download": true, "both": false} {
		stage := testStage(t)
		digest := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.xxhash128")
		writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), "203.0.113.1\n")
		writeFile(t, digest, "0123456789abcdef0123456789abcdef")
		got := stage.Run(context.Background(), testFeed("ipv4", "enabled", "auto", server.URL+"/feed"), Change{Force: force})
		if got.Disposition != "reparsed" {
			t.Fatalf("force %s answered 304 = %+v, want reparsed", force, got)
		}
		if regularExists(digest) != kept {
			t.Errorf("force %s: the transfer digest kept = %v, want %v", force, regularExists(digest), kept)
		}
	}
}

// A whois feed of which nothing resolves fails and keeps its last download and list.
func TestWhoisWithNothingResolvedKeepsTheLastList(t *testing.T) {
	stage := testStage(t)
	resolve := true
	stage.Fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		if resolve {
			return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
		}
		return nil, errors.New("lookup failed")
	}
	feed := testFeed("ipv4", "enabled", "whois", "one.example")
	if got := run(stage, feed, "none"); got.Disposition != "changed" {
		t.Fatalf("the first run = %+v", got)
	}
	orig, list := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")
	before := map[string]string{orig: readFile(t, orig), list: readFile(t, list)}
	resolve = false
	if got := run(stage, feed, "none"); got.Disposition != "failed" || got.Stage != "whois" || got.Reason != "whois_failed" {
		t.Fatalf("the run of which nothing resolves = %+v, want failed/whois/whois_failed", got)
	}
	for path, want := range before {
		if got := readFile(t, path); got != want {
			t.Errorf("%s = %q after nothing resolved, want %q kept", filepath.Base(path), got, want)
		}
	}
}

// A download that is no regular file is refused before the transfer, and what a link points at is never touched.
func TestDownloadThatIsNoRegularFileIsRefused(t *testing.T) {
	stage, feed, source := localStage(t)
	writeFile(t, source, "203.0.113.1\n")
	target := filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, target, "kept\n")
	orig := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")
	if err := os.Symlink(target, orig); err != nil {
		t.Fatal(err)
	}
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "baseline_backup_failed" {
		t.Fatalf("a run over a linked download = %+v, want failed/fetch/baseline_backup_failed", got)
	}
	if info, err := os.Lstat(orig); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the linked download is left %v (%v), want the link untouched", info, err)
	}
	if got := readFile(t, target); got != "kept\n" {
		t.Errorf("the link's target = %q, want it untouched", got)
	}
}
