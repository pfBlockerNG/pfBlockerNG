package feedstage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Scenario: the download cannot be inspected.
// Given a published feed with its download, when inspecting the download fails for a reason other than its absence, then a
// run that parses from the baseline fails instead of taking the download for missing and transferring again: the download
// and the list stay.
func TestBaselineThatCannotBeInspectedFailsTheFeed(t *testing.T) {
	stage, feed, source := localStage(t)
	dir := stage.Paths.FeedDir
	writeFile(t, source, "198.51.100.2\n")
	orig, list := filepath.Join(dir, "feed_v4.orig"), filepath.Join(dir, "feed_v4.parsed.ip")
	writeFile(t, orig, "198.51.100.1\n")
	writeFile(t, list, "198.51.100.1\n")
	withFault(t, func(op, path string) error {
		if op == "lstat" && path == orig {
			return syscall.EIO
		}
		return nil
	})
	got := stage.Run(context.Background(), feed, Change{Force: "parse"})
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "baseline_unavailable" {
		t.Fatalf("a run whose download cannot be inspected = %+v, want failed/fetch/baseline_unavailable", got)
	}
	for _, path := range []string{orig, list} {
		if body := readFile(t, path); body != "198.51.100.1\n" {
			t.Errorf("after the failed run %s = %q, want it untouched", filepath.Base(path), body)
		}
	}
}

// Scenario: something that is no regular file stands at the download of a Hold feed.
// Given a Hold feed with its published list, when its download is a symbolic link, then the run fails instead of reading
// the download as missing and holding the list: a link is taken neither for the download nor for its absence.
func TestDownloadThatIsNoRegularFileFailsAHoldFeed(t *testing.T) {
	stage, feed, _ := localStage(t)
	feed.State = "hold"
	dir := stage.Paths.FeedDir
	target := filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, target, "198.51.100.9\n")
	orig, list := filepath.Join(dir, "feed_v4.orig"), filepath.Join(dir, "feed_v4.parsed.ip")
	if err := os.Symlink(target, orig); err != nil {
		t.Fatal(err)
	}
	writeFile(t, list, "198.51.100.1\n")
	got := stage.Run(context.Background(), feed, Change{Force: "none"})
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "baseline_unavailable" {
		t.Fatalf("a Hold run over a linked download = %+v, want failed/fetch/baseline_unavailable", got)
	}
	if info, err := os.Lstat(orig); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the linked download is left %v (%v), want the link untouched", info, err)
	}
	if body := readFile(t, list); body != "198.51.100.1\n" {
		t.Errorf("after the failed run the list = %q, want it untouched", body)
	}
}

// Scenario: Recover is given a feed folder path that is not clean.
// Given a feed folder reached through a symbolic link, when Recover gets the link's path with a trailing slash (which
// resolves through the link), or a path of the real folder that is not clean, then Recover refuses it and touches nothing.
func TestRecoverRefusesAPathThatIsNotClean(t *testing.T) {
	base := t.TempDir()
	feeds, link := filepath.Join(base, "feeds"), filepath.Join(base, "link")
	if err := os.Mkdir(feeds, 0o700); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(feeds, stagePrefix+"leftover")
	writeFile(t, leftover, "x\n")
	if err := os.Symlink(feeds, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link + "/", feeds + "/", base + "/./feeds", base + "//feeds"} {
		if err := Recover(path); err == nil {
			t.Errorf("Recover(%q) reported success, want the path refused", path)
		}
	}
	if !regularExists(leftover) {
		t.Fatal("a refused Recover removed a staged file")
	}
}
