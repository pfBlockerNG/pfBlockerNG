package feedstage

import (
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// Scenario: COMMIT stands, but the run folder cannot be synced after it.
// Given a published baseline and a changed source, when the sync of the run folder right after COMMIT is renamed into
// place fails, and removing the run's new list would fail too, then the run is committed: it fails at publish with
// baseline_commit_failed (the feed may have changed) and leaves its run folder whole, and Recover publishes the new
// download together with its own list, never the new list beside the old download.
func TestACommitWhoseFolderSyncFailsIsFinishedForward(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	saved := step
	t.Cleanup(func() { step = saved })
	afterCommit, failedSync := false, false
	step = func(name string) { afterCommit = afterCommit || name == "committed" }
	withFault(t, func(op, path string) error {
		run := filepath.Join(dir, ".pfbrun-Feed_v4")
		switch {
		case op == "sync" && path == run && afterCommit && !failedSync:
			failedSync = true
			return syscall.EIO
		case op == "remove" && path == filepath.Join(run, "Feed_v4.parsed.ip"):
			return syscall.EIO
		}
		return nil
	})
	stage, feed := killStage(root)
	r := run(stage, feed, "none")
	fault, step = noFault, saved
	if !failedSync {
		t.Fatal("the run never synced its run folder after COMMIT")
	}
	if r.Disposition != "failed" || r.Stage != "publish" || r.Reason != "baseline_commit_failed" {
		t.Errorf("the run = %+v, want failed at publish with baseline_commit_failed", r)
	}
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	orig, list := readFile(t, filepath.Join(dir, "Feed_v4.orig")), readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip"))
	if orig != "198.51.100.2\n" || list != "198.51.100.2\n" {
		t.Errorf("after Recover the download is %q and the list %q, want both of the new source", orig, list)
	}
	journalLeftovers(t, dir, "after Recover")
}

// Scenario: the feed folder cannot be synced once the run folder is made.
// Given a published baseline and a changed source, when syncing the feed folder fails, then the run fails at once with
// run_folder_failed: the feed folder is the baseline and no run folder is left, since a run folder that may not survive
// a power loss is no place for a commit.
func TestARunFolderThatCannotBeMadeDurableFailsTheRun(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	baseline := publishedState(t, dir)
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	withFault(t, func(op, path string) error {
		if op == "sync" && path == dir {
			return syscall.EIO
		}
		return nil
	})
	stage, feed := killStage(root)
	r := run(stage, feed, "none")
	fault = noFault
	if r.Disposition != "failed" || r.Stage != "fetch" || r.Reason != "run_folder_failed" {
		t.Errorf("the run = %+v, want failed at fetch with run_folder_failed", r)
	}
	if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
		t.Errorf("the feed folder is\n %q\nwant the baseline\n %q", got, baseline)
	}
	if found, _ := filepath.Glob(filepath.Join(dir, ".pfbrun-*")); len(found) != 0 {
		t.Errorf("the failed run left %s", strings.Join(found, ", "))
	}
}
