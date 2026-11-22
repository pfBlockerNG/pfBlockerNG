package feedstage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Scenario: a run of the feed was KILLed, and the next run comes before any Recover.
// Given a run folder an earlier run left, committed or not, when the feed runs without Recover first, then the run
// finishes the committed folder (a Hold feed then holds the list it published) or deletes the uncommitted one, and
// publishes its own change: no run folder is left either way.
func TestRunFinishesOrDeletesALeftoverRunFolder(t *testing.T) {
	t.Run("committed", func(t *testing.T) {
		stage, feed, source := localStage(t)
		writeFile(t, source, "198.51.100.1\n")
		if r := run(stage, feed, "none"); r.Disposition != "changed" {
			t.Fatalf("the baseline run = %+v", r)
		}
		dir := stage.Paths.FeedDir
		runFolder(t, dir, "feed_v4", "rename feed_v4.parsed.ip\n", map[string]string{"feed_v4.parsed.ip": "203.0.113.50\n"})
		feed.State = "hold"
		if r := run(stage, feed, "none"); r.Disposition != "held" {
			t.Fatalf("the Hold run = %+v, want held", r)
		}
		if got := readFile(t, filepath.Join(dir, "feed_v4.parsed.ip")); got != "203.0.113.50\n" {
			t.Errorf("the list is %q, want the one the committed run folder publishes", got)
		}
		journalLeftovers(t, dir, "after the Hold run")
	})
	t.Run("uncommitted", func(t *testing.T) {
		stage, feed, source := localStage(t)
		writeFile(t, source, "198.51.100.2\n")
		dir := stage.Paths.FeedDir
		runFolder(t, dir, "feed_v4", "", map[string]string{"feed_v4.parsed.ip": "203.0.113.50\n", "COMMIT.tmp": "rename x\n"})
		if r := run(stage, feed, "none"); r.Disposition != "changed" {
			t.Fatalf("the run = %+v, want the change published", r)
		}
		if got := readFile(t, filepath.Join(dir, "feed_v4.parsed.ip")); got != "198.51.100.2\n" {
			t.Errorf("the list is %q, want the run's own", got)
		}
		journalLeftovers(t, dir, "after the run")
	})
}

// Scenario: a run folder the run cannot finish, delete or make.
// Given a feed whose run folder name holds a regular file, when the feed runs, then it fails at publish with
// run_folder_unrecoverable and the file stays. Given a feed folder in which a published file cannot be inspected when
// the run folder is seeded, then the run fails at fetch with run_folder_failed and no run folder is left.
func TestRunFailsOnARunFolderItCannotUse(t *testing.T) {
	t.Run("unrecoverable", func(t *testing.T) {
		stage, feed, source := localStage(t)
		writeFile(t, source, "198.51.100.2\n")
		blocker := filepath.Join(stage.Paths.FeedDir, ".pfbrun-feed_v4")
		writeFile(t, blocker, "not a folder\n")
		r := run(stage, feed, "none")
		if r.Disposition != "failed" || r.Stage != "publish" || r.Reason != "run_folder_unrecoverable" {
			t.Errorf("the run = %+v, want failed at publish with run_folder_unrecoverable", r)
		}
		if got := readFile(t, blocker); got != "not a folder\n" {
			t.Errorf("the file at the run folder's name became %q", got)
		}
	})
	t.Run("seeding fails", func(t *testing.T) {
		stage, feed, source := localStage(t)
		writeFile(t, source, "198.51.100.2\n")
		etag := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.etag")
		writeFile(t, etag, `"old"`)
		withFault(t, func(op, path string) error {
			if op == "lstat" && path == etag {
				return syscall.EIO
			}
			return nil
		})
		r := run(stage, feed, "none")
		fault = noFault
		if r.Disposition != "failed" || r.Stage != "fetch" || r.Reason != "run_folder_failed" {
			t.Errorf("the run = %+v, want failed at fetch with run_folder_failed", r)
		}
		journalLeftovers(t, stage.Paths.FeedDir, "after the failed run")
	})
}

// Scenario: a failed transfer cannot publish what it retires.
// Given a published feed with its validators, when the transfer fails and the commit of the retired validators is not
// durable, then the feed fails at fetch with validators_retire_failed, never with the transfer's own reason: the caller
// must know the validators may still stand.
func TestAFailedRetireOfTheValidatorsIsReported(t *testing.T) {
	stage, feed, source := localStage(t)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	etag := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.etag")
	writeFile(t, etag, `"old"`)
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	withFault(t, func(op, path string) error {
		if op == "sync" && filepath.Base(path) == "COMMIT.tmp" {
			return syscall.EIO
		}
		return nil
	})
	r := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	fault = noFault
	if r.Disposition != "failed" || r.Stage != "fetch" || r.Reason != "validators_retire_failed" {
		t.Errorf("the run = %+v, want failed at fetch with validators_retire_failed", r)
	}
	if got := readFile(t, etag); got != `"old"` {
		t.Errorf("the ETag is %q, want it standing after the failed commit", got)
	}
	journalLeftovers(t, stage.Paths.FeedDir, "after the failed run")
}
