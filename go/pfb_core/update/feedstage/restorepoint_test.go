package feedstage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// withStep sets the step seam for the rest of the test.
func withStep(t *testing.T, f func(name string)) {
	t.Helper()
	saved := step
	t.Cleanup(func() { step = saved })
	step = f
}

// killedAfterPostScript leaves in dir what a KILL right after an IP post-script leaves of a run of feed that transferred
// a changed source: the download set over the old download (oldBody) uncommitted, the new download (newBody) at the restore
// point, and the script's output at the download. The old sidecars are the set's backups; the new ones stand.
func killedAfterPostScript(t *testing.T, feed feedfetch.Feed, oldBody, newBody string) map[string]string {
	t.Helper()
	old := map[string]string{".orig": oldBody, ".orig.xxhash128": "old digest", ".orig.etag": `"old"`}
	for suffix, body := range old {
		writeFile(t, feedPath(feed, suffix), body)
	}
	if _, err := snapshotPaths(feedStatePaths(feed)); err != nil {
		t.Fatal(err)
	}
	for suffix, body := range map[string]string{".orig": newBody, ".orig.xxhash128": "new digest", ".orig.etag": `"new"`} {
		replaceFile(t, feedPath(feed, suffix), body)
	}
	writeFile(t, feedPath(feed, restorePoint), newBody)
	writeFile(t, feedPath(feed, ".orig"), "script output\n") // in place, as the IP post-script writes
	return old
}

// Scenario: Recover cannot put a restore point back.
// Given what a KILL after an IP post-script leaves (an uncommitted download set and the new download at the restore point),
// when Recover cannot rename the restore point back, then Recover fails and keeps the set: rolled back now, its backups
// would be gone when a later Recover renames the restore point (the uncommitted download) over the old download. The retry
// then puts back the old download with its sidecars.
func TestRecoverRollsADownloadBackOnlyAfterItsRestorePoint(t *testing.T) {
	dir := t.TempDir()
	feed := feedfetch.Feed{Dir: dir, Name: "a_v4"}
	old := killedAfterPostScript(t, feed, "198.51.100.1\n", "198.51.100.2\n")
	restore := feedPath(feed, restorePoint)
	withFault(t, func(op, path string) error {
		if op == "rename" && path == restore {
			return syscall.EIO
		}
		return nil
	})
	if err := Recover(dir); err == nil {
		t.Fatal("the Recover that could not put the restore point back reported success")
	}
	if found := backupsAt(t, dir, "a_v4.orig"); len(found) != 1 {
		t.Fatalf("after the first Recover the download has backups %v, want its one backup kept while the restore point stays", found)
	}
	fault = noFault
	if err := Recover(dir); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	for suffix, want := range old {
		if got := readFile(t, feedPath(feed, suffix)); got != want {
			t.Errorf("after the retry a_v4%s = %q, want the old %q", suffix, got, want)
		}
	}
	journalLeftovers(t, dir, "after the retry")
}

// Scenario: a run finds what a KILL after the post-script left.
// Given what a KILL after an IP post-script leaves, when the next run starts without a Recover, then it puts the restore
// point back before it rolls the set back, as Recover does: the old download stands, with no restore point left to go over
// it later.
func TestRunFinishesALeftoverRestorePointBeforeItsSet(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	feed := feedfetch.Feed{Dir: dir, Name: "Feed_v4"}
	killedAfterPostScript(t, feed, "198.51.100.1\n", "198.51.100.2\n")
	stage, f := killStage(root)
	if r := stage.Run(context.Background(), f, Change{Force: "parse"}); r.Disposition == "failed" {
		t.Fatalf("the run after the KILL = %+v", r)
	}
	if _, err := os.Lstat(feedPath(feed, restorePoint)); !os.IsNotExist(err) {
		t.Fatalf("the run left the restore point (%v), which a later Recover would put over the old download", err)
	}
	for _, suffix := range []string{".orig", ".parsed.ip"} {
		if got := readFile(t, feedPath(feed, suffix)); got != "198.51.100.1\n" {
			t.Errorf("after the run Feed_v4%s = %q, want the old download's", suffix, got)
		}
	}
	journalLeftovers(t, dir, "after the run")
}

// Scenario: an IP post-script removes its own restore point.
// Given a published baseline and a changed source, when the IP post-script rewrites the new download and removes the
// restore point, so that the download cannot be put back, then the feed fails at the post-script before its list is
// published, and the journal puts the baseline download back: the script's output never becomes the baseline.
func TestPostScriptRestoreThatFailsFailsTheFeed(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	script := "#!/bin/sh\nprintf '10.9.9.9\\n' > \"$1\"\nrm -f \"$1.post\"\n"
	if err := os.WriteFile(filepath.Join(root, "scripts", "post.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	stage, feed := killStage(root)
	feed.PostScript = "post.sh"
	got := run(stage, feed, "none")
	if got.Disposition != "failed" || got.Stage != "post-script" || got.Reason != "post_script_restore_failed" {
		t.Fatalf("the run whose download cannot be put back = %+v, want failed/post-script/post_script_restore_failed", got)
	}
	for _, name := range []string{"Feed_v4.orig", "Feed_v4.parsed.ip"} {
		if body := readFile(t, filepath.Join(dir, name)); body != "198.51.100.1\n" {
			t.Errorf("after the failed run %s = %q, want the baseline's", name, body)
		}
	}
	journalLeftovers(t, dir, "after the failed run")
}

// Scenario: the restore point cannot be renamed back during the run.
// Given a published baseline and a changed source, when the IP post-script succeeds but its restore point cannot be
// renamed back over the download, then the run fails before its list is published and leaves its download set to Recover:
// rolled back now, the set would leave the restore point (the new download) to go over the baseline later. Once the rename
// can be made again, Recover puts the baseline download back.
func TestRunKeepsItsDownloadSetWhileTheRestorePointStays(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	orig, aside := filepath.Join(dir, "Feed_v4.orig"), filepath.Join(root, "aside")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	if err := os.WriteFile(filepath.Join(root, "scripts", "post.sh"), []byte("#!/bin/sh\nprintf '10.9.9.9\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A folder that is not empty at the download fails every rename over it, until the test takes it away.
	withStep(t, func(name string) {
		if name != "post-script" {
			return
		}
		if err := os.Rename(orig, aside); err != nil {
			t.Error(err)
		}
		if err := os.MkdirAll(filepath.Join(orig, "busy"), 0o700); err != nil {
			t.Error(err)
		}
	})
	stage, feed := killStage(root)
	feed.PostScript = "post.sh"
	got := run(stage, feed, "none")
	step = func(string) {}
	if got.Disposition != "failed" || got.Stage != "publish" || got.Reason != "baseline_restore_failed" {
		t.Fatalf("the run whose restore point cannot be put back = %+v, want failed/publish/baseline_restore_failed", got)
	}
	if !regularExists(filepath.Join(dir, "Feed_v4"+restorePoint)) || len(backupsAt(t, dir, "Feed_v4.orig")) != 1 {
		t.Fatalf("the failed run did not keep both its restore point and the download's backup")
	}
	if err := os.RemoveAll(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, orig); err != nil {
		t.Fatal(err)
	}
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for _, name := range []string{"Feed_v4.orig", "Feed_v4.parsed.ip"} {
		if body := readFile(t, filepath.Join(dir, name)); body != "198.51.100.1\n" {
			t.Errorf("after Recover %s = %q, want the baseline's", name, body)
		}
	}
	journalLeftovers(t, dir, "after Recover")
}

// Scenario: the post-script is installed while the run is under way.
// Given a published download, a server that answers 304 and a configured IP post-script not yet installed when the run
// starts, when the script is installed before it runs, rewrites the download in place and the publication then fails, then
// the download is put back as it was: the backup follows the configured name, a copy the script cannot write through.
func TestLatePostScriptNeverReachesTheBackup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	stage := testStage(t)
	scripts := t.TempDir()
	stage.Paths.ScriptDirs = []string{scripts}
	dir := stage.Paths.FeedDir
	orig := filepath.Join(dir, "feed_v4.orig")
	writeFile(t, orig, "203.0.113.1\n")
	// A folder where the list goes fails the publication.
	if err := os.Mkdir(filepath.Join(dir, "feed_v4.parsed.ip"), 0o700); err != nil {
		t.Fatal(err)
	}
	withStep(t, func(name string) {
		if name != "backup:feed_v4.orig" {
			return
		}
		if err := os.WriteFile(filepath.Join(scripts, "post.sh"), []byte("#!/bin/sh\nprintf '10.9.9.9\\n' > \"$1\"\n"), 0o755); err != nil {
			t.Error(err)
		}
	})
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	feed.PostScript = "post.sh"
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	if got.Disposition != "failed" || got.Stage != "publish" {
		t.Fatalf("the run whose publication fails = %+v, want failed at publish", got)
	}
	if body := readFile(t, orig); body != "203.0.113.1\n" {
		t.Fatalf("after the failed run the download is %q, want the download before the run", body)
	}
	journalLeftovers(t, dir, "after the failed run")
}
