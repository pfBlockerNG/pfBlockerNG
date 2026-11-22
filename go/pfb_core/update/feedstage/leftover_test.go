package feedstage

import (
	"os"
	"path/filepath"
	"testing"
)

// Scenario: a set a failed rollback left behind.
// Given a run whose rollback fails, so that its set stays in the feed folder (its pre-script replaced the download with a
// folder, which the backup cannot be renamed over, and failed), and then a run that publishes a second source, when a
// third run is KILLed while it backs up the download and the folder is recovered, then the download and the list are the
// second run's: the first set never puts its older download back over a newer one.
func TestLeftoverSetNeverPutsAnOlderDownloadBack(t *testing.T) {
	if boundary := os.Getenv(killAtEnv); boundary != "" {
		killChildAt(os.Getenv(killRootEnv), boundary)
	}
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	orig, source := filepath.Join(dir, "Feed_v4.orig"), filepath.Join(root, "db", "feed.txt")
	writeFile(t, source, "198.51.100.2\n")
	killScript(t, root, "pre.sh", "rm -f '"+orig+"' && mkdir '"+orig+"'; exit 1")
	stage, feed := killStage(root)
	feed.PreScript = "pre.sh"
	if r := run(stage, feed, "none"); r.Disposition != "failed" || r.Reason != "baseline_restore_failed" {
		t.Fatalf("the run whose rollback meets a folder = %+v, want failed with baseline_restore_failed", r)
	}
	if found := backupsAt(t, dir, "Feed_v4.orig"); len(found) != 1 {
		t.Fatalf("the failed rollback left the backups %v of the download, want one", found)
	}
	if err := os.Remove(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "scripts", "pre.sh")); err != nil {
		t.Fatal(err)
	}

	writeFile(t, source, "198.51.100.3\n")
	stage, feed = killStage(root)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the second run = %+v, want the second source published", r)
	}
	writeFile(t, source, "198.51.100.4\n")
	killAt(t, "TestLeftoverSetNeverPutsAnOlderDownloadBack", root, "backup:Feed_v4.orig")
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for name, want := range map[string]string{"Feed_v4.orig": "198.51.100.3\n", "Feed_v4.parsed.ip": "198.51.100.3\n"} {
		if got := readFile(t, filepath.Join(dir, name)); got != want {
			t.Errorf("after the third run's KILL and Recover %s = %q, want the second run's %q", name, got, want)
		}
	}
	noLeftovers(t, dir)
}

// Scenario: a set left behind that the next run cannot finish.
// Given a run whose rollback fails and leaves its set, when the next run of the feed cannot finish that set either (the
// folder is still in the download's place), then the run fails at publish with baseline_restore_failed and opens no set
// of its own: the folder still holds only the first set's backup.
func TestLeftoverSetThatCannotBeFinishedFailsTheFeed(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	orig := filepath.Join(dir, "Feed_v4.orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	killScript(t, root, "pre.sh", "rm -f '"+orig+"' && mkdir '"+orig+"'; exit 1")
	stage, feed := killStage(root)
	feed.PreScript = "pre.sh"
	if r := run(stage, feed, "none"); r.Reason != "baseline_restore_failed" {
		t.Fatalf("the run whose rollback meets a folder = %+v, want baseline_restore_failed", r)
	}
	left := backupsAt(t, dir, "Feed_v4.orig")
	if err := os.Remove(filepath.Join(root, "scripts", "pre.sh")); err != nil {
		t.Fatal(err)
	}
	stage, feed = killStage(root)
	if r := stage.Run(t.Context(), feed, Change{Force: "download"}); r.Disposition != "failed" || r.Stage != "publish" ||
		r.Reason != "baseline_restore_failed" {
		t.Errorf("the next run over the set it cannot finish = %+v, want failed at publish with baseline_restore_failed", r)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != left[0] && e.Name()[0] == '.' {
			t.Errorf("the next run left %s beside the first set's backup %s", e.Name(), left[0])
		}
	}
}
