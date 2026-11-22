package feedstage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// backupsAt lists the files named as a backup of target in the feed folder dir.
func backupsAt(t *testing.T, dir, target string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+target+backupMark) {
			found = append(found, e.Name())
		}
	}
	return found
}

// killWhileBackingUp KILLs a run of a changed source while it backs up target, before the backup has its name, and checks
// that the recovery leaves the baseline and that the next run publishes the change.
func killWhileBackingUp(t *testing.T, test, target string) {
	t.Helper()
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	killAt(t, test, root, "backup:"+target)
	if found := backupsAt(t, dir, target); len(found) != 0 {
		t.Fatalf("at the KILL %v are named as backups of %s before they are whole", found, target)
	}
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for name, want := range map[string]string{"Feed_v4.orig": "198.51.100.1\n", "Feed_v4.parsed.ip": "198.51.100.1\n"} {
		if got := readFile(t, filepath.Join(dir, name)); got != want {
			t.Errorf("after recovery %s = %q, want the baseline %q", name, got, want)
		}
	}
	noLeftovers(t, dir)
	stage, feed := killStage(root)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the run after recovery = %+v, want the change published", r)
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Fatalf("the run after recovery published %q, want the changed source", got)
	}
}

// Scenario: KILL while the download is backed up.
// Given a published baseline and a changed source, when the Updater is killed while it backs up the download before the
// transfer, then no incomplete file carries a backup name, and the recovery leaves the baseline download and list.
func TestKillWhileBackingUpTheDownloadKeepsTheBaseline(t *testing.T) {
	if boundary := os.Getenv(killAtEnv); boundary != "" {
		killChildAt(os.Getenv(killRootEnv), boundary)
	}
	killWhileBackingUp(t, "TestKillWhileBackingUpTheDownloadKeepsTheBaseline", "Feed_v4.orig")
}

// Scenario: KILL while the published list is backed up.
// Given a published baseline and a changed source already transferred and parsed, when the Updater is killed while the
// publication backs up the list, then no incomplete file carries a backup name, and the recovery puts the baseline
// download back beside the list it was parsed into.
func TestKillWhileBackingUpTheListKeepsTheBaseline(t *testing.T) {
	if boundary := os.Getenv(killAtEnv); boundary != "" {
		killChildAt(os.Getenv(killRootEnv), boundary)
	}
	killWhileBackingUp(t, "TestKillWhileBackingUpTheListKeepsTheBaseline", "Feed_v4.parsed.ip")
}
