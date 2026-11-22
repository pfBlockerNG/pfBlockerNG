package feedstage

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func noFault(string, string) error { return nil }

// withFault sets the fault seam for the rest of the test.
func withFault(t *testing.T, f func(op, path string) error) {
	t.Helper()
	saved := fault
	t.Cleanup(func() { fault = saved })
	fault = f
}

// replaceFile gives path new content under a new inode, as every writer of a feed's files does: by a rename.
func replaceFile(t *testing.T, path, body string) {
	t.Helper()
	staged := filepath.Join(filepath.Dir(path), "staged.new")
	writeFile(t, staged, body)
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
}

// Scenario: a rollback cannot read a backup.
// Given a set over a download that was replaced since, when the rollback cannot read the backup for a reason other than
// its absence, then the rollback fails and keeps the backup, so that the next rollback still puts the download back.
func TestRollbackKeepsABackupItCannotRead(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a_v4.orig")
	writeFile(t, target, "old\n")
	set, err := snapshotPaths([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, target, "new\n")
	backup := set.entries[0].path
	withFault(t, func(op, path string) error {
		if op == "lstat" && path == backup {
			return syscall.EIO
		}
		return nil
	})
	if err := set.rollback(); err == nil {
		t.Errorf("the rollback that could not read the backup reported success")
	}
	if !regularExists(backup) {
		t.Fatalf("the rollback removed the backup it could not read: the download %q can no longer be put back",
			readFile(t, target))
	}
	fault = noFault
	if err := set.rollback(); err != nil {
		t.Fatalf("the next rollback: %v", err)
	}
	if got := readFile(t, target); got != "old\n" {
		t.Errorf("after the next rollback the download is %q, want the old one", got)
	}
	journalLeftovers(t, dir, "after the next rollback")
}

// Scenario: a commit marker that cannot be synced.
// Given a set over a replaced download, when syncing its commit marker fails, then the commit reports the error and keeps
// the set's entries. A marker removed again leaves the set to roll back to the old download; a marker that cannot be
// removed leaves the set committed: the rollback leaves it alone, and Recover finishes it forward to the new download.
func TestCommitThatIsNotDurableIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name        string
		markerStays bool
		want        string // the download after the rollback and Recover
	}{
		{"marker removed again", false, "old\n"},
		{"marker stays", true, "new\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "a_v4.orig")
			writeFile(t, target, "old\n")
			set, err := snapshotPaths([]string{target})
			if err != nil {
				t.Fatal(err)
			}
			replaceFile(t, target, "new\n")
			marker := filepath.Join(dir, commitMark+set.id)
			withFault(t, func(op, path string) error {
				if path == marker && (op == "sync" || op == "remove" && tc.markerStays) {
					return syscall.EIO
				}
				return nil
			})
			if err := set.commit(); err == nil {
				t.Fatalf("the commit whose marker could not be synced reported success")
			}
			if !regularExists(set.entries[0].path) {
				t.Fatalf("the commit that is not durable removed the backup")
			}
			if got := regularExists(marker); got != tc.markerStays {
				t.Errorf("after the commit the marker exists = %v, want %v", got, tc.markerStays)
			}
			rollbackErr := set.rollback()
			fault = noFault
			if rollbackErr != nil {
				t.Fatalf("the rollback: %v", rollbackErr)
			}
			if err := Recover(dir); err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if got := readFile(t, target); got != tc.want {
				t.Errorf("after the rollback and Recover the download is %q, want %q", got, tc.want)
			}
			journalLeftovers(t, dir, "after Recover")
		})
	}
}

// Scenario: the commit of the download's set is not durable.
// Given a published baseline and a changed source, when syncing the marker of the run's last commit (the download's set,
// after the lists' set) fails, then the feed fails at publish with baseline_commit_failed. The download goes back to the
// baseline when the marker could be removed again, and stays the new one, finished by Recover, when it could not; the
// next run then publishes the change.
func TestRunReportsACommitThatIsNotDurable(t *testing.T) {
	for _, tc := range []struct {
		markerStays bool
		want        string
	}{{false, "198.51.100.1\n"}, {true, "198.51.100.2\n"}} {
		root := killRoot(t, "198.51.100.1\n")
		dir := filepath.Join(root, "orig")
		writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
		markers, last := 0, ""
		withFault(t, func(op, path string) error {
			if !strings.HasPrefix(filepath.Base(path), commitMark) {
				return nil
			}
			if op == "sync" {
				if markers++; markers == 2 {
					last = path
				}
			}
			if path == last && (op == "sync" || op == "remove" && tc.markerStays) {
				return syscall.EIO
			}
			return nil
		})
		stage, feed := killStage(root)
		r := run(stage, feed, "none")
		fault = noFault
		if r.Disposition != "failed" || r.Stage != "publish" || r.Reason != "baseline_commit_failed" {
			t.Errorf("marker stays %v: the run whose download commit is not durable = %+v, want failed at publish with "+
				"baseline_commit_failed", tc.markerStays, r)
		}
		if err := Recover(dir); err != nil {
			t.Fatalf("marker stays %v: Recover: %v", tc.markerStays, err)
		}
		if got := readFile(t, filepath.Join(dir, "Feed_v4.orig")); got != tc.want {
			t.Errorf("marker stays %v: after Recover the download is %q, want %q", tc.markerStays, got, tc.want)
		}
		noLeftovers(t, dir)
		if r := run(stage, feed, "none"); r.Disposition == "failed" {
			t.Errorf("marker stays %v: the next run = %+v", tc.markerStays, r)
		}
		if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
			t.Errorf("marker stays %v: the next run left the list %q, want the change", tc.markerStays, got)
		}
	}
}

// Scenario: an absent record beside a backup of the same target, the backup unreadable.
// Given a set holding a backup and an absent record of one target, when the first rollback cannot read the backup, then the
// absent record stays beside it: the next rollback must still let the record beat the backup, so that the target ends up
// absent and the old copy never comes back over it.
func TestAbsentRecordOutlivesABackupThatFailed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Feed_v4.orig.etag")
	writeFile(t, target, "old\n")
	set, err := snapshotPaths([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	set.keepAbsent(target)
	if len(set.entries) != 2 {
		t.Fatalf("the set holds %d entries, want a backup and an absent record", len(set.entries))
	}
	replaceFile(t, target, "new\n")
	backup, record := set.entries[0].path, set.entries[1].path
	withFault(t, func(op, path string) error {
		if op == "lstat" && path == backup {
			return syscall.EIO
		}
		return nil
	})
	if err := set.rollback(); err == nil {
		t.Errorf("the rollback that could not read the backup reported success")
	}
	if !regularExists(record) {
		t.Fatalf("the rollback removed the absent record while its backup stays")
	}
	fault = noFault
	if err := set.rollback(); err != nil {
		t.Fatalf("the next rollback: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("after the next rollback the target exists (%v), want it absent", err)
	}
	journalLeftovers(t, dir, "after the next rollback")
}

// Scenario: a committed set whose entries could not all be removed.
// Given a commit whose marker is durable but whose finish fails on a backup, when the set is rolled back afterwards, then
// the rollback does nothing: the new files stay.
func TestRollbackOfACommittedSetWhoseFinishFailedKeepsTheNewFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a_v4.orig")
	writeFile(t, target, "old\n")
	set, err := snapshotPaths([]string{target})
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, target, "new\n")
	backup := set.entries[0].path
	withFault(t, func(op, path string) error {
		if op == "remove" && path == backup {
			return syscall.EIO
		}
		return nil
	})
	if err := set.commit(); err != nil {
		t.Fatalf("the commit whose marker is durable: %v", err)
	}
	if err := set.rollback(); err != nil {
		t.Fatalf("the rollback of a committed set: %v", err)
	}
	if got := readFile(t, target); got != "new\n" {
		t.Errorf("after the rollback of a committed set the download is %q, want the new one", got)
	}
}
