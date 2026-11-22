package feedstage

import (
	"os"
	"path/filepath"
	"reflect"
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

// Scenario: the commit of a run is not durable, or cannot be finished.
// Given a published baseline and a changed source, when syncing the run's COMMIT.tmp fails, then the feed fails at publish
// with parsed_publish_failed, the feed folder is the baseline byte for byte and no run folder is left. When instead an
// operation of the written COMMIT fails, then the feed fails at publish with baseline_commit_failed (the feed may have
// changed), its run folder stays, and Recover finishes it forward: the new download and its list stand together. Either
// way the next run publishes the change and installs its download.
func TestRunReportsACommitThatIsNotDurable(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		fail         func(op, path string) bool
		want         string // the download after Recover
	}{
		{"COMMIT.tmp not synced", "parsed_publish_failed", func(op, path string) bool {
			return op == "sync" && filepath.Base(path) == "COMMIT.tmp"
		}, "198.51.100.1\n"},
		{"an operation of COMMIT fails", "baseline_commit_failed", func(op, path string) bool {
			return op == "rename" && filepath.Base(path) == "Feed_v4.parsed.ip" &&
				strings.HasPrefix(filepath.Base(filepath.Dir(path)), ".pfbrun-")
		}, "198.51.100.2\n"},
	} {
		root := killRoot(t, "198.51.100.1\n")
		dir := filepath.Join(root, "orig")
		baseline := publishedState(t, dir)
		writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
		withFault(t, func(op, path string) error {
			if tc.fail(op, path) {
				return syscall.EIO
			}
			return nil
		})
		stage, feed := killStage(root)
		r := run(stage, feed, "none")
		fault = noFault
		if r.Disposition != "failed" || r.Stage != "publish" || r.Reason != tc.reason {
			t.Errorf("%s: the run = %+v, want failed at publish with %s", tc.name, r, tc.reason)
		}
		if tc.reason == "parsed_publish_failed" {
			if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
				t.Errorf("%s: the feed folder is\n %q\nwant the baseline\n %q", tc.name, got, baseline)
			}
			runLeftovers(t, dir, tc.name+", after the failed run")
		} else if !committed(dir) {
			t.Errorf("%s: the failed run left no committed run folder for Recover to finish", tc.name)
		}
		if err := Recover(dir); err != nil {
			t.Fatalf("%s: Recover: %v", tc.name, err)
		}
		if got := readFile(t, filepath.Join(dir, "Feed_v4.orig")); got != tc.want {
			t.Errorf("%s: after Recover the download is %q, want %q", tc.name, got, tc.want)
		}
		if tc.want == "198.51.100.2\n" {
			if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != tc.want {
				t.Errorf("%s: after Recover the list is %q, want the one of the new download", tc.name, got)
			}
		}
		runLeftovers(t, dir, tc.name+", after Recover")
		if r := run(stage, feed, "none"); r.Disposition == "failed" {
			t.Errorf("%s: the next run = %+v", tc.name, r)
		}
		for _, name := range []string{"Feed_v4.parsed.ip", "Feed_v4.orig"} {
			if got := readFile(t, filepath.Join(dir, name)); got != "198.51.100.2\n" {
				t.Errorf("%s: the next run left %s = %q, want the change", tc.name, name, got)
			}
		}
	}
}
