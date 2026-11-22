package feedstage

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// runFolder makes the run folder of the feed stem in the feed folder dir with files, and COMMIT holding commit unless it
// is "": what a KILL leaves of a run.
func runFolder(t *testing.T, dir, stem, commit string, files map[string]string) string {
	t.Helper()
	run := filepath.Join(dir, ".pfbrun-"+stem)
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		writeFile(t, filepath.Join(run, name), body)
	}
	if commit != "" {
		writeFile(t, filepath.Join(run, "COMMIT"), commit)
	}
	return run
}

// assertFiles fails unless the feed folder dir holds exactly the regular files want.
func assertFiles(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			t.Errorf("%s is left a %v", e.Name(), e.Type())
			continue
		}
		got[e.Name()] = readFile(t, filepath.Join(dir, e.Name()))
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s = %q, want %q", name, got[name], body)
		}
		delete(got, name)
	}
	for name := range got {
		t.Errorf("%s is left", name)
	}
}

// Scenario: an Update was killed in the middle of two feeds.
// Given a run folder that holds its COMMIT, part of whose operations were done, and a run folder without COMMIT, when the
// next Update recovers the feed folder, then the committed run is finished forward (a rename whose source is gone is done,
// the removal of a missing file is done), the uncommitted run is deleted with the feed's files untouched, and no run
// folder is left.
func TestRecoverFinishesACommittedRunAndDropsAnUncommittedOne(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a_v4.orig":           "new download of a\n", // renamed in before the KILL
		"a_v4.orig.etag":      `"old"`,
		"a_v4.parsed.ip":      "old list of a\n",
		"b_v4.orig":           "download of b\n",
		"b_v4.parsed.ip":      "list of b\n",
		"b_v4.orig.xxhash128": "digest of b\n",
	} {
		writeFile(t, filepath.Join(dir, name), body)
	}
	runFolder(t, dir, "a_v4", "remove a_v4.orig.xxhash128\nremove a_v4.orig.etag\nrename a_v4.orig\nrename a_v4.parsed.ip\n"+
		"rename a_v4.parsed.src.xxhash128\n", map[string]string{
		"a_v4.parsed.ip":            "new list of a\n",
		"a_v4.parsed.src.xxhash128": "record of a\n",
		"a_v4.pre":                  "staged pre-script copy\n",
	})
	runFolder(t, dir, "b_v4", "", map[string]string{
		"b_v4.orig":      "abandoned download of b\n",
		"b_v4.parsed.ip": "abandoned list of b\n",
		"COMMIT.tmp":     "rename b_v4.orig\n",
	})
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	assertFiles(t, dir, map[string]string{
		"a_v4.orig":                 "new download of a\n",
		"a_v4.parsed.ip":            "new list of a\n",
		"a_v4.parsed.src.xxhash128": "record of a\n",
		"b_v4.orig":                 "download of b\n",
		"b_v4.parsed.ip":            "list of b\n",
		"b_v4.orig.xxhash128":       "digest of b\n",
	})
}

// Scenario: a committed run left a published file as it found it.
// Given a run folder whose COMMIT renames the download while its file is still the hard link the run was seeded with, when
// Recover finishes it, then that operation is skipped, never tried: a rename of a file over a link of itself does nothing
// and would leave its source behind. The download stands and the run folder is gone.
func TestCommitSkipsAFileTheRunLeftAsItWas(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "a_v4.orig")
	writeFile(t, orig, "download of a\n")
	run := runFolder(t, dir, "a_v4", "rename a_v4.orig\n", nil)
	if err := os.Link(orig, filepath.Join(run, "a_v4.orig")); err != nil {
		t.Fatal(err)
	}
	withFault(t, func(op, path string) error {
		if op == "rename" && filepath.Dir(path) == run {
			return syscall.EIO
		}
		return nil
	})
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover over a run that left its download as it was: %v (a rename was tried)", err)
	}
	fault = noFault
	assertFiles(t, dir, map[string]string{"a_v4.orig": "download of a\n"})
}

// Scenario: a script leaves a file of its own beside the feed's.
// Given a published baseline, a pre-script and an IP post-script that each leave a file beside the one they are given and
// beside their folder, when the feed runs with a changed source, then the change is published and none of those files
// reaches the feed folder: a run publishes only the names of its feed's own files.
func TestRunNeverPublishesAStrayScriptFile(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	// Each script writes its witness, outside the feed folder, once its stray files exist.
	witnesses := t.TempDir()
	killScript(t, root, "pre.sh", `printf 'x\n' > "$1.foo"; printf 'x\n' > "$(dirname "$1")/Feed_v4.foo"; : > '`+witnesses+`/pre'`)
	killScript(t, root, "post.sh", `printf 'x\n' > "$1.bar"; printf 'x\n' > "$(dirname "$1")/Feed_v4.bar"; : > '`+witnesses+`/post'`)
	stage, feed := killStage(root)
	feed.PreScript, feed.PostScript = "pre.sh", "post.sh"
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the run = %+v, want the change published", r)
	}
	for _, name := range []string{"pre", "post"} {
		if _, err := os.Stat(filepath.Join(witnesses, name)); err != nil {
			t.Fatalf("the %s-script never left its stray files: %v", name, err)
		}
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Errorf("the run published %q, want the changed source", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".foo") || strings.HasSuffix(e.Name(), ".bar") || strings.HasPrefix(e.Name(), ".pfb") {
			t.Errorf("the run left %s in the feed folder", e.Name())
		}
	}
}

// Scenario: a COMMIT names a file that is no published file of its feed.
// Given a run folder whose COMMIT names another feed's file, a name outside the feed's own files, a path, or an operation
// that is no rename or removal, when Recover reads it, then Recover fails and touches nothing: the feed folder and the run
// folder stay as they were.
func TestRecoverRefusesABadNameInCommit(t *testing.T) {
	for _, commit := range []string{
		"rename b_v4.orig\n",
		"rename a_v4.foo\n",
		"rename ../a_v4.orig\n",
		"rename a_v4.orig/x\n",
		"remove a_v4.parsed.src\n",
		"copy a_v4.orig\n",
		"rename a_v4.orig extra\n",
		"rename\n",
	} {
		dir := t.TempDir()
		for name, body := range map[string]string{"a_v4.orig": "download of a\n", "b_v4.orig": "download of b\n"} {
			writeFile(t, filepath.Join(dir, name), body)
		}
		run := runFolder(t, dir, "a_v4", commit, map[string]string{"a_v4.orig": "new download of a\n",
			"b_v4.orig": "planted download of b\n", "a_v4.foo": "stray\n"})
		if err := Recover(dir); err == nil {
			t.Errorf("COMMIT %q: Recover succeeded, want it refused", commit)
		}
		if got, want := publishedState(t, dir), map[string]string{"a_v4.orig": "-rw------- download of a\n",
			"b_v4.orig": "-rw------- download of b\n"}; !reflect.DeepEqual(got, want) {
			t.Errorf("COMMIT %q: the feed folder is %q, want %q untouched", commit, got, want)
		}
		if got := readFile(t, filepath.Join(run, "COMMIT")); got != commit {
			t.Errorf("COMMIT %q: Recover changed it to %q", commit, got)
		}
	}
}

// Scenario: a run folder holds a symbolic link or a file that is no regular file.
// Given a committed run folder whose renamed file is a symbolic link, one whose COMMIT is a FIFO, a run folder that is
// itself a symbolic link, and an uncommitted run folder holding a symbolic link, a FIFO and a folder with a link to an
// outside folder, when Recover runs, then it refuses the first three and publishes nothing of them, and deletes the last
// without following its links: what they point at stays untouched.
func TestRecoverRefusesALinkOrSpecialFileInARunFolder(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	writeFile(t, secret, "outside\n")

	t.Run("a renamed file is a link", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a_v4.orig"), "download of a\n")
		run := runFolder(t, dir, "a_v4", "rename a_v4.orig\n", nil)
		if err := os.Symlink(secret, filepath.Join(run, "a_v4.orig")); err != nil {
			t.Fatal(err)
		}
		if err := Recover(dir); err == nil {
			t.Error("Recover published a symbolic link, want it refused")
		}
		if info, err := os.Lstat(filepath.Join(dir, "a_v4.orig")); err != nil || !info.Mode().IsRegular() ||
			readFile(t, filepath.Join(dir, "a_v4.orig")) != "download of a\n" {
			t.Errorf("the download is %v (%v), want the regular download untouched", info, err)
		}
	})
	t.Run("COMMIT is a FIFO", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a_v4.orig"), "download of a\n")
		run := runFolder(t, dir, "a_v4", "", map[string]string{"a_v4.orig": "new download of a\n"})
		if err := syscall.Mkfifo(filepath.Join(run, "COMMIT"), 0o600); err != nil {
			t.Skipf("no FIFOs here: %v", err)
		}
		if err := Recover(dir); err == nil {
			t.Error("Recover took a FIFO for COMMIT, want it refused")
		}
		if got := readFile(t, filepath.Join(dir, "a_v4.orig")); got != "download of a\n" {
			t.Errorf("the download is %q, want it untouched", got)
		}
	})
	t.Run("the run folder is a link", func(t *testing.T) {
		dir, target := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(target, "a_v4.orig"), "behind the link\n")
		writeFile(t, filepath.Join(target, "COMMIT"), "rename a_v4.orig\n")
		if err := os.Symlink(target, filepath.Join(dir, ".pfbrun-a_v4")); err != nil {
			t.Fatal(err)
		}
		if err := Recover(dir); err == nil {
			t.Error("Recover followed a run folder that is a symbolic link, want it refused")
		}
		if _, err := os.Lstat(filepath.Join(dir, "a_v4.orig")); !os.IsNotExist(err) {
			t.Errorf("Recover published a file from behind the link (%v)", err)
		}
		assertFiles(t, target, map[string]string{"a_v4.orig": "behind the link\n", "COMMIT": "rename a_v4.orig\n"})
	})
	t.Run("an uncommitted run holds links and a FIFO", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a_v4.orig"), "download of a\n")
		run := runFolder(t, dir, "a_v4", "", nil)
		if err := os.Symlink(secret, filepath.Join(run, "a_v4.orig")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(run, ".post"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(run, ".post", "a_v4.orig")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(run, "a_v4.norm"), 0o600); err != nil {
			t.Skipf("no FIFOs here: %v", err)
		}
		if err := Recover(dir); err != nil {
			t.Fatalf("Recover: %v", err)
		}
		assertFiles(t, dir, map[string]string{"a_v4.orig": "download of a\n"})
		assertFiles(t, outside, map[string]string{"secret": "outside\n"})
	})
}
