package feedfetch

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"syscall"
	"testing"
)

// A category folder's generations are named .<name>.<pid>.<8 hex> beside it (#4141).
var categoryGeneration = regexp.MustCompile(`^\.ut1\.[0-9]+\.[0-9a-f]{8}$`)

// categoryDB is a database folder whose ut1 category links to a previous generation holding ut1_adult "old\n".
func categoryDB(t *testing.T) (db, live string) {
	t.Helper()
	db = t.TempDir()
	live = filepath.Join(db, "ut1")
	prev := filepath.Join(db, ".ut1.1.00000000")
	if err := os.Mkdir(prev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAdult("old\n")(prev); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".ut1.1.00000000", live); err != nil {
		t.Fatal(err)
	}
	return db, live
}

func writeAdult(content string) func(string) error {
	return func(dir string) error { return os.WriteFile(filepath.Join(dir, "ut1_adult"), []byte(content), 0o644) }
}

// assertDB checks the database folder holds the category link and the named generations, and nothing else (the lock
// file aside).
func assertDB(t *testing.T, db string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(db)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if e.Name() != ".ut1.lock" {
			got = append(got, e.Name())
		}
	}
	want = append([]string{"ut1"}, want...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the database folder holds %v, want %v", got, want)
	}
}

// linked is the generation the category links to.
func linked(t *testing.T, live string) string {
	t.Helper()
	to, err := os.Readlink(live)
	if err != nil {
		t.Fatalf("%s is not a link: %v", live, err)
	}
	if !categoryGeneration.MatchString(to) {
		t.Fatalf("%s links to %q, not a generation beside it", live, to)
	}
	return to
}

func assertAdult(t *testing.T, live, want string) {
	t.Helper()
	if got, err := os.ReadFile(filepath.Join(live, "ut1_adult")); err != nil || string(got) != want {
		t.Errorf("ut1/ut1_adult = (%q, %v), want %q", got, err, want)
	}
}

// A category goes live in one step: the only rename onto it is a link to the new generation, so the folder is never
// absent and a run killed at any point leaves the previous generation or the new one.
func TestACategoryIsPublishedByOneLinkRename(t *testing.T) {
	db, live := categoryDB(t)
	var onto []string
	real := rename
	rename = func(from, to string) error {
		onto = append(onto, to)
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	if !slices.Equal(onto, []string{live}) {
		t.Errorf("renames onto %v, want one onto %s", onto, live)
	}
	gen := linked(t, live)
	assertAdult(t, live, "new\n")
	assertDB(t, db, ".ut1.1.00000000", gen)
}

// Only the current generation and the one before it remain.
func TestOnlyTwoCategoryGenerationsRemain(t *testing.T) {
	db, live := categoryDB(t)
	var gens []string
	for _, content := range []string{"a\n", "b\n", "c\n"} {
		if !replaceDir(live, writeAdult(content)) {
			t.Fatal("the category was not published")
		}
		gens = append(gens, linked(t, live))
	}
	assertAdult(t, live, "c\n")
	assertDB(t, db, gens[1], gens[2])
}

// A failed extraction or link rename leaves the previous generation live, and nothing staged beside it.
func TestAFailedCategoryPublicationKeepsThePrevious(t *testing.T) {
	t.Run("extraction", func(t *testing.T) {
		db, live := categoryDB(t)
		if replaceDir(live, func(string) error { return os.ErrInvalid }) {
			t.Fatal("published a failed extraction")
		}
		if linked(t, live) != ".ut1.1.00000000" {
			t.Error("the link moved")
		}
		assertAdult(t, live, "old\n")
		assertDB(t, db, ".ut1.1.00000000")
	})
	t.Run("rename", func(t *testing.T) {
		db, live := categoryDB(t)
		real := rename
		rename = func(string, string) error { return syscall.EIO }
		t.Cleanup(func() { rename = real })
		if replaceDir(live, writeAdult("new\n")) {
			t.Fatal("published without its rename")
		}
		if linked(t, live) != ".ut1.1.00000000" {
			t.Error("the link moved")
		}
		assertAdult(t, live, "old\n")
		assertDB(t, db, ".ut1.1.00000000")
	})
}

// A category that is still a real folder (from before #4141) is set aside once as the previous generation; a failed
// link rename puts it back.
func TestARealCategoryFolderIsSetAsideOnce(t *testing.T) {
	realFolder := func(t *testing.T) (string, string) {
		db := t.TempDir()
		live := filepath.Join(db, "ut1")
		if err := os.Mkdir(live, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeAdult("old\n")(live); err != nil {
			t.Fatal(err)
		}
		return db, live
	}
	t.Run("published", func(t *testing.T) {
		db, live := realFolder(t)
		if !replaceDir(live, writeAdult("new\n")) {
			t.Fatal("the category was not published")
		}
		gen := linked(t, live)
		assertAdult(t, live, "new\n")
		entries, _ := filepath.Glob(filepath.Join(db, ".ut1.*.*"))
		var aside string
		for _, e := range entries {
			if filepath.Base(e) != gen {
				aside = filepath.Base(e)
			}
		}
		if !categoryGeneration.MatchString(aside) {
			t.Fatalf("the real folder was not set aside as a generation: %v", entries)
		}
		assertAdult(t, filepath.Join(db, aside), "old\n")
		assertDB(t, db, aside, gen)
	})
	t.Run("rename fails", func(t *testing.T) {
		db, live := realFolder(t)
		real := rename
		rename = func(string, string) error { return syscall.EIO }
		t.Cleanup(func() { rename = real })
		if replaceDir(live, writeAdult("new\n")) {
			t.Fatal("published without its rename")
		}
		if info, err := os.Lstat(live); err != nil || !info.IsDir() {
			t.Fatalf("the real folder is not back: %v", err)
		}
		assertAdult(t, live, "old\n")
		assertDB(t, db)
	})
}

// A publication removes what earlier ones left by the names they use (stale generations and their links); any other
// name stays, and a missing category (a run killed while setting a real folder aside) removes no generation.
func TestStaleCategoryGenerationsAreRemovedByName(t *testing.T) {
	db, live := categoryDB(t)
	stale := ".ut1.7.0badcafe"
	kept := []string{".ut1.notes", ".ut1.7.0BADCAFE", ".ut1.x.0badcafe", ".ut1.7.0badcafe0", ".ut2.7.0badcafe", "ut1.old"}
	for _, name := range append([]string{stale}, kept...) {
		if err := os.MkdirAll(filepath.Join(db, name, "inside"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(".ut1.7.0badcafe", filepath.Join(db, ".ut1.7.0badcafe.link")); err != nil {
		t.Fatal(err)
	}
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	assertDB(t, db, append([]string{".ut1.1.00000000", linked(t, live)}, kept...)...)

	db, live = categoryDB(t)
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	assertDB(t, db, ".ut1.1.00000000", linked(t, live))
}

// A publication holds the category's lock beside it for the whole run: while another holds it, it creates nothing and
// is refused, so one publication's cleanup never meets a generation another is still writing.
func TestACategoryPublicationHoldsItsLock(t *testing.T) {
	db, live := categoryDB(t)
	held, err := os.OpenFile(filepath.Join(db, ".ut1.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	extracted := false
	if replaceDir(live, func(dir string) error { extracted = true; return writeAdult("new\n")(dir) }) || extracted {
		t.Fatal("published under another publication's lock")
	}
	assertAdult(t, live, "old\n")
	assertDB(t, db, ".ut1.1.00000000")
	syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
	inside := false
	if !replaceDir(live, func(dir string) error {
		other, err := os.OpenFile(filepath.Join(db, ".ut1.lock"), os.O_RDWR, 0)
		if err == nil {
			inside = syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil
			other.Close()
		}
		return writeAdult("new\n")(dir)
	}) || !inside {
		t.Fatalf("the extraction ran without the lock held (locked: %v)", inside)
	}
}

// A link to the previous generation spelt as a path (absolute, or with a ./ prefix) still names it: the cleanup keeps it.
func TestAPreviousCategoryLinkedByPathIsKept(t *testing.T) {
	for _, spelling := range []string{"abs", "./"} {
		t.Run(spelling, func(t *testing.T) {
			db, live := categoryDB(t)
			to := "./.ut1.1.00000000"
			if spelling == "abs" {
				to = filepath.Join(db, ".ut1.1.00000000")
			}
			if err := os.Remove(live); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(to, live); err != nil {
				t.Fatal(err)
			}
			if !replaceDir(live, writeAdult("new\n")) {
				t.Fatal("the category was not published")
			}
			assertDB(t, db, ".ut1.1.00000000", linked(t, live))
		})
	}
}

// While a real category folder gives way to the link, it waits under the name recoverDirs puts back
// (.pfbstagebak2_<name>), so a run killed before the link lands leaves it to be restored by the next run, failed
// download or not; once the link is in place it becomes the previous generation.
func TestARealCategoryFolderWaitsUnderTheRecoverableName(t *testing.T) {
	db := t.TempDir()
	live := filepath.Join(db, "ut1")
	if err := os.Mkdir(live, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAdult("old\n")(live); err != nil {
		t.Fatal(err)
	}
	waiting := false
	real := rename
	rename = func(from, to string) error {
		if to == live {
			b, err := os.ReadFile(filepath.Join(db, stageBackup+"ut1", "ut1_adult"))
			waiting = err == nil && string(b) == "old\n"
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	if !waiting {
		t.Errorf("the real folder was not under %sut1 when the link replaced it", stageBackup)
	}
	gen := linked(t, live)
	entries, _ := filepath.Glob(filepath.Join(db, ".ut1.*.*"))
	var aside string
	for _, e := range entries {
		if filepath.Base(e) != gen {
			aside = filepath.Base(e)
		}
	}
	assertAdult(t, filepath.Join(db, aside), "old\n")
	assertDB(t, db, aside, gen)

	// killed before the link landed: the next run, even a failed one, puts the folder back
	if err := os.Remove(live); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(db, aside), filepath.Join(db, stageBackup+"ut1")); err != nil {
		t.Fatal(err)
	}
	if replaceDir(live, func(string) error { return os.ErrInvalid }) {
		t.Fatal("published a failed extraction")
	}
	assertAdult(t, live, "old\n")
}

// A folder set aside beside a category that is a link to a generation (a run killed after its link landed) is dropped:
// the link stands, and every publication in the folder goes on.
func TestABackupBesideALinkedCategoryIsDropped(t *testing.T) {
	db, live := categoryDB(t)
	if err := os.MkdirAll(filepath.Join(db, stageBackup+"ut1", "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	assertAdult(t, live, "new\n")
	assertDB(t, db, ".ut1.1.00000000", linked(t, live))
}

// A publication refused before its link rename (a target that is a file, or a real folder that cannot be set aside)
// leaves no generation behind.
func TestARefusedCategoryPublicationLeavesNoGeneration(t *testing.T) {
	t.Run("target is a file", func(t *testing.T) {
		db := t.TempDir()
		live := filepath.Join(db, "ut1")
		if err := os.WriteFile(live, []byte("a file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if replaceDir(live, writeAdult("new\n")) {
			t.Fatal("published over a file")
		}
		assertDB(t, db)
	})
	t.Run("set-aside fails", func(t *testing.T) {
		db := t.TempDir()
		live := filepath.Join(db, "ut1")
		if err := os.Mkdir(live, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(db, stageBackup+"ut1"), nil, 0o644); err != nil {
			t.Fatal(err) // a file at the set-aside name: renaming the folder onto it fails
		}
		if replaceDir(live, writeAdult("new\n")) {
			t.Fatal("published without setting the folder aside")
		}
		assertDB(t, db, stageBackup+"ut1")
	})
}

// A generation is readable by the unprivileged readers of a published category whatever the umask.
func TestACategoryGenerationIsWorldReadable(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	_, live := categoryDB(t)
	if !replaceDir(live, writeAdult("new\n")) {
		t.Fatal("the category was not published")
	}
	info, err := os.Stat(live)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("the generation's mode = %v, want 0755", info.Mode().Perm())
	}
}

// A folder set aside beside a link that names no folder (dangling, or a link to a file) holds the only copy of the
// category: it is put back in the link's place, not dropped.
func TestABackupBesideABrokenLinkIsPutBack(t *testing.T) {
	for _, broken := range []string{"dangling", "file"} {
		t.Run(broken, func(t *testing.T) {
			db, live := categoryDB(t)
			if err := os.RemoveAll(filepath.Join(db, ".ut1.1.00000000")); err != nil {
				t.Fatal(err)
			}
			if broken == "file" {
				if err := os.WriteFile(filepath.Join(db, ".ut1.1.00000000"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			backup := filepath.Join(db, stageBackup+"ut1")
			if err := os.Mkdir(backup, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writeAdult("kept\n")(backup); err != nil {
				t.Fatal(err)
			}
			if !recoverDirs(db) {
				t.Fatal("the backup was not settled")
			}
			if info, err := os.Lstat(live); err != nil || !info.IsDir() {
				t.Fatalf("the backup is not back in the link's place: %v", err)
			}
			assertAdult(t, live, "kept\n")
		})
	}
}

// A category that is a link this code did not make (it names no generation beside it) is the administrator's layout:
// the publication refuses it and leaves the link as it is, as before #4141.
func TestAForeignCategoryLinkIsRefused(t *testing.T) {
	db := t.TempDir()
	elsewhere := t.TempDir()
	if err := writeAdult("theirs\n")(elsewhere); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(db, "ut1")
	if err := os.Symlink(elsewhere, live); err != nil {
		t.Fatal(err)
	}
	if replaceDir(live, writeAdult("new\n")) {
		t.Fatal("replaced a link to the administrator's folder")
	}
	if to, err := os.Readlink(live); err != nil || to != elsewhere {
		t.Errorf("ut1 links to %q, %v; want %s", to, err, elsewhere)
	}
	assertAdult(t, live, "theirs\n")
	assertDB(t, db)
}
