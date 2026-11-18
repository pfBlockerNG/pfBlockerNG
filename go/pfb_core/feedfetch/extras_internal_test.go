package feedfetch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMember refuses a member name that would leave the staging directory, whatever checked the names before it
// (pfb_archive_unsafe_member is the first line; this is the last).
func TestWriteMemberRefusesANameThatLeavesTheDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "staged")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{}
	for _, name := range []string{"../escape", "a/../../escape", "/abs/escape"} {
		if err := f.writeMember(dir, name, false, true, strings.NewReader("x")); err == nil {
			t.Errorf("writeMember(%q) = nil, want a refusal", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); err == nil {
		t.Errorf("a member was written outside the staging directory")
	}
	if err := f.writeMember(dir, "ok/file", false, true, strings.NewReader("x")); err != nil {
		t.Errorf("writeMember(ok/file) = %v, want nil", err)
	}
}

// A merge whose later rename fails puts back every live file an earlier rename already replaced: the share holds the old
// generation whole, never a mix (PHP leaves the mix; CodeRabbit on #4059).
func TestAMergeThatFailsPartWayRestoresWhatItReplaced(t *testing.T) {
	share := t.TempDir()
	for name, content := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	real := rename
	rename = func(from, to string) error {
		if filepath.Dir(to) == share && filepath.Base(to) == "b.csv" && strings.Contains(from, ".pfbstagedir_") {
			calls++
			return os.ErrPermission
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	f := &Fetcher{}
	ok := f.mergeIntoDir(share, func(dir string) error {
		for name, content := range map[string]string{"a.csv": "new a\n", "b.csv": "new b\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if ok || calls == 0 {
		t.Fatalf("(merged, failed renames) = (%v, %d), want a failed merge", ok, calls)
	}
	for name, want := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		got, err := os.ReadFile(filepath.Join(share, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = (%q, %v), want %q", name, got, err, want)
		}
	}
	entries, _ := os.ReadDir(share)
	if len(entries) != 2 {
		t.Errorf("the share holds %d entries after the failed merge, want the 2 live files only", len(entries))
	}
}

// A rollback whose own rename fails keeps the backup: the old file is not lost with it (CodeRabbit on #4059).
func TestAFailedRollbackKeepsTheBackup(t *testing.T) {
	share := t.TempDir()
	for name, content := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	real := rename
	rename = func(from, to string) error {
		if strings.Contains(from, ".pfbstagedir_") && filepath.Base(to) == "b.csv" {
			return os.ErrPermission // the publication fails part-way
		}
		if strings.Contains(from, ".pfbbackup_") {
			return os.ErrPermission // and so does putting a.csv back
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	f := &Fetcher{}
	ok := f.mergeIntoDir(share, func(dir string) error {
		for name, content := range map[string]string{"a.csv": "new a\n", "b.csv": "new b\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if ok {
		t.Fatal("the merge succeeded, want a failure")
	}
	kept, _ := filepath.Glob(filepath.Join(share, ".pfbbackup_*", "a.csv"))
	if len(kept) != 1 {
		t.Fatalf("backups of a.csv after the failed rollback: %v, want the one copy kept", kept)
	}
	if got, err := os.ReadFile(kept[0]); err != nil || string(got) != "old a\n" {
		t.Errorf("kept backup = (%q, %v), want the old a.csv", got, err)
	}
}
