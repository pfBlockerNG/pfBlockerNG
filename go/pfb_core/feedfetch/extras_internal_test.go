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
