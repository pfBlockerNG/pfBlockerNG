package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheProgramsStdinIsARegularFileNeverAPipe(t *testing.T) {
	p, dir := program(t, `echo ran > "$D/ran"; [ -f /dev/fd/0 ] || echo "fd 0" > "$D/notfile"`)
	if _, err := runCmd(t, p, Request{Trigger: "manual"}, newLog(t)); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatalf("the program did not run to its check: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notfile")); err == nil {
		t.Error("the program's stdin is not a regular file: a pipe makes Run wait for a descendant that keeps it open")
	}
}
