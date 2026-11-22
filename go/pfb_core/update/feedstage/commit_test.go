package feedstage

import (
	"os"
	"path/filepath"
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
