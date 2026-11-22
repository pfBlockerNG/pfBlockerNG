package feedfetch

import (
	"os"
	"path/filepath"
	"testing"
)

// A body with one name gains its newline in place: it needs one more byte of space, not a second copy of the download.
// A body another name links to gains it on a copy, and the other name keeps its bytes.
func TestFinishAppendsTheNewlineInPlaceOnlyForAnUnsharedBody(t *testing.T) {
	t.Run("unshared body keeps its inode", func(t *testing.T) {
		body := filepath.Join(t.TempDir(), "feed.raw")
		if err := os.WriteFile(body, []byte("198.51.100.2"), 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := finish(body); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(body)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) {
			t.Errorf("the unshared body was replaced by a copy, want the newline appended to the same file")
		}
		if got := readBack(t, body); got != "198.51.100.2\n" {
			t.Errorf("the body is %q, want it with its newline", got)
		}
	})
	t.Run("linked body leaves the other link untouched", func(t *testing.T) {
		dir := t.TempDir()
		other := linkedFile(t, dir, "feed.raw", "198.51.100.2")
		body := filepath.Join(dir, "feed.raw")
		if err := finish(body); err != nil {
			t.Fatal(err)
		}
		if got := readBack(t, other); got != "198.51.100.2" {
			t.Errorf("the other link became %q, want it untouched", got)
		}
		if got := readBack(t, body); got != "198.51.100.2\n" {
			t.Errorf("the body is %q, want it with its newline", got)
		}
	})
}
