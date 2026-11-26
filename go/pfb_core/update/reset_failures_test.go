package update

import (
	"os"
	"path/filepath"
	"testing"
)

// issue #4257: a reset that clears no count leaves updater.json byte for byte, so nothing of it, a field this binary does
// not know included, is lost to a click that changed nothing.
func TestAResetThatClearsNoCountLeavesTheStateAsItIs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	held := `{"pendingFeeds":[],"failuresDay":"2026-11-26","failures":{"A":3},"later":1}`
	if err := os.WriteFile(path, []byte(held), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetFailures(dir, []string{"Absent"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != held {
		t.Errorf("a reset of a feed with no count rewrote the state:\n%s\nwant\n%s", got, held)
	}

	none := `{"pendingFeeds":["P"],"later":1}`
	if err := os.WriteFile(path, []byte(none), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetFailures(dir, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != none {
		t.Errorf("a reset of a state with no counts rewrote it:\n%s\nwant\n%s", got, none)
	}
}
