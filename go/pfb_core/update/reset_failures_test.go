package update

import (
	"os"
	"path/filepath"
	"testing"
)

// issue #4257: a reset of a state with no count leaves updater.json byte for byte, so nothing of it, a field this binary
// does not know included, is lost to a click that changed nothing.
func TestAResetThatClearsNoCountLeavesTheStateAsItIs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	none := `{"pendingFeeds":["P"],"later":1}`
	if err := os.WriteFile(path, []byte(none), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetFailures(dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != none {
		t.Errorf("a reset of a state with no counts rewrote it:\n%s\nwant\n%s", got, none)
	}
}

// owner, 2026-11-26: a reset may come while an Update runs. The Update decides from the counts it read at its start and
// adds only its own failures to what the state holds when it saves: a reset made meanwhile stands, under the state's lock.
func TestAFailureCountedAfterAResetAddsToTheResetCountsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	if err := os.WriteFile(path, []byte(`{"pendingFeeds":["P"],"failuresDay":"2026-11-26","failures":{"A":2,"B":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &updater{stateDir: dir, state: readUpdaterState(dir)}

	if err := ResetFailures(dir); err != nil {
		t.Fatal(err)
	}
	if err := u.countFailure("A"); err != nil {
		t.Fatal(err)
	}
	got := readUpdaterState(dir)
	if got.FailuresDay != "2026-11-26" || len(got.Failures) != 1 || got.Failures["A"] != 1 {
		t.Errorf("after a reset and one failure of A: %+v, want only A once, on the Update's day", got)
	}
	if len(got.PendingFeeds) != 1 || got.PendingFeeds[0] != "P" {
		t.Errorf("the Update's own state was not kept: %+v", got)
	}

	// without a reset, its failures add to what is there
	if err := u.countFailure("A"); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(dir); got.Failures["A"] != 2 {
		t.Errorf("a second failure of A: %+v, want A twice", got.Failures)
	}
}

// A state that is missing or cannot be read when the Updater saves is no reset (a reset never removes the file): the
// Updater keeps the counts it read at its start, as before, and adds its own.
func TestASaveOverAMissingStateKeepsTheCountsReadAtTheStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	if err := os.WriteFile(path, []byte(`{"pendingFeeds":[],"failuresDay":"2026-11-26","failures":{"A":3}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &updater{stateDir: dir, state: readUpdaterState(dir)}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := u.countFailure("B"); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(dir); got.Failures["A"] != 3 || got.Failures["B"] != 1 {
		t.Errorf("counts after a save over a missing state: %+v, want A's 3 kept and B once", got.Failures)
	}
}
