package update

import (
	"os"
	"path/filepath"
	"syscall"
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

// The first save after midnight writes no count of the day before: the Update counts from its own day only.
func TestASaveOnANewDayWritesNoCountOfTheDayBefore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	if err := os.WriteFile(path, []byte(`{"pendingFeeds":[],"failuresDay":"2026-11-25","failures":{"X":5}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &updater{stateDir: dir, state: readUpdaterState(dir)}
	u.state.FailuresDay, u.state.Failures = "2026-11-26", nil // as workList sets them on a new day
	if err := u.pendingAfter([]string{"P"}); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(dir); len(got.Failures) != 0 {
		t.Errorf("a save on a new day wrote counts: %+v, want none", got)
	}
}

// The state's lock is exclusive: what holds it keeps every other taker out until it is released.
func TestTheStatesLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	lock, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(filepath.Join(dir, updaterStateName+".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Error("the state's lock was taken a second time while held")
	}
	lock.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("the state's lock is still held after its release: %v", err)
	}
}

// A state lost after this Update already wrote counts: the counts it last wrote stand, not only those read at its start.
func TestASaveOverAStateLostMidUpdateKeepsTheCountsItWrote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, updaterStateName)
	if err := os.WriteFile(path, []byte(`{"pendingFeeds":[],"failuresDay":"2026-11-26","failures":{"A":3}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &updater{stateDir: dir, state: readUpdaterState(dir)}
	if err := u.countFailure("B"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := u.countFailure("C"); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(dir).Failures; got["A"] != 3 || got["B"] != 1 || got["C"] != 1 {
		t.Errorf("counts after a state lost mid-Update: %v, want A 3, B 1, C 1", got)
	}
}
