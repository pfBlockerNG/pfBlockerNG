package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// issue #4257: while the operation lock is held by something other than a worker (a reset holding the gate), a receipt that
// was already recorded is no result waiting: Recover answers nothing to do, so neither GetUpdate nor the quarter-hour tick is
// refused meanwhile. A finished receipt not yet recorded still asks for recovery.
func TestRecoverUnderAHeldLockAsksForRecoveryOnlyForAnUnrecordedResult(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "update.log")
	finished := int64(1)
	write := func(settled bool) {
		t.Helper()
		st := workerState{Version: workerVersion, Nonce: strings.Repeat("ab", 32), Path: "/usr/local/bin/update", StartedAt: 1,
			FinishedAt: &finished, Settled: settled, ExitCode: new(int)}
		if err := writeWorkerState(logPath+".status", st); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := operationLock(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	never := func(int64, map[string]int64, Result, error) error {
		t.Error("apply ran under a lock held elsewhere")
		return nil
	}

	write(true)
	if err := Recover(logPath, never); err != nil {
		t.Errorf("Recover of a recorded result under a held lock = %v, want nil", err)
	}
	write(false)
	if err := Recover(logPath, never); !errors.Is(err, ErrRecoveryRequired) {
		t.Errorf("Recover of an unrecorded result under a held lock = %v, want ErrRecoveryRequired", err)
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

	if err := ResetFailures(dir, nil); err != nil {
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
