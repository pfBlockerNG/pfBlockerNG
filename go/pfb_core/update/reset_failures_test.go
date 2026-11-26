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

// Exclusive refuses after Stop, as Start does, and runs nothing.
func TestExclusiveAfterStopIsRefusedAndRunsNothing(t *testing.T) {
	g := New(filepath.Join(t.TempDir(), "update.log"), nil, nil)
	g.Stop()
	if err := g.Exclusive(func() error { t.Error("fn ran after Stop"); return nil }); !errors.Is(err, ErrStopped) {
		t.Errorf("Exclusive after Stop = %v, want ErrStopped", err)
	}
}

// Exclusive refuses while an Update holds the gate, and runs nothing.
func TestExclusiveWhileAnUpdateRunsIsRefusedAndRunsNothing(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual", Scope: "both", Force: "none"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Exclusive(func() error { t.Error("fn ran while an Update held the gate"); return nil }); !errors.Is(err, ErrRunning) {
		t.Errorf("Exclusive during an Update = %v, want ErrRunning", err)
	}
	h.finish(t, nil)
	settle(t, g)
}

// Exclusive makes Start's checks under its admission: a finished result not recorded yet is ErrRecoveryRequired (the caller
// records it and asks again), and fn does not run over it.
func TestExclusiveOverAnUnrecordedResultAsksForRecoveryAndRunsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "update.log")
	finished := int64(1)
	st := workerState{Version: workerVersion, Nonce: strings.Repeat("cd", 32), Path: "/usr/local/bin/update", StartedAt: 1,
		FinishedAt: &finished, ExitCode: new(int)}
	if err := writeWorkerState(logPath+".status", st); err != nil {
		t.Fatal(err)
	}
	g := New(logPath, nil, nil)
	t.Cleanup(g.Stop)
	if err := g.Exclusive(func() error { t.Error("fn ran over an unrecorded result"); return nil }); !errors.Is(err, ErrRecoveryRequired) {
		t.Errorf("Exclusive over an unrecorded result = %v, want ErrRecoveryRequired", err)
	}
}
