package scheduler

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const receiptNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func writeReceipt(t *testing.T, logPath, body string) {
	t.Helper()
	if err := os.Chmod(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func receipt(occurrence int64) string {
	return `{"version":1,"nonce":"` + receiptNonce + `","path":"/bin/true","request":{"trigger":"scheduled"},"startedAt":1,"finishedAt":50,"exitCode":0,"occurrences":{"` + feedA + `":` + strconv.FormatInt(occurrence, 10) + `},"result":{"outcomes":{"` + feedA + `":"success"}}}`
}

func TestRecoveredReceiptSettlesTheReservedOccurrenceOnce(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	logPath := filepath.Join(t.TempDir(), "update.log")
	f.s.cfg.LogPath = logPath
	writeReceipt(t, logPath, receipt(occ10))
	if err := f.s.Recover(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Recover(); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(f.path)
	if err != nil || string(first) != string(second) {
		t.Fatalf("replay changed the schedule:\n%s\n%s\n%v", first, second, err)
	}
	finished, completed := int64(50), occ10
	wantItem(t, f.items(), feedA, schedule.Item{LastSuccessfulCheck: &finished, LastCompletedOccurrence: &completed, CompletionOutcome: schedule.Success})
}

func TestOldReceiptDoesNotConsumeANewerPendingOccurrence(t *testing.T) {
	later := occ10 + 900
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(later)}))
	logPath := filepath.Join(t.TempDir(), "update.log")
	f.s.cfg.LogPath = logPath
	writeReceipt(t, logPath, receipt(occ10))
	if err := f.s.Recover(); err != nil {
		t.Fatal(err)
	}
	finished := int64(50)
	wantItem(t, f.items(), feedA, schedule.Item{LastSuccessfulCheck: &finished, PendingOccurrence: &later})
}

func TestScheduleWriteFailureDoesNotSettleTheReceipt(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	logPath := filepath.Join(t.TempDir(), "update.log")
	f.s.cfg.LogPath = logPath
	f.s.cfg.StatePath = t.TempDir()
	writeReceipt(t, logPath, receipt(occ10))
	if err := f.s.Recover(); err == nil {
		t.Fatal("a schedule write to a directory reported success")
	}
	if f.s.st[feedA].PendingOccurrence == nil || *f.s.st[feedA].PendingOccurrence != occ10 {
		t.Fatalf("failed write changed memory: %+v", f.s.st[feedA])
	}
	body, err := os.ReadFile(logPath + ".status")
	if err != nil || strings.Contains(string(body), `"settled":true`) {
		t.Fatalf("receipt settled despite the schedule write failure: %s %v", body, err)
	}
}

func TestUncapturedNumericSuccessIsNotStored(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	logPath := filepath.Join(t.TempDir(), "update.log")
	f.s.cfg.LogPath = logPath
	writeReceipt(t, logPath, `{"version":1,"nonce":"`+receiptNonce+`","path":"/bin/true","request":{"trigger":"scheduled"},"startedAt":1,"finishedAt":50,"exitCode":0,"occurrences":{"`+feedA+`":`+strconv.FormatInt(occ10, 10)+`},"result":{"outcomes":{"`+feedA+`":"success","123":"success"}}}`)
	if err := f.s.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.items()["123"]; ok {
		t.Fatal("an uncaptured numeric success was stored")
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := schedule.ParseState(raw); err != nil {
		t.Fatalf("stored schedule no longer validates: %v\n%s", err, raw)
	}
	finished, completed := int64(50), occ10
	wantItem(t, f.items(), feedA, schedule.Item{LastSuccessfulCheck: &finished, LastCompletedOccurrence: &completed, CompletionOutcome: schedule.Success})
}

func TestRejectedRetryCannotLeakReservationIntoManualAdmission(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	f.s.Bind(func(update.Request, func() (map[string]int64, error)) error { return update.ErrRunning })
	if err := f.s.Start("retry", "", ""); !errors.Is(err, update.ErrRunning) {
		t.Fatal(err)
	}
	later := occ10 + 900
	f.s.st[feedA] = schedule.Item{PendingOccurrence: &later}
	if err := writeState(f.path, f.s.st); err != nil {
		t.Fatal(err)
	}
	f.s.Bind(func(_ update.Request, commit func() (map[string]int64, error)) error { _, err := commit(); return err })
	if err := f.s.Start("manual", "both", "none"); err != nil {
		t.Fatal(err)
	}
	if p := f.s.st[feedA].PendingOccurrence; p == nil || *p != later {
		t.Fatalf("manual admission overwrote newer pending with stale rejected retry: %+v", f.s.st[feedA])
	}
}

func TestPrepareFailureDoesNotLeakIntoManualAdmission(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	f.s.cfg.StatePath = t.TempDir()
	f.s.Bind(func(_ update.Request, commit func() (map[string]int64, error)) error {
		_, err := commit()
		return err
	})
	if err := f.s.Start("retry", "", ""); err == nil {
		t.Fatal("a directory state path reported a successful prepare")
	}
	later := occ10 + 900
	f.s.st[feedA] = schedule.Item{PendingOccurrence: &later}
	if err := f.s.Start("manual", "both", "none"); err != nil {
		t.Fatal(err)
	}
	if p := f.s.st[feedA].PendingOccurrence; p == nil || *p != later {
		t.Fatalf("manual admission reused the failed prepare: %+v", f.s.st[feedA])
	}
}

func TestSuccessfulAdmissionDoesNotLeakIntoManualAdmission(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	f.s.Bind(func(_ update.Request, commit func() (map[string]int64, error)) error {
		_, err := commit()
		return err
	})
	if err := f.s.Start("retry", "", ""); err != nil {
		t.Fatal(err)
	}
	later := occ10 + 900
	f.s.st[feedA] = schedule.Item{PendingOccurrence: &later}
	if err := writeState(f.path, f.s.st); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Start("manual", "both", "none"); err != nil {
		t.Fatal(err)
	}
	if p := f.s.st[feedA].PendingOccurrence; p == nil || *p != later {
		t.Fatalf("manual admission reused the successful reservation: %+v", f.s.st[feedA])
	}
}

func TestRecoveryRetryCommitsTheSecondAdmissionOnly(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: pending(occ10)}))
	logPath := filepath.Join(t.TempDir(), "update.log")
	f.s.cfg.LogPath = logPath
	writeReceipt(t, logPath, receipt(occ10))
	var rejected bool
	var snap map[string]int64
	f.s.Bind(func(_ update.Request, commit func() (map[string]int64, error)) error {
		if !rejected {
			rejected = true
			return update.ErrRecoveryRequired
		}
		var err error
		snap, err = commit()
		return err
	})
	if err := f.s.Start("retry", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, reused := snap[feedA]; reused || f.s.st[feedA].PendingOccurrence != nil || f.s.st[feedA].LastCompletedOccurrence == nil {
		t.Fatalf("second admission reused the rejected reservation: snap=%v state=%+v", snap, f.s.st[feedA])
	}
}
