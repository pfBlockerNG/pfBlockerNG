package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

type retainedWorkerStatus struct {
	Request struct {
		Trigger string `json:"trigger"`
		Scope   string `json:"scope"`
		Force   string `json:"force"`
	} `json:"request"`
	StartedAt  int64  `json:"startedAt"`
	FinishedAt *int64 `json:"finishedAt"`
	ExitCode   *int   `json:"exitCode"`
	Settled    bool   `json:"settled"`
}

func retainedStatus(t *testing.T, path string) retainedWorkerStatus {
	t.Helper()
	var state retainedWorkerStatus
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("worker status is not JSON: %v\n%s", err, body)
	}
	return state
}

func waitRetainedTerminal(t *testing.T, path string) retainedWorkerStatus {
	t.Helper()
	var state retainedWorkerStatus
	waitFor(t, func() bool {
		body, err := os.ReadFile(path)
		return err == nil && json.Unmarshal(body, &state) == nil && state.FinishedAt != nil
	})
	return state
}

func waitRetainedUnlock(t *testing.T, logPath string) {
	t.Helper()
	waitFor(t, func() bool {
		lease, err := (&update.Command{}).Admit(logPath)
		if errors.Is(err, update.ErrRunning) || errors.Is(err, update.ErrRecoveryRequired) {
			return false
		}
		if err != nil {
			t.Fatalf("waiting for retained worker unlock: %v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatalf("closing retained worker test lease: %v", err)
		}
		return true
	})
}

func readScheduleState(t *testing.T, path string) schedule.State {
	t.Helper()
	state, err := schedule.ParseState(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestRestartObservesLiveWorkerWithoutDuplicateOrTruncation(t *testing.T) {
	holdQuarters(t)
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"live-1","trigger":"manual","scope":"ip"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")

	logPath := filepath.Join(c.state, "update.log")
	statusPath := logPath + ".status"
	logBefore := mustRead(t, logPath)
	statusBefore := mustRead(t, statusPath)
	infoBefore, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}

	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)
	got := restart.post("GetUpdate", `{}`)
	var view updateView
	if got.status != http.StatusOK || json.Unmarshal(got.body, &view) != nil {
		t.Errorf("GetUpdate after restart = %d %s, want the retained live worker", got.status, got.body)
	} else if !view.Running || view.Update == nil || view.Update.Trigger != "manual" || view.Update.Scope != "ip" || view.Update.FinishedAt != nil {
		t.Errorf("GetUpdate after restart = %+v, want the retained live worker running", view)
	}
	refused := restart.post("StartUpdate", `{"requestId":"live-2","trigger":"apply"}`)
	wantError(t, refused, http.StatusConflict, codeConflict)
	if f.runs() != 1 {
		t.Errorf("restart launched %d Update programs, want the original one only", f.runs())
	}
	infoAfter, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) || string(mustRead(t, logPath)) != string(logBefore) || string(mustRead(t, statusPath)) != string(statusBefore) {
		t.Errorf("restart replaced or rewrote the live admission artifacts")
	}

	f.release()
	waitRetainedTerminal(t, statusPath)
}

func TestRestartReconcilesRetainedCompletionBeforeTheNextTick(t *testing.T) {
	holdQuarters(t)
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"},"attempted":["ipv4:Feed1_v4"]}`)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"terminal-1","trigger":"retry"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")

	statePath := filepath.Join(c.state, "schedule_state.json")
	pending := readScheduleState(t, statePath)["ipv4:Feed1_v4"].PendingOccurrence
	if pending == nil {
		t.Fatal("retry admission did not persist the feed occurrence")
	}
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}
	f.release()
	statusPath := filepath.Join(c.state, "update.log.status")
	terminal := waitRetainedTerminal(t, statusPath)
	if terminal.Settled || terminal.FinishedAt == nil || terminal.ExitCode == nil || *terminal.ExitCode != 0 {
		t.Fatalf("worker terminal before restart = %+v, want an unsettled exit-0 receipt", terminal)
	}
	waitRetainedUnlock(t, filepath.Join(c.state, "update.log"))

	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)
	got := restart.post("GetUpdate", `{}`)
	var view updateView
	if got.status != http.StatusOK || json.Unmarshal(got.body, &view) != nil {
		t.Errorf("GetUpdate after terminal restart = %d %s, want retained completion", got.status, got.body)
	} else if view.Running || view.Update == nil || view.Update.Trigger != terminal.Request.Trigger || view.Update.StartedAt != terminal.StartedAt ||
		view.Update.FinishedAt == nil || *view.Update.FinishedAt != *terminal.FinishedAt || view.Update.Result != "success" {
		t.Errorf("GetUpdate after terminal restart = %+v, want retained success at %d", view, *terminal.FinishedAt)
	}
	item := readScheduleState(t, statePath)["ipv4:Feed1_v4"]
	if item.PendingOccurrence != nil || item.LastCompletedOccurrence == nil || *item.LastCompletedOccurrence != *pending ||
		item.LastSuccessfulCheck == nil || *item.LastSuccessfulCheck != *terminal.FinishedAt {
		t.Errorf("schedule state before any tick = %+v, want retained occurrence %d settled at %d", item, *pending, *terminal.FinishedAt)
	}
	if status := retainedStatus(t, statusPath); !status.Settled {
		t.Errorf("startup reconciliation left the retained receipt unsettled: %+v", status)
	}
	if f.runs() != 1 {
		t.Errorf("restart ran the Update program %d times, want once", f.runs())
	}
}

func TestRestartFailsClosedOnMalformedUnsettledReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, receipt string
	}{
		{"truncated", `{"version":1`},
		{"terminal without disposition", `{"version":1,"nonce":"` + strings.Repeat("a", 64) + `","path":"/bin/true","request":{"trigger":"apply"},"startedAt":1,"finishedAt":2,"result":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdQuarters(t)
			dir := scratchDir(t)
			stateDir := filepath.Join(dir, "state")
			if err := os.Mkdir(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(stateDir, "schedule_state.json")
			const occurrence = int64(1700000000)
			if err := os.WriteFile(statePath, []byte(`{"schema":1,"items":{"ipv4:Feed1_v4":{"pending_occurrence":1700000000}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(stateDir, "update.log")
			if err := os.WriteFile(logPath, []byte("retained\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			statusPath := logPath + ".status"
			if err := os.WriteFile(statusPath, []byte(tc.receipt), 0o600); err != nil {
				t.Fatal(err)
			}
			logBefore, statusBefore := mustRead(t, logPath), mustRead(t, statusPath)
			f := newFakeUpdate(t)
			core := startCore(t, dir, "--update-cmd", f.path)

			wantError(t, core.post("GetUpdate", `{}`), http.StatusServiceUnavailable, codeUnavailable)
			wantError(t, core.post("StartUpdate", `{"requestId":"malformed","trigger":"apply"}`), http.StatusServiceUnavailable, codeUnavailable)
			item := readScheduleState(t, statePath)["ipv4:Feed1_v4"]
			if item.PendingOccurrence == nil || *item.PendingOccurrence != occurrence {
				t.Errorf("malformed receipt discarded pending work: %+v", item)
			}
			if string(mustRead(t, logPath)) != string(logBefore) || string(mustRead(t, statusPath)) != string(statusBefore) {
				t.Error("malformed receipt was replaced or rewritten")
			}
			if f.runs() != 0 {
				t.Errorf("malformed receipt launched %d programs, want none", f.runs())
			}
		})
	}
}

// issue #4257: a worker a restarted Core retained still runs and writes updater.json, with no Update admitted in this
// process: ResetFeedFailures refuses it as a conflict, from the worker's lease, and changes nothing.
func TestResetFeedFailuresUnderARetainedLiveWorkerIsAConflictAndChangesNothing(t *testing.T) {
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	state := `{"pendingFeeds":[],"failuresDay":"2026-11-26","failures":{"A":3}}`
	path := filepath.Join(c.state, "updater.json")
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	wantJSON(t, c.post("StartUpdate", `{"requestId":"live-1","trigger":"manual","scope":"ip"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}

	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)
	wantError(t, restart.post("ResetFeedFailures", `{"requestId":"f1"}`), http.StatusConflict, codeConflict)
	if got := string(mustRead(t, path)); got != state {
		t.Errorf("updater.json under a retained worker = %s, want it unchanged", got)
	}

	f.release()
	waitRetainedTerminal(t, filepath.Join(c.state, "update.log.status"))
}
