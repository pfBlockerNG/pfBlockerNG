package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestGetUpdateReconcilesWorkerThatCompletesAfterStartup(t *testing.T) {
	holdQuarters(t)
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"}}`)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"after-start-1","trigger":"retry"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")
	statePath := filepath.Join(c.state, "schedule_state.json")
	pending := readScheduleState(t, statePath)["ipv4:Feed1_v4"].PendingOccurrence
	if pending == nil {
		t.Fatal("retry admission did not persist the feed occurrence")
	}
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}

	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)
	f.release()
	terminal := waitRetainedTerminal(t, filepath.Join(c.state, "update.log.status"))
	var view updateView
	waitFor(t, func() bool {
		got := restart.post("GetUpdate", `{}`)
		if got.status == http.StatusServiceUnavailable {
			return false
		}
		if got.status != http.StatusOK || json.Unmarshal(got.body, &view) != nil {
			t.Fatalf("GetUpdate after post-startup completion = %d %s", got.status, got.body)
		}
		return !view.Running && view.Update != nil && view.Update.FinishedAt != nil
	})
	if *view.Update.FinishedAt != *terminal.FinishedAt || view.Update.Result != "success" {
		t.Errorf("GetUpdate after post-startup completion = %+v, want retained success at %d", view, *terminal.FinishedAt)
	}
	item := readScheduleState(t, statePath)["ipv4:Feed1_v4"]
	if item.PendingOccurrence != nil || item.LastCompletedOccurrence == nil || *item.LastCompletedOccurrence != *pending {
		t.Errorf("GetUpdate did not reconcile the retained occurrence: %+v", item)
	}
}

func TestTerminalPublicationBeforeUnlockIsUnavailableThenReconciled(t *testing.T) {
	holdQuarters(t)
	dir := scratchDir(t)
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "schedule_state.json")
	if err := os.WriteFile(statePath, []byte(`{"schema":1,"items":{"ipv4:Feed1_v4":{"pending_occurrence":1}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(stateDir, "update.log")
	writeUnsettledReceipt(t, logPath)
	lock, err := os.OpenFile(logPath+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() })
	f := newFakeUpdate(t)
	core := startCore(t, dir, "--update-cmd", f.path)

	wantError(t, core.post("GetUpdate", `{}`), http.StatusServiceUnavailable, codeUnavailable)
	if retainedStatus(t, logPath+".status").Settled {
		t.Fatal("a terminal receipt was settled while its worker lock was still held")
	}
	if readScheduleState(t, statePath)["ipv4:Feed1_v4"].PendingOccurrence == nil {
		t.Fatal("a terminal receipt consumed pending work before worker unlock")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	got := core.post("GetUpdate", `{}`)
	var view updateView
	if got.status != http.StatusOK || json.Unmarshal(got.body, &view) != nil || view.Update == nil || view.Update.Result != "success" || view.Update.FinishedAt == nil {
		t.Errorf("GetUpdate after worker unlock = %d %s, want reconciled retained success", got.status, got.body)
	}
	if status := retainedStatus(t, logPath+".status"); !status.Settled {
		t.Errorf("GetUpdate after unlock left receipt unsettled: %+v", status)
	}
	if item := readScheduleState(t, statePath)["ipv4:Feed1_v4"]; item.PendingOccurrence != nil || item.LastCompletedOccurrence == nil || *item.LastCompletedOccurrence != 1 {
		t.Errorf("GetUpdate after unlock did not settle pending work: %+v", item)
	}
}

func TestObservationErrorsReleaseTheLeaseAndOrphanArtifactsFailClosed(t *testing.T) {
	t.Run("malformed status releases observation lease", func(t *testing.T) {
		holdQuarters(t)
		dir := scratchDir(t)
		stateDir := filepath.Join(dir, "state")
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(stateDir, "update.log")
		if err := os.WriteFile(logPath, []byte("retained\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath+".status", []byte(`{"version":1`), 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeUpdate(t)
		f.release()
		core := startCore(t, dir, "--update-cmd", f.path)
		wantError(t, core.post("GetUpdate", `{}`), http.StatusServiceUnavailable, codeUnavailable)
		if err := os.Remove(logPath + ".status"); err != nil {
			t.Fatal(err)
		}
		wantJSON(t, core.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)
		wantJSON(t, core.post("StartUpdate", `{"requestId":"repaired","trigger":"apply"}`), http.StatusOK, `{}`)
		core.waitFinished("apply")
	})

	t.Run("request and result without status are unavailable", func(t *testing.T) {
		holdQuarters(t)
		dir := scratchDir(t)
		stateDir := filepath.Join(dir, "state")
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(stateDir, "update.log")
		if err := os.WriteFile(logPath, []byte("retained\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		request, result := []byte("orphan-request\n"), []byte("orphan-result\n")
		if err := os.WriteFile(logPath+".request", request, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath+".result", result, 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeUpdate(t)
		core := startCore(t, dir, "--update-cmd", f.path)
		wantError(t, core.post("GetUpdate", `{}`), http.StatusServiceUnavailable, codeUnavailable)
		wantError(t, core.post("StartUpdate", `{"requestId":"orphan","trigger":"apply"}`), http.StatusServiceUnavailable, codeUnavailable)
		if string(mustRead(t, logPath+".request")) != string(request) || string(mustRead(t, logPath+".result")) != string(result) {
			t.Error("orphan operation artifacts were replaced")
		}
		if f.runs() != 0 {
			t.Errorf("orphan artifacts launched %d programs, want none", f.runs())
		}
	})
}

func TestObservationRacingAdmissionNeverMutatesTheNewIdentity(t *testing.T) {
	holdQuarters(t)
	c, f := startUpdateCore(t)
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"race-old","trigger":"apply"}`), http.StatusOK, `{}`)
	c.waitFinished("apply")
	statusPath := filepath.Join(c.state, "update.log.status")
	oldStatus := mustRead(t, statusPath)
	var oldIdentity struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(oldStatus, &oldIdentity); err != nil || oldIdentity.Nonce == "" {
		t.Fatalf("old worker identity = %q, %v", oldIdentity.Nonce, err)
	}
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}
	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)

	begin := make(chan struct{})
	viewReply, startReply := make(chan reply, 1), make(chan reply, 1)
	go func() { <-begin; viewReply <- restart.post("GetUpdate", `{}`) }()
	go func() {
		<-begin
		startReply <- restart.post("StartUpdate", `{"requestId":"race-new","trigger":"apply"}`)
	}()
	close(begin)
	view, started := <-viewReply, <-startReply
	if started.status == http.StatusServiceUnavailable {
		wantError(t, started, http.StatusServiceUnavailable, codeUnavailable)
		started = restart.post("StartUpdate", `{"requestId":"race-new-retry","trigger":"apply"}`)
	}
	wantJSON(t, started, http.StatusOK, `{}`)
	switch view.status {
	case http.StatusServiceUnavailable:
		wantError(t, view, http.StatusServiceUnavailable, codeUnavailable)
	case http.StatusOK:
		var observed updateView
		if json.Unmarshal(view.body, &observed) != nil || observed.Update == nil {
			t.Errorf("racing GetUpdate returned false idle: %s", view.body)
		}
	default:
		t.Errorf("racing GetUpdate = %d %s, want a valid observation or terminal/unlock unavailable", view.status, view.body)
	}
	waitFor(t, func() bool { return f.runs() == 2 && string(mustRead(t, statusPath)) != string(oldStatus) })
	final := restart.waitFinished("apply")
	if final.Update == nil || final.Update.Result != "success" || f.runs() != 2 {
		t.Errorf("new admission after observation = %+v, runs %d; want its own success exactly once", final, f.runs())
	}
	var newIdentity struct {
		Nonce string `json:"nonce"`
	}
	if body := mustRead(t, statusPath); json.Unmarshal(body, &newIdentity) != nil || newIdentity.Nonce == "" || newIdentity.Nonce == oldIdentity.Nonce {
		t.Errorf("new admission identity = %q, want one different from %q", newIdentity.Nonce, oldIdentity.Nonce)
	}
}
