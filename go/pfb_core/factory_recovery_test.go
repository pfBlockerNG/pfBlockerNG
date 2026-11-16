package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFactoryCompletionAndRestartRecoverTheReceiptBeforeTheNextAdmission(t *testing.T) {
	holdQuarters(t)
	dir := scratchDir(t)
	statePath := filepath.Join(dir, "state", "schedule_state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	seedOccurrence := int64(1)
	restorePending(t, statePath, seedOccurrence)
	f := newFakeUpdate(t)
	c := startCore(t, dir, "--update-cmd", f.path)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"},"attempted":["ipv4:Feed1_v4"]}`)
	releasePath := filepath.Join(f.dir, "release")
	f.release()
	if got := c.post("StartUpdate", `{"requestId":"factory-1","trigger":"retry"}`); got.status != 200 {
		t.Fatalf("StartUpdate = %d %s", got.status, got.body)
	}
	c.waitFinished("retry")
	statusPath := filepath.Join(c.state, "update.log.status")
	status, err := os.ReadFile(statusPath)
	if err != nil || !strings.Contains(string(status), `"settled":true`) {
		t.Fatalf("factory completion did not settle the receipt: %s %v", status, err)
	}
	var receipt struct {
		Occurrences map[string]int64 `json:"occurrences"`
		Result      struct {
			Outcomes map[string]string `json:"outcomes"`
		} `json:"result"`
	}
	if err := json.Unmarshal(status, &receipt); err != nil {
		t.Fatal(err)
	}
	oldOccurrence, ok := receipt.Occurrences["ipv4:Feed1_v4"]
	if !ok {
		t.Fatalf("old receipt has no Feed1_v4 occurrence: %+v", receipt.Occurrences)
	}
	if got := receipt.Result.Outcomes["ipv4:Feed1_v4"]; got != "success" {
		t.Fatalf("old receipt Feed1_v4 outcome = %q, want success", got)
	}
	if err := os.Remove(releasePath); err != nil {
		t.Fatal(err)
	}
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}
	unsetSettled(t, statusPath)
	restorePending(t, statePath, oldOccurrence)
	restart := startCore(t, dir, "--update-cmd", f.path)
	if !strings.Contains(string(mustRead(t, statusPath)), `"settled":true`) {
		t.Fatal("restart did not settle the old receipt before admission")
	}
	t.Cleanup(f.release)
	done := make(chan reply, 1)
	go func() { done <- restart.post("StartUpdate", `{"requestId":"factory-2","trigger":"apply"}`) }()
	select {
	case got := <-done:
		if got.status != 200 {
			t.Fatalf("first StartUpdate after restart = %d %s\n%s", got.status, got.body, restart.stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first StartUpdate after restart deadlocked")
	}

	waitFor(t, func() bool { return f.runs() == 2 })
	if request := f.request(); !strings.Contains(request, `"trigger":"apply"`) {
		t.Fatalf("second worker request = %s, want the distinct apply execution", request)
	}
	if view := restart.getUpdate(""); !view.Running || view.Update == nil || view.Update.Trigger != "apply" {
		t.Fatalf("second Update before release = %+v, want a running apply at its barrier", view)
	}
	var saved struct {
		Items map[string]struct {
			LastCompletedOccurrence *int64 `json:"last_completed_occurrence"`
			PendingOccurrence       *int64 `json:"pending_occurrence"`
			CompletionOutcome       string `json:"completion_outcome"`
		} `json:"items"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(restart.state, "schedule_state.json")), &saved); err != nil {
		t.Fatal(err)
	}
	item, ok := saved.Items["ipv4:Feed1_v4"]
	if !ok || item.LastCompletedOccurrence == nil || *item.LastCompletedOccurrence != oldOccurrence || item.CompletionOutcome != "success" {
		t.Fatalf("recovered feed state before second outcome = %+v, want occurrence %d completed from the old receipt", item, oldOccurrence)
	}
	if item.PendingOccurrence != nil && *item.PendingOccurrence == oldOccurrence {
		t.Fatalf("old occurrence remained pending before second outcome: %+v", item)
	}
	f.release()
	if end := restart.waitFinished("apply"); end.Update.Result != "success" {
		t.Errorf("second Update after recovery = %+v; want success", end.Update)
	}
	if got := f.runs(); got != 2 {
		t.Errorf("worker executions = %d, want exactly two", got)
	}
}

func TestFactorySettlementFailureLeavesTheReceiptUnsettled(t *testing.T) {
	c, f := startUpdateCore(t)
	c.initialize()
	if c.stop() != 0 {
		t.Fatalf("Core exited %d\n%s", c.code, c.stderr.String())
	}
	state := filepath.Join(c.state, "schedule_state.json")
	if err := os.Remove(state); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeUnsettledReceipt(t, filepath.Join(c.state, "update.log"))
	restart := startCore(t, filepath.Dir(c.state), "--update-cmd", f.path)
	got := restart.post("StartUpdate", `{"requestId":"factory-fail","trigger":"apply"}`)
	if got.status == 200 {
		t.Fatalf("StartUpdate succeeded although the schedule could not be written: %s", got.body)
	}
	if strings.Contains(string(mustRead(t, filepath.Join(c.state, "update.log.status"))), `"settled":true`) {
		t.Fatal("failed settlement marked the receipt settled")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unsetSettled(t *testing.T, path string) {
	t.Helper()
	b := mustRead(t, path)
	next := strings.ReplaceAll(string(b), `,"settled":true`, "")
	if next == string(b) {
		t.Fatalf("receipt has no settled flag: %s", b)
	}
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
}

func restorePending(t *testing.T, path string, occurrence int64) {
	t.Helper()
	state := fmt.Sprintf(`{"schema":1,"items":{"ipv4:Feed1_v4":{"pending_occurrence":%d}}}`, occurrence)
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeUnsettledReceipt(t *testing.T, logPath string) {
	t.Helper()
	if err := os.WriteFile(logPath, []byte("previous-update\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/bin/true","request":{"trigger":"apply"},"startedAt":1,"finishedAt":50,"exitCode":0,"occurrences":{"ipv4:Feed1_v4":1},"result":{"outcomes":{"ipv4:Feed1_v4":"success"}}}`
	if err := os.WriteFile(logPath+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
