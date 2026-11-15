package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFactoryCompletionAndRestartRecoverTheReceiptBeforeTheNextAdmission(t *testing.T) {
	c, f := startUpdateCore(t)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"},"attempted":["ipv4:Feed1_v4"]}`)
	f.release()
	if got := c.post("StartUpdate", `{"requestId":"factory-1","trigger":"retry"}`); got.status != 200 {
		t.Fatalf("StartUpdate = %d %s", got.status, got.body)
	}
	c.waitFinished("retry")
	status, err := os.ReadFile(filepath.Join(c.state, "update.log.status"))
	if err != nil || !strings.Contains(string(status), `"settled":true`) {
		t.Fatalf("factory completion did not settle the receipt: %s %v", status, err)
	}
	logBefore := mustRead(t, filepath.Join(c.state, "update.log"))
	parent := filepath.Dir(c.state)
	if c.stop() != 0 {
		t.Fatalf("first Core exited %d\n%s", c.code, c.stderr.String())
	}
	unsetSettled(t, filepath.Join(c.state, "update.log.status"))
	restorePending(t, filepath.Join(c.state, "schedule_state.json"))
	restart := startCore(t, parent, "--update-cmd", f.path)
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
	if got := mustRead(t, filepath.Join(c.state, "update.log")); string(got) == string(logBefore) && strings.Contains(string(status), `"settled":false`) {
		t.Fatal("restart neither settled the old receipt nor admitted a new Update")
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(c.state, "update.log.status"))), `"settled":true`) {
		t.Fatal("restart admission left the old receipt unsettled")
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

func restorePending(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"schema":1,"items":{"ipv4:Feed1_v4":{"pending_occurrence":1}}}`), 0o600); err != nil {
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
