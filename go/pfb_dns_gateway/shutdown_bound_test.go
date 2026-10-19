package main

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

// The rc stop sends KILL five seconds after TERM, so a shutdown has a budget of its own that covers every wait in it:
// the transports, the decider's patience for EOF and the kill. This decider ignores EOF and its kill is refused (what
// a decider that is still root after the privilege drop answers), so only the budget can end the shutdown. The EOF
// patience is an hour: if the budget did not cap it, the shutdown would outlast the watchdog.
func TestShutdownEndsInsideItsBudgetWhenTheDeciderIgnoresEOFAndCannotBeKilled(t *testing.T) {
	pidfile := t.TempDir() + "/decider.pid"
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "ignore-eof")
	cfg.killAfter = time.Hour
	cfg.shutdownBudget = 400 * time.Millisecond
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	pid := readPid(t, pidfile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) }) // the refused kill leaves the decider running
	srv.child.killProcess = func() error { return syscall.EPERM }

	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end inside its budget")

	text := logs.text()
	for _, want := range []string{"did not exit within", "cannot kill the decider", "still running"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the log must say %q:\n%s", want, text)
		}
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the decider must still be running (its kill was refused): %v", err)
	}
}
