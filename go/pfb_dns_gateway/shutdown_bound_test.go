package main

import (
	"strings"
	"sync"
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

// The shutdown's waits for the decider share one budget: what the first leaves is all the second may take, so no stage
// can add a bound of its own on top. The waits are recorded as they are asked for (a duration is not asserted on, the
// bounds asked for are): their sum must fit the budget, whatever the decider does.
func TestEveryWaitForTheDeciderInAShutdownIsTakenOutOfTheOneBudget(t *testing.T) {
	pidfile := t.TempDir() + "/decider.pid"
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "ignore-eof")
	cfg.killAfter = time.Hour // far more than the budget: the budget must be what limits the wait for EOF
	const budget = 400 * time.Millisecond
	cfg.shutdownBudget = budget
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	pid := readPid(t, pidfile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	srv.child.killProcess = func() error { return syscall.EPERM }
	var mu sync.Mutex
	var waits []time.Duration
	srv.child.waiting = func(d time.Duration) { mu.Lock(); waits = append(waits, d); mu.Unlock() }

	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end inside its budget")

	mu.Lock()
	defer mu.Unlock()
	if len(waits) != 2 {
		t.Fatalf("the shutdown waited for the decider %d times (%v), want twice: for EOF, then after the kill", len(waits), waits)
	}
	if waits[0] <= 0 {
		t.Fatalf("the decider was given no time to leave on EOF: %v", waits)
	}
	var total time.Duration
	for _, d := range waits {
		total += d
	}
	if total > budget {
		t.Fatalf("the waits for the decider are %v, together %v: more than the one budget of %v", waits, total, budget)
	}
}

// What the rc stop gives the gateway after TERM before it sends KILL: the `5)` tick of the stop script that
// pfb_dns_proxy_service() writes (pfblockerng.inc), pinned there by DnsProxyServiceTest
// (testAProcessIgnoringTermIsKilledAfterFiveTicksAndItsStalePidfilesAreRemoved). A KILL leaves the ready file behind.
const rcStopKillAfter = 5 * time.Second

// The default budget has to end the shutdown before the rc stop's KILL, and the decider's patience for EOF has to fit
// in it.
func TestTheDefaultShutdownBudgetEndsBeforeTheRcStopSendsKill(t *testing.T) {
	if defaultShutdownBudget >= rcStopKillAfter {
		t.Fatalf("the shutdown budget is %v, the rc stop sends KILL %v after TERM: a slow shutdown would be killed with its ready file in place", defaultShutdownBudget, rcStopKillAfter)
	}
	if defaultKillAfter >= defaultShutdownBudget {
		t.Fatalf("the decider's patience for EOF is %v and the whole shutdown has %v: the patience would never fit", defaultKillAfter, defaultShutdownBudget)
	}
}
