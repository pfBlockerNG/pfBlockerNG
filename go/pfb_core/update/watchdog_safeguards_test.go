//go:build linux || freebsd

package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestADeadWatchdogKeepsItsGroupIdentityUntilCleanupCanNoLongerSignalIt(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.retire(false) })
	if err := w.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	recv(t, w.exited, "the watchdog's death was never observed")
	// An unreaped group-leader pid cannot be reused for an unrelated process group.
	awaitZombie(t, w.cmd.Process.Pid)
}

func TestUnexpectedWatchdogDeathIsTheCauseOfPromptGroupCleanup(t *testing.T) {
	c, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
kill -KILL "$(ps -o pgid= -p $$ | tr -d ' ')"
wait`)
	ctx, cancel := context.WithTimeoutCause(context.Background(), 10*time.Second, errors.New("STUCK: watchdog death did not initiate cleanup"))
	defer cancel()
	_, err := c.Run(ctx, Request{}, newLog(t))
	if err == nil || !strings.Contains(err.Error(), "watchdog exited while the program was running") {
		t.Errorf("Run() = %v; want interruption caused by watchdog death, not natural expiry or the salvage watchdog", err)
	}
	child := recordedPid(t, dir)
	if !gone(child) {
		t.Errorf("watchdog-death cleanup left program child %d alive", child)
	}
}

func TestAStartFailureLeavesNoUnwaitedOwnedChildAndProcessInspectionMustWork(t *testing.T) {
	c, _ := program(t, "exit 0")
	c.Path += ".missing"
	if _, err := c.Run(context.Background(), Request{}, newLog(t)); err == nil {
		t.Fatal("Run succeeded for a missing program")
	}
	children, err := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid())).CombinedOutput()
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 1 {
		t.Errorf("pgrep for owned children = %q, %v; want exit 1 (no matches), never an inspection failure", children, err)
	}
	// No own-child zombie may remain either; pgrep's live-process view is not sufficient.
	if pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Errorf("wait after failed program start = pid %d, %v; want ECHILD", pid, err)
	}
}
