package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Policy sets the foreground process group's TERM and post-KILL grace.
type Policy struct {
	Grace time.Duration
}

// Outcome keeps the direct command status separate from ownership failures.
type Outcome struct {
	CommandErr  error
	Interrupted error
	WatchdogErr error
}

// leaderExited reports whether the program has exited; replaced only by tests.
var leaderExited = exitedUnreaped

// reap waits for the actual program; replaced only by tests to hold its exit/reap window open.
var reap = (*exec.Cmd).Wait

// Run owns cmd's process group and watchdog, but leaves exited programs' descendants alone.
// The caller supplies an unstarted command and owns its arguments, environment and IO.
func Run(ctx context.Context, cmd *exec.Cmd, policy Policy) Outcome {
	if ctx.Err() != nil {
		return Outcome{CommandErr: context.Cause(ctx)}
	}
	watcher, err := startWatchdog(ctx)
	if err != nil {
		return Outcome{WatchdogErr: err}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: watcher.cmd.Process.Pid}
	select {
	case <-watcher.exited:
		_ = watcher.retire(false)
		return Outcome{WatchdogErr: errors.New("watchdog exited before the program started")}
	default:
	}
	if ctx.Err() != nil {
		return Outcome{CommandErr: context.Cause(ctx), WatchdogErr: watcher.retire(false)}
	}
	if err := cmd.Start(); err != nil {
		return Outcome{CommandErr: err, WatchdogErr: watcher.retire(false)}
	}
	exited, decision := make(chan struct{}), make(chan error, 1)
	go func() {
		var cause error
		select {
		case <-exited:
			decision <- nil
			return
		case <-ctx.Done():
			cause = fmt.Errorf("program was killed: %w", context.Cause(ctx))
		case <-watcher.exited:
			cause = errors.New("watchdog exited while the program was running")
		}
		if leaderExited(cmd.Process.Pid) || exitedUnreaped(cmd.Process.Pid) {
			decision <- nil
			return
		}
		group := -watcher.cmd.Process.Pid
		_ = syscall.Kill(group, syscall.SIGTERM)
		if !groupGone(group, policy.Grace) {
			_ = syscall.Kill(group, syscall.SIGKILL)
			_ = watcher.reap()
			groupGone(group, policy.Grace)
		}
		decision <- cause
	}()
	commandErr := reap(cmd)
	close(exited)
	interrupted := <-decision
	watchErr := watcher.retire(interrupted != nil)
	return Outcome{CommandErr: commandErr, Interrupted: interrupted, WatchdogErr: watchErr}
}

// groupGone observes the group without reaping its identity-reserving watchdog.
func groupGone(group int, grace time.Duration) bool {
	for deadline := time.Now().Add(grace); ; time.Sleep(10 * time.Millisecond) {
		if errors.Is(syscall.Kill(group, 0), syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}
