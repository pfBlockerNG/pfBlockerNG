package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Policy sets the foreground process group's grace and whether exited programs may leave descendants.
type Policy struct {
	Grace            time.Duration
	LeaveGroupOnExit bool
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

// Run owns cmd's process group and watchdog until the selected exit policy is complete.
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
		if !policy.LeaveGroupOnExit {
			// No program started, so only the owned watchdog needs to be stopped.
			var watchErr error
			if exitedUnreaped(watcher.cmd.Process.Pid) {
				watchErr = errors.New("watchdog exited before the program started")
			}
			_ = watcher.cmd.Process.Kill()
			_ = watcher.reap()
			return Outcome{CommandErr: err, WatchdogErr: errors.Join(watchErr, watcher.retire(true))}
		}
		return Outcome{CommandErr: err, WatchdogErr: watcher.retire(false)}
	}
	type cleanupDecision struct {
		interrupted error
		cleanup     bool
	}
	exited, decision := make(chan struct{}), make(chan cleanupDecision, 1)
	go func() {
		if !policy.LeaveGroupOnExit {
			decision <- cleanupDecision{interrupted: strictCleanup(ctx, cmd, watcher, exited, policy.Grace), cleanup: true}
			return
		}
		var cause error
		select {
		case <-exited:
			decision <- cleanupDecision{}
			return
		case <-ctx.Done():
			cause = fmt.Errorf("program was killed: %w", context.Cause(ctx))
		case <-watcher.exited:
			cause = errors.New("watchdog exited while the program was running")
		}
		if leaderExited(cmd.Process.Pid) || exitedUnreaped(cmd.Process.Pid) {
			decision <- cleanupDecision{}
			return
		}
		group := -watcher.cmd.Process.Pid
		_ = syscall.Kill(group, syscall.SIGTERM)
		if !groupGone(group, policy.Grace) {
			_ = syscall.Kill(group, syscall.SIGKILL)
			_ = watcher.reap()
			groupGone(group, policy.Grace)
		}
		decision <- cleanupDecision{interrupted: cause, cleanup: true}
	}()
	commandErr := reap(cmd)
	close(exited)
	result := <-decision
	watchErr := watcher.retire(result.cleanup)
	return Outcome{CommandErr: commandErr, Interrupted: result.interrupted, WatchdogErr: watchErr}
}

// strictCleanup observes kernel exit independently of Wait's descendant-held IO pipes.
func strictCleanup(ctx context.Context, cmd *exec.Cmd, watcher *watchdog, exited <-chan struct{}, grace time.Duration) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	group := -watcher.cmd.Process.Pid
	ctxDone, watchExited := ctx.Done(), watcher.exited
	var cause error
	var deadline time.Time
	for {
		// An unexpected owner exit is still a failure when the program has also exited.
		if exitedUnreaped(watcher.cmd.Process.Pid) {
			cause = errors.New("watchdog exited while the program was running")
			watchExited = nil
		}
		if exitedUnreaped(cmd.Process.Pid) {
			break
		}
		if cause != nil && deadline.IsZero() {
			_ = syscall.Kill(group, syscall.SIGTERM)
			deadline = time.Now().Add(grace)
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			break
		}
		select {
		case <-tick.C:
		case <-exited:
		case <-watchExited:
			cause = errors.New("watchdog exited while the program was running")
			watchExited = nil
		case <-ctxDone:
			ctxDone = nil
			if !exitedUnreaped(cmd.Process.Pid) && cause == nil {
				cause = fmt.Errorf("program was killed: %w", context.Cause(ctx))
			}
		}
	}
	_ = syscall.Kill(group, syscall.SIGKILL)
	_ = watcher.reap()
	groupGone(group, grace)
	return cause
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
