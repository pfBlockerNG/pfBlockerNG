package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Outcome keeps the command's actual status separate from process-owner failures.
type Outcome struct {
	CommandErr  error
	Interrupted error
	WatchdogErr error
}

// reap waits for the command; tests hold its exit/reap window open.
var reap = (*exec.Cmd).Wait

// Run owns cmd's process group until its leader and every attached descendant are gone.
func Run(ctx context.Context, cmd *exec.Cmd, grace time.Duration) Outcome {
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
		return Outcome{WatchdogErr: errors.New("watchdog exited before the command started")}
	default:
	}
	if ctx.Err() != nil {
		return Outcome{CommandErr: context.Cause(ctx), WatchdogErr: watcher.retire(false)}
	}
	if err := cmd.Start(); err != nil {
		var watchErr error
		if exitedUnreaped(watcher.cmd.Process.Pid) {
			watchErr = errors.New("watchdog exited before the command started")
		}
		_ = watcher.cmd.Process.Kill()
		_ = watcher.reap()
		return Outcome{CommandErr: err, WatchdogErr: errors.Join(watchErr, watcher.retire(true))}
	}

	exited, decision := make(chan struct{}), make(chan error, 1)
	go func() { decision <- strictCleanup(ctx, cmd, watcher, exited, grace) }()
	commandErr := reap(cmd)
	close(exited)
	interrupted := <-decision
	watchErr := watcher.retire(true)
	return Outcome{CommandErr: commandErr, Interrupted: interrupted, WatchdogErr: watchErr}
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
		if exitedUnreaped(watcher.cmd.Process.Pid) {
			cause = errors.New("watchdog exited while the command was running")
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
			cause = errors.New("watchdog exited while the command was running")
			watchExited = nil
		case <-ctxDone:
			ctxDone = nil
			if !exitedUnreaped(cmd.Process.Pid) && cause == nil {
				cause = fmt.Errorf("command was killed: %w", context.Cause(ctx))
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
