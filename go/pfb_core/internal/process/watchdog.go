package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// superviseArg re-executes this binary as the transient process watchdog; fd 3 reports readiness and fd 4 receives completion.
const superviseArg = "--process-supervise"

const coreDied = syscall.SIGHUP

// Completion acknowledgement has its own budget: a short TERM grace does not imply the watchdog can exit that fast.
const watchdogAckTimeout = 3 * time.Second
// coreDeathGrace is the TERM window before the parent-death watchdog escalates.
const coreDeathGrace = 3 * time.Second

func init() {
	if len(os.Args) == 2 && os.Args[1] == superviseArg {
		os.Exit(supervise())
	}
}

// The completion pipe belongs only to Core: its EOF, not an unrelated HUP, proves Core abandoned the command.
func supervise() int {
	signal.Notify(make(chan os.Signal, 1), coreDied, syscall.SIGTERM)
	ready, completion := os.NewFile(3, "ready"), os.NewFile(4, "completion")
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	if _, err := ready.Write([]byte{1}); err != nil {
		return 1
	}
	_ = ready.Close()
	var completed [1]byte
	if _, err := io.ReadFull(completion, completed[:]); err == nil && completed[0] == 1 {
		return 0
	}
	group := -syscall.Getpgrp()
	_ = syscall.Kill(group, syscall.SIGTERM)
	time.Sleep(coreDeathGrace)
	_ = syscall.Kill(group, syscall.SIGKILL)
	select {}
}

type watchdog struct {
	cmd        *exec.Cmd
	completion *os.File
	exited     chan struct{}
	err        error
	reaped     bool
}

func startWatchdog(ctx context.Context) (*watchdog, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("the process watchdog cannot be found: %w", err)
	}
	ready, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer ready.Close()
	defer readyW.Close()
	completion, completionW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer completion.Close()
	w := &watchdog{cmd: exec.Command(self, superviseArg), completion: completionW, exited: make(chan struct{})}
	w.cmd.ExtraFiles = []*os.File{readyW, completion}
	w.cmd.SysProcAttr = procAttr()
	if err := w.cmd.Start(); err != nil {
		_ = completionW.Close()
		return nil, err
	}
	_ = readyW.Close()
	_ = completion.Close()
	go func() {
		if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
			// shortcut: other OSes lack the non-reaping query; only Linux and FreeBSD run Core.
			w.err = w.cmd.Wait()
			w.reaped = true
		} else {
			// Keep the group leader's identity reserved until Core has sent its last group signal.
			for !exitedUnreaped(w.cmd.Process.Pid) {
				time.Sleep(10 * time.Millisecond)
			}
		}
		close(w.exited)
	}()
	readiness := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := io.ReadFull(ready, b[:])
		if err == nil && b[0] != 1 {
			err = errors.New("invalid readiness byte")
		}
		readiness <- err
	}()
	select {
	case err = <-readiness:
		if err == nil {
			select {
			case <-w.exited:
				err = errors.New("the process watchdog exited before the command started")
			default:
				return w, nil
			}
		}
	case <-w.exited:
		err = errors.New("the process watchdog exited before readiness")
		_ = ready.Close()
		<-readiness
	case <-ctx.Done():
		err = context.Cause(ctx)
		_ = ready.Close()
		<-readiness
	}
	_ = completionW.Close()
	_ = w.cmd.Process.Kill()
	_ = w.reap()
	return nil, err
}

func (w *watchdog) reap() error {
	<-w.exited
	if !w.reaped {
		w.err = w.cmd.Wait()
		w.reaped = true
	}
	return w.err
}

// retire commits completion before acknowledging the watchdog's exit; cleanup never reports a successful command.
func (w *watchdog) retire(cleanup bool) error {
	var err error
	if !cleanup {
		_, err = w.completion.Write([]byte{1})
	}
	_ = w.completion.Close()
	timer := time.NewTimer(watchdogAckTimeout)
	defer timer.Stop()
	select {
	case <-w.exited:
	case <-timer.C:
		_ = w.cmd.Process.Kill()
		_ = w.reap()
		return errors.New("the process watchdog did not acknowledge completion")
	}
	_ = w.reap()
	if cleanup {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the process watchdog could not receive completion: %w", err)
	}
	if w.err != nil {
		return fmt.Errorf("the process watchdog failed: %w", w.err)
	}
	return nil
}
