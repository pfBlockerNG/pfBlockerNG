//go:build linux || freebsd

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const stuck = 15 * time.Second

func TestWatchdogReadinessAndControlDescriptors(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.retire(true) })
	group, err := syscall.Getpgid(w.cmd.Process.Pid)
	if err != nil || group != w.cmd.Process.Pid {
		t.Fatalf("ready watchdog group = %d, %v; want its pid %d", group, err, w.cmd.Process.Pid)
	}
	if err := w.retire(false); err != nil {
		t.Fatalf("ready watchdog did not acknowledge completion: %v", err)
	}
	cmd := exec.Command("/bin/sh", "-c", "test ! -e /dev/fd/3 && test ! -e /dev/fd/4")
	if out := Run(context.Background(), cmd, time.Second); out.CommandErr != nil || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Errorf("strict command inherited watchdog descriptors: %+v", out)
	}
}

func TestWatchdogWithFailedReadinessExits(t *testing.T) {
	ready, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = ready.Close()
	defer readyW.Close()
	completion, completionW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Close()
	defer completionW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], superviseArg)
	cmd.ExtraFiles = []*os.File{readyW, completion}
	cmd.SysProcAttr = procAttr()
	if err := cmd.Run(); err == nil || ctx.Err() != nil {
		t.Errorf("watchdog with failed readiness = %v, context %v; want its own immediate error", err, ctx.Err())
	}
}

func TestDeadWatchdogKeepsItsGroupIdentityUntilReaped(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	recv(t, w.exited, "the watchdog's death was never observed")
	awaitZombie(t, w.cmd.Process.Pid)
	if err := w.retire(true); err != nil {
		t.Errorf("reap a dead watchdog: %v", err)
	}
}

func TestRunPreservesTerminalExitStatus(t *testing.T) {
	for _, tc := range []struct {
		end    string
		status int
		signal syscall.Signal
	}{
		{end: "exit 0"},
		{end: "exit 7", status: 7},
		{end: "exit 75", status: 75},
		{end: "kill -TERM $$", signal: syscall.SIGTERM},
	} {
		t.Run(tc.end, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", tc.end)
			out := Run(context.Background(), cmd, time.Second)
			if out.Interrupted != nil || out.WatchdogErr != nil {
				t.Fatalf("ownership outcome = %+v", out)
			}
			if tc.end == "exit 0" {
				if out.CommandErr != nil {
					t.Fatal(out.CommandErr)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(out.CommandErr, &exit) {
				t.Fatalf("command error = %v; want direct ExitError", out.CommandErr)
			}
			if tc.signal != 0 {
				ws := exit.Sys().(syscall.WaitStatus)
				if !ws.Signaled() || ws.Signal() != tc.signal {
					t.Errorf("wait status = %v; want signal %v", ws, tc.signal)
				}
			} else if exit.ExitCode() != tc.status {
				t.Errorf("exit = %d; want %d", exit.ExitCode(), tc.status)
			}
		})
	}
}

func TestRunKillsAttachedDescendantBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	alivePath, readyPath, releasePath := filepath.Join(dir, "alive"), filepath.Join(dir, "ready"), filepath.Join(dir, "release")
	for _, path := range []string{alivePath, readyPath, releasePath} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive, err := os.OpenFile(alivePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alive.Close() })
	release, err := os.OpenFile(releasePath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	ready, err := os.OpenFile(readyPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close() })
	t.Cleanup(func() {
		_, _ = release.Write([]byte("release\n"))
		waitFIFOEOF(t, alive)
	})
	cmd := exec.Command("/bin/sh", "-c", `( exec 9> "$ALIVE"; echo ready > "$READY"; read -r line < "$RELEASE" ) &
read -r line < "$READY"
exit 0`)
	cmd.Env = append(os.Environ(), "ALIVE="+alivePath, "READY="+readyPath, "RELEASE="+releasePath)
	out := Run(context.Background(), cmd, time.Second)
	if out.CommandErr != nil || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("Run = %+v; want normal completion", out)
	}
	var b [1]byte
	if n, err := syscall.Read(int(alive.Fd()), b[:]); n != 0 || err != nil {
		t.Errorf("attached child at Run return = %d, %v; want EOF", n, err)
	}
}

func TestRunCancellationAllowsCooperativeTermGrace(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", `trap 'echo handled > "$D/handled"; while [ ! -e "$D/release" ]; do sleep 0.01; done; exit 0' TERM
echo ready > "$D/ready"
while :; do sleep 60; done`)
	cmd.Env = append(os.Environ(), "D="+dir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Outcome, 1)
	finished := false
	t.Cleanup(func() {
		if finished {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(stuck):
			t.Error("salvage: TERM-grace run did not finish")
		}
	})
	go func() { done <- Run(ctx, cmd, time.Second) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	awaitFile(t, filepath.Join(dir, "handled"))
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out := recv(t, done, "cooperative TERM handler did not finish")
	finished = true
	if out.CommandErr != nil || !errors.Is(out.Interrupted, context.Canceled) || out.WatchdogErr != nil {
		t.Errorf("graceful cancellation outcome = %+v", out)
	}
}

func TestRunEscalatesWhenTheLeaderIgnoresTerm(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", `trap '' TERM
echo ready > "$D/ready"
while :; do sleep 60; done`)
	cmd.Env = append(os.Environ(), "D="+dir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Outcome, 1)
	finished := false
	t.Cleanup(func() {
		if finished {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(stuck):
			t.Error("salvage: TERM-ignoring run did not finish")
		}
	})
	go func() { done <- Run(ctx, cmd, 100*time.Millisecond) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	out := recv(t, done, "TERM-ignoring leader was not killed after grace")
	finished = true
	var exit *exec.ExitError
	if !errors.Is(out.Interrupted, context.Canceled) || !errors.As(out.CommandErr, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || out.WatchdogErr != nil {
		t.Errorf("escalated cancellation outcome = %+v", out)
	}
}

func TestRunCancellationAfterExitBeforeReapPreservesExitStatus(t *testing.T) {
	dir := t.TempDir()
	alivePath, readyPath, releasePath := filepath.Join(dir, "alive"), filepath.Join(dir, "ready"), filepath.Join(dir, "release")
	for _, path := range []string{alivePath, readyPath, releasePath} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive, err := os.OpenFile(alivePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alive.Close() })
	release, err := os.OpenFile(releasePath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	ready, err := os.OpenFile(readyPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close() })
	t.Cleanup(func() {
		_, _ = release.Write([]byte("release\n"))
		waitFIFOEOF(t, alive)
	})
	cmd := exec.Command("/bin/sh", "-c", `( exec 9> "$ALIVE"; echo ready > "$READY"; read -r line < "$RELEASE" ) &
read -r line < "$READY"
exit 7`)
	cmd.Env = append(os.Environ(), "ALIVE="+alivePath, "READY="+readyPath, "RELEASE="+releasePath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldReap := reap
	t.Cleanup(func() { reap = oldReap })
	reap = func(cmd *exec.Cmd) error {
		awaitZombie(t, cmd.Process.Pid)
		cancel()
		return cmd.Wait()
	}
	out := Run(ctx, cmd, time.Second)
	var exit *exec.ExitError
	if !errors.As(out.CommandErr, &exit) || exit.ExitCode() != 7 || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Errorf("late cancellation outcome = %+v; want actual exit 7 only", out)
	}
	var b [1]byte
	if n, err := syscall.Read(int(alive.Fd()), b[:]); n != 0 || err != nil {
		t.Errorf("late-reap attached child = %d, %v; want EOF", n, err)
	}
}

func TestUnexpectedWatchdogDeathCleansTheProgramGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", `group=$(ps -o pgid= -p $$ | tr -d ' ')
kill -KILL "$group"
exec sleep 60`)
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	out := Run(ctx, cmd, 100*time.Millisecond)
	if out.Interrupted == nil || out.Interrupted.Error() != "watchdog exited while the command was running" || out.WatchdogErr != nil {
		t.Errorf("watchdog death outcome = %+v", out)
	}
}

func TestUnrelatedHangupDoesNotAbandonTheGroup(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.retire(true) })
	if err := syscall.Kill(-w.cmd.Process.Pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if err := w.retire(false); err != nil {
		t.Errorf("unrelated HUP interfered with completion: %v", err)
	}
}

func TestRunKeepsStartErrorAndAlreadyCancelledCause(t *testing.T) {
	out := Run(context.Background(), exec.Command(filepath.Join(t.TempDir(), "missing")), time.Second)
	if !errors.Is(out.CommandErr, os.ErrNotExist) || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("missing executable = %+v", out)
	}
	if pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Errorf("wait after failed start = %d, %v; want ECHILD", pid, err)
	}
	cause := errors.New("cancelled before start")
	ended, stop := context.WithCancelCause(context.Background())
	stop(cause)
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	out = Run(ended, cmd, time.Second)
	if out.CommandErr != cause || out.Interrupted != nil || out.WatchdogErr != nil || cmd.Process != nil {
		t.Errorf("already-cancelled context = %+v, process %v", out, cmd.Process)
	}
}

func TestCoreDeathCleansAttachedGroup(t *testing.T) {
	dir := t.TempDir()
	alivePath, releasePath := filepath.Join(dir, "alive"), filepath.Join(dir, "release")
	for _, path := range []string{alivePath, releasePath} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive, err := os.OpenFile(alivePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alive.Close() })
	release, err := os.OpenFile(releasePath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	core := exec.Command(os.Args[0], "-test.run=^$")
	core.Env = append(os.Environ(), coreDirEnv+"="+dir, "D="+dir, "ALIVE="+alivePath, "RELEASE="+releasePath)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if core.ProcessState == nil {
			_ = core.Process.Kill()
			_, _ = core.Process.Wait()
		}
		_, _ = release.Write([]byte("release\n"))
		waitFIFOEOF(t, alive)
	})
	awaitFile(t, filepath.Join(dir, "ready"))
	if err := core.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Process.Wait(); err != nil {
		t.Fatalf("wait for killed Core: %v", err)
	}
	waitFIFOEOF(t, alive)
}

const coreDirEnv = "PFB_PROCESS_TEST_CORE_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(coreDirEnv); dir != "" {
		cmd := exec.Command("/bin/sh", "-c", `( trap '' TERM; exec 9> "$ALIVE"; echo ready > "$D/ready"; read -r line < "$RELEASE" ) & wait`)
		out := Run(context.Background(), cmd, time.Second)
		fmt.Fprintln(os.Stderr, out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func awaitFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: file %s never appeared", path)
		}
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(stuck):
		t.Fatal("STUCK: " + what)
		var zero T
		return zero
	}
}

func waitFIFOEOF(t *testing.T, f *os.File) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(10 * time.Millisecond) {
		var b [1]byte
		n, err := syscall.Read(int(f.Fd()), b[:])
		if n == 0 && err == nil {
			return
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("FIFO cleanup read = %d, %v", n, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: attached process still holds FIFO %s", f.Name())
		}
	}
}
