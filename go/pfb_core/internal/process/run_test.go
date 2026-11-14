//go:build linux || freebsd

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const stuck = 15 * time.Second

func TestTheWatchdogAcknowledgesReadinessWithItsOwnProcessGroupEstablished(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.reap() })
	group, err := syscall.Getpgid(w.cmd.Process.Pid)
	if err != nil || group != w.cmd.Process.Pid {
		t.Errorf("ready watchdog group = %d, %v; want its pid %d", group, err, w.cmd.Process.Pid)
	}
	if err := w.retire(false); err != nil {
		t.Errorf("ready watchdog did not acknowledge completion: %v", err)
	}
}

func TestAStoppedWatchdogsAcknowledgementTimeoutLeavesTheSuccessfulProgramsDaemon(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.reap() })
	request, requestW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	defer requestW.Close()
	response, responseW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	defer responseW.Close()
	daemon := exec.Command("/bin/sh", "-c", "printf r; read token; printf a; exec sleep 60")
	daemon.Stdin, daemon.Stdout = request, responseW
	daemon.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: w.cmd.Process.Pid}
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Process.Kill(); _ = daemon.Wait() })
	_ = request.Close()
	_ = responseW.Close()
	if err := response.SetReadDeadline(time.Now().Add(stuck)); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(response, reply[:]); err != nil || reply[0] != 'r' {
		t.Fatalf("daemon readiness = %q, %v; want r", reply, err)
	}
	if err := w.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(stuck); ; {
		probe, stop := context.WithTimeout(context.Background(), time.Second)
		state, err := exec.CommandContext(probe, "ps", "-o", "stat=", "-p", strconv.Itoa(w.cmd.Process.Pid)).Output()
		stop()
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(state)), "T") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: watchdog never stopped: state %q, %v", state, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := w.retire(false); err == nil || !strings.Contains(err.Error(), "did not acknowledge completion") {
		t.Errorf("retire(stopped watchdog) = %v; want an acknowledgement failure", err)
	}
	if _, err := requestW.Write([]byte("continue\n")); err != nil {
		t.Fatalf("successful daemon could not receive its post-retirement request: %v", err)
	}
	if _, err := io.ReadFull(response, reply[:]); err != nil || reply[0] != 'a' {
		t.Errorf("daemon post-retirement acknowledgement = %q, %v; want a (still executing)", reply, err)
	}
}

func TestAWatchdogThatCannotReportReadinessExitsInsteadOfWaitingForCompletion(t *testing.T) {
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
		t.Errorf("watchdog with failed readiness = %v, context %v; want its own immediate error, not a wait for completion", err, ctx.Err())
	}
}

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

func TestRunPreservesTerminalStatusAndAttachedDescendants(t *testing.T) {
	for _, end := range []string{"exit 0", "exit 7", "exit 75", "kill -TERM $$"} {
		t.Run(end, func(t *testing.T) {
			cmd, dir := fixture(t, `echo $PPID > "$D/parent"
sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
`+end)
			ctx, cancel := context.WithTimeout(context.Background(), stuck)
			defer cancel()
			out := Run(ctx, cmd, Policy{Grace: 100 * time.Millisecond})
			if out.Interrupted != nil || out.WatchdogErr != nil {
				t.Fatalf("ownership phases = %+v", out)
			}
			if end == "exit 0" {
				if out.CommandErr != nil {
					t.Fatal(out.CommandErr)
				}
			} else {
				var status *exec.ExitError
				if !errors.As(out.CommandErr, &status) {
					t.Fatalf("command error = %v; want real ExitError", out.CommandErr)
				}
				ws := status.Sys().(syscall.WaitStatus)
				if end == "kill -TERM $$" {
					if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
						t.Errorf("status = %v; want TERM", ws)
					}
				} else {
					want, _ := strconv.Atoi(strings.TrimPrefix(end, "exit "))
					if status.ExitCode() != want {
						t.Errorf("exit = %d; want %d", status.ExitCode(), want)
					}
				}
			}
			if parent := pidFile(t, filepath.Join(dir, "parent")); parent != os.Getpid() {
				t.Errorf("actual parent = %d; want Core %d", parent, os.Getpid())
			}
			child := ownedChild(t, dir)
			if exited(child) {
				t.Errorf("daemon %d was killed after %s", child, end)
			}
		})
	}
}

func TestRunKeepsStartErrorAndAlreadyCancelledCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	out := Run(ctx, exec.Command(filepath.Join(t.TempDir(), "missing")), Policy{Grace: time.Millisecond})
	if !errors.Is(out.CommandErr, os.ErrNotExist) || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("missing executable = %+v", out)
	}
	// No own-child zombie may remain after watchdog retirement.
	if pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Errorf("wait after start failure = %d, %v; want ECHILD", pid, err)
	}
	cause := errors.New("cancelled before start")
	ended, stop := context.WithCancelCause(context.Background())
	stop(cause)
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	out = Run(ended, cmd, Policy{Grace: time.Millisecond})
	if out.CommandErr != cause || out.Interrupted != nil || out.WatchdogErr != nil || cmd.Process != nil {
		t.Errorf("already cancelled = %+v, process %v", out, cmd.Process)
	}
}

func TestLateCancellationUsesActualExitBeforeReap(t *testing.T) {
	cmd, dir := fixture(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
exit 7`)
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	oldReap, oldExited := reap, leaderExited
	defer func() { reap, leaderExited = oldReap, oldExited }()
	decided := make(chan struct{})
	leaderExited = func(int) bool {
		close(decided)
		return false // require the actual-kernel fallback before the held reap
	}
	reap = func(c *exec.Cmd) error {
		awaitZombie(t, c.Process.Pid)
		cancel()
		recv(t, decided, "cancellation never inspected the exited leader")
		return c.Wait()
	}
	out := Run(ctx, cmd, Policy{Grace: 100 * time.Millisecond})
	var status *exec.ExitError
	if !errors.As(out.CommandErr, &status) || status.ExitCode() != 7 || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Errorf("late cancellation = %+v; want real exit 7 only", out)
	}
	if child := ownedChild(t, dir); exited(child) {
		t.Errorf("late cancellation killed daemon %d", child)
	}
}

func TestCancellationCleansAnIgnoringChildAndPreservesWaitStatus(t *testing.T) {
	cmd, dir := fixture(t, `(trap '' TERM; exec 5>"$D/live"; echo ready > "$D/ready"; read token < "$D/release") >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
wait`)
	for _, name := range []string{"live", "release"} {
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	live, err := syscall.Open(filepath.Join(dir, "live"), syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(live)
	release, err := os.OpenFile(filepath.Join(dir, "release"), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	cause := errors.New("requested stop")
	ctx, cancel := context.WithTimeoutCause(context.Background(), stuck, errors.New("STUCK: cancellation cleanup"))
	defer cancel()
	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(errors.New("fixture salvage"))
	done := make(chan Outcome, 1)
	go func() { done <- Run(runCtx, cmd, Policy{Grace: 100 * time.Millisecond}) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	child := ownedChild(t, dir)
	t.Cleanup(func() {
		// Cooperatively release the fixture if the assertion path aborts; bound salvage and retain owned-PID fallback.
		_, _ = release.Write([]byte("release\n"))
		if !gone(child) {
			_ = syscall.Kill(child, syscall.SIGKILL)
		}
	})
	var probe [1]byte
	if n, err := syscall.Read(live, probe[:]); n != -1 || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("ready child's FIFO = %d, %v; want EAGAIN from its live writer", n, err)
	}
	stop(cause)
	out := recv(t, done, "cancelled command did not return")
	// This is the first observation after Run: no poll can let delayed EOF cleanup satisfy it.
	if n, err := syscall.Read(live, probe[:]); n != 0 || err != nil {
		t.Errorf("FIFO immediately after Run = %d, %v; want EOF (child's writer already closed)", n, err)
	}
	var status *exec.ExitError
	if !errors.As(out.CommandErr, &status) || !status.Sys().(syscall.WaitStatus).Signaled() {
		t.Errorf("actual command status = %v; want real signal ExitError", out.CommandErr)
	}
	if !errors.Is(out.Interrupted, cause) || !strings.HasPrefix(out.Interrupted.Error(), "program was killed: ") || out.WatchdogErr != nil {
		t.Errorf("cancellation phases = %+v", out)
	}
}

func TestUnexpectedWatchdogDeathCleansTheGroup(t *testing.T) {
	cmd, dir := fixture(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
kill -KILL "$(ps -o pgid= -p $$ | tr -d ' ')"
wait`)
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	out := Run(ctx, cmd, Policy{Grace: 100 * time.Millisecond})
	if out.Interrupted == nil || out.Interrupted.Error() != "watchdog exited while the program was running" {
		t.Errorf("unexpected watchdog death = %+v", out)
	}
	if child := ownedChild(t, dir); !gone(child) {
		t.Errorf("watchdog death left child %d", child)
	}
}

func TestUnrelatedHUPDoesNotAbandonTheGroup(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.reap() })
	if err := syscall.Kill(-w.cmd.Process.Pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if err := w.retire(false); err != nil {
		t.Errorf("HUP interfered with completion: %v", err)
	}
}

func fixture(t *testing.T, body string) (*exec.Cmd, string) {
	t.Helper()
	dir := t.TempDir()
	log, err := os.Create(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cmd := exec.Command("/bin/sh", "-c", body)
	cmd.Env = append(os.Environ(), "D="+dir)
	cmd.Stdout, cmd.Stderr = log, log
	return cmd, dir
}

func pidFile(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid file %s = %q, %v", path, b, err)
	}
	return pid
}

func ownedChild(t *testing.T, dir string) int {
	t.Helper()
	awaitFile(t, filepath.Join(dir, "child"))
	pid := pidFile(t, filepath.Join(dir, "child"))
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
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

func awaitZombie(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		if exitedUnreaped(pid) {
			if err := syscall.Kill(pid, 0); err != nil {
				t.Fatalf("exited child %d lost its unreaped identity: %v", pid, err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: child %d never exited", pid)
		}
	}
}

func exited(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := exec.CommandContext(ctx, "ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(state)), "Z")
}

func gone(pid int) bool {
	for deadline := time.Now().Add(stuck); ; time.Sleep(20 * time.Millisecond) {
		if exited(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

const coreDirEnv = "PFB_PROCESS_TEST_CORE_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(coreDirEnv); dir != "" {
		cmd := exec.Command("/bin/sh", "-c", `echo $$ > "$D/child"; echo ready > "$D/ready"; exec sleep 60`)
		cmd.Env = append(os.Environ(), "D="+dir)
		out := Run(context.Background(), cmd, Policy{Grace: 100 * time.Millisecond})
		fmt.Fprintln(os.Stderr, out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestCoreDeathCleansTheProgram(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	core := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	core.Env = append(os.Environ(), coreDirEnv+"="+dir)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Process.Kill(); _ = core.Wait() })
	awaitFile(t, filepath.Join(dir, "ready"))
	pid := ownedChild(t, dir)
	if exited(pid) {
		t.Fatalf("program %d did not start live", pid)
	}
	if err := core.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = core.Wait()
	if !gone(pid) {
		t.Errorf("program %d survived Core death", pid)
	}
}

func TestRunLeavesCallerDescriptorsAndPipeHoldingDescendantAlone(t *testing.T) {
	dir := t.TempDir()
	result, err := os.Create(filepath.Join(dir, "result"))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	output, outputW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	defer outputW.Close()
	cmd := exec.Command("/bin/sh", "-c", `sleep 60 </dev/null &
echo $! > "$D/child"
printf payload >&3
exit 0`)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "D="+dir)
	cmd.Stdout, cmd.Stderr = outputW, outputW
	cmd.ExtraFiles = []*os.File{result}
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	out := Run(ctx, cmd, Policy{Grace: 100 * time.Millisecond})
	if out.CommandErr != nil || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("pipe-holding terminal outcome = %+v", out)
	}
	child := ownedChild(t, dir)
	if exited(child) {
		t.Errorf("pipe-holding intentional child %d did not survive", child)
	}
	if _, err := result.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(result)
	if err != nil || string(payload) != "payload" {
		t.Errorf("caller's fd 3 = %q, %v; want payload", payload, err)
	}
}
