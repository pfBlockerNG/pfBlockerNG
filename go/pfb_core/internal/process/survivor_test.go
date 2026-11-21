//go:build linux || freebsd

package process

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// survivorFIFOs makes the alive, ready and release FIFOs of a child whose life the test observes: the child holds
// alive open for writing, so a read answers EAGAIN while it runs and EOF once it is gone.
func survivorFIFOs(t *testing.T) (dir string, alive, release *os.File) {
	t.Helper()
	dir = t.TempDir()
	for _, name := range []string{"alive", "ready", "release", "idle"} {
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive, err := os.OpenFile(filepath.Join(dir, "alive"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alive.Close() })
	release, err = os.OpenFile(filepath.Join(dir, "release"), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	ready, err := os.OpenFile(filepath.Join(dir, "ready"), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close() })
	t.Cleanup(func() {
		_, _ = release.Write([]byte("release\n"))
		waitFIFOEOF(t, alive)
	})
	return dir, alive, release
}

func assertStillRunning(t *testing.T, alive *os.File, what string) {
	t.Helper()
	var b [1]byte
	if n, err := syscall.Read(int(alive.Fd()), b[:]); !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("%s at return = %d, %v; want EAGAIN (still running): the survivor policy signalled it", what, n, err)
	}
}

// A hook may start a service that outlives it, holding the hook's output file open: the run returns at the hook's own
// exit with its status, waits for nothing it started, and signals nothing it started.
func TestRunSurvivorReturnsAtLeaderExitLeavingAChildThatHoldsItsOutput(t *testing.T) {
	dir, alive, _ := survivorFIFOs(t)
	output, err := os.CreateTemp(dir, "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd := exec.Command("/bin/sh", "-c", `( exec 9> "$D/alive"; echo child > "$D/ready"; read -r line < "$D/release" ) &
read -r line < "$D/ready"
echo leader
exit 7`)
	cmd.Env = append(os.Environ(), "D="+dir)
	cmd.Stdout, cmd.Stderr = output, output
	done := make(chan Outcome, 1)
	go func() { done <- RunSurvivor(context.Background(), cmd, time.Second) }()
	out := recv(t, done, "the run waited for a child that holds its output")
	var exit *exec.ExitError
	if !errors.As(out.CommandErr, &exit) || exit.ExitCode() != 7 || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("RunSurvivor = %+v; want the leader's exit status 7 and no interruption", out)
	}
	assertStillRunning(t, alive, "the hook's child")
	if got, _ := os.ReadFile(output.Name()); string(got) != "leader\n" {
		t.Errorf("output file = %q; want the leader's line", got)
	}
}

// On its limit (ctx), the hook's own process gets TERM; a child it started is not signalled, even one that ignores TERM
// and would die with a process-group KILL.
func TestRunSurvivorTermsOnlyTheLeaderWhenItsLimitEnds(t *testing.T) {
	dir, alive, _ := survivorFIFOs(t)
	cmd := exec.Command("/bin/sh", "-c", `( trap '' TERM; exec 9> "$D/alive"; echo child > "$D/ready"; read -r line < "$D/release" ) &
read -r line < "$D/ready"
echo ready > "$D/leader"
read -r line < "$D/idle"`)
	cmd.Env = append(os.Environ(), "D="+dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Outcome, 1)
	go func() { done <- RunSurvivor(ctx, cmd, time.Second) }()
	awaitFile(t, filepath.Join(dir, "leader"))
	cancel()
	out := recv(t, done, "the leader did not end on TERM")
	var exit *exec.ExitError
	if !errors.Is(out.Interrupted, context.Canceled) || !errors.As(out.CommandErr, &exit) ||
		exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("RunSurvivor = %+v; want the leader ended by TERM and the run interrupted", out)
	}
	assertStillRunning(t, alive, "the TERM-ignoring child")
}

// A hook that ignores TERM is KILLed once the grace has passed.
func TestRunSurvivorKillsALeaderThatIgnoresTermAfterTheGrace(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", `trap '' TERM
echo ready > "$D/ready"
exec sleep 3600`)
	cmd.Env = append(os.Environ(), "D="+dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Outcome, 1)
	go func() { done <- RunSurvivor(ctx, cmd, 100*time.Millisecond) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	out := recv(t, done, "the TERM-ignoring leader was not killed after the grace")
	var exit *exec.ExitError
	if !errors.Is(out.Interrupted, context.Canceled) || !errors.As(out.CommandErr, &exit) ||
		exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("RunSurvivor = %+v; want the leader KILLed and the run interrupted", out)
	}
}

// Output must be a file, never a pipe a service could hold open: anything else is refused before anything starts.
func TestRunSurvivorRefusesOutputThatIsNotAFile(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "canary")
	for name, set := range map[string]func(*exec.Cmd){
		"stdout": func(c *exec.Cmd) { c.Stdout = &bytes.Buffer{} },
		"stderr": func(c *exec.Cmd) { c.Stderr = &bytes.Buffer{} },
		"stdin":  func(c *exec.Cmd) { c.Stdin = &bytes.Buffer{} },
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", `touch "$1"`, "sh", canary)
			set(cmd)
			out := RunSurvivor(context.Background(), cmd, time.Second)
			if out.CommandErr == nil || cmd.Process != nil {
				t.Fatalf("RunSurvivor with a non-file %s = %+v, started %v; want a refusal before start", name, out, cmd.Process != nil)
			}
			if _, err := os.Stat(canary); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the refused command ran: %v", err)
			}
		})
	}
}

func TestRunSurvivorKeepsTheStatusTheStartErrorAndAnEndedContext(t *testing.T) {
	out := RunSurvivor(context.Background(), exec.Command("/bin/sh", "-c", "exit 0"), time.Second)
	if out != (Outcome{}) {
		t.Errorf("a clean exit = %+v; want the zero Outcome", out)
	}
	out = RunSurvivor(context.Background(), exec.Command(filepath.Join(t.TempDir(), "missing")), time.Second)
	if !errors.Is(out.CommandErr, fs.ErrNotExist) || out.Interrupted != nil {
		t.Errorf("a missing program = %+v; want its start error", out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	out = RunSurvivor(ctx, cmd, time.Second)
	if !errors.Is(out.CommandErr, context.Canceled) || cmd.Process != nil {
		t.Errorf("an ended context = %+v, started %v; want its cause and nothing started", out, cmd.Process != nil)
	}
}
