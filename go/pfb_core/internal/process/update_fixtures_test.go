//go:build linux || freebsd

package process_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// stuck is the outer watchdog: it only salvages a hung test, no assertion rests on it.
const stuck = 30 * time.Second
const coreDirEnv = "PFB_TEST_CORE_DIR"

// program writes a #!/bin/sh script running body into a directory of its own, which the script sees as $D.
func program(t *testing.T, body string) (*update.Command, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "update.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nD='"+dir+"'\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &update.Command{Path: path}, dir
}

// newLog opens a progress log the way the Gate does: a file for appending.
func newLog(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "update.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// recordedPid is the pid the program wrote to "child" in its directory; the process is killed when the test ends.
func recordedPid(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "child"))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program never recorded its child: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program's child file holds %q: %v", b, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

// exited reports whether pid is no longer a live process; a zombie counts as exited (a bare container may not reap it).
func exited(t testing.TB, pid int) bool {
	t.Helper()
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, err := exec.CommandContext(ctx, "ps", "-o", "stat=", "-p", strconv.Itoa(pid)).CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(state))) == 0 {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		t.Fatalf("ENVIRONMENT: cannot inspect process %d with ps: state %q, %v", pid, state, err)
	}
	return strings.HasPrefix(strings.TrimSpace(string(state)), "Z")
}

// gone waits for pid to exit, within the watchdog.
func gone(t testing.TB, pid int) bool {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(20 * time.Millisecond) {
		if exited(t, pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// awaitFile returns once path exists.
func awaitFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: %s never appeared", path)
		}
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) (v T) {
	t.Helper()
	select {
	case v = <-ch:
	case <-time.After(stuck):
		t.Fatalf("STUCK: %s", what)
	}
	return v
}

func TestUpdateFixtureExitedRecognizesAnUnreapedZombie(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })
	if !gone(t, cmd.Process.Pid) {
		t.Fatalf("STUCK: child %d did not exit before reap", cmd.Process.Pid)
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("child %d lost its unreaped identity: %v", cmd.Process.Pid, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !exited(t, cmd.Process.Pid) {
		t.Fatalf("reaped child %d is still reported alive", cmd.Process.Pid)
	}
}

func TestUpdateFixtureExitedRejectsUnavailablePS(t *testing.T) {
	const childEnv = "PFB_TEST_UPDATE_FIXTURE_MISSING_PS"
	if os.Getenv(childEnv) == "1" {
		t.Setenv("PATH", t.TempDir())
		exited(t, os.Getpid())
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestUpdateFixtureExitedRejectsUnavailablePS$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err == nil || !strings.Contains(string(out), "ENVIRONMENT: cannot inspect process") {
		t.Fatalf("missing ps inspection = %q, %v (context %v); want a fatal inspection diagnostic", out, err, ctx.Err())
	}
}
