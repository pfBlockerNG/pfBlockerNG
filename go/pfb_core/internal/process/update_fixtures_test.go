//go:build linux || freebsd

package process_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
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
func exited(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	return err == nil && bytes.HasPrefix(stat[bytes.LastIndexByte(stat, ')')+2:], []byte("Z"))
}

// gone waits for pid to exit, within the watchdog.
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
