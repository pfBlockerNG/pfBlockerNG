package update

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestLifetimeLockIsFreeWhileADetachedServiceStillLives(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "hold"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_WRONLY|syscall.O_NONBLOCK, 0o600)
		if err == nil {
			_, _ = f.Write([]byte{1})
			f.Close()
		}
	})
	body := "#!/bin/sh\nexport PFB_INHERIT_HELPER=1 PFB_INHERIT_MARKER='" + dir + "/alive' PFB_INHERIT_HOLD='" + dir + "/hold' PFB_INHERIT_PID='" + dir + "/child'\n" +
		"setsid " + self + " -test.run=^$ >/dev/null 2>&1 &\nexit 0\n"
	path := filepath.Join(dir, "update.sh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	if _, err := (&Command{Path: path}).Run(context.Background(), Request{Trigger: "apply"}, log); err != nil {
		t.Fatalf("%v\n%s", err, logText(t, log))
	}
	awaitFile(t, filepath.Join(dir, "alive"))
	pidText, err := os.ReadFile(filepath.Join(dir, "child"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("detached service died before the lock check: %v", err)
	}
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("lifetime lock was not free while the detached service was still alive: %v", err)
	}
	lock.Close()
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("detached service died before the lock was observed free: %v", err)
	}
	release, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_WRONLY|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	release.Close()
	awaitFile(t, filepath.Join(dir, "child"))
}
