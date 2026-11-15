package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestInheritedDescriptorsDoNotKeepTheLifetimeLock(t *testing.T) {
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
	body := "#!/bin/sh\nexport PFB_INHERIT_HELPER=1 PFB_INHERIT_MARKER='" + dir + "/alive' PFB_INHERIT_HOLD='" + dir + "/hold' PFB_INHERIT_PID='" + dir + "/child'\n" +
		"exec " + self + " -test.run=^$\n"
	path := filepath.Join(dir, "update.sh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	ended := make(chan error, 1)
	go func() { _, err := (&Command{Path: path}).Run(context.Background(), Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "alive"))
	pidText, err := os.ReadFile(filepath.Join(dir, "child"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("cannot inventory the survivor's descriptors: %v", err)
	}
	for _, fd := range fds {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err == nil && strings.HasSuffix(target, ".lock") {
			t.Errorf("survivor fd %s still names the lifetime lock %s", fd.Name(), target)
		}
	}
	release, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = release.Write([]byte{1})
	release.Close()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("worker retained the lifetime lock after the survivor exited: %v", err)
	}
	lock.Close()
}
