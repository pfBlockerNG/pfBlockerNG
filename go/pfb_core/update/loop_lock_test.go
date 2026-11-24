package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAKilledWorkersRsyncDiesWithIt kills the worker while a feed's rsync, a child of the worker, is still transferring
// into the feed folder. The rsync must die with the worker: left running, it would write into the folder the next Update
// stages the same feed in, with nothing left to bound how long it runs (issue #4038, 9j-2).
func TestAKilledWorkersRsyncDiesWithIt(t *testing.T) {
	sb, c, hold := rsyncSandbox(t, "echo $$ > \"$D/rsync\"\n: > \"$D/started\"\nread _ < \"$D/release\"\n"+
		"for last; do :; done\nprintf '192.0.2.1\\n' > \"$last\"\n")
	release, err := os.OpenFile(filepath.Join(hold, "release"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = release.WriteString("go\n"); _ = release.Close() })

	sb.prepare(t, c, 0)
	done := make(chan error, 1)
	go func() {
		_, err := runCmd(t, &Command{Path: sb.self, Loop: sb.loop}, c.Steps[0].Request, sb.log)
		done <- err
	}()
	awaitFile(t, filepath.Join(hold, "started"))
	rsync := pidIn(t, filepath.Join(hold, "rsync"))
	if err := syscall.Kill(workerOf(t, rsync), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned success for a killed worker")
		}
	case <-time.After(stuck):
		t.Fatal("STUCK: Run did not return after the worker was killed")
	}
	for deadline := time.Now().Add(stuck); alive(rsync); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the killed worker's rsync still runs: it would write into the next Update's feed folder")
		}
	}
	awaitUnlocked(t, sb.log.Name()).Close()
}

// TestAProcessTheRsyncLeavesBehindDoesNotKeepTheUpdateLock: a child that leaves a process running and exits (here the
// rsync) must not hand that process the Update lock, or every later Update is refused until it dies (issue #4038, 9j-2).
func TestAProcessTheRsyncLeavesBehindDoesNotKeepTheUpdateLock(t *testing.T) {
	sb, c, hold := rsyncSandbox(t, "sleep 60 </dev/null >/dev/null 2>&1 &\necho $! > \"$D/left\"\n"+
		"for last; do :; done\nprintf '192.0.2.1\\n' > \"$last\"\n")
	sb.prepare(t, c, 0)
	if _, err := runCmd(t, &Command{Path: sb.self, Loop: sb.loop}, c.Steps[0].Request, sb.log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	left := pidIn(t, filepath.Join(hold, "left"))
	t.Cleanup(func() { _ = syscall.Kill(left, syscall.SIGKILL) })
	awaitUnlocked(t, sb.log.Name()).Close()
	if !alive(left) {
		t.Fatal("the process the rsync left behind is gone: the test proves nothing")
	}
}

// TestAKilledWorkerKeepsTheUpdateLockUntilItsHookExits kills the worker while a pre-hook runs. The hook is not killed
// (the hooks' survivor policy), so the Update lock stays held until the hook's own process exits, and no longer: a
// service the hook started does not keep it (issue #4225).
func TestAKilledWorkerKeepsTheUpdateLockUntilItsHookExits(t *testing.T) {
	fx := newLoopFixture(t)
	hold := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(hold, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(filepath.Join(hold, "release"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = release.WriteString("go\n"); _ = release.Close() })
	script(t, filepath.Join(fx.hooks, "hook_pre_rec.sh"), "D="+hold+"\nsleep 60 </dev/null >/dev/null 2>&1 &\n"+
		"echo $! > \"$D/service\"\necho $$ > \"$D/hook\"\n: > \"$D/started\"\nread _ < \"$D/release\"")

	c := &Command{Path: filepath.Join(fx.applyDir, "apply.sh"), Loop: fx.loop()}
	done := make(chan error, 1)
	go func() {
		_, err := runCmd(t, c, manual(), fx.log)
		done <- err
	}()
	awaitFile(t, filepath.Join(hold, "started"))
	service := pidIn(t, filepath.Join(hold, "service"))
	t.Cleanup(func() { _ = syscall.Kill(service, syscall.SIGKILL) })
	if err := syscall.Kill(workerOf(t, pidIn(t, filepath.Join(hold, "hook"))), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned success for a killed worker")
		}
	case <-time.After(stuck):
		t.Fatal("STUCK: Run did not return after the worker was killed")
	}

	lock, err := operationLock(fx.log.Name())
	if err == nil {
		lock.Close()
	}
	if !errors.Is(err, ErrRunning) {
		t.Fatalf("the killed worker's Update lock was free while its hook still ran: the next Update would be admitted (%v)", err)
	}
	if _, err := release.WriteString("go\n"); err != nil {
		t.Fatal(err)
	}
	awaitUnlocked(t, fx.log.Name()).Close()
	if !alive(service) {
		t.Fatal("the hook's service is gone: the test proves nothing about it")
	}
}

// rsyncSandbox is the corpus's first Update with the feed E2E1A fetched over rsync by a stand-in running body; D in body
// is the stand-in's folder, which holds the FIFO "release".
func rsyncSandbox(t *testing.T, body string) (*e2eSandbox, e2eCase, string) {
	t.Helper()
	c := e2eCaseNamed(t, "both_first_run_then_unchanged_then_changed")
	var snap bytes.Buffer
	if err := json.Compact(&snap, c.Expect[0].Snapshot); err != nil {
		t.Fatal(err)
	}
	const row = `"format":"auto","header":"E2E1A","state":"enabled","url":"{{FEEDS}}/e2e1_v4a"`
	if !strings.Contains(snap.String(), row) {
		t.Fatalf("the corpus snapshot no longer has the feed E2E1A: %s", snap.String())
	}
	c.Expect[0].Snapshot = json.RawMessage(strings.Replace(snap.String(), row,
		`"format":"rsync","header":"E2E1A","state":"enabled","url":"127.0.0.2::e2e/e2e1_v4a"`, 1))
	sb := newE2ESandbox(t, c, "")
	hold := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(hold, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	rsync := filepath.Join(hold, "rsync")
	if err := os.WriteFile(rsync, []byte("#!/bin/sh\nD="+hold+"\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.loop.RsyncBin = rsync
	return sb, c, hold
}

// pidIn is the pid a stand-in wrote to path.
func pidIn(t *testing.T, path string) int {
	t.Helper()
	awaitFile(t, path)
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		b, _ := os.ReadFile(path)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("ENVIRONMENT: %s holds no pid: %q", path, b)
		}
	}
}

// procStat is the fields of /proc/<pid>/stat after the command name: the state, then the parent's pid.
func procStat(pid int) ([]string, error) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:])), nil
}

// workerOf is the worker among pid's ancestors.
func workerOf(t *testing.T, pid int) int {
	t.Helper()
	for p := pid; p > 1; {
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(p) + "/cmdline")
		if err != nil {
			t.Skipf("ENVIRONMENT: no /proc to find the worker: %v", err)
		}
		if bytes.Contains(cmdline, []byte(workerArg)) {
			return p
		}
		fields, err := procStat(p)
		if err != nil || len(fields) < 2 {
			break
		}
		p, _ = strconv.Atoi(fields[1])
	}
	t.Fatalf("no worker among the ancestors of %d", pid)
	return 0
}

// alive is whether pid runs; a zombie does not. Without /proc, whether pid can be signalled.
func alive(pid int) bool {
	fields, err := procStat(pid)
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat("/proc/self/stat"); statErr != nil {
			return syscall.Kill(pid, 0) == nil
		}
		return false
	}
	if err != nil {
		return false
	}
	return len(fields) > 0 && fields[0] != "Z"
}
