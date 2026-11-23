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

// TestAKilledWorkerKeepsTheUpdateLockWhileItsRsyncStillWrites kills the worker while a feed's rsync, a child of the
// worker, is still transferring into the feed folder. The next Update must not be admitted until that child has exited:
// it would run the same feed in the same folder while the orphan still writes there (issue #4038, 9j-2).
func TestAKilledWorkerKeepsTheUpdateLockWhileItsRsyncStillWrites(t *testing.T) {
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

	// The rsync stand-in: it records its parent, the worker, waits for the test, then writes the download.
	hold := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(hold, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(filepath.Join(hold, "release"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = release.WriteString("go\n")
		awaitUnlocked(t, sb.log.Name()).Close() // the stand-in writes into its folder until it exits
		_ = release.Close()
	})
	rsync := filepath.Join(hold, "rsync")
	script := "#!/bin/sh\nD=" + hold + "\necho $PPID > \"$D/worker\"\n: > \"$D/started\"\nread _ < \"$D/release\"\n" +
		"for last; do :; done\nprintf '192.0.2.1\\n' > \"$last\"\n: > \"$D/wrote\"\n"
	if err := os.WriteFile(rsync, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.loop.RsyncBin = rsync

	sb.prepare(t, c, 0)
	done := make(chan error, 1)
	go func() {
		_, err := runCmd(t, &Command{Path: sb.self, Loop: sb.loop}, c.Steps[0].Request, sb.log)
		done <- err
	}()
	awaitFile(t, filepath.Join(hold, "started"))
	b, err := os.ReadFile(filepath.Join(hold, "worker"))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || worker <= 1 {
		t.Fatalf("ENVIRONMENT: the rsync stand-in recorded its parent as %q", b)
	}
	if err := syscall.Kill(worker, syscall.SIGKILL); err != nil {
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
	if _, err := os.Stat(filepath.Join(hold, "wrote")); err == nil {
		t.Fatal("the rsync stand-in finished before the worker was killed: the test proves nothing")
	}

	lock, err := operationLock(sb.log.Name())
	if err == nil {
		lock.Close()
	}
	if !errors.Is(err, ErrRunning) {
		t.Fatalf("the killed worker's Update lock was free while its rsync still ran: the next Update would be admitted (%v)", err)
	}
	if _, err := release.WriteString("go\n"); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(hold, "wrote"))
	awaitUnlocked(t, sb.log.Name()).Close()
}
