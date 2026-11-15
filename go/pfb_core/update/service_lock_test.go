package update

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("lifetime lock was not free while the detached service was still alive: %v", err)
	}
	lock.Close()
	release, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	release.Close()
	awaitFile(t, filepath.Join(dir, "child"))
}

func TestWorkerTrimPublishesGenerationAndRestartsTheCursor(t *testing.T) {
	p, dir := program(t, `printf 'prefix-line\n'
echo ready > "$D/ready"
dd if=/dev/zero bs=1048576 count=9 status=none
printf '\nnewest-after-trim\n'
exec 3<> "$D/hold"
read release <&3`)
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
	log := independentLog(t)
	ended := make(chan error, 1)
	go func() { _, err := p.Run(context.Background(), Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	g := New(log.Name(), nil, nil)
	g.status = &Status{Trigger: "apply", StartedAt: 1}
	first := mustView(t, g, 0, len("prefix-line\n"))
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		state, err := readWorkerState(log.Name() + ".status")
		if err == nil && state.LogGen > 0 {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			release, _ := os.OpenFile(filepath.Join(dir, "hold"), os.O_RDWR, 0o600)
			if release != nil {
				_, _ = release.Write([]byte{1})
				release.Close()
			}
			select {
			case <-ended:
			case <-time.After(time.Second):
			}
			info, _ := log.Stat()
			t.Fatalf("STUCK: the worker trim did not publish a log generation; log size %d", info.Size())
		}
	}
	second := mustView(t, g, first.Next, len("prefix-line\n"))
	start, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(start) < len(second.Log) || string(start[:len(second.Log)]) != second.Log {
		t.Fatalf("cursor %d read %q, file starts %q", first.Next, second.Log, start[:min(len(start), 40)])
	}
	release, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = release.Write([]byte("finish\n"))
	release.Close()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
}
