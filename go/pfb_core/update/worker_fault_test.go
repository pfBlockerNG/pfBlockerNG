package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWorkerPublicationFailureCannotReportSuccessOrRetainOwnership(t *testing.T) {
	p, dir := independentProgram(t)
	log := independentLog(t)
	ended := make(chan error, 1)
	go func() { _, err := p.Run(context.Background(), Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	// A real directory where the atomic terminal file belongs makes publication fail even under root.
	if err := os.Remove(log.Name() + ".status"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(log.Name()+".status", 0o700); err != nil {
		t.Fatal(err)
	}
	releaseIndependent(t, dir)
	if err := recv(t, ended, "worker never returned after failed publication"); err == nil {
		t.Fatal("failed durable publication reported success")
	}
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("failed publication retained lifetime ownership: %v", err)
	}
	lock.Close()
	if _, err := p.Run(context.Background(), Request{Trigger: "apply"}, log); err == nil {
		t.Fatal("malformed terminal path allowed another program launch")
	}
	starts, err := os.ReadFile(filepath.Join(dir, "starts"))
	if err != nil || strings.Count(string(starts), "started") != 1 {
		t.Fatalf("program starts = %q, %v; want exactly one after failed publication", starts, err)
	}
}

func TestWorkerPreparationFilesystemErrorsNeverLaunchProgram(t *testing.T) {
	for _, suffix := range []string{".lock", ".status", ".request", ".result"} {
		t.Run(suffix, func(t *testing.T) {
			p, dir := program(t, `echo ran > "$D/ran"`)
			log := independentLog(t)
			if err := os.Mkdir(log.Name()+suffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Run(context.Background(), Request{Trigger: "apply"}, log); err == nil {
				t.Fatalf("preparation accepted directory at %s", suffix)
			}
			if _, err := os.Stat(filepath.Join(dir, "ran")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("program launched through failed %s preparation: %v", suffix, err)
			}
			if suffix != ".lock" {
				lock, err := operationLock(log.Name())
				if err != nil {
					t.Fatalf("failed preparation retained ownership: %v", err)
				}
				lock.Close()
			}
		})
	}
}

func TestWorkerPeriodicLogBoundRemainsOwnedAfterObserverLeaves(t *testing.T) {
	p, dir := program(t, `exec 4<> "$D/release"
echo ready > "$D/ready"
read release <&4
dd if=/dev/zero bs=1048576 count=9 2>/dev/null
printf '\nperiodic-newest\n'
echo burst > "$D/burst"
read release <&4`)
	// Reuse the same real FIFO protocol as the independent transaction fixture.
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	_ = recv(t, ended, "observer did not stop")
	releaseIndependent(t, dir)
	awaitFile(t, filepath.Join(dir, "burst"))
	deadline := time.NewTimer(stuck)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	trimmed := false
	for !trimmed {
		info, err := log.Stat()
		if err != nil {
			t.Fatal(err)
		}
		trimmed = info.Size() <= maxLog/2
		if !trimmed {
			select {
			case <-tick.C:
			case <-deadline.C:
				releaseIndependent(t, dir)
				_ = awaitWorkerCompletion(t, log.Name())
				t.Fatal("STUCK: orphaned running worker did not periodically bound its log")
			}
		}
	}
	releaseIndependent(t, dir)
	_ = awaitWorkerCompletion(t, log.Name())
	if body := logText(t, log); !strings.HasSuffix(body, "periodic-newest\n") {
		t.Fatalf("periodic trim lost newest complete output: %q", body[max(0, len(body)-80):])
	}
}
