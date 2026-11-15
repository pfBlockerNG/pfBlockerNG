package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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

func TestWorkerTranscriptRemainsCompleteAfterObserverLeaves(t *testing.T) {
	p, dir := program(t, `exec 4<> "$D/release"
printf 'early-output\n'
echo ready > "$D/ready"
read release <&4
dd if=/dev/zero bs=1048576 count=9 2>/dev/null
printf '\nperiodic-newest\n'
sleep 2
echo burst > "$D/burst"
read release <&4
printf '{"version":1}\n' >&3`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f, err := os.OpenFile(filepath.Join(dir, "release"), os.O_WRONLY|syscall.O_NONBLOCK, 0o600)
		if err == nil {
			_, _ = f.WriteString("cleanup\ncleanup\n")
			_ = f.Close()
		}
	})
	log := independentLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	if err := recv(t, ended, "observer did not stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want canceled observation", err)
	}
	releaseIndependent(t, dir)
	awaitFile(t, filepath.Join(dir, "burst"))
	const block = 9 << 20
	expected := append([]byte("early-output\n"), bytes.Repeat([]byte{0}, block)...)
	expected = append(expected, []byte("\nperiodic-newest\n")...)
	if body, err := os.ReadFile(log.Name()); err != nil || !bytes.Equal(body, expected) {
		t.Fatalf("orphan worker transcript has %d bytes, %v; want complete %d-byte output", len(body), err, len(expected))
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil || state.FinishedAt != nil || state.LogGen != 0 {
		t.Fatalf("orphan worker receipt = %+v, %v; want unfinished generation 0", state, err)
	}
	releaseIndependent(t, dir)
	state = awaitWorkerCompletion(t, log.Name())
	if state.FinishedAt == nil {
		t.Fatalf("worker completion = %+v; want a terminal receipt", state)
	}
	if body, err := os.ReadFile(log.Name()); err != nil || !bytes.Equal(body, expected) {
		t.Fatalf("completed worker transcript has %d bytes, %v; want complete %d-byte output", len(body), err, len(expected))
	}
}
