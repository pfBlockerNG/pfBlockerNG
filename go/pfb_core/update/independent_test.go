package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The helper is an actual disposable controller, not the process which owns the test.
func TestIndependentControllerHelper(t *testing.T) {
	if os.Getenv("PFB_INDEPENDENT_HELPER") != "1" {
		return
	}
	log, err := os.OpenFile(os.Getenv("PFB_INDEPENDENT_LOG"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	_, err = (&Command{Path: os.Getenv("PFB_INDEPENDENT_PROGRAM")}).Run(context.Background(), Request{Trigger: "apply"}, log)
	if err != nil {
		t.Fatal(err)
	}
}

func independentProgram(t *testing.T) (*Command, string) {
	t.Helper()
	p, dir := program(t, `exec 4<> "$D/release"
echo started >> "$D/starts"
echo ready > "$D/ready"
read release <&4
printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n' >&3
echo completed > "$D/completed"`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, dir
}

func independentLog(t *testing.T) *os.File {
	t.Helper()
	log := newLog(t)
	if err := os.Chmod(filepath.Dir(log.Name()), 0o700); err != nil {
		t.Fatal(err)
	}
	return log
}

func releaseIndependent(t *testing.T, dir string) {
	t.Helper()
	// Nonblocking open fails promptly if no live transaction still owns the reader.
	fd, err := syscall.Open(filepath.Join(dir, "release"), syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("transaction did not survive controller loss: opening release FIFO: %v", err)
	}
	f := os.NewFile(uintptr(fd), "release")
	defer f.Close()
	if _, err := f.WriteString("finish\n"); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentWorkerSurvivesControllerDeath(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			p, dir := independentProgram(t)
			log := independentLog(t)
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			controller := exec.Command(self, "-test.run=^TestIndependentControllerHelper$")
			controller.Env = append(os.Environ(), "PFB_INDEPENDENT_HELPER=1", "PFB_INDEPENDENT_PROGRAM="+p.Path, "PFB_INDEPENDENT_LOG="+log.Name())
			controller.Stdout, controller.Stderr = log, log
			if err := controller.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = controller.Process.Kill() })
			awaitFile(t, filepath.Join(dir, "ready"))
			if err := controller.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			_ = controller.Wait()
			// A second controller must never execute a conflicting program.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = p.Run(ctx, Request{Trigger: "apply"}, log)
			if !errors.Is(err, ErrRunning) {
				t.Errorf("restarted controller Run = %v, want ErrRunning while worker owns transaction", err)
			}
			releaseIndependent(t, dir)
			awaitFile(t, filepath.Join(dir, "completed"))
			awaitWorkerCompletion(t, log.Name()) // the worker publishes .status after the program completes (#4166)
			starts, err := os.ReadFile(filepath.Join(dir, "starts"))
			if err != nil || strings.Count(string(starts), "started") != 1 {
				t.Errorf("program starts = %q, %v; want exactly one", starts, err)
			}
		})
	}
}

func TestIndependentWorkerContextEndsObservationNotTransaction(t *testing.T) {
	p, dir := independentProgram(t)
	log := independentLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	if err := recv(t, ended, "controller observation did not stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want canceled observation", err)
	}
	releaseIndependent(t, dir)
	awaitFile(t, filepath.Join(dir, "completed"))
	awaitWorkerCompletion(t, log.Name()) // the worker publishes .status after the program completes (#4166)
}
