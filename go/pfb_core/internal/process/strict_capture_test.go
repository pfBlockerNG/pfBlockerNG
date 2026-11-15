//go:build linux || freebsd

package process

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// strictCapture holds exec's copy completion after observing the real pipe's EOF.
type strictCapture struct {
	bytes.Buffer
	eof     chan error
	release <-chan struct{}
}

func (c *strictCapture) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(&c.Buffer, r)
	c.eof <- err
	<-c.release
	return n, err
}

func TestStrictRunClosesDescendantHeldCaptureBeforeReapAndIODrain(t *testing.T) {
	cmd, _ := fixture(t, `(printf r >&5; read salvage <&4) &
read release <&3
printf payload
exit 0`)
	leaderGate, leaderRelease, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer leaderGate.Close()
	defer leaderRelease.Close()
	descendantGate, descendantRelease, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer descendantGate.Close()
	defer descendantRelease.Close()
	ready, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer readyW.Close()
	cmd.ExtraFiles = []*os.File{leaderGate, descendantGate, readyW}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	capture := &strictCapture{eof: make(chan error, 1), release: release}
	cmd.Stdout, cmd.Stderr = capture, capture
	started := make(chan struct{}, 1)
	oldReap := reap
	reap = func(c *exec.Cmd) error {
		started <- struct{}{}
		<-release
		return c.Wait()
	}
	outcome := make(chan Outcome, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = leaderRelease.Close()
		_ = descendantRelease.Close()
		unblock()
		select {
		case <-done:
		case <-time.After(stuck):
			t.Error("STUCK: strict capture Run did not finish after salvage")
		}
		reap = oldReap
	})
	go func() {
		outcome <- Run(context.Background(), cmd, Policy{Grace: 100 * time.Millisecond})
		close(done)
	}()
	recv(t, started, "Run never reached the held reap")
	_ = readyW.Close()
	descendantReady := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := io.ReadFull(ready, b[:])
		descendantReady <- err
	}()
	if err := recv(t, descendantReady, "capture-holding descendant never reported readiness"); err != nil {
		t.Fatalf("descendant readiness = %v; want one byte", err)
	}
	if _, err := io.WriteString(leaderRelease, "release\n"); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, capture.eof, "strict cleanup did not close the descendant-held capture before reap/IO release"); err != nil {
		t.Fatalf("capture read ended with %v; want EOF", err)
	}
	select {
	case out := <-outcome:
		t.Fatalf("Run returned before reap/IO release: %+v", out)
	default:
	}
	unblock()
	out := recv(t, outcome, "strict Run did not finish after reap/IO release")
	if out.CommandErr != nil || out.Interrupted != nil || out.WatchdogErr != nil {
		t.Fatalf("strict capture outcome = %+v; want success", out)
	}
	if got := capture.String(); got != "payload" {
		t.Errorf("captured output = %q; want payload", got)
	}
}
