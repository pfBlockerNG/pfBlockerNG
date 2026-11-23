package update

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// WHEN a loop Update is running THEN the status Core published at its launch, which every Core reads while the worker
// runs, has no loop member either.
func TestTheStatusOfARunningLoopUpdateHasNoLoopMember(t *testing.T) {
	fx := loopAnswering(t, plainReply)
	adir := fx.adapterDir
	started, proceed := filepath.Join(adir, "started"), filepath.Join(adir, "proceed")
	for _, fifo := range []string{started, proceed} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log, c := fx.log, fx.command()
	ran := make(chan error, 1)
	go func() { _, err := runCmd(t, c, Request{Trigger: "manual"}, log); ran <- err }()
	opened := awaitFIFOWriter(t, started) // returns once the adapter, and so the worker, runs
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-ran:
		t.Fatalf("Run = %v before the adapter started", err)
	case <-time.After(stuck):
		t.Fatalf("STUCK: the adapter did not start within %v", stuck)
	}
	members := fileMembers(t, log.Name()+".status")
	releaseFIFO(t, proceed) // lets the adapter answer
	if err := <-ran; err != nil {
		t.Errorf("Run = %v, want success", err)
	}
	if _, ok := members["finishedAt"]; ok {
		t.Fatalf("the status read while the worker runs is already terminal: %v", members)
	}
	if loop, ok := members["loop"]; ok {
		t.Errorf("the running Update's status carries the loop %s, want none", loop)
	}
}
