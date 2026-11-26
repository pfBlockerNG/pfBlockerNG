package update

import (
	"errors"
	"testing"
)

// A worker retained from an earlier Core holds the operation lock while this Core's own admission is free: Hold runs nothing.
func TestHoldIsRefusedWhileARetainedWorkerHoldsTheOperationLock(t *testing.T) {
	log := independentLog(t)
	g := New(log.Name(), nil, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)
	if err := writeWorkerState(log.Name()+".status", workerState{
		Version: workerVersion, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path: "/bin/true", Request: Request{Trigger: "manual"}, StartedAt: 100,
	}); err != nil {
		t.Fatal(err)
	}
	retained, err := operationLock(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	ran := false
	if err := g.Hold(func() error { ran = true; return nil }); !errors.Is(err, ErrRunning) || ran {
		t.Errorf("Hold while a retained worker runs = %v, ran %v; want ErrRunning and nothing run", err, ran)
	}
}

// issue #4264: Hold runs a short write of what an Update writes (the temporary unlocks' manifest) under the admission an
// Update takes, so the resource store keeps one writer at a time.
func TestHoldRunsItsWorkWhileNoUpdateRuns(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	ran := false
	if err := g.Hold(func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("Hold = %v, ran %v; want nil and its work run", err, ran)
	}
	// the admission is given back: an Update starts after it
	if err := g.Start(Request{Trigger: "manual"}, nil); err != nil {
		t.Fatalf("Start after Hold = %v", err)
	}
	h.finish(t, nil)
}

func TestHoldIsRefusedWhileAnUpdateRuns(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual"}, nil); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := g.Hold(func() error { ran = true; return nil }); !errors.Is(err, ErrRunning) || ran {
		t.Errorf("Hold while an Update runs = %v, ran %v; want ErrRunning and nothing run", err, ran)
	}
	h.finish(t, nil)
}

func TestHoldReturnsItsWorksErrorAndAnUpdateStartsAfterIt(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	want := errors.New("the work failed")
	if err := g.Hold(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("Hold = %v, want the work's error", err)
	}
	if err := g.Start(Request{Trigger: "manual"}, nil); err != nil {
		t.Fatalf("Start after a failed Hold = %v", err)
	}
	h.finish(t, nil)
}

func TestHoldIsRefusedAfterStop(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	g.Stop()
	ran := false
	if err := g.Hold(func() error { ran = true; return nil }); !errors.Is(err, ErrStopped) || ran {
		t.Errorf("Hold after Stop = %v, ran %v; want ErrStopped and nothing run", err, ran)
	}
}
