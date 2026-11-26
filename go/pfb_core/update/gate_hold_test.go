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

// While a Hold holds the operation lock, the finished Update it follows stays readable: Hold is no Update.
func TestAViewDuringAHoldReportsTheFinishedUpdate(t *testing.T) {
	log := independentLog(t)
	finished, exitCode := int64(200), 0
	if err := writeWorkerState(log.Name()+".status", workerState{
		Version: workerVersion, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path: "/bin/true", Request: Request{Trigger: "manual"}, StartedAt: 100,
		FinishedAt: &finished, ExitCode: &exitCode, Settled: true,
	}); err != nil {
		t.Fatal(err)
	}
	g := New(log.Name(), nil, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)

	var view View
	var viewErr error
	if err := g.Hold(func() error { view, viewErr = g.View(-1, 0); return nil }); err != nil {
		t.Fatal(err)
	}

	if viewErr != nil || view.Running || view.Update == nil || view.Update.FinishedAt == nil || *view.Update.FinishedAt != finished {
		t.Errorf("View during a Hold = %+v, %v; want the finished Update, not running", view, viewErr)
	}
}

// A View never sees the operation lock a Hold takes or gives back without seeing the Hold: each is under the Gate's mutex.
func TestViewsDuringHoldsNeverFail(t *testing.T) {
	log := independentLog(t)
	finished, exitCode := int64(200), 0
	if err := writeWorkerState(log.Name()+".status", workerState{
		Version: workerVersion, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path: "/bin/true", Request: Request{Trigger: "manual"}, StartedAt: 100,
		FinishedAt: &finished, ExitCode: &exitCode, Settled: true,
	}); err != nil {
		t.Fatal(err)
	}
	g := New(log.Name(), nil, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)
	stop, failed := make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(failed)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := g.View(-1, 0); err != nil {
				failed <- err
				return
			}
		}
	}()
	for range 2000 {
		if err := g.Hold(func() error { return nil }); err != nil {
			t.Fatalf("Hold = %v", err)
		}
	}
	close(stop)
	if err := <-failed; err != nil {
		t.Errorf("a View during Holds = %v", err)
	}
}

// A finished Update that awaits recovery keeps the store to its recovery, as Start does.
func TestHoldIsRefusedWhileAFinishedUpdateAwaitsRecovery(t *testing.T) {
	log := independentLog(t)
	finished, exitCode := int64(200), 0
	if err := writeWorkerState(log.Name()+".status", workerState{
		Version: workerVersion, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path: "/bin/true", Request: Request{Trigger: "manual"}, StartedAt: 100,
		FinishedAt: &finished, ExitCode: &exitCode,
	}); err != nil {
		t.Fatal(err)
	}
	g := New(log.Name(), nil, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)

	ran := false
	if err := g.Hold(func() error { ran = true; return nil }); !errors.Is(err, ErrRecoveryRequired) || ran {
		t.Errorf("Hold while a finished Update awaits recovery = %v, ran %v; want ErrRecoveryRequired and nothing run", err, ran)
	}
}
