package update

import (
	"context"
	"os"
	"testing"
)

// issue #4260: an Update has one start. Core stamps it when the gate admits the Update, and the worker's status, which
// GetUpdate reports once it is published, carries that stamp too: the settings reload before the launch can take seconds,
// and a client that follows its Update by its start must not see the start move.
func TestTheWorkerStatusCarriesTheAdmissionStart(t *testing.T) {
	command, _ := program(t, "exit 0")
	log := newLog(t)
	lease, err := command.Admit(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	lease.startedAt = 100
	if _, err := lease.Launch(context.Background(), command, Request{Trigger: "manual", Scope: "both", Force: "none"}, log); err != nil {
		t.Fatal(err)
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil {
		t.Fatal(err)
	}
	if state.StartedAt != 100 {
		t.Errorf("the worker status started at %d, want the admission's 100", state.StartedAt)
	}
}

func TestTheGateHandsItsStartToTheLease(t *testing.T) {
	command, _ := program(t, "exit 0")
	log := newLog(t)
	g := New(log.Name(), nil, nil)
	g.Admit = command.Admit
	leased := make(chan int64, 1)
	g.Launch = func(ctx context.Context, lease *Admission, req Request, f *os.File) (Result, error) {
		leased <- lease.startedAt
		return lease.Launch(ctx, command, req, f)
	}
	t.Cleanup(g.Stop)
	if err := g.Start(Request{Trigger: "manual", Scope: "both", Force: "none"}, nil); err != nil {
		t.Fatal(err)
	}
	got := <-leased
	view, err := g.View(-1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if view.Update == nil || got == 0 || got != view.Update.StartedAt {
		t.Errorf("the lease started at %d, the gate reports %+v: want one start", got, view.Update)
	}
	settle(t, g)
}
