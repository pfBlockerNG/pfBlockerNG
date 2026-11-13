package scheduler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// runHarness runs f.s.Run with an injected timer: every wait is reported on asked and ends when the test sends on fire.
type runHarness struct {
	asked    chan time.Duration
	fire     chan time.Time
	cancel   context.CancelFunc
	finished chan struct{}
}

func startRun(t *testing.T, f *fixture) *runHarness {
	t.Helper()
	h := &runHarness{asked: make(chan time.Duration), fire: make(chan time.Time), finished: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	go func() {
		defer close(h.finished)
		f.s.Run(ctx, func(d time.Duration) <-chan time.Time {
			h.asked <- d
			return h.fire
		})
	}()
	return h
}

func (h *runHarness) stop(t *testing.T) {
	t.Helper()
	h.cancel()
	recv(t, h.finished, "Run to return after its context was cancelled")
}

func TestRunTicksAtEveryQuarterHourBoundary(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	f.setNow(time.Date(2026, time.November, 13, 10, 50, 7, 500_000_000, time.UTC))
	h := startRun(t, f)

	if d := recv(t, h.asked, "the first wait"); d != 9*time.Minute+52*time.Second+500*time.Millisecond {
		t.Errorf("first wait = %v, want 9m52.5s, to the 11:00:00 boundary", d)
	}
	if n := f.calls(); n != 0 {
		t.Errorf("%d evaluations before the first boundary", n)
	}

	f.setNow(time.Date(2026, time.November, 13, 11, 0, 0, 0, time.UTC))
	h.fire <- time.Time{}

	if d := recv(t, h.asked, "the second wait"); d != 15*time.Minute { // the second wait is asked once the Tick returned
		t.Errorf("second wait = %v, want 15m, to the 11:15:00 boundary", d)
	}
	if n := f.calls(); n != 1 {
		t.Errorf("%d evaluations after one boundary, want 1", n)
	}
	if reqs := f.requests(); len(reqs) != 1 {
		t.Fatalf("%d Updates requested, want 1", len(reqs))
	}
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)

	h.stop(t)
	if n := f.calls(); n != 1 {
		t.Errorf("%d evaluations after Run was cancelled, want 1", n)
	}
}

func TestRunKeepsTickingAfterAFailedTick(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	f.setModelErr(errors.New("settings unavailable"))
	h := startRun(t, f)
	recv(t, h.asked, "the first wait")

	h.fire <- time.Time{}

	recv(t, h.asked, "a wait after the failed Tick") // Run asks for the next boundary only if it kept going
	if n := f.calls(); n != 1 {
		t.Errorf("%d evaluations, want 1", n)
	}
	h.stop(t)
}

func TestRunReturnsOnACancelledContextEvenWithTheDefaultTimer(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		f.s.Run(ctx, nil)
	}()

	recv(t, finished, "Run to return for a cancelled context")
	if n := f.calls(); n != 0 {
		t.Errorf("%d evaluations for a cancelled context", n)
	}
}

// Scenario: the Scheduler is wired to a real Update gate the way Core will: the gate calls the scheduler's Done.
func TestSchedulerRecordsWhatARealGateReports(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)})) // alpha and dcc are due
	ran := make(chan update.Request, 1)
	run := func(_ context.Context, req update.Request, _ *os.File) (update.Result, error) {
		ran <- req
		return update.Result{Outcomes: map[string]string{feedA: "success", dcc: "success"}}, nil
	}
	g := update.New(filepath.Join(t.TempDir(), "update.log"), run, f.s.Done)
	f.s.Bind(g.Start)

	f.tick()

	wantRequest(t, recv(t, ran, "the gate to run the Update"), "scheduled", []string{feedA}, []string{dcc})
	g.Stop() // returns once the run ended and the gate called Done
	st := f.items()
	wantItem(t, st, feedA, schedule.Item{
		LastSuccessfulCheck: new(nowT.Unix()), LastCompletedOccurrence: new(occ10), CompletionOutcome: schedule.Success,
	})
	wantItem(t, st, dcc, schedule.Item{
		LastSuccessfulCheck: new(nowT.Unix()), LastCompletedOccurrence: new(occ03), CompletionOutcome: schedule.Success,
	})
}

// Scenario: ticks, results, views and asked Updates arrive from different goroutines (the quarter-hour timer, the gate's
// goroutine, the API). Under -race this fails when a path skips the scheduler's lock; the end state must be what a restart reads.
func TestConcurrentTicksResultsViewsAndStartsLeaveAConsistentState(t *testing.T) {
	f := newFixture(t, allEntries(), "")
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 30 {
				switch (g + i) % 4 {
				case 0:
					if err := f.s.Tick(); err != nil {
						t.Errorf("Tick: %v", err)
					}
				case 1:
					f.s.Done(update.Request{Trigger: "scheduled"}, update.Result{
						Outcomes: map[string]string{feedA: "success", dcc: "success"}, Attempted: []string{bl}, GeoIPReady: new(i%2 == 0),
					}, nil)
				case 2:
					if _, err := f.s.View(); err != nil {
						t.Errorf("View: %v", err)
					}
				case 3:
					if err := f.s.Start("retry", "", ""); err != nil {
						t.Errorf("Start(retry): %v", err)
					}
				}
			}
		})
	}
	wg.Wait()

	live := viewJSON(t, f)
	f.items() // the file parses whole
	restarted := newFixture(t, allEntries(), "")
	restarted.path = f.path
	restarted.s = New(restarted.config())
	if got := viewJSON(t, restarted); got != live {
		t.Errorf("a restarted scheduler reads %s\nthe live one answers  %s", got, live)
	}
}
