package scheduler

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// Scenario: a quarter-hour Update for alpha and dcc was admitted, ran, and reports.
func TestDoneRecordsASuccessAndClearsThePendingOccurrence(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)}))
	f.tick()
	req := f.last()
	st := f.items()
	wantItem(t, st, feedA, schedule.Item{PendingOccurrence: new(occ10)})
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03)})

	later := nowT.Add(5 * time.Minute)
	f.setNow(later)
	f.s.Done(req, update.Result{Outcomes: map[string]string{feedA: "success", dcc: "success"}}, nil)

	st = f.items()
	wantItem(t, st, feedA, schedule.Item{
		LastSuccessfulCheck: new(later.Unix()), LastCompletedOccurrence: new(occ10), CompletionOutcome: schedule.Success,
	})
	wantItem(t, st, dcc, schedule.Item{
		LastSuccessfulCheck: new(later.Unix()), LastCompletedOccurrence: new(occ03), CompletionOutcome: schedule.Success,
	})
	wantItem(t, st, bl, schedule.Item{LastCompletedOccurrence: new(occ03), CompletionOutcome: schedule.Success})
}

func TestDoneRecordsTheRetryCapAndKeepsOutcomesWhenTheRunFailed(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)}))
	f.tick()

	f.s.Done(f.last(), update.Result{Outcomes: map[string]string{feedA: "retry-cap-reached"}}, errors.New("exit status 1"))

	st := f.items()
	wantItem(t, st, feedA, schedule.Item{LastCompletedOccurrence: new(occ10), CompletionOutcome: schedule.RetryCapReached})
	// dcc reported nothing, so its reservation stays for the next quarter hour.
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03)})
	if !strings.Contains(f.logText(), "exit status 1") {
		t.Errorf("the failed run was not logged: %q", f.logText())
	}
}

// Scenario: dcc ran and failed. The Update reports it as attempted, with no outcome.
func TestDoneMarksAFailedExtraAttemptedSoItWaitsForItsNextOccurrence(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: completed(occ10), bl: completed(occ03)}))
	f.tick()
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d Updates requested, want dcc's 1", n)
	}
	wantRequest(t, f.last(), "scheduled", nil, []string{dcc})

	f.s.Done(f.last(), update.Result{Attempted: []string{dcc, "ipv4:ghost_v4"}}, errors.New("dcc failed"))

	st := f.items()
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03), PendingAttempted: true})
	if _, ok := st["ipv4:ghost_v4"]; ok {
		t.Error("an id without a pending occurrence got an item")
	}

	// The next quarter hour does not run it again: the schedule's next due for dcc is tomorrow's slot.
	f.setNow(nowT.Add(15 * time.Minute))
	f.tick()
	if n := len(f.requests()); n != 1 {
		t.Errorf("dcc was run again before its next occurrence: %d Updates requested", n)
	}
	v, err := f.s.View()
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Extras[dcc].NextDue; got != nextDCC {
		t.Errorf("dcc next due = %d, want tomorrow's slot %d", got, nextDCC)
	}

	// When that occurrence comes, dcc is requested again, with a fresh reservation that is no longer attempted.
	f.setNow(time.Unix(nextDCC, 0).Add(5 * time.Minute))
	f.tick()
	if n := len(f.requests()); n != 2 {
		t.Fatalf("%d Updates requested after the next occurrence, want 2", n)
	}
	if got := f.last().Extras; len(got) != 1 || got[0] != dcc {
		t.Errorf("extras = %v, want [%s]", got, dcc)
	}
	wantItem(t, f.items(), dcc, schedule.Item{PendingOccurrence: new(nextDCC)})
}

func TestDoneSkipsARejectedOutcomeAndRecordsTheOthers(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)}))
	f.tick() // alpha is due
	later := nowT.Add(time.Minute)
	f.setNow(later)

	f.s.Done(f.last(), update.Result{Outcomes: map[string]string{
		"bad id!":     "success",
		"123":         "success", // PHP would make a numeric key an integer
		feedB:         "failed",  // not an outcome a run can report
		feedA:         "success",
		"extra:other": "success",
	}}, nil)

	st := f.items()
	wantItem(t, st, feedA, schedule.Item{
		LastSuccessfulCheck: new(later.Unix()), LastCompletedOccurrence: new(occ10), CompletionOutcome: schedule.Success,
	})
	for _, id := range []string{"bad id!", "123", feedB, "extra:other"} {
		if _, ok := st[id]; ok {
			t.Errorf("a rejected outcome created an item for %q", id)
		}
	}
	for _, id := range []string{"bad id!", "123", feedB, "extra:other"} {
		if !strings.Contains(f.logText(), id) {
			t.Errorf("the rejection of %q was not logged: %q", id, f.logText())
		}
	}
}
