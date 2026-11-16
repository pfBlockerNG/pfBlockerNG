package scheduler

import (
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

func TestManualIPSuccessSettlesOnlyMatchingAdmittedOccurrences(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{
		feedA: pending(occ10),
		feedB: pending(occ10),
		feedC: pending(occ10),
	}))
	var admitted map[string]int64
	f.s.Bind(func(req update.Request, commit func() (map[string]int64, error)) error {
		if len(req.Feeds) != 0 {
			t.Fatalf("manual request feeds = %v, want the program to select its current feeds", req.Feeds)
		}
		var err error
		admitted, err = commit()
		return err
	})

	if err := f.s.Start("manual", "ip", "none"); err != nil {
		t.Fatal(err)
	}
	if admitted[feedA] != occ10 || admitted[feedC] != occ10 {
		t.Fatalf("admitted occurrences = %v, want both pending IP occurrences", admitted)
	}
	if _, ok := admitted[feedB]; ok {
		t.Fatalf("admitted occurrences = %v, DNSBL is outside an IP pass", admitted)
	}

	later := occ10 + 900
	f.s.st[feedC] = schedule.Item{PendingOccurrence: &later}
	if err := writeState(f.path, f.s.st); err != nil {
		t.Fatal(err)
	}
	finished := int64(50)
	if err := f.s.reconcile(finished, admitted, update.Result{Outcomes: map[string]string{
		feedA: "success",
		feedC: "success",
	}}, nil); err != nil {
		t.Fatal(err)
	}

	st := f.items()
	wantItem(t, st, feedA, schedule.Item{LastSuccessfulCheck: &finished, LastCompletedOccurrence: new(occ10), CompletionOutcome: schedule.Success})
	wantItem(t, st, feedB, schedule.Item{PendingOccurrence: new(occ10)})
	wantItem(t, st, feedC, schedule.Item{LastSuccessfulCheck: &finished, PendingOccurrence: &later})
}
