package schedule

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

// sequentially is what RecordOutcomes must equal: the outcomes recorded one RecordOutcome call at a time (each id touches
// only its own item, so the order does not matter), a rejected one skipped, the reason kept by id.
func sequentially(st State, outcomes map[string]Outcome, now int64) (State, map[string]error) {
	rejected := map[string]error{}
	for _, id := range slices.Sorted(maps.Keys(outcomes)) {
		next, err := RecordOutcome(st, id, outcomes[id], now, nil)
		if err != nil {
			rejected[id] = err
			continue
		}
		st = next
	}
	return st, rejected
}

func sameRejections(t *testing.T, got, want map[string]error) {
	t.Helper()
	for _, id := range slices.Sorted(maps.Keys(want)) {
		if got[id] == nil || got[id].Error() != want[id].Error() {
			t.Errorf("%q: rejected with %v, want %v", id, got[id], want[id])
		}
	}
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[id]; !ok {
			t.Errorf("%q: rejected with %v, want recorded", id, got[id])
		}
	}
}

func mixedOutcomes() (State, map[string]Outcome) {
	st := State{
		"ipv4:a_v4":  {PendingOccurrence: new(int64(100))},
		"ipv4:b_v4":  {PendingOccurrence: new(int64(100)), PendingAttempted: true},
		"ipv6:c_v6":  {LastCompletedOccurrence: new(int64(50)), CompletionOutcome: Success},
		"dnsbl:d":    {LastCompletedOccurrence: new(int64(50)), CompletionOutcome: Success},
		"extra:dcc":  {PendingOccurrence: new(int64(200))},
		"dnsbl:keep": {LastSuccessfulCheck: new(int64(7))},
	}
	return st, map[string]Outcome{
		"ipv4:a_v4": Success,         // completes its pending occurrence
		"ipv4:b_v4": RetryCapReached, // completes it with the retry cap, and loses its attempted flag
		"ipv6:c_v6": Success,         // no pending occurrence: only stamps the check
		"dnsbl:d":   RetryCapReached, // no pending occurrence: changes nothing
		"dnsbl:e":   Success,         // an id the state does not hold yet
		"dnsbl:f":   RetryCapReached, // ... and one that would change nothing
		"extra:dcc": Success,
		"bad id":    Success,  // not a feed id
		"123":       Success,  // PHP would make a numeric key an integer
		"ipv4:x":    Success,  // an ipv4 id ends in _v4
		"dnsbl:g":   "failed", // not an outcome a run can report
	}
}

// Scenario: a run reports the outcomes of many feeds at once. Recording them in one call must give the state, and reject the
// ids, exactly as recording them one at a time does, whether a stamp is acceptable (now 1000) or not (now -1: the stamped
// item would be invalid, so the validation of the written state rejects just that id).
func TestRecordOutcomesEqualsRecordingOneAtATime(t *testing.T) {
	cases := []struct {
		name         string
		now          int64
		wantRejected []string
	}{
		{"a valid stamp", 1000, []string{"123", "bad id", "dnsbl:g", "ipv4:x"}},
		{"a stamp the state would refuse", -1, []string{"123", "bad id", "dnsbl:g", "extra:dcc", "ipv4:a_v4", "ipv4:x", "ipv6:c_v6", "dnsbl:e"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, outcomes := mixedOutcomes()
			wantState, wantRejected := sequentially(st, outcomes, c.now)
			if got := slices.Sorted(maps.Keys(wantRejected)); !slices.Equal(got, slices.Sorted(slices.Values(c.wantRejected))) {
				t.Fatalf("the one-at-a-time reference rejected %v, the case expects %v: fix the case", got, c.wantRejected)
			}

			gotState, gotRejected := RecordOutcomes(st, outcomes, c.now)

			if !reflect.DeepEqual(gotState, wantState) {
				t.Errorf("state = %v\nwant    %v", gotState, wantState)
			}
			sameRejections(t, gotRejected, wantRejected)
		})
	}
}

func TestRecordOutcomesCompletesPendingOccurrencesAndStampsChecks(t *testing.T) {
	st, outcomes := mixedOutcomes()

	got, rejected := RecordOutcomes(st, outcomes, 1000)

	if len(rejected) != 4 {
		t.Errorf("rejected %v, want the four ids that are not outcomes", rejected)
	}
	want := map[string]Item{
		"ipv4:a_v4":  {LastSuccessfulCheck: new(int64(1000)), LastCompletedOccurrence: new(int64(100)), CompletionOutcome: Success},
		"ipv4:b_v4":  {LastCompletedOccurrence: new(int64(100)), CompletionOutcome: RetryCapReached},
		"ipv6:c_v6":  {LastSuccessfulCheck: new(int64(1000)), LastCompletedOccurrence: new(int64(50)), CompletionOutcome: Success},
		"dnsbl:d":    {LastCompletedOccurrence: new(int64(50)), CompletionOutcome: Success},
		"dnsbl:e":    {LastSuccessfulCheck: new(int64(1000))},
		"extra:dcc":  {LastSuccessfulCheck: new(int64(1000)), LastCompletedOccurrence: new(int64(200)), CompletionOutcome: Success},
		"dnsbl:keep": {LastSuccessfulCheck: new(int64(7))},
	}
	if len(got) != len(want) { // dnsbl:f, a retry cap with nothing pending, makes no item
		t.Errorf("state holds %d items, want %d: %v", len(got), len(want), got)
	}
	for id, item := range want {
		if !reflect.DeepEqual(got[id], item) {
			t.Errorf("%s: %+v, want %+v", id, got[id], item)
		}
	}
}

func TestRecordOutcomesLeavesItsInputAloneAndReturnsACopy(t *testing.T) {
	st, outcomes := mixedOutcomes()
	before := maps.Clone(st)

	got, _ := RecordOutcomes(st, outcomes, 1000)
	got["dnsbl:planted"] = Item{LastSuccessfulCheck: new(int64(1))}

	if !reflect.DeepEqual(st, before) {
		t.Errorf("the input state changed: %v, was %v", st, before)
	}
}

func TestRecordOutcomesWithNoOutcomesReturnsACopyAndRejectsNothing(t *testing.T) {
	st, _ := mixedOutcomes()

	got, rejected := RecordOutcomes(st, nil, 1000)

	if !reflect.DeepEqual(got, st) || len(rejected) != 0 {
		t.Errorf("got %v and %v, want a copy of %v and no rejection", got, rejected, st)
	}
	got["dnsbl:planted"] = Item{LastSuccessfulCheck: new(int64(1))}
	if _, ok := st["dnsbl:planted"]; ok {
		t.Error("the result shares its map with the input")
	}
}

// A state that is not valid is never changed: every id is rejected, an id that is no outcome for its own reason first, as
// RecordOutcome answers.
func TestRecordOutcomesRejectsEveryIdOfAnInvalidState(t *testing.T) {
	st, outcomes := mixedOutcomes()
	st["dnsbl:broken"] = Item{PendingAttempted: true} // attempted without a pending occurrence
	wantState, wantRejected := sequentially(st, outcomes, 1000)
	if len(wantRejected) != len(outcomes) {
		t.Fatalf("the reference rejected %d of %d outcomes: fix the case", len(wantRejected), len(outcomes))
	}

	gotState, gotRejected := RecordOutcomes(st, outcomes, 1000)

	if !reflect.DeepEqual(gotState, wantState) {
		t.Errorf("state = %v, want it unchanged: %v", gotState, wantState)
	}
	sameRejections(t, gotRejected, wantRejected)
}
