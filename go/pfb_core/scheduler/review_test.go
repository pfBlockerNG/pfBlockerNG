package scheduler

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// Scenario: one run reports the outcomes of thousands of feeds. Recording them must cost work proportional to the state, not to
// the state once per outcome (5000 feeds took 31 s under the scheduler's lock, with the gate held). The test counts the
// bytes Done allocates, which a regression to a copy per outcome multiplies by the number of feeds; it asserts no duration.
func TestDoneOfManyFeedsRecordsEveryOutcomeWithWorkProportionalToTheState(t *testing.T) {
	const feeds = 2000
	ids := make([]string, feeds)
	entries := make([]schedule.Entry, feeds)
	outcomes := make(map[string]string, feeds)
	for i := range ids {
		ids[i] = fmt.Sprintf("ipv4:feed%04d_v4", i)
		entries[i] = hourly(ids[i])
		outcomes[ids[i]] = "success"
	}
	f := newFixture(t, model(true, entries...), "")
	f.tick()
	if got := len(f.last().Feeds); got != feeds {
		t.Fatalf("the tick asked for %d feeds, want %d", got, feeds)
	}
	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)
	f.s.Done(f.last(), update.Result{Outcomes: outcomes}, nil)
	runtime.ReadMemStats(&after)

	st := f.items()
	for _, id := range ids {
		it := st[id]
		if it.PendingOccurrence != nil || it.LastCompletedOccurrence == nil || *it.LastCompletedOccurrence != occ10 ||
			it.CompletionOutcome != schedule.Success || it.LastSuccessfulCheck == nil || *it.LastSuccessfulCheck != nowT.Unix() {
			t.Fatalf("%s: item %s, want its occurrence %d completed", id, describe(it), occ10)
		}
	}
	// A pass over the state costs a few hundred kilobytes; a copy per outcome costs hundreds of megabytes.
	const limit = 64 << 20
	if used := after.TotalAlloc - before.TotalAlloc; used > limit {
		t.Errorf("Done of %d outcomes allocated %d bytes, over the %d that one pass over the state needs", feeds, used, limit)
	}
}

// Scenario: the settings are slow to answer (the model is built from them) while a run ends. The model is an input that
// needs none of the scheduler's state, so a read in progress must not hold up recording the run's result.
func TestAModelReadInProgressDoesNotBlockDone(t *testing.T) {
	cases := []struct {
		name string
		call func(*Scheduler) error
		want func(*testing.T, *fixture) // what the call must show of the Done that ran during its model read
	}{
		{"Tick", func(s *Scheduler) error { return s.Tick() }, func(t *testing.T, f *fixture) {
			// The state is read after the model: the evaluation sees the GeoIP report Done made meanwhile.
			wantRequest(t, f.last(), "scheduled", nil, []string{dcc})
		}},
		{"View", func(s *Scheduler) error { _, err := s.View(); return err }, func(*testing.T, *fixture) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, allEntries(), quiet)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			cfg := f.config()
			cfg.Model = func() (schedule.Model, error) {
				entered <- struct{}{}
				<-release
				return f.getModel()
			}
			s := New(cfg)
			s.Bind(f.start)
			returned := make(chan error, 1)
			go func() { returned <- c.call(s) }()
			recv(t, entered, "the model read to begin")

			doneReturned := make(chan struct{})
			go func() {
				s.Done(update.Request{Trigger: "scheduled"}, update.Result{GeoIPReady: new(false)}, nil)
				close(doneReturned)
			}()
			recv(t, doneReturned, "Done to return while the model read was blocked")

			unblock()
			if err := recv(t, returned, "the call to return once the model read ended"); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			c.want(t, f)
		})
	}
}

// Scenario: an Update reports ids as attempted. Only an Extra's failure is a state the tick reads (a failed Extra waits for its
// next occurrence); a feed that fails is retried by the next quarter hour through its pending occurrence alone.
func TestDoneMarksOnlyExtrasAttemptedNeverFeeds(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)})) // alpha and dcc are due
	f.tick()
	wantItem(t, f.items(), feedA, schedule.Item{PendingOccurrence: new(occ10)})

	f.s.Done(f.last(), update.Result{Attempted: []string{feedA, dcc}}, nil)

	st := f.items()
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03), PendingAttempted: true})
	wantItem(t, st, feedA, schedule.Item{PendingOccurrence: new(occ10)})
}

// Scenario: the state file cannot be replaced (here a directory sits where it should be, so the rename fails). The write
// is reported and the temporary file it made is not left behind to be mistaken for state.
func TestAFailedWriteLeavesNoTemporaryFile(t *testing.T) {
	f := newFixture(t, model(true, daily(dcc)), "")
	if err := os.Mkdir(f.path, 0o700); err != nil {
		t.Fatal(err)
	}
	f.s = New(f.config())
	f.s.Bind(f.start)

	f.tick() // reserves dcc and tries to write it

	if !strings.Contains(f.logText(), "not written") {
		t.Fatalf("the failed write was not logged: %q", f.logText())
	}
	if strays := f.strays(); len(strays) != 0 {
		t.Errorf("temporary files were left behind: %v", strays)
	}
}
