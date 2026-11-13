package scheduler

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

func (f *fixture) setModel(m schedule.Model) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.model = m
}

func (f *fixture) tick() {
	f.t.Helper()
	if err := f.s.Tick(); err != nil {
		f.t.Fatalf("Tick: %v", err)
	}
}

func pending(at int64) string { return fmt.Sprintf(`{"pending_occurrence":%d}`, at) }

// Scenario: every feed and Extra has completed its latest slot.
func TestTickWithNothingDueStartsNothingAndWritesNothing(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	f.removeFile() // a write would bring it back

	f.tick()

	if reqs := f.requests(); len(reqs) != 0 {
		t.Errorf("nothing is due, yet %+v was requested", reqs)
	}
	f.noFile()

	// The quiet above is the schedule's answer, not a scheduler that never starts: an hour later the next slot is due.
	f.setNow(nowT.Add(time.Hour))
	f.tick()
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
}

func TestTickRequestsADueFeedAndReservesItsOccurrence(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)}))

	f.tick()

	if reqs := f.requests(); len(reqs) != 1 {
		t.Fatalf("%d Updates requested, want 1", len(reqs))
	}
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
	wantItem(t, f.items(), feedA, schedule.Item{PendingOccurrence: new(occ10)})
}

func TestTickRequestsDueFeedsInModelOrderAndLeavesDisabledOnesOut(t *testing.T) {
	m := model(true, hourly(feedB), entry(feedC, "01hour", false), hourly(feedA), daily(dcc), weekly(bl))
	f := newFixture(t, m, stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03), feedC: pending(occ10)}))

	f.tick()

	wantRequest(t, f.last(), "scheduled", []string{feedB, feedA}, nil)
}

func TestTickRequestsDueExtrasWithDCCBeforeBL(t *testing.T) {
	f := newFixture(t, model(true, weekly(bl), daily(dcc)), "") // bl is listed first

	f.tick()

	wantRequest(t, f.last(), "scheduled", nil, []string{dcc, bl})
	st := f.items()
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03)})
	wantItem(t, st, bl, schedule.Item{PendingOccurrence: new(occ03)})
}

// Scenario: the Outpost reported that the GeoIP generation is not ready, so dcc must run to finish it.
func TestTickRunsDCCWhileTheOutpostReportsGeoIPNotReady(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	result := func(r update.Result) {
		f.s.Done(update.Request{Trigger: "scheduled"}, r, nil)
	}

	f.tick()
	if n := len(f.requests()); n != 0 {
		t.Fatalf("GeoIP counts as ready until the Outpost says otherwise, yet %d Updates were requested", n)
	}

	result(update.Result{GeoIPReady: new(false)})
	f.tick()
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d Updates requested once GeoIP was reported not ready, want 1", n)
	}
	wantRequest(t, f.last(), "scheduled", nil, []string{dcc})

	result(update.Result{}) // a result that says nothing about GeoIP keeps the last word
	f.tick()
	if n := len(f.requests()); n != 2 {
		t.Fatalf("%d Updates requested after a silent result, want 2", n)
	}

	result(update.Result{GeoIPReady: new(true)})
	f.tick()
	if n := len(f.requests()); n != 2 {
		t.Errorf("%d Updates requested after GeoIP was reported ready again, want 2", n)
	}
}

func TestTickPutsAForcedDCCBeforeADueBL(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{feedA: completed(occ10), dcc: completed(occ03)})) // bl is due
	f.s.Done(update.Request{Trigger: "scheduled"}, update.Result{GeoIPReady: new(false)}, nil)

	f.tick()

	wantRequest(t, f.last(), "scheduled", nil, []string{dcc, bl})
}

// Scenario: an Update is already running when the quarter hour comes.
func TestTickSkipsWhileAnUpdateRunsAndKeepsNoReservation(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)})) // alpha and dcc are due
	f.removeFile()
	f.setStartErr(update.ErrRunning)

	if err := f.s.Tick(); err != nil {
		t.Fatalf("a skipped scheduled Update is not a failure, Tick returned %v", err)
	}

	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d Updates asked for, want the one the gate refused", n)
	}
	wantRequest(t, f.last(), "scheduled", []string{feedA}, []string{dcc})
	f.noFile()
	if !strings.Contains(f.logText(), update.ErrRunning.Error()) {
		t.Errorf("the skip was not logged: %q", f.logText())
	}

	// Nothing was reserved: an outcome finds no pending occurrence, so it only stamps the check and completes nothing.
	f.s.Done(f.last(), update.Result{Outcomes: map[string]string{feedA: "success", dcc: "success"}}, nil)
	st := f.items()
	wantItem(t, st, feedA, schedule.Item{LastSuccessfulCheck: new(nowT.Unix())})
	wantItem(t, st, dcc, schedule.Item{LastSuccessfulCheck: new(nowT.Unix())})

	// The next quarter hour, with the gate free, asks for the same Update again.
	f.setStartErr(nil)
	f.tick()
	if n := len(f.requests()); n != 2 {
		t.Fatalf("%d Updates asked for, want 2", n)
	}
	wantRequest(t, f.last(), "scheduled", []string{feedA}, []string{dcc})
	wantItem(t, f.items(), feedA, schedule.Item{LastSuccessfulCheck: new(nowT.Unix()), PendingOccurrence: new(occ10)})
}

func TestTickReturnsAStartFailureAndKeepsNoReservation(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)})) // alpha is due
	f.removeFile()
	f.setStartErr(update.ErrStopped)

	err := f.s.Tick()

	if !errors.Is(err, update.ErrStopped) {
		t.Errorf("Tick returned %v, want the gate's %v", err, update.ErrStopped)
	}
	f.noFile()
}

// Scenario: scheduled updates are off. Feeds are never selected, even those the state still holds a pending occurrence for.
func TestUnscheduledModelSelectsNoFeedEvenWhenOneIsPending(t *testing.T) {
	m := model(false, hourly(feedA), daily(dcc), weekly(bl))
	f := newFixture(t, m, stateText(map[string]string{feedA: pending(occ10), dcc: completed(occ03), bl: completed(occ03)}))

	f.tick()
	if n := len(f.requests()); n != 0 {
		t.Fatalf("scheduled updates are off and no Extra is due, yet %d Updates were requested", n)
	}

	f.setModel(model(true, hourly(feedA), daily(dcc), weekly(bl)))
	f.tick()
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
}

func TestUnscheduledModelStillRunsDueExtras(t *testing.T) {
	m := model(false, hourly(feedA), daily(dcc), weekly(bl))
	f := newFixture(t, m, stateText(map[string]string{feedA: pending(occ10), bl: completed(occ03)})) // alpha pending, dcc due

	f.tick()

	wantRequest(t, f.last(), "scheduled", nil, []string{dcc})
}

func TestTickReturnsAModelErrorAndStartsNothing(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)})) // alpha is due
	f.removeFile()
	broken := errors.New("settings unavailable")
	f.setModelErr(broken)

	if err := f.s.Tick(); !errors.Is(err, broken) {
		t.Errorf("Tick returned %v, want %v", err, broken)
	}
	if err := f.s.Start("retry", "", ""); !errors.Is(err, broken) {
		t.Errorf("a retry returned %v, want %v", err, broken)
	}
	if _, err := f.s.View(); !errors.Is(err, broken) {
		t.Errorf("View returned %v, want %v", err, broken)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d Updates requested without a model", n)
	}
	f.noFile()
	if !strings.Contains(f.logText(), broken.Error()) {
		t.Errorf("the model error was not logged: %q", f.logText())
	}

	// The state loaded before the failure is still the scheduler's: once the model is back, alpha alone is due.
	f.setModelErr(nil)
	f.tick()
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
}

func TestSchedulerWithoutABoundGateStartsNothingAndSaysSo(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)})) // alpha is due
	f.s = New(f.config())                                                                                       // no Bind
	f.removeFile()

	if err := f.s.Tick(); err == nil {
		t.Error("Tick without a gate returned no error")
	}
	if err := f.s.Start("apply", "", ""); err == nil {
		t.Error("Start without a gate returned no error")
	}
	f.noFile()
}

// Scenario: the process has no clock, zone or logger configured; the defaults must make every entry point work.
func TestNilClockZoneAndLoggerFallBackToDefaults(t *testing.T) {
	failing := false
	s := New(Config{
		Model: func() (schedule.Model, error) {
			if failing {
				return schedule.Model{}, errors.New("settings unavailable")
			}
			return model(true, hourly(feedA)), nil
		},
		StatePath: t.TempDir() + "/schedule_state.json",
	})
	s.Bind(func(update.Request) error { return nil })

	if err := s.Tick(); err != nil {
		t.Errorf("Tick: %v", err)
	}
	if _, err := s.View(); err != nil {
		t.Errorf("View: %v", err)
	}
	s.Done(update.Request{}, update.Result{}, errors.New("exit status 1"))
	failing = true
	if err := s.Tick(); err == nil {
		t.Error("a failing model returned no error")
	}
}

// Scenario: the Outpost asks for an Update because a *.fail marker or a missing manifest says feeds are pending.
func TestRetryStartsEvenWhenNothingIsDue(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	f.tick()
	if n := len(f.requests()); n != 0 {
		t.Fatalf("a tick requested %d Updates with nothing due", n)
	}

	if err := f.s.Start("retry", "", ""); err != nil {
		t.Fatalf("Start(retry): %v", err)
	}

	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d Updates requested, want 1", n)
	}
	wantRequest(t, f.last(), "retry", nil, nil)
}

func TestRetryCarriesWhatIsDueLikeATickAndIgnoresScopeAndForce(t *testing.T) {
	f := newFixture(t, allEntries(), stateText(map[string]string{bl: completed(occ03)})) // alpha and dcc are due

	if err := f.s.Start("retry", "ip", "parse"); err != nil {
		t.Fatalf("Start(retry): %v", err)
	}

	wantRequest(t, f.last(), "retry", []string{feedA}, []string{dcc})
	st := f.items()
	wantItem(t, st, feedA, schedule.Item{PendingOccurrence: new(occ10)})
	wantItem(t, st, dcc, schedule.Item{PendingOccurrence: new(occ03)})
}

func TestApplyStartsAnUpdateWithoutFeedsOrExtras(t *testing.T) {
	f := newFixture(t, allEntries(), "") // everything is due
	f.setModelErr(errors.New("settings unavailable"))

	if err := f.s.Start("apply", "", ""); err != nil {
		t.Fatalf("Start(apply): %v", err)
	}

	want := update.Request{Trigger: "apply", Scope: "both", Force: "none"}
	if reqs := f.requests(); len(reqs) != 1 || !reflect.DeepEqual(reqs[0], want) {
		t.Errorf("requests = %+v, want [%+v]", reqs, want)
	}
	if f.calls() != 0 {
		t.Error("an apply read the schedule model: it must not depend on what is due")
	}
	f.noFile()
}

func TestManualStartsAnUpdateWithTheScopeAndForceAsked(t *testing.T) {
	f := newFixture(t, allEntries(), "") // everything is due

	if err := f.s.Start("manual", "ip", "parse"); err != nil {
		t.Fatalf("Start(manual): %v", err)
	}

	want := update.Request{Trigger: "manual", Scope: "ip", Force: "parse"}
	if reqs := f.requests(); len(reqs) != 1 || !reflect.DeepEqual(reqs[0], want) {
		t.Errorf("requests = %+v, want [%+v]", reqs, want)
	}
	f.noFile()
}

func TestManualAcceptsEveryScopeAndForce(t *testing.T) {
	f := newFixture(t, allEntries(), "")
	var want []update.Request
	for _, scope := range []string{"ip", "dnsbl", "both"} {
		for _, force := range []string{"none", "parse", "download", "both"} {
			if err := f.s.Start("manual", scope, force); err != nil {
				t.Errorf("Start(manual, %s, %s): %v", scope, force, err)
			}
			want = append(want, update.Request{Trigger: "manual", Scope: scope, Force: force})
		}
	}
	if got := f.requests(); !reflect.DeepEqual(got, want) {
		t.Errorf("requests = %+v, want %+v", got, want)
	}
}

func TestStartRejectsWhatIsNotAnAskableUpdate(t *testing.T) {
	cases := []struct{ name, trigger, scope, force string }{
		{"scheduled is the scheduler's own trigger", "scheduled", "both", "none"},
		{"empty trigger", "", "both", "none"},
		{"unknown trigger", "bogus", "both", "none"},
		{"manual without a scope", "manual", "", "none"},
		{"manual with an unknown scope", "manual", "all", "none"},
		{"manual with a scope of the wrong case", "manual", "Both", "none"},
		{"manual without a force", "manual", "both", ""},
		{"manual with an unknown force", "manual", "both", "full"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, allEntries(), "")
			if err := f.s.Start(c.trigger, c.scope, c.force); err == nil {
				t.Error("Start returned no error")
			}
			if reqs := f.requests(); len(reqs) != 0 {
				t.Errorf("%+v was requested", reqs)
			}
			f.noFile()
		})
	}
}

func TestStartReturnsTheGatesRefusalUnchanged(t *testing.T) {
	for _, c := range []struct{ trigger, scope, force string }{{"manual", "both", "none"}, {"apply", "", ""}, {"retry", "", ""}} {
		t.Run(c.trigger, func(t *testing.T) {
			f := newFixture(t, allEntries(), stateText(map[string]string{dcc: completed(occ03), bl: completed(occ03)}))
			f.removeFile()
			f.setStartErr(update.ErrRunning)

			if err := f.s.Start(c.trigger, c.scope, c.force); err != update.ErrRunning {
				t.Errorf("Start returned %v, want update.ErrRunning itself", err)
			}
			f.noFile() // a refused retry reserves nothing either
		})
	}
}

func viewJSON(t *testing.T, f *fixture) string {
	t.Helper()
	v, err := f.s.View()
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestViewAnswersTheScheduleOfCacheEntries(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)

	want := fmt.Sprintf(`{"scheduled":true,"feeds":{"lastRun":%d,"nextDue":%d},"extras":{"extra:bl":{"lastRun":%d,"nextDue":%d},"extra:dcc":{"lastRun":%d,"nextDue":%d}},"lastSuccessfulCheck":{}}`,
		occ10, occ10+3600, occ03, nextBL, occ03, nextDCC)
	if got := viewJSON(t, f); got != want {
		t.Errorf("view = %s\nwant   %s", got, want)
	}
}

func TestViewOfAnUnscheduledModelHasNoFeedsAndOnlyEnabledExtras(t *testing.T) {
	m := model(false, hourly(feedA), daily(dcc), entry(bl, "Weekly", false))
	f := newFixture(t, m, quiet)

	want := fmt.Sprintf(`{"scheduled":false,"feeds":null,"extras":{"extra:dcc":{"lastRun":%d,"nextDue":%d}},"lastSuccessfulCheck":{}}`, occ03, nextDCC)
	if got := viewJSON(t, f); got != want {
		t.Errorf("view = %s\nwant   %s", got, want)
	}
}

func TestViewOfAModelWithNothingScheduledHasAnEmptyExtrasObject(t *testing.T) {
	f := newFixture(t, model(true), "")

	want := `{"scheduled":true,"feeds":null,"extras":{},"lastSuccessfulCheck":{}}`
	if got := viewJSON(t, f); got != want {
		t.Errorf("view = %s\nwant   %s", got, want)
	}
}

// Scenario: the metrics export reads each item's last successful check from the schedule view (issue #3941).
func TestViewListsTheLastSuccessfulCheckOfEveryItemThatHasOne(t *testing.T) {
	state := stateText(map[string]string{
		feedA:          `{"last_successful_check":1700000000,"last_completed_occurrence":` + fmt.Sprint(occ10) + `,"completion_outcome":"success"}`,
		dcc:            `{"last_successful_check":1700000100,"last_completed_occurrence":` + fmt.Sprint(occ03) + `,"completion_outcome":"success"}`,
		bl:             completed(occ03),              // completed an occurrence, never a successful check
		"ipv4:gone_v4": `{"last_successful_check":5}`, // no longer in the model: its last success is still the last
	})
	f := newFixture(t, allEntries(), state)

	v, err := f.s.View()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{feedA: 1700000000, dcc: 1700000100, "ipv4:gone_v4": 5}
	if !reflect.DeepEqual(v.LastSuccessfulCheck, want) {
		t.Errorf("lastSuccessfulCheck = %v, want %v", v.LastSuccessfulCheck, want)
	}
	if got := viewJSON(t, f); !strings.Contains(got, `"lastSuccessfulCheck":{"extra:dcc":1700000100,"ipv4:alpha_v4":1700000000,"ipv4:gone_v4":5}`) {
		t.Errorf("view = %s, want the map as an object keyed by item id", got)
	}
}

func TestViewHasAnEmptyLastSuccessfulCheckObjectNotNullWhenNothingSucceeded(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)

	if got := viewJSON(t, f); !strings.Contains(got, `"lastSuccessfulCheck":{}`) {
		t.Errorf("view = %s, want lastSuccessfulCheck to be an empty object", got)
	}
}
