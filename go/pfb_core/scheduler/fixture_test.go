package scheduler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// stuck is the outer watchdog: it only salvages a hung test, no assertion rests on it.
const stuck = 30 * time.Second

// The tests run on Friday 2026-11-13 10:20 UTC. The default schedule is Friday 03:00, so the hourly feeds have their slot at
// minute 0, the daily dcc at 03:00 and the weekly bl on Fridays at 03:00.
var (
	nowT    = time.Date(2026, time.November, 13, 10, 20, 0, 0, time.UTC)
	occ10   = time.Date(2026, time.November, 13, 10, 0, 0, 0, time.UTC).Unix() // the hourly slot nowT is past
	occ03   = time.Date(2026, time.November, 13, 3, 0, 0, 0, time.UTC).Unix()  // today's daily and weekly slot
	nextDCC = occ03 + 24*3600                                                  // tomorrow's daily slot
	nextBL  = occ03 + 7*24*3600                                                // next Friday's weekly slot
)

const (
	feedA = "ipv4:alpha_v4"
	feedB = "dnsbl:beta"
	feedC = "ipv6:gamma_v6"
	dcc   = "extra:dcc"
	bl    = "extra:bl"
)

func entry(id, cadence string, enabled bool) schedule.Entry {
	return schedule.Entry{ID: id, Cadence: cadence, Enabled: enabled}
}
func hourly(id string) schedule.Entry { return entry(id, "01hour", true) }
func daily(id string) schedule.Entry  { return entry(id, "EveryDay", true) }
func weekly(id string) schedule.Entry { return entry(id, "Weekly", true) }

func model(scheduled bool, entries ...schedule.Entry) schedule.Model {
	return schedule.Model{Scheduled: scheduled, Default: schedule.Schedule{Weekday: 5, Hour: 3, Minute: 0}, Entries: entries}
}

// allEntries is the usual model: one hourly feed and both Extras.
func allEntries() schedule.Model { return model(true, hourly(feedA), daily(dcc), weekly(bl)) }

// completed is a state item that finished the occurrence at.
func completed(at int64) string {
	return fmt.Sprintf(`{"last_completed_occurrence":%d,"completion_outcome":"success"}`, at)
}

// stateText is the text of a state file holding the given items (id to the item's JSON).
func stateText(items map[string]string) string {
	raw := map[string]json.RawMessage{}
	for id, it := range items {
		raw[id] = json.RawMessage(it)
	}
	b, err := json.Marshal(map[string]any{"schema": 1, "items": raw})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// quiet is a state in which nothing is due at nowT for allEntries().
var quiet = stateText(map[string]string{feedA: completed(occ10), dcc: completed(occ03), bl: completed(occ03)})

// fixture is a Scheduler over a temp state file, a steerable clock, model and start, and a recorder of requests and logs.
type fixture struct {
	t     *testing.T
	s     *Scheduler
	path  string
	clock atomic.Int64 // Unix nanoseconds

	mu         sync.Mutex
	model      schedule.Model
	modelErr   error
	modelCalls int
	startErr   error
	attempts   []update.Request // every Request passed to start, accepted or not
	logs       []string
}

// newFixture builds a Scheduler whose state file holds state ("" means no file) and binds its start to the fixture.
func newFixture(t *testing.T, m schedule.Model, state string) *fixture {
	t.Helper()
	f := &fixture{t: t, model: m, path: filepath.Join(t.TempDir(), "schedule_state.json")}
	f.clock.Store(nowT.UnixNano())
	if state != "" {
		if err := os.WriteFile(f.path, []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.s = New(f.config())
	f.s.Bind(f.start)
	return f
}

func (f *fixture) config() Config {
	return Config{Model: f.getModel, StatePath: f.path, Loc: time.UTC, Now: f.now, Logf: f.logf}
}

func (f *fixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }

func (f *fixture) setNow(at time.Time) { f.clock.Store(at.UnixNano()) }

func (f *fixture) getModel() (schedule.Model, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modelCalls++
	return f.model, f.modelErr
}

func (f *fixture) start(r update.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, r)
	return f.startErr
}

func (f *fixture) logf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func (f *fixture) setStartErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startErr = err
}

func (f *fixture) setModelErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modelErr = err
}

func (f *fixture) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modelCalls
}

func (f *fixture) requests() []update.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attempts)
}

func (f *fixture) logText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

// last is the one most recent request, failing the test when there is none.
func (f *fixture) last() update.Request {
	f.t.Helper()
	reqs := f.requests()
	if len(reqs) == 0 {
		f.t.Fatal("no Update was requested")
	}
	return reqs[len(reqs)-1]
}

// items reads the state file back through the parser the Core owns, failing the test when it is absent or invalid.
func (f *fixture) items() schedule.State {
	f.t.Helper()
	raw, err := os.ReadFile(f.path)
	if err != nil {
		f.t.Fatalf("the state file cannot be read: %v", err)
	}
	st, err := schedule.ParseState(raw)
	if err != nil {
		f.t.Fatalf("the state file is invalid: %v\n%s", err, raw)
	}
	return st
}

// noFile fails the test when the state file exists (a write brings it back after a test removed it).
func (f *fixture) noFile() {
	f.t.Helper()
	if _, err := os.Stat(f.path); err == nil {
		f.t.Error("the state file was written")
	} else if !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
}

// removeFile deletes the state file that New loaded, so that a later write is visible as the file's return.
func (f *fixture) removeFile() {
	f.t.Helper()
	if err := os.Remove(f.path); err != nil {
		f.t.Fatal(err)
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) (v T) {
	t.Helper()
	select {
	case v = <-ch:
	case <-time.After(stuck):
		t.Fatalf("STUCK: %s", what)
	}
	return v
}

// wantRequest checks a request's trigger and lists; scope is always both and force none for what the scheduler builds
// itself.
func wantRequest(t *testing.T, got update.Request, trigger string, feeds, extras []string) {
	t.Helper()
	want := update.Request{Trigger: trigger, Scope: "both", Force: "none", Feeds: feeds, Extras: extras}
	if got.Trigger != want.Trigger || got.Scope != want.Scope || got.Force != want.Force ||
		!slices.Equal(got.Feeds, want.Feeds) || !slices.Equal(got.Extras, want.Extras) {
		t.Errorf("request = %+v, want %+v", got, want)
	}
}

// wantItem checks one state item's fields: nil for an absent number.
func wantItem(t *testing.T, st schedule.State, id string, want schedule.Item) {
	t.Helper()
	got, ok := st[id]
	if !ok {
		t.Errorf("%s: no item, want %s", id, describe(want))
		return
	}
	if describe(got) != describe(want) {
		t.Errorf("%s: item %s, want %s", id, describe(got), describe(want))
	}
}

func describe(it schedule.Item) string {
	num := func(p *int64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprint(*p)
	}
	return fmt.Sprintf("{check %s, completed %s (%q), pending %s, attempted %v}",
		num(it.LastSuccessfulCheck), num(it.LastCompletedOccurrence), it.CompletionOutcome, num(it.PendingOccurrence), it.PendingAttempted)
}
