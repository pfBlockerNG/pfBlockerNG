package scheduler

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// Scenario: Core starts. The state file may be absent (first start after the cutover), valid, or not usable; an unusable one
// is logged and replaced by an empty state, so the first evaluation recomputes what is due.
func TestNewLoadsTheStateFileOrStartsEmpty(t *testing.T) {
	write := func(text string) func(*testing.T, string) {
		return func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name      string
		prepare   func(*testing.T, string)
		wantLog   bool
		wantStart bool // alpha is due when the state is empty, and not when the file says it completed its slot
	}{
		{"no file", func(*testing.T, string) {}, false, true},
		{"valid file", write(stateText(map[string]string{feedA: completed(occ10)})), false, false},
		{"not JSON", write("{not json"), true, true},
		{"unknown schema", write(`{"schema":2,"items":{}}`), true, true},
		{"item with an unknown field", write(`{"schema":1,"items":{"ipv4:alpha_v4":{"bogus":1}}}`), true, true},
		{"a directory where the file should be", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, model(true, hourly(feedA)), "")
			c.prepare(t, f.path)
			f.s = New(f.config())
			f.s.Bind(f.start)

			if got := f.logText() != ""; got != c.wantLog {
				t.Errorf("New logged = %v (%q), want %v", got, f.logText(), c.wantLog)
			}
			if err := f.s.Tick(); err != nil {
				t.Fatalf("Tick: %v", err)
			}
			if got := len(f.requests()) == 1; got != c.wantStart {
				t.Errorf("Tick requested an Update = %v, want %v", got, c.wantStart)
			}
			if c.wantStart {
				wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
			}
		})
	}
}

// Scenario: the state directory is not writable at first. The scheduler goes on in memory and the next write catches up.
func TestAFailedWriteIsLoggedKeepsTheStateInMemoryAndTheNextWriteRetries(t *testing.T) {
	f := newFixture(t, model(true, daily(dcc)), "")
	dir := filepath.Join(t.TempDir(), "state")
	f.path = filepath.Join(dir, "schedule_state.json")
	f.s = New(f.config()) // a missing directory is a missing file, not a failure
	f.s.Bind(f.start)
	if f.logText() != "" {
		t.Fatalf("New logged for a missing state file: %q", f.logText())
	}

	f.tick() // reserves dcc's occurrence, and cannot write it
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d Updates requested, want 1", n)
	}
	if f.logText() == "" {
		t.Error("the failed write was not logged")
	}
	f.s.Done(f.last(), update.Result{Outcomes: map[string]string{dcc: "success"}}, nil) // cannot write either

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.s.Done(f.last(), update.Result{}, nil) // the next write persists the state that stayed in memory

	wantItem(t, f.items(), dcc, schedule.Item{
		LastSuccessfulCheck: new(nowT.Unix()), LastCompletedOccurrence: new(occ03), CompletionOutcome: schedule.Success,
	})
}

func TestPersistedStateRoundTripsThroughParseStateWithMode0600(t *testing.T) {
	seed := stateText(map[string]string{
		feedA:             `{"last_successful_check":1,"last_completed_occurrence":2,"completion_outcome":"retry-cap-reached","pending_occurrence":3,"pending_attempted":true}`,
		feedB:             pending(9),
		dcc:               completed(occ03),
		"ipv4:foreign_v4": `{"last_successful_check":7}`,
	})
	f := newFixture(t, model(true), seed) // no entries: nothing is reserved, so the state must come back as it was
	want := f.items()
	f.removeFile()

	if err := f.s.Start("retry", "", ""); err != nil { // an admitted start persists the state
		t.Fatalf("Start(retry): %v", err)
	}

	if got := f.items(); !reflect.DeepEqual(got, want) {
		t.Errorf("persisted state = %v, want %v", got, want)
	}
	info, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(f.path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a temporary file was left behind (stat error %v)", err)
	}
}

func TestPersistedEmptyStateIsAValidFile(t *testing.T) {
	f := newFixture(t, model(true), "")

	if err := f.s.Start("retry", "", ""); err != nil {
		t.Fatalf("Start(retry): %v", err)
	}

	if st := f.items(); len(st) != 0 {
		t.Errorf("persisted state = %v, want empty", st)
	}
	if raw, _ := os.ReadFile(f.path); !strings.Contains(string(raw), `"schema":1`) {
		t.Errorf("state file = %s, want schema 1", raw)
	}
}
