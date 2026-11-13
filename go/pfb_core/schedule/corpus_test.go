package schedule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
	_ "time/tzdata" // the corpus's zones resolve on a host without zoneinfo too
)

// Replays testdata/schedule.json (schema: testdata/README.md). The PHP runner, tests/php/ScheduleCorpusTest.php, replays
// the same file through the old path: a case where Core and the old path differ fails on one side.

// sectionKeys are the keys of each section's cases, in order (the PHP runner holds the same list).
var sectionKeys = map[string][]string{
	"next_occurrence": {"id", "description", "timezone", "cadence", "weekday", "hour", "minute", "reference", "expect"},
	"plan":            {"id", "description", "timezone", "default", "now", "groups", "expect"},
	"extra_plan":      {"id", "description", "timezone", "default", "now", "entries", "state", "cache", "geoip_ready", "expect"},
	"next_due":        {"id", "description", "timezone", "scheduled", "default", "now", "entries", "state", "expect"},
	"quiet_hours":     {"id", "description", "timezone", "now", "window", "expect"},
	"state_valid":     {"id", "description", "input", "expect"},
	"set_pending":     {"id", "description", "state", "occurrences", "expect"},
	"record_outcome":  {"id", "description", "state", "item", "outcome", "now", "expected_occurrence", "expect"},
	"model":           {"id", "description", "general", "sections", "extras", "expect"},
	"blacklist":       {"id", "description", "blacklist", "expect"},
}

var sectionOrder = []string{"next_occurrence", "plan", "extra_plan", "next_due", "quiet_hours", "state_valid", "set_pending",
	"record_outcome", "model", "blacklist"}

type corpusCase struct {
	section string
	id      string
	raw     map[string]json.RawMessage
}

// strict decodes one key of a case into v, unknown fields refused.
func (c corpusCase) strict(t *testing.T, key string, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(c.raw[key]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s/%s: %s: %v", c.section, c.id, key, err)
	}
}

func (c corpusCase) loc(t *testing.T) *time.Location {
	t.Helper()
	var name string
	c.strict(t, "timezone", &name)
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("%s/%s: %v", c.section, c.id, err)
	}
	return loc
}

// orderedKeys returns the keys of a JSON object in document order.
func orderedKeys(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object")
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// loadCorpus reads testdata/<file>: its top-level keys must be schema, then order; each case's keys are keys[section].
func loadCorpus(t *testing.T, file string, order []string, keys map[string][]string) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	top, err := orderedKeys(raw)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if !reflect.DeepEqual(top, append([]string{"schema"}, order...)) {
		t.Fatalf("%s keys %v, want schema then %v", file, top, order)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["schema"]) != "1" {
		t.Fatalf("%s: schema %s, want 1", file, doc["schema"])
	}
	var cases []corpusCase
	for _, section := range order {
		var list []json.RawMessage
		if err := json.Unmarshal(doc[section], &list); err != nil || len(list) == 0 {
			t.Fatalf("%s: %s must be a non-empty list", file, section)
		}
		seen := map[string]bool{}
		for i, item := range list {
			got, err := orderedKeys(item)
			if err != nil || !reflect.DeepEqual(got, keys[section]) {
				t.Fatalf("%s: %s[%d] has keys %v, want %v", file, section, i, got, keys[section])
			}
			c := corpusCase{section: section, raw: map[string]json.RawMessage{}}
			if err := json.Unmarshal(item, &c.raw); err != nil {
				t.Fatal(err)
			}
			var description string
			if json.Unmarshal(c.raw["id"], &c.id) != nil || c.id == "" ||
				json.Unmarshal(c.raw["description"], &description) != nil || description == "" {
				t.Fatalf("%s: %s[%d] needs a non-empty id and description", file, section, i)
			}
			if seen[c.id] {
				t.Fatalf("%s: duplicate id %s/%s", file, section, c.id)
			}
			seen[c.id] = true
			cases = append(cases, c)
		}
	}
	return cases
}

type corpusEntry struct {
	ID       string    `json:"id"`
	Cadence  string    `json:"cadence"`
	Enabled  bool      `json:"enabled"`
	Override *Schedule `json:"override"`
}

func (e corpusEntry) entry() Entry {
	return Entry{ID: e.ID, Cadence: e.Cadence, Enabled: e.Enabled, Override: e.Override}
}

// state reads a corpus items object the way the state file holds it.
func (c corpusCase) state(t *testing.T, key string) State {
	t.Helper()
	st, err := ParseState([]byte(`{"schema":1,"items":` + string(c.raw[key]) + `}`))
	if err != nil {
		t.Fatalf("%s/%s: %s is not a valid state: %v", c.section, c.id, key, err)
	}
	return st
}

func (c corpusCase) entries(t *testing.T) []Entry {
	t.Helper()
	var list []corpusEntry
	c.strict(t, "entries", &list)
	out := make([]Entry, 0, len(list))
	for _, e := range list {
		out = append(out, e.entry())
	}
	return out
}

func check(t *testing.T, c corpusCase, want, got any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		var description string
		_ = json.Unmarshal(c.raw["description"], &description)
		t.Errorf("%s/%s: %s\nexpected %#v\nactual   %#v", c.section, c.id, description, want, got)
	}
}

func nonNil(m map[string]int64) map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	return m
}

func TestScheduleCorpus(t *testing.T) {
	for _, c := range loadCorpus(t, "schedule.json", sectionOrder, sectionKeys) {
		t.Run(c.section+"/"+c.id, func(t *testing.T) {
			switch c.section {
			case "next_occurrence":
				var in struct {
					Cadence   string `json:"cadence"`
					Weekday   int    `json:"weekday"`
					Hour      int    `json:"hour"`
					Minute    int    `json:"minute"`
					Reference int64  `json:"reference"`
				}
				for _, k := range []string{"cadence", "weekday", "hour", "minute", "reference"} {
					c.strict(t, k, map[string]any{"cadence": &in.Cadence, "weekday": &in.Weekday, "hour": &in.Hour,
						"minute": &in.Minute, "reference": &in.Reference}[k])
				}
				next, ok, err := NextOccurrence(in.Cadence, Schedule{Weekday: in.Weekday, Hour: in.Hour, Minute: in.Minute}, in.Reference, c.loc(t))
				got := any(nil)
				switch {
				case err != nil:
					got = "invalid"
				case ok:
					got = next
				}
				var want any
				switch raw := string(c.raw["expect"]); raw {
				case "null":
				case `"invalid"`:
					want = "invalid"
				default:
					var n int64
					c.strict(t, "expect", &n)
					want = n
				}
				check(t, c, want, got)
			case "plan":
				var def Schedule
				var now int64
				var groups []struct {
					corpusEntry
					LastCompleted *int64 `json:"last_completed_occurrence"`
				}
				c.strict(t, "default", &def)
				c.strict(t, "now", &now)
				c.strict(t, "groups", &groups)
				in := make([]Group, 0, len(groups))
				for _, g := range groups {
					in = append(in, Group{Entry: g.entry(), LastCompleted: g.LastCompleted})
				}
				var want struct {
					Due         []string         `json:"due"`
					NextDue     *int64           `json:"next_due"`
					Occurrences map[string]int64 `json:"occurrences"`
				}
				c.strict(t, "expect", &want)
				got := Plan(in, def, now, c.loc(t))
				check(t, c, append([]string{}, want.Due...), append([]string{}, got.Due...))
				check(t, c, want.NextDue, got.NextDue)
				check(t, c, nonNil(want.Occurrences), nonNil(got.Occurrences))
			case "extra_plan":
				var def Schedule
				var now int64
				var geoip bool
				var cache map[string]struct {
					NextDue int64 `json:"next_due"`
				}
				c.strict(t, "default", &def)
				c.strict(t, "now", &now)
				c.strict(t, "geoip_ready", &geoip)
				c.strict(t, "cache", &cache)
				var nextDue map[string]int64
				if cache != nil {
					nextDue = map[string]int64{}
					for id, e := range cache {
						nextDue[id] = e.NextDue
					}
				}
				var want struct {
					Due         []string         `json:"due"`
					Occurrences map[string]int64 `json:"occurrences"`
				}
				c.strict(t, "expect", &want)
				due, occurrences := ExtraPlan(Model{Default: def, Entries: c.entries(t)}, c.state(t, "state"), now, c.loc(t), nextDue, geoip)
				check(t, c, append([]string{}, want.Due...), append([]string{}, due...))
				check(t, c, nonNil(want.Occurrences), nonNil(occurrences))
			case "next_due":
				var m Model
				var now int64
				c.strict(t, "scheduled", &m.Scheduled)
				c.strict(t, "default", &m.Default)
				c.strict(t, "now", &now)
				m.Entries = c.entries(t)
				var want map[string]struct {
					LastRun *int64 `json:"last_run"`
					NextDue *int64 `json:"next_due"`
					Jitter  *int64 `json:"jitter"`
				}
				c.strict(t, "expect", &want)
				wantEntries := map[string]LedgerEntry{}
				for id, e := range want {
					if e.LastRun == nil || e.NextDue == nil || e.Jitter == nil {
						t.Fatalf("next_due/%s: expect[%s] lacks last_run, next_due or jitter", c.id, id)
					}
					wantEntries[id] = LedgerEntry{LastRun: *e.LastRun, NextDue: *e.NextDue, Jitter: *e.Jitter}
				}
				got := CacheEntries(m, c.state(t, "state"), now, c.loc(t))
				if got == nil {
					got = map[string]LedgerEntry{}
				}
				check(t, c, wantEntries, got)
			case "quiet_hours":
				var now int64
				var window string
				var want bool
				c.strict(t, "now", &now)
				c.strict(t, "window", &window)
				c.strict(t, "expect", &want)
				check(t, c, want, InApplyWindow(now, window, c.loc(t)))
			case "state_valid":
				var input string
				var want bool
				c.strict(t, "input", &input)
				c.strict(t, "expect", &want)
				_, err := ParseState([]byte(input))
				check(t, c, want, err == nil)
			case "set_pending":
				var occurrences map[string]int64
				c.strict(t, "occurrences", &occurrences)
				got, err := SetPending(c.state(t, "state"), occurrences)
				if string(c.raw["expect"]) == `"rejected"` {
					check(t, c, "rejected", map[bool]any{true: "rejected", false: got}[err != nil])
					return
				}
				if err != nil {
					t.Fatalf("set_pending/%s: %v", c.id, err)
				}
				check(t, c, c.state(t, "expect"), got)
			case "record_outcome":
				var item, outcome string
				var now int64
				var expected *int64
				c.strict(t, "item", &item)
				c.strict(t, "outcome", &outcome)
				c.strict(t, "now", &now)
				c.strict(t, "expected_occurrence", &expected)
				got, err := RecordOutcome(c.state(t, "state"), item, Outcome(outcome), now, expected)
				if string(c.raw["expect"]) == `"rejected"` {
					check(t, c, "rejected", map[bool]any{true: "rejected", false: got}[err != nil])
					return
				}
				if err != nil {
					t.Fatalf("record_outcome/%s: %v", c.id, err)
				}
				check(t, c, c.state(t, "expect"), got)
			case "model":
				var general, sections map[string]any
				var extras *struct {
					DCC bool `json:"dcc"`
					BL  BL   `json:"bl"`
				}
				c.strict(t, "general", &general)
				c.strict(t, "sections", &sections)
				c.strict(t, "extras", &extras)
				var ex *Extras
				if extras != nil {
					ex = &Extras{DCC: extras.DCC, BL: extras.BL}
				}
				got, err := RuntimeModel(general, sections, ex)
				var reject struct {
					Reject *string `json:"reject"`
				}
				_ = json.Unmarshal(c.raw["expect"], &reject)
				if reject.Reject != nil {
					check(t, c, *reject.Reject, fmt.Sprint(err))
					return
				}
				var want struct {
					Scheduled  bool          `json:"scheduled"`
					Default    Schedule      `json:"default"`
					Entries    []corpusEntry `json:"entries"`
					ConfigHash string        `json:"config_hash"`
				}
				c.strict(t, "expect", &want)
				if err != nil {
					t.Fatalf("model/%s: %v", c.id, err)
				}
				wantModel := Model{ConfigHash: want.ConfigHash, Scheduled: want.Scheduled, Default: want.Default, Entries: []Entry{}}
				for _, e := range want.Entries {
					wantModel.Entries = append(wantModel.Entries, e.entry())
				}
				if got.Entries == nil {
					got.Entries = []Entry{}
				}
				check(t, c, wantModel, got)
			case "blacklist":
				var section map[string]any
				c.strict(t, "blacklist", &section)
				got, err := BlacklistExtra(section)
				var want struct {
					Reject  *string `json:"reject"`
					Enabled bool    `json:"enabled"`
					Cadence string  `json:"cadence"`
				}
				c.strict(t, "expect", &want)
				if want.Reject != nil {
					check(t, c, *want.Reject, fmt.Sprint(err))
					return
				}
				if err != nil {
					t.Fatalf("blacklist/%s: %v", c.id, err)
				}
				check(t, c, BL{Enabled: want.Enabled, Cadence: want.Cadence}, got)
			}
		})
	}
}
