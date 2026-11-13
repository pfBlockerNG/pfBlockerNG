package schedule

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Replays testdata/tick.json (schema: the "Tick corpus" section of testdata/README.md): the two steps of
// pfblockerng_tick() that Core takes over. This is the only runner: the PHP one, ScheduleTickCorpusTest, and the functions it
// replayed went with the cutover (#3941), so a change to this corpus is a change to Core's behavior.

var tickSectionOrder = []string{"feed_plan", "reserve"}

var tickSectionKeys = map[string][]string{
	"feed_plan": {"id", "description", "timezone", "scheduled", "default", "now", "entries", "state", "expect"},
	"reserve":   {"id", "description", "state", "occurrences", "expect"},
}

// unvalidatedState reads a corpus items object into a State without validating it: a reserve case may hold a state
// Reserve must refuse, which ParseState (and so corpusCase.state) would not return.
func (c corpusCase) unvalidatedState(t *testing.T, key string) State {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(c.raw[key]))
	dec.UseNumber()
	var items map[string]any
	if err := dec.Decode(&items); err != nil {
		t.Fatalf("%s/%s: %s: %v", c.section, c.id, key, err)
	}
	st := State{}
	for id, raw := range items {
		it, ok := parseItem(raw)
		if !ok {
			t.Fatalf("%s/%s: %s[%s] is not an item", c.section, c.id, key, id)
		}
		st[id] = it
	}
	return st
}

func TestTickCorpus(t *testing.T) {
	for _, c := range loadCorpus(t, "tick.json", tickSectionOrder, tickSectionKeys) {
		t.Run(c.section+"/"+c.id, func(t *testing.T) {
			switch c.section {
			case "feed_plan":
				var m Model
				var now int64
				c.strict(t, "scheduled", &m.Scheduled)
				c.strict(t, "default", &m.Default)
				c.strict(t, "now", &now)
				m.Entries = c.entries(t)
				var want struct {
					Due         []string         `json:"due"`
					Occurrences map[string]int64 `json:"occurrences"`
				}
				c.strict(t, "expect", &want)
				got := FeedPlan(m, c.state(t, "state"), now, c.loc(t))
				check(t, c, append([]string{}, want.Due...), append([]string{}, got.Due...))
				check(t, c, nonNil(want.Occurrences), nonNil(got.Occurrences))
			case "reserve":
				var occurrences map[string]int64
				c.strict(t, "occurrences", &occurrences)
				got, err := Reserve(c.unvalidatedState(t, "state"), occurrences)
				if string(c.raw["expect"]) == `"rejected"` {
					check(t, c, "rejected", map[bool]any{true: "rejected", false: got}[err != nil])
					return
				}
				if err != nil {
					t.Fatalf("reserve/%s: %v", c.id, err)
				}
				check(t, c, c.state(t, "expect"), got)
			}
		})
	}
}
