package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The parity fixture of the schedule projection (issue #3941): tests/core/fixtures/settings_schedule_parity.json, frozen
// against today's PHP by tests/php/CoreSettingsScheduleParityTest.php. A case's `schedule` is what the adapter reads from its
// config.xml: Core accepts it and reads it back as it is. A refused row is hostile input: Core refuses it, naming `field`.
type scheduleFixture struct {
	Schema     int    `json:"schema"`
	Projection string `json:"projection"`
	Cases      []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Config      json.RawMessage `json:"config"`
		Schedule    json.RawMessage `json:"schedule"`
		Feeds       json.RawMessage `json:"feeds"`
		Model       json.RawMessage `json:"model"`
	} `json:"cases"`
	Refused []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Schedule    json.RawMessage `json:"schedule"`
		Field       string          `json:"field"`
	} `json:"refused"`
}

func loadScheduleFixture(t *testing.T) scheduleFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_schedule_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc scheduleFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "schedule" || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// scheduleChanges is a schedule value as a change set: each of its fields set.
func scheduleChanges(t *testing.T, value json.RawMessage) map[string]map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(value, &fields); err != nil {
		t.Fatalf("%s: %v", value, err)
	}
	return map[string]map[string]json.RawMessage{"schedule": fields}
}

func TestTheScheduleProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	for _, c := range loadScheduleFixture(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			st := open(t, t.TempDir())
			if _, err := st.Initialize(nil); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Save(1, scheduleChanges(t, c.Schedule)); err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			var want map[string]any
			if err := json.Unmarshal(c.Schedule, &want); err != nil {
				t.Fatal(err)
			}
			if have := jsonOf(t, projection(t, get(t, st, "schedule"), "schedule").Value); have != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, have, jsonOf(t, want))
			}
		})
	}
}

func TestTheScheduleProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	st := open(t, t.TempDir())
	if _, err := st.Initialize(nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range loadScheduleFixture(t).Refused {
		t.Run(c.ID, func(t *testing.T) {
			err := st.Validate(scheduleChanges(t, c.Schedule))
			v, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("%s\nValidate = %v, want a ValidationError", c.Description, err)
			}
			var named []string
			for _, f := range v.Fields {
				named = append(named, f.Field)
			}
			if !slices.Contains(named, "schedule."+c.Field) {
				t.Errorf("%s\nValidate refused %v, want it to name schedule.%s", c.Description, named, c.Field)
			}
		})
	}
}
