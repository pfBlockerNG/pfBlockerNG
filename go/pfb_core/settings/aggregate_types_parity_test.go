package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The parity fixture of the Uber aggregate selection (issue #4038, sub-slice 9h): tests/core/fixtures/
// settings_aggregate_types_parity.json, frozen against today's PHP by tests/php/CoreSettingsAggregateTypesParityTest.php. A
// case's aggregates is what the adapter answers in policy/ip for a stored gen/pfb_agg_types; Core reads it back as it is.
type aggregateTypesFixture struct {
	Schema      int    `json:"schema"`
	Projection  string `json:"projection"`
	Field       string `json:"field"`
	Description string `json:"description"`
	Cases       []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Stored      json.RawMessage `json:"stored"`
		PHP         []string        `json:"php"`
		Aggregates  []any           `json:"aggregates"`
	} `json:"cases"`
	Refused []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Aggregates  any    `json:"aggregates"`
	} `json:"refused"`
}

func loadAggregateTypesFixture(t *testing.T) aggregateTypesFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_aggregate_types_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc aggregateTypesFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "policy/ip" || doc.Field != "aggregates" || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, field %q, %d cases, %d refused", doc.Schema, doc.Projection, doc.Field, len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// WHEN the adapter answers a selection THEN Core reads it back as it is, each class today's reader selected, in its order.
func TestCoreReadsTheAdaptersAggregateSelectionBackAsTodaysReaderSelects(t *testing.T) {
	for _, c := range loadAggregateTypesFixture(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/ip": {"aggregates": c.Aggregates}}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			policy, err := st.GetClear("policy/ip")
			if err != nil {
				t.Fatal(err)
			}
			var classes []string
			for _, item := range policy["aggregates"].([]any) {
				classes = append(classes, item.(map[string]any)["class"].(string))
			}
			var want []string
			for _, typ := range c.PHP {
				want = append(want, strings.ToLower(typ))
			}
			if !reflect.DeepEqual(classes, want) {
				t.Errorf("%s\nread %q, today's reader selects %q", c.Description, classes, c.PHP)
			}
		})
	}
}

// WHEN the adapter answers a selection outside the four lower-case classes, each once, in a list THEN Core refuses the read,
// naming the field.
func TestCoreRefusesAnAggregateSelectionOutsideTheFourClassesNamingTheField(t *testing.T) {
	for _, c := range loadAggregateTypesFixture(t).Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/ip": {"aggregates": c.Aggregates}}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.Aggregates))
			}
			if st != nil || !strings.Contains(err.Error(), "policy/ip.aggregates") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming policy/ip.aggregates", c.Description, st, err)
			}
		})
	}
}
