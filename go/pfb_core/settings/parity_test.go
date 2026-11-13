package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The parity fixture of settings/dns (issue #3842): tests/core/fixtures/settings_dns_parity.json, frozen against today's
// PHP by tests/php/CoreSettingsDnsParityTest.php. Each case's input (its native value when it has none) is saved into a
// freshly initialized store: Core's verdict must be the case's, and an accepted save must leave exactly its native values.
func TestTheDnsProjectionMatchesTodaysPhpOnEveryFixtureCase(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_dns_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema     int    `json:"schema"`
		Projection string `json:"projection"`
		Cases      []struct {
			ID          string                     `json:"id"`
			Description string                     `json:"description"`
			Source      string                     `json:"source"`
			Values      map[string]*string         `json:"values"`
			Input       map[string]json.RawMessage `json:"input"`
			Valid       bool                       `json:"valid"`
			Native      map[string]json.RawMessage `json:"native"`
		} `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "dns" || len(doc.Cases) == 0 {
		t.Fatalf("fixture schema %d projection %q with %d cases, want schema 1, dns, some cases", doc.Schema, doc.Projection, len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Valid == (c.Native == nil) {
				t.Fatalf("an accepted case has native values and a refused one none: valid %v, native %v", c.Valid, c.Native)
			}
			input := c.Input
			if input == nil {
				input = c.Native
			}
			st := open(t, t.TempDir())
			if _, err := st.Initialize(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			_, err := st.Save(t.Context(), 1, map[string]map[string]json.RawMessage{"dns": input})
			if accepted := err == nil; accepted != c.Valid {
				t.Fatalf("%s\nCore's verdict on %s: accepted %v (%v), PHP's %v", c.Description, jsonOf(t, input), accepted, err, c.Valid)
			}
			if !c.Valid {
				return
			}
			value := projection(t, get(t, st, "dns"), "dns").Value
			for field, want := range c.Native {
				if have := jsonOf(t, value[field]); have != string(want) {
					t.Errorf("%s\n%s = %s, PHP gives %s", c.Description, field, have, want)
				}
			}
		})
	}
}
