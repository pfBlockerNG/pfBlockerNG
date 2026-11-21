package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type dnsFixture struct {
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
	Refused []struct {
		ID          string                     `json:"id"`
		Description string                     `json:"description"`
		Input       map[string]json.RawMessage `json:"input"`
		Field       string                     `json:"field"`
	} `json:"refused"`
}

func loadDnsFixture(t *testing.T) dnsFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_dns_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc dnsFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "dns" || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d projection %q with %d cases and %d refused, want schema 1, dns, some of both", doc.Schema, doc.Projection,
			len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// The parity fixture of settings/dns (issue #3842): tests/core/fixtures/settings_dns_parity.json, frozen against today's
// PHP by tests/php/CoreSettingsDnsParityTest.php. Each case's input (its native value when it has none) is saved into a
// freshly initialized store: Core's verdict must be the case's, and an accepted save must leave exactly its native values.
func TestTheDnsProjectionMatchesTodaysPhpOnEveryFixtureCase(t *testing.T) {
	doc := loadDnsFixture(t)
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
				var compact bytes.Buffer
				if err := json.Compact(&compact, want); err != nil {
					t.Fatal(err)
				}
				if have := jsonOf(t, value[field]); have != compact.String() {
					t.Errorf("%s\n%s = %s, PHP gives %s", c.Description, field, have, compact.String())
				}
			}
		})
	}
}

// A refused row (issue #4036) is a value of the noAAAA or Group Policy fields the Outpost's adapter never answers and its write refuses
// (CoreSettingsDnsParityTest): Core refuses to save it, naming the field, and keeps what it held.
func TestTheDnsProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadDnsFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st := open(t, t.TempDir())
			if _, err := st.Initialize(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			_, err := st.Save(t.Context(), 1, map[string]map[string]json.RawMessage{"dns": c.Input})
			var invalid *ValidationError
			if !errors.As(err, &invalid) || !slices.ContainsFunc(invalid.Fields, func(f FieldError) bool { return f.Field == "dns."+c.Field }) {
				t.Fatalf("%s\nSave(%s) = %v, want a refusal naming dns.%s", c.Description, jsonOf(t, c.Input), err, c.Field)
			}
			if snap := get(t, st, "dns"); snap.Revision != 1 {
				t.Errorf("a refused save moved the revision to %d", snap.Revision)
			}
		})
	}
}
