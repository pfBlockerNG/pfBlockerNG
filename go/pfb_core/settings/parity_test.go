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
		Ini         map[string]*string         `json:"ini"` // the raw [noAAAA] and [GP_Bypass_List] text today's writer gives (issue #4036)
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
	// The raw ini of a case touching the noAAAA or Group Policy fields (issue #4036) cannot vanish from a regenerated fixture
	for _, c := range doc.Cases {
		touches := false
		for key := range c.Values {
			touches = touches || slices.Contains([]string{"dnsbl/pfb_noaaaa", "dnsbl/pfb_noaaaa_list", "dnsbl/pfb_gp", "dnsbl/pfb_gp_bypass_list"}, key)
		}
		for field := range c.Native {
			touches = touches || slices.Contains([]string{"noAaaa", "noAaaaList", "groupPolicy", "groupPolicyBypassList"}, field)
		}
		if touches && c.Ini == nil {
			t.Errorf("case %s touches the noAAAA or Group Policy fields but carries no ini", c.ID)
		}
	}
	return doc
}

// The parity fixture of settings/dns (issue #3842): tests/core/fixtures/settings_dns_parity.json, frozen against today's
// PHP by tests/php/CoreSettingsDnsParityTest.php. Each case's input (its native value when it has none) is saved into a freshly
// initialized store: Core's verdict must be the case's, and an accepted save must leave exactly its native values. A stored case
// with no input whose noAAAA list holds entries is a list the Outpost's adapter reads and a client writes back (issue #4036): the
// store first loads that list alone, as the adapter's read brings it in, so the save still proves every other field.
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
			var held []any
			if c.Source == "stored" && c.Input == nil && c.Native["noAaaaList"] != nil {
				if err := json.Unmarshal(c.Native["noAaaaList"], &held); err != nil {
					t.Fatal(err)
				}
			}
			if len(held) > 0 {
				var err error
				if st, err = Load(newRefreshBackend(1, map[string]map[string]any{"dns": {"noAaaaList": held}}), testSchema()); err != nil {
					t.Fatalf("%s\nthe adapter's read of noAaaaList %s does not load: %v", c.Description, jsonOf(t, held), err)
				}
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

// A write may add only a noAAAA entry the DNSBL page accepts (issue #4036), while an entry the Outpost's read brought in that the
// page refuses stays writable, so a client can write back what it read.
func TestANoAaaaEntryAWriteAddsIsHeldToTheDnsblPagesRule(t *testing.T) {
	st, err := Load(newRefreshBackend(1, map[string]map[string]any{"dns": {"noAaaaList": []any{map[string]any{"domain": "*.example.com"}}}}), testSchema())
	if err != nil {
		t.Fatalf("a stored entry the page refuses does not load: %v", err)
	}
	added := `{"dns": {"noAaaaList": [{"domain": "*.example.com"}, {"domain": "example.com."}, {"domain": ".ads.example.net"}, {"domain": "1.0"}, {"domain": "example.org.."}]}}`
	if _, err := st.Save(t.Context(), 1, changes(t, added)); err != nil {
		t.Fatalf("Save(%s) = %v, want the held entry kept and the entries the page accepts added", added, err)
	}
	refused := `{"dns": {"noAaaaList": [{"domain": "*.example.com"}, {"domain": "*.other.example"}]}}`
	_, err = st.Save(t.Context(), 2, changes(t, refused))
	var invalid *ValidationError
	if !errors.As(err, &invalid) || len(invalid.Fields) != 1 || invalid.Fields[0].Field != "dns.noAaaaList[1].domain" {
		t.Fatalf("Save(%s) = %v, want dns.noAaaaList[1].domain refused alone", refused, err)
	}
}

// A dry run never refuses a noAAAA entry for the DNSBL page's rule (issue #4036): a page validates the whole projection as config.xml
// holds it, which may carry an entry Core has not loaded yet. The rule holds on a real write, where the stored list is compared.
func TestTheDryRunLeavesTheAddedNoAaaaEntryRuleToTheWrite(t *testing.T) {
	st := open(t, t.TempDir())
	if _, err := st.Initialize(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if v := projection(t, get(t, st, "dns"), "dns").Value["noAaaaList"]; jsonOf(t, v) != "[]" {
		t.Fatalf("before-state: Core holds noAaaaList %s, want []", jsonOf(t, v))
	}
	list := `{"dns": {"noAaaaList": [{"domain": "ok.example"}, {"domain": "*.example.com"}]}}`
	if err := st.Validate(changes(t, list)); err != nil {
		t.Errorf("Validate(%s) = %v, want it accepted: the dry run leaves the added-entry rule to the write", list, err)
	}
	_, err := st.Save(t.Context(), 1, changes(t, list))
	var invalid *ValidationError
	if !errors.As(err, &invalid) || len(invalid.Fields) != 1 || invalid.Fields[0].Field != "dns.noAaaaList[1].domain" {
		t.Fatalf("Save(%s) = %v, want dns.noAaaaList[1].domain refused alone", list, err)
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
