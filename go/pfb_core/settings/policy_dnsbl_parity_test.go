package settings

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The parity fixture of the policy/dnsbl projection (issue #4031): tests/core/fixtures/settings_policy_dnsbl_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsPolicyDnsblParityTest.php. A case's `policyDnsbl` (over the fixture's defaults) is what the
// adapter reads from its config.xml: Core accepts it and reads it back as it is. A refused row is a value Core refuses to read, naming
// `field`: Core does not trust what the backend answers.
type policyDnsblFixture struct {
	Schema     int             `json:"schema"`
	Projection string          `json:"projection"`
	Defaults   map[string]any  `json:"defaults"`
	Base       json.RawMessage `json:"base"`
	Cases      []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Bare        bool            `json:"bare"`
		Config      json.RawMessage `json:"config"`
		Text        json.RawMessage `json:"text"`
		Groups      json.RawMessage `json:"groups"`
		Blacklist   json.RawMessage `json:"blacklist"`
		PolicyDnsbl map[string]any  `json:"policyDnsbl"`
		PHP         json.RawMessage `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		PolicyDnsbl map[string]any `json:"policyDnsbl"`
		Field       string         `json:"field"`
	} `json:"refused"`
}

func loadPolicyDnsblFixture(t *testing.T) policyDnsblFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_policy_dnsbl_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc policyDnsblFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "policy/dnsbl" || len(doc.Defaults) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d defaults, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Defaults), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// policyDnsblOver is the fixture's defaults with over laid on them: the whole policy/dnsbl value a backend answers.
func (d policyDnsblFixture) policyDnsblOver(over map[string]any) map[string]any {
	values := maps.Clone(d.Defaults)
	maps.Copy(values, over)
	return values
}

// productionPolicyDnsbl is the projection policy/dnsbl of the production schema, failing the test when the schema has none.
func productionPolicyDnsbl(t *testing.T) Projection {
	t.Helper()
	for _, p := range Production().Projections {
		if p.ID == "policy/dnsbl" {
			return p
		}
	}
	t.Fatal("the production schema has no projection policy/dnsbl")
	return Projection{}
}

func TestTheProductionSchemaListsPolicyDnsblWritableAfterGeoipWithTheFixturesFieldsInOrder(t *testing.T) {
	var ids []string
	for _, p := range Production().Projections {
		ids = append(ids, p.ID)
	}
	if want := []string{"dns", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl", "schedule", "ingest", "policy/ip", "feeds/geoip", "policy/dnsbl", "extras", "hooks", "maintenance"}; !slices.Equal(ids, want) {
		t.Errorf("projections = %v, want %v", ids, want)
	}
	p := productionPolicyDnsbl(t)
	if p.ReadOnly {
		t.Error("policy/dnsbl is read-only, want writable: Core changes the DNSBL build policy")
	}
	var names []string
	for _, f := range p.Fields {
		names = append(names, f.Name)
	}
	want := []string{"enabled", "whitelist", "top1m", "top1mCount", "top1mInclusions", "tldBlacklist", "tldExclusions", "tldAllow", "tldAllowGtld", "tldAllowCctld",
		"tldAllowItld", "tldAllowBgtld", "regex", "regexList", "safeSearch", "safeSearchYoutube", "safeSearchDoh", "safeSearchDohList", "dnsblIpAction", "logging",
		"blacklistLogging", "groups"}
	if !slices.Equal(names, want) {
		t.Errorf("policy/dnsbl fields = %v, want %v", names, want)
	}
}

func TestTheFixturesDefaultsAreThePolicyDnsblProjectionsDefaults(t *testing.T) {
	have := map[string]any{}
	for _, f := range productionPolicyDnsbl(t).Fields {
		have[f.Name] = f.Default
	}
	if want := loadPolicyDnsblFixture(t).Defaults; jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, want))
	}
}

func TestThePolicyDnsblProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	doc := loadPolicyDnsblFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := doc.policyDnsblOver(c.PolicyDnsbl)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/dnsbl": want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			got, err := st.GetClear("policy/dnsbl")
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
}

func TestThePolicyDnsblProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadPolicyDnsblFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/dnsbl": doc.policyDnsblOver(c.PolicyDnsbl)}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.PolicyDnsbl))
			}
			if st != nil || !strings.Contains(err.Error(), "policy/dnsbl."+c.Field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming policy/dnsbl.%s", c.Description, st, err, c.Field)
			}
		})
	}
}
