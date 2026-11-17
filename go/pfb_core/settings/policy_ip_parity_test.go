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

// The parity fixture of the policy/ip projection (issue #4031): tests/core/fixtures/settings_policy_ip_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsPolicyIpParityTest.php. A case's `policyIp` (over the fixture's defaults) is what the adapter
// reads from its config.xml: Core accepts it and reads it back as it is. A refused row is a value Core refuses to read, naming
// `field`: Core does not trust what the backend answers.
type policyIPFixture struct {
	Schema     int            `json:"schema"`
	Projection string         `json:"projection"`
	Defaults   map[string]any `json:"defaults"`
	Cases      []struct {
		ID              string          `json:"id"`
		Description     string          `json:"description"`
		Config          json.RawMessage `json:"config"`
		SuppressionText json.RawMessage `json:"suppressionText"`
		PolicyIP        map[string]any  `json:"policyIp"`
		PHP             json.RawMessage `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		PolicyIP    map[string]any `json:"policyIp"`
		Field       string         `json:"field"`
	} `json:"refused"`
}

func loadPolicyIPFixture(t *testing.T) policyIPFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_policy_ip_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc policyIPFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "policy/ip" || len(doc.Defaults) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d defaults, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Defaults), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// policyIPOver is the fixture's defaults with over laid on them: the whole policy/ip value a backend answers.
func (d policyIPFixture) policyIPOver(over map[string]any) map[string]any {
	values := maps.Clone(d.Defaults)
	maps.Copy(values, over)
	return values
}

// productionPolicyIP is the projection policy/ip of the production schema, failing the test when the schema has none.
func productionPolicyIP(t *testing.T) Projection {
	t.Helper()
	for _, p := range Production().Projections {
		if p.ID == "policy/ip" {
			return p
		}
	}
	t.Fatal("the production schema has no projection policy/ip")
	return Projection{}
}

func TestTheProductionSchemaListsPolicyIpWritableAfterIngestWithTheFixturesFieldsInOrder(t *testing.T) {
	var ids []string
	for _, p := range Production().Projections {
		ids = append(ids, p.ID)
	}
	if want := []string{"dns", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl", "schedule", "ingest", "policy/ip", "feeds/geoip", "policy/dnsbl", "extras", "hooks", "maintenance"}; !slices.Equal(ids, want) {
		t.Errorf("projections = %v, want %v", ids, want)
	}
	p := productionPolicyIP(t)
	if p.ReadOnly {
		t.Error("policy/ip is read-only, want writable: Core changes the IP policy")
	}
	var names []string
	for _, f := range p.Fields {
		names = append(names, f.Name)
	}
	want := []string{"dedup", "aggregate", "max", "maxLimit", "pMax", "pMaxLimit", "dMax", "dMaxLimit", "countryWhitelistAction", "countryBlacklistAction",
		"countryWhitelist", "etBlock", "etMatch", "suppressionV4", "suppressionV6"}
	if !slices.Equal(names, want) {
		t.Errorf("policy/ip fields = %v, want %v", names, want)
	}
}

func TestTheFixturesDefaultsAreThePolicyIpProjectionsDefaults(t *testing.T) {
	have := map[string]any{}
	for _, f := range productionPolicyIP(t).Fields {
		have[f.Name] = f.Default
	}
	if want := loadPolicyIPFixture(t).Defaults; jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, want))
	}
}

func TestThePolicyIpProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	doc := loadPolicyIPFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := doc.policyIPOver(c.PolicyIP)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/ip": want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			got, err := st.GetClear("policy/ip")
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
}

func TestThePolicyIpProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadPolicyIPFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"policy/ip": doc.policyIPOver(c.PolicyIP)}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.PolicyIP))
			}
			if st != nil || !strings.Contains(err.Error(), "policy/ip."+c.Field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming policy/ip.%s", c.Description, st, err, c.Field)
			}
		})
	}
}
