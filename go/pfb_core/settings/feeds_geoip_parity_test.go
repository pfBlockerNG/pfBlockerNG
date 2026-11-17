package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The parity fixture of the feeds/geoip projection (issue #4031): tests/core/fixtures/settings_feeds_geoip_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsFeedsGeoipParityTest.php. A case's `groups` (each over the fixture's defaults) is what the adapter
// reads from its config.xml: Core accepts it and reads it back as it is. A refused row is a whole value Core refuses to read, naming
// `field`: Core does not trust what the backend answers.
type feedsGeoipFixture struct {
	Schema     int    `json:"schema"`
	Projection string `json:"projection"`
	Continents []struct {
		Name    string `json:"name"`
		Alias   string `json:"alias"`
		Section string `json:"section"`
	} `json:"continents"`
	Defaults struct {
		Groups []map[string]any `json:"groups"`
	} `json:"defaults"`
	Cases []struct {
		ID          string                    `json:"id"`
		Description string                    `json:"description"`
		Config      json.RawMessage           `json:"config"`
		ConfigRaw   json.RawMessage           `json:"configRaw"`
		Groups      map[string]map[string]any `json:"groups"`
		PHP         json.RawMessage           `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		Value       map[string]any `json:"value"`
		Field       string         `json:"field"`
	} `json:"refused"`
}

func loadFeedsGeoipFixture(t *testing.T) feedsGeoipFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_feeds_geoip_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc feedsGeoipFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "feeds/geoip" || len(doc.Continents) != 9 || len(doc.Defaults.Groups) != 9 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d continents, %d default groups, %d cases, %d refused", doc.Schema, doc.Projection,
			len(doc.Continents), len(doc.Defaults.Groups), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// valueOver is the whole feeds/geoip value a backend answers: the fixture's defaults with each group of over (by name) laid on its default.
func (d feedsGeoipFixture) valueOver(over map[string]map[string]any) map[string]any {
	groups := make([]any, 0, len(d.Defaults.Groups))
	for _, def := range d.Defaults.Groups {
		group := map[string]any{}
		for k, v := range def {
			group[k] = v
		}
		for k, v := range over[def["name"].(string)] {
			group[k] = v
		}
		groups = append(groups, group)
	}
	return map[string]any{"groups": groups}
}

func productionFeedsGeoip(t *testing.T) Projection {
	t.Helper()
	for _, p := range Production().Projections {
		if p.ID == "feeds/geoip" {
			return p
		}
	}
	t.Fatal("the production schema has no projection feeds/geoip")
	return Projection{}
}

func TestTheProductionSchemaListsFeedsGeoipWritableAfterPolicyIpWithTheFixturesFieldsInOrder(t *testing.T) {
	var ids []string
	for _, p := range Production().Projections {
		ids = append(ids, p.ID)
	}
	if want := []string{"dns", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl", "schedule", "ingest", "policy/ip", "feeds/geoip", "policy/dnsbl", "extras", "hooks", "maintenance"}; !slices.Equal(ids, want) {
		t.Errorf("projections = %v, want %v", ids, want)
	}
	p := productionFeedsGeoip(t)
	if p.ReadOnly {
		t.Error("feeds/geoip is read-only, want writable: Core changes the GeoIP continents")
	}
	if len(p.Fields) != 1 || p.Fields[0].Name != "groups" || p.Fields[0].Key != "name" {
		t.Fatalf("feeds/geoip fields = %+v, want one list `groups` keyed by name", p.Fields)
	}
	var names []string
	for _, f := range p.Fields[0].Items {
		names = append(names, f.Name)
	}
	if want := []string{"name", "action", "listClass", "countriesV4", "countriesV6"}; !slices.Equal(names, want) {
		t.Errorf("a continent group's fields = %v, want %v", names, want)
	}
}

func TestTheFixturesDefaultsAreTheFeedsGeoipProjectionsDefaults(t *testing.T) {
	doc := loadFeedsGeoipFixture(t)
	have := map[string]any{}
	for _, f := range productionFeedsGeoip(t).Fields {
		have[f.Name] = f.Default
	}
	if want := map[string]any{"groups": doc.valueOver(nil)["groups"]}; jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, want))
	}
}

func TestTheFeedsGeoipProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	doc := loadFeedsGeoipFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := doc.valueOver(c.Groups)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"feeds/geoip": want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			got, err := st.GetClear("feeds/geoip")
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
}

func TestTheFeedsGeoipProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadFeedsGeoipFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"feeds/geoip": c.Value}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.Value))
			}
			if st != nil || !strings.Contains(err.Error(), "feeds/geoip."+c.Field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming feeds/geoip.%s", c.Description, st, err, c.Field)
			}
		})
	}
}
