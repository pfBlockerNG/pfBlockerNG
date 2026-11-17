package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parity fixture of the maintenance projection: tests/core/fixtures/settings_maintenance_parity.json. A case's `maintenance`
// (over the fixture's defaults) is what the adapter reads from config.xml and the sentinel file `cronDisable` says is there;
// Core accepts it and reads it back as it is. A refused row is a value Core refuses to read, naming `field`.
type maintenanceFixture struct {
	Schema     int            `json:"schema"`
	Projection string         `json:"projection"`
	Defaults   map[string]any `json:"defaults"`
	Cases      []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Config      json.RawMessage `json:"config"`
		CronDisable *bool           `json:"cronDisable"`
		Maintenance map[string]any  `json:"maintenance"`
		PHP         json.RawMessage `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		Maintenance map[string]any `json:"maintenance"`
		Field       string         `json:"field"`
	} `json:"refused"`
}

func loadMaintenanceFixture(t *testing.T) maintenanceFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_maintenance_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc maintenanceFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "maintenance" || len(doc.Defaults) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d defaults, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Defaults), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

func (d maintenanceFixture) over(over map[string]any) map[string]any {
	values := maps.Clone(d.Defaults)
	maps.Copy(values, over)
	return values
}

func maintenanceProjectionOf(t *testing.T) Projection {
	t.Helper()
	for _, p := range Production().Projections {
		if p.ID == "maintenance" {
			return p
		}
	}
	t.Fatal("the production schema has no maintenance projection")
	return Projection{}
}

func TestTheMaintenanceProjectionIsPublishedReadOnlyWithTheFixturesDefaults(t *testing.T) {
	p := maintenanceProjectionOf(t)
	if !p.ReadOnly {
		t.Error("settings/maintenance is not read-only")
	}
	have := map[string]any{}
	for _, f := range p.Fields {
		have[f.Name] = f.Default
		if f.Name == "clearIpCounters" || f.Name == "clearDnsblCounters" {
			if f.Type != TypeEnum || jsonOf(t, f.Enum) != `["never","daily","weekly"]` {
				t.Errorf("%s is %s %v, want an enum never, daily, weekly", f.Name, f.Type, f.Enum)
			}
		}
	}
	if want := loadMaintenanceFixture(t).Defaults; jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, want))
	}
	if last := Production().Projections[len(Production().Projections)-1].ID; last != "maintenance" {
		t.Errorf("the last projection is %s, want maintenance appended last", last)
	}
}

func TestTheMaintenanceProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	doc := loadMaintenanceFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := doc.over(c.Maintenance)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"maintenance": want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			got, err := st.GetClear("maintenance")
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
}

// A value Core does not hold is refused as the store refuses it for ingest: the read fails naming maintenance.<field> and no
// store is made.
func TestTheMaintenanceProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadMaintenanceFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"maintenance": doc.over(c.Maintenance)}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.Maintenance))
			}
			if st != nil || !strings.Contains(err.Error(), "maintenance."+c.Field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming maintenance.%s", c.Description, st, err, c.Field)
			}
		})
	}
}

// A field the backend leaves out is its default, as the store reads a field of ingest the backend does not hold.
func TestAMaintenanceFieldTheBackendLeavesOutIsItsDefault(t *testing.T) {
	st, err := Load(newRefreshBackend(1, map[string]map[string]any{"maintenance": {"enabled": true}}), Production())
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetClear("maintenance")
	if err != nil {
		t.Fatal(err)
	}
	want := loadMaintenanceFixture(t).over(map[string]any{"enabled": true})
	if jsonOf(t, got) != jsonOf(t, want) {
		t.Errorf("a backend holding only enabled reads as %s, want %s", jsonOf(t, got), jsonOf(t, want))
	}
}

// A change set that names the maintenance projection is refused whole by Save, Validate and Initialize, as for ingest.
func TestAChangeSetThatNamesTheMaintenanceProjectionIsRefusedWhole(t *testing.T) {
	for name, body := range map[string]string{
		"a valid value":    `{"dns": {"control": true}, "maintenance": {"enabled": true}}`,
		"an empty object":  `{"maintenance": {}}`,
		"null":             `{"maintenance": null}`,
		"a field it lacks": `{"maintenance": {"nosuchfield": 1}}`,
		"an invalid value": `{"maintenance": {"clearIpCounters": "monthly"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			refused := func(method string, err error) {
				t.Helper()
				var v *ValidationError
				if !errors.As(err, &v) || len(v.Fields) != 1 || v.Fields[0].Field != "maintenance" || !strings.Contains(v.Fields[0].Message, "read-only") {
					t.Errorf("%s = %v, want one ValidationError naming maintenance as read-only", method, err)
				}
			}
			b := newRefreshBackend(1, map[string]map[string]any{"maintenance": loadMaintenanceFixture(t).over(nil)})
			st := storeOver(t, b)
			refused("Validate", st.Validate(changes(t, body)))
			_, err := st.Save(t.Context(), 1, changes(t, body))
			refused("Save", err)
			if b.writes != 0 {
				t.Errorf("a refused Save wrote %d times, want nothing written", b.writes)
			}
			uninitialized := storeOver(t, newRefreshBackend(0, nil))
			_, err = uninitialized.Initialize(t.Context(), changes(t, body))
			refused("Initialize", err)
		})
	}
}
