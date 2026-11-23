package settings

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parity fixture of the ingest projection (issue #3975): tests/core/fixtures/settings_ingest_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsIngestParityTest.php. A case's `ingest` (over the fixture's defaults) is what the adapter
// reads from its config.xml and the platform: Core accepts it and reads it back as it is. A refused row is a value Core refuses
// to read, naming `field`: Core does not trust what the backend answers.
type ingestFixture struct {
	Schema     int            `json:"schema"`
	Projection string         `json:"projection"`
	Defaults   map[string]any `json:"defaults"`
	// SkipFeedFailures are the failure counts at which a case's php.skipfeedCap holds today's retry-cap decision.
	SkipFeedFailures []int `json:"skipFeedFailures"`
	Cases            []struct {
		ID            string          `json:"id"`
		Description   string          `json:"description"`
		Config        json.RawMessage `json:"config"`
		AllowlistText *string         `json:"allowlistText"`
		Platform      json.RawMessage `json:"platform"`
		CronDisable   json.RawMessage `json:"cronDisable"`
		Vips          json.RawMessage `json:"vips"`
		Pending       json.RawMessage `json:"pending"`
		Departure     string          `json:"departure"`
		Ingest        map[string]any  `json:"ingest"`
		PHP           json.RawMessage `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		Ingest      map[string]any `json:"ingest"`
		Field       string         `json:"field"`
	} `json:"refused"`
}

func loadIngestFixture(t *testing.T) ingestFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_ingest_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc ingestFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "ingest" || len(doc.Defaults) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d defaults, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Defaults), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// ingestOver is the fixture's defaults with over laid on them: the whole ingest value a backend answers.
func (d ingestFixture) ingestOver(over map[string]any) map[string]any {
	values := maps.Clone(d.Defaults)
	maps.Copy(values, over)
	return values
}

func TestTheFixturesDefaultsAreTheIngestProjectionsDefaults(t *testing.T) {
	have := map[string]any{}
	for _, f := range ingestProjection().Fields {
		have[f.Name] = f.Default
	}
	if want := loadIngestFixture(t).Defaults; jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, want))
	}
}

func TestTheIngestProjectionAcceptsAndReadsBackWhatTheAdapterReadsOnEveryFixtureCase(t *testing.T) {
	doc := loadIngestFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := doc.ingestOver(c.Ingest)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"ingest": want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			got, err := st.GetClear("ingest")
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
}

func TestTheIngestProjectionRefusesTheFixturesHostileInputNamingTheField(t *testing.T) {
	doc := loadIngestFixture(t)
	for _, c := range doc.Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"ingest": doc.ingestOver(c.Ingest)}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.Ingest))
			}
			if st != nil || !strings.Contains(err.Error(), "ingest."+c.Field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming ingest.%s", c.Description, st, err, c.Field)
			}
		})
	}
}

// WHEN the adapter answers ingest.skipFeedLimit THEN the comparison the work list makes (a limit that is not 0 and a failure
// count at or past it), re-derived here on the limit Core reads, gives today's pfb_update_check() decision at every count, except
// on a case that names its departure, where the two must differ (issue #4038). It checks the value, not the work list itself.
func TestTheSkipFeedLimitCapsRetriesAsTodaysPHPAtEveryFailureCount(t *testing.T) {
	doc := loadIngestFixture(t)
	seen := 0
	for _, c := range doc.Cases {
		var php struct {
			SkipfeedCap []bool `json:"skipfeedCap"`
		}
		if err := json.Unmarshal(c.PHP, &php); err != nil {
			t.Fatal(err)
		}
		if php.SkipfeedCap == nil {
			continue
		}
		seen++
		t.Run(c.ID, func(t *testing.T) {
			if len(php.SkipfeedCap) != len(doc.SkipFeedFailures) {
				t.Fatalf("%d decisions for %d failure counts", len(php.SkipfeedCap), len(doc.SkipFeedFailures))
			}
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"ingest": doc.ingestOver(c.Ingest)}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			ingest, err := st.GetClear("ingest")
			if err != nil {
				t.Fatal(err)
			}
			limit := ingest["skipFeedLimit"].(int64)
			same := true
			for i, failed := range doc.SkipFeedFailures {
				if (limit != 0 && int64(failed) >= limit) != php.SkipfeedCap[i] {
					same = false
				}
			}
			if c.Departure == "" && !same {
				t.Errorf("%s\nlimit %d caps otherwise than today's PHP %v at %v", c.Description, limit, php.SkipfeedCap, doc.SkipFeedFailures)
			}
			if c.Departure != "" && same {
				t.Errorf("%s\nthe case names a departure (%s), yet limit %d caps as today's PHP", c.Description, c.Departure, limit)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no case holds php.skipfeedCap")
	}
}
