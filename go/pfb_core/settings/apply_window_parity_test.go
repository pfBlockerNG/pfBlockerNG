package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
)

// The parity fixture of the apply window (issue #4038, sub-slice 9c): tests/core/fixtures/settings_apply_window_parity.json,
// frozen against today's PHP by tests/php/CoreSettingsApplyWindowParityTest.php. A case's applyWindow is what the adapter
// answers in ingest for a stored gen/pfb_quiet_hours, and php today's decision at each instant (minutes after midnight). Core
// reads the window back as it is, and schedule.InApplyWindow on it decides as today's PHP did on the stored value.
type applyWindowFixture struct {
	Schema      int     `json:"schema"`
	Projection  string  `json:"projection"`
	Field       string  `json:"field"`
	Description string  `json:"description"`
	Instants    []int64 `json:"instants"`
	Cases       []struct {
		ID          string          `json:"id"`
		Description string          `json:"description"`
		Stored      json.RawMessage `json:"stored"`
		ApplyWindow string          `json:"applyWindow"`
		PHP         []bool          `json:"php"`
	} `json:"cases"`
	Refused []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		ApplyWindow any    `json:"applyWindow"`
	} `json:"refused"`
}

func loadApplyWindowFixture(t *testing.T) applyWindowFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_apply_window_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc applyWindowFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "ingest" || doc.Field != "applyWindow" || len(doc.Instants) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, field %q, %d instants, %d cases, %d refused", doc.Schema, doc.Projection, doc.Field,
			len(doc.Instants), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

func TestCoreReadsTheAdaptersApplyWindowBackAndDecidesAsTodaysPHPAtEveryInstant(t *testing.T) {
	doc := loadApplyWindowFixture(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"ingest": {"applyWindow": c.ApplyWindow}}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			ingest, err := st.GetClear("ingest")
			if err != nil {
				t.Fatal(err)
			}
			window, _ := ingest["applyWindow"].(string)
			if window != c.ApplyWindow {
				t.Fatalf("%s\nread %q, want %q", c.Description, ingest["applyWindow"], c.ApplyWindow)
			}
			for i, minute := range doc.Instants {
				if got := schedule.InApplyWindow(minute*60, window, time.UTC); got != c.PHP[i] {
					t.Errorf("%s\nat minute %d InApplyWindow(%q) = %v, today's PHP on %s = %v", c.Description, minute, window, got, c.Stored, c.PHP[i])
				}
			}
		})
	}
}

func TestCoreRefusesAnApplyWindowOutsideItsOneSpellingNamingTheField(t *testing.T) {
	for _, c := range loadApplyWindowFixture(t).Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"ingest": {"applyWindow": c.ApplyWindow}}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.ApplyWindow))
			}
			if st != nil || !strings.Contains(err.Error(), "ingest.applyWindow:") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming ingest.applyWindow", c.Description, st, err)
			}
		})
	}
}
