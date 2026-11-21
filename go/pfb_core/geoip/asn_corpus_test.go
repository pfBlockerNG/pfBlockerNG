package geoip_test

// The ASN table corpus (#4034 slice 5c): JSON scenarios in tests/geoip/fixtures/asn that today's `pfblockerng.sh
// asn_table` passes (tests/php/GeoipAsnTableCorpusTest.php runs it under LC_ALL=C) and this package passes. A scenario
// (unknown keys are refused):
//
//	description  what the scenario pins.
//	csv          asn.csv: content (see corpusContent), null when there is none, or {"dir": true} for a folder of that
//	             name.
//	expect       table (pfblockerng_asn.txt afterwards; it holds "AS0 [ previous ]\n" before the run) and log (what the
//	             run appends to the Extras log, its time reading "{now}"). Run reports a publication exactly when it logs one.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/geoip"
)

type asnCSV struct {
	corpusContent
	Dir bool
}

func (c *asnCSV) UnmarshalJSON(b []byte) error {
	var d struct {
		Dir bool `json:"dir"`
	}
	if json.Unmarshal(b, &d) == nil && d.Dir {
		c.Dir = true
		return nil
	}
	return c.corpusContent.UnmarshalJSON(b)
}

type asnCase struct {
	Description string  `json:"description"`
	CSV         *asnCSV `json:"csv"`
	Expect      struct {
		Table corpusContent `json:"table"`
		Log   string        `json:"log"`
	} `json:"expect"`
}

func TestASNTableCorpus(t *testing.T) {
	files, _ := filepath.Glob("../../../tests/geoip/fixtures/asn/*.json")
	if len(files) == 0 {
		t.Fatal("no ASN corpus scenarios")
	}
	now := time.Date(2026, 11, 21, 9, 30, 5, 0, time.Local)
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var sc asnCase
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&sc); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			a := geoip.ASNTable{CSV: filepath.Join(root, "asn.csv"), Table: filepath.Join(root, "pfblockerng_asn.txt"), Now: now}
			if err := os.WriteFile(a.Table, []byte("AS0 [ previous ]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			switch {
			case sc.CSV == nil:
			case sc.CSV.Dir:
				os.Mkdir(a.CSV, 0o755)
			default:
				if err := os.WriteFile(a.CSV, sc.CSV.bytes(t), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var log strings.Builder
			a.Log = &log
			ok := a.Run(context.Background())

			if want := sc.Expect.Log != ""; ok != want {
				t.Errorf("Run = %v, want %v: a run publishes a table exactly when it logs the update", ok, want)
			}
			got, _ := os.ReadFile(a.Table)
			if want := sc.Expect.Table.bytes(t); !bytes.Equal(got, want) {
				t.Errorf("pfblockerng_asn.txt = %.200q, want %.200q", got, want)
			}
			if want := strings.ReplaceAll(sc.Expect.Log, "{now}", now.Format(time.DateTime)); log.String() != want {
				t.Errorf("Extras log = %q, want %q", log.String(), want)
			}
			if entries, _ := os.ReadDir(root); len(entries) != 2 && sc.CSV != nil || len(entries) != 1 && sc.CSV == nil {
				t.Errorf("the run left %d entries in the folder: a temporary file stayed", len(entries))
			}
		})
	}
}
