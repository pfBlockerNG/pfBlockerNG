package update

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// verbCall is one Extras verb the stage ran, as a stand-in for Fetcher.RunExtras saw it.
type verbCall struct {
	name string
	args []string
}

// extrasBox is a box whose every Extra has its data: MaxMind's share files and country folder, TOP1M's list and
// baseline, and each selected Blacklist provider's category folder.
func extrasBox(t *testing.T) Extras {
	t.Helper()
	root := t.TempDir()
	x := Extras{GeoIPShare: filepath.Join(root, "share"), DBDir: filepath.Join(root, "db"), CCDir: filepath.Join(root, "share", "cc"),
		Enabled: true, Settings: feedfetch.ExtrasSettings{MaxMindAccount: "1", MaxMindKey: "k", Top1M: true,
			Providers: []feedfetch.BlacklistProvider{{ID: "ut1", Selected: true}, {ID: "shalla"}, {ID: "olbat", Selected: true}}}}
	for _, p := range []string{
		"share/GeoLite2-Country.mmdb", "share/GeoLite2-Country-Blocks-IPv4.csv", "share/cc/.geoip_isos",
		"share/cc/Top_Spammers_v4.info", "db/top-1m.csv", "db/top-1m.csv.zip.orig", "db/ut1/ut1_ads", "db/olbat/olbat_ads",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

// stand records each verb and answers with the exit code given for it (0 when none), calling the verb's conversion as
// RunExtras does for a dcc that downloaded no failed geoip row.
func stand(x *Extras, exits map[string]int) *[]verbCall {
	var calls []verbCall
	x.RunVerb = func(ctx context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
		calls = append(calls, verbCall{v.Name, v.Args})
		if v.Name == "dcc" && v.Convert != nil {
			v.Convert(ctx)
		}
		code := exits[v.Name]
		return code, feedfetch.ExtrasResult{OK: code == 0 || code == 2}
	}
	return &calls
}

func touchFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Feature: stage 5 runs the Extras due, extra:dcc then extra:bl
//
//	Scenario: both due in either order run dcc first, as scheduled runs, bl with the selected providers in settings order
func TestExtrasRunDCCThenBL(t *testing.T) {
	x := extrasBox(t)
	calls := stand(&x, nil)
	out := x.Stage(context.Background(), []string{"extra:bl", "extra:dcc"})
	want := []verbCall{{"dcc", []string{"scheduled"}}, {"bl", []string{"scheduled", "ut1,olbat"}}}
	if !slices.EqualFunc(*calls, want, func(a, b verbCall) bool { return a.name == b.name && slices.Equal(a.args, b.args) }) {
		t.Errorf("verbs = %v, want %v", *calls, want)
	}
	if !slices.Equal(out.Succeeded, []string{"extra:dcc", "extra:bl"}) || len(out.Attempted) != 0 {
		t.Errorf("outcome = %+v, want both succeeded", out)
	}
}

// Scenario: an Extra not due whose data is all there does not run.
func TestAnExtraNotDueWithItsDataDoesNotRun(t *testing.T) {
	x := extrasBox(t)
	calls := stand(&x, nil)
	out := x.Stage(context.Background(), nil)
	if len(*calls) != 0 || len(out.Succeeded)+len(out.Attempted) != 0 {
		t.Errorf("verbs %v, outcome %+v; want nothing run", *calls, out)
	}
}

// Scenario Outline: an Extra whose data is missing is due, though the schedule did not name it (today's on-demand
// fetches: MaxMind at apply.inc:3434-3439, TOP1M at pfb_top1m_refresh_needed(), a Blacklist category never downloaded).
func TestAnExtraWhoseDataIsMissingIsDue(t *testing.T) {
	for _, tc := range []struct {
		missing string
		verb    string
	}{
		{"share/GeoLite2-Country.mmdb", "dcc"},
		{"share/GeoLite2-Country-Blocks-IPv4.csv", "dcc"},
		{"share/cc/.geoip_isos", "dcc"},
		{"share/cc/Top_Spammers_v4.info", "dcc"},
		{"db/top-1m.csv", "dcc"},
		{"db/top-1m.csv.zip.orig", "dcc"},
		{"db/olbat/olbat_ads", "bl"}, // the category folder is empty
	} {
		t.Run(tc.missing, func(t *testing.T) {
			x := extrasBox(t)
			root := filepath.Dir(x.DBDir)
			if err := os.Remove(filepath.Join(root, tc.missing)); err != nil {
				t.Fatal(err)
			}
			calls := stand(&x, nil)
			out := x.Stage(context.Background(), nil)
			if len(*calls) != 1 || (*calls)[0].name != tc.verb {
				t.Errorf("verbs = %v, want %s alone", *calls, tc.verb)
			}
			if !slices.Equal(out.Succeeded, []string{"extra:" + tc.verb}) {
				t.Errorf("succeeded = %q", out.Succeeded)
			}
		})
	}
}

// Scenario: data an Extra is not configured for is not missing: no MaxMind credentials, TOP1M off, no provider selected.
func TestDataOfAnExtraNotConfiguredIsNotMissing(t *testing.T) {
	x := extrasBox(t)
	x.Settings.MaxMindKey, x.Settings.Top1M = "", false
	for i := range x.Settings.Providers {
		x.Settings.Providers[i].Selected = false
	}
	if err := os.RemoveAll(x.GeoIPShare); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(x.DBDir); err != nil {
		t.Fatal(err)
	}
	calls := stand(&x, nil)
	x.Stage(context.Background(), nil)
	if len(*calls) != 0 {
		t.Errorf("verbs = %v, want none", *calls)
	}
}

// Scenario: a failed Extra is attempted, keeps the previous data and does not stop the stage.
func TestAFailedExtraIsAttemptedAndTheNextRuns(t *testing.T) {
	x := extrasBox(t)
	calls := stand(&x, map[string]int{"dcc": 1})
	out := x.Stage(context.Background(), []string{"extra:dcc", "extra:bl"})
	if len(*calls) != 2 {
		t.Errorf("verbs = %v, want dcc and bl", *calls)
	}
	if !slices.Equal(out.Attempted, []string{"extra:dcc"}) || !slices.Equal(out.Succeeded, []string{"extra:bl"}) {
		t.Errorf("outcome = %+v", out)
	}
}

// Scenario Outline: extra:bl with pfBlockerNG off or no provider selected runs nothing and is attempted, as today
// (pfb_core_update_scheduled()), so the scheduler does not ask again every quarter hour.
func TestBlacklistWithNothingToRunIsAttempted(t *testing.T) {
	for name, edit := range map[string]func(*Extras){
		"pfBlockerNG off": func(x *Extras) { x.Enabled = false },
		"no provider selected": func(x *Extras) {
			for i := range x.Settings.Providers {
				x.Settings.Providers[i].Selected = false
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := extrasBox(t)
			edit(&x)
			calls := stand(&x, nil)
			out := x.Stage(context.Background(), []string{"extra:bl"})
			if len(*calls) != 0 || !slices.Equal(out.Attempted, []string{"extra:bl"}) {
				t.Errorf("verbs %v, outcome %+v", *calls, out)
			}
		})
	}
}

// Scenario: a dcc exit of 2 or 3 is a change of Extras data (today's $dcc_changed), a failure (3) attempted.
func TestADCCChangeIsReported(t *testing.T) {
	for code, attempted := range map[int]bool{2: false, 3: true} {
		x := extrasBox(t)
		stand(&x, map[string]int{"dcc": code})
		out := x.Stage(context.Background(), []string{"extra:dcc"})
		if !out.Changed || (len(out.Attempted) == 1) != attempted {
			t.Errorf("exit %d: outcome %+v", code, out)
		}
	}
}

// Feature: the conversions run when their source changed
//
//	Scenario Outline: the country conversion runs after a new MaxMind download (geoip.update) or when the country
//	  folder lacks its data; it reports GeoIPChanged only when it published, and the marker goes only then
func TestTheCountryConversionRunsWhenItsSourceChanged(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		marker, ccMissing       bool
		convertOK               bool
		wantConvert, wantChange bool
		wantMarker              bool
	}{
		{name: "unchanged source", convertOK: true},
		{name: "a new download", marker: true, convertOK: true, wantConvert: true, wantChange: true},
		{name: "a new download that fails to convert", marker: true, wantConvert: true, wantMarker: true},
		{name: "the country folder lacks its data", ccMissing: true, convertOK: true, wantConvert: true, wantChange: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := extrasBox(t)
			marker := filepath.Join(x.DBDir, "geoip.update")
			if tc.marker {
				touchFile(t, marker)
			}
			if tc.ccMissing {
				if err := os.RemoveAll(x.CCDir); err != nil {
					t.Fatal(err)
				}
			}
			converted := false
			x.Convert = func(context.Context) bool { converted = true; return tc.convertOK }
			stand(&x, nil)
			out := x.Stage(context.Background(), []string{"extra:dcc"})
			if converted != tc.wantConvert {
				t.Errorf("converted = %v, want %v", converted, tc.wantConvert)
			}
			if out.GeoIPChanged != tc.wantChange {
				t.Errorf("GeoIPChanged = %v, want %v", out.GeoIPChanged, tc.wantChange)
			}
			if _, err := os.Stat(marker); (err == nil) != tc.wantMarker {
				t.Errorf("geoip.update present = %v, want %v", err == nil, tc.wantMarker)
			}
		})
	}
}

// Scenario: the ASN conversion is handed to the download, which runs it after a new asn.csv only.
func TestTheASNConversionIsHandedToTheDownload(t *testing.T) {
	x := extrasBox(t)
	ran := false
	x.ASNTable = func(context.Context) { ran = true }
	x.RunVerb = func(ctx context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
		if v.ASNTable == nil {
			t.Error("the verb carries no ASN conversion")
		} else {
			v.ASNTable(ctx)
		}
		return 0, feedfetch.ExtrasResult{OK: true}
	}
	x.Stage(context.Background(), []string{"extra:dcc"})
	if !ran {
		t.Error("the ASN conversion did not reach the download")
	}
}

// Scenario: the stage hands the verb the box's folders and settings and its log.
func TestTheVerbCarriesTheBoxsFoldersAndSettings(t *testing.T) {
	x := extrasBox(t)
	var log strings.Builder
	x.Log = &log
	var got feedfetch.ExtrasVerb
	x.RunVerb = func(_ context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
		got = v
		return 0, feedfetch.ExtrasResult{OK: true}
	}
	x.Stage(context.Background(), []string{"extra:dcc"})
	if got.GeoIPShare != x.GeoIPShare || got.DBDir != x.DBDir || got.Settings.MaxMindKey != "k" || got.Log != &log {
		t.Errorf("verb = %+v", got)
	}
}
