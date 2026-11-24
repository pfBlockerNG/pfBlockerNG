// The Core input (issue #4036, sub-slice 7d) against both decider corpora: the dnsbl/* resources the Core assembler
// publishes from each corpus module (tests/dns_proxy/fixtures/core_input, kept equal to the assembler by
// go/pfb_core/dnsbl/corpus_test.go) are served by a fake Core API, coreinput.Sync writes them into a module directory,
// and the decider builds from that directory.
//
// The parity corpus boots on it and answers every case as the fixture expects: the Core input changes no decision. The
// build oracle compares the build with the file input's build over the same data, each feed's raw file holding the rows
// Core publishes for it (a sorted, de-duplicated set: the owner's decision of 2026-11-23, whose departures 7a recorded)
// and TOP1M likewise; the PSL rules are compared as sets, since Core publishes them sorted.
package decider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
)

// coreGoldens is a golden file's scenarios as the resources a fake Core serves: each body as its lines, the generation of
// each body the one its manifest row names, the manifest's own "1".
func coreGoldens(t *testing.T, name string) map[string]map[string]coretest.Resource {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "dns_proxy", "fixtures", "core_input", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Scenarios map[string]struct {
			Resources map[string]struct{ Body []string }
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]coretest.Resource{}
	for scenario, s := range doc.Scenarios {
		res := map[string]coretest.Resource{}
		for id, r := range s.Resources {
			res[id] = coretest.Resource{Generation: "1", Body: coretest.Lines(r.Body)}
		}
		for _, line := range s.Resources["dnsbl/manifest"].Body {
			var row struct{ Resource, Generation string }
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if r, ok := res[row.Resource]; ok {
				r.Generation = row.Generation
				res[row.Resource] = r
			}
		}
		out[scenario] = res
	}
	return out
}

// syncFromCore serves resources on a fake Core API and has coreinput.Sync write them into dir.
func syncFromCore(t *testing.T, dir string, resources map[string]coretest.Resource) {
	t.Helper()
	srv := coretest.Start(t, resources)
	if _, changed, err := coreinput.Sync(context.Background(), coreinput.New(srv.Socket), dir, coreinput.State{}); err != nil || !changed {
		t.Fatalf("Sync: changed %v, %v", changed, err)
	}
}

func TestParityCorpusFromCore(t *testing.T) {
	goldens := coreGoldens(t, "parity.json")
	fixtures := paritycorpus.Fixtures()
	_, source, err := paritycorpus.LoadFamilies(filepath.Join(fixtures, "families.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(fixtures, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	ran := 0
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		if name == "families" {
			continue
		}
		resources, ok := goldens[name]
		if !ok {
			t.Errorf("%s: no Core input in the goldens", name)
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			boot := func(t *testing.T, s *paritycorpus.Scenario) (*pfbUnbound, *Frontend) {
				t.Helper()
				dir := t.TempDir()
				if err := paritycorpus.WriteModule(dir, s.Module); err != nil {
					t.Fatal(err)
				}
				// Only the ini and what Core does not publish stay: the DNSBL data comes from Core.
				var manifest struct{ Feeds []struct{ Raw string } }
				if err := json.Unmarshal(s.Module.Manifest, &manifest); err != nil {
					t.Fatal(err)
				}
				gone := []string{"pfb_py_sources.json", "pfb_py_top1m.txt", "pfb_py_ss.txt", "dnsbl_psl"}
				for _, f := range manifest.Feeds {
					gone = append(gone, f.Raw)
				}
				for _, rel := range gone {
					if err := os.Remove(filepath.Join(dir, rel)); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				syncFromCore(t, dir, resources)
				module, err := boot(dir, testLogDir)
				if err != nil {
					t.Fatalf("boot: %v", err)
				}
				stopModule(t, module)
				return module, newFrontend(module)
			}
			runScenarioWith(t, file, source, boot, func(t *testing.T, line string) { t.Error(line) })
		})
	}
	if ran < 60 {
		t.Fatalf("ran %d scenarios from Core, want the full corpus", ran)
	}
}

func TestDnsblBuildFromCoreMatchesTheFileInput(t *testing.T) {
	goldens := coreGoldens(t, "build_oracle.json")
	rows := bldOracle(t).Build
	compared := 0
	for i := range rows {
		row := &rows[i]
		if row.Want == nil {
			continue // the file input builds nothing; Core never publishes what such a manifest describes
		}
		if row.SidecarMode != nil {
			continue // a TOP1M sidecar that is a link, a folder or absent is a state of the file input alone
		}
		resources, ok := goldens[row.Name]
		if !ok {
			t.Errorf("%s: no Core input in the goldens", row.Name)
			continue
		}
		compared++
		t.Run(row.Name, func(t *testing.T) {
			dir, manifestPath := bldStage(t, row)
			sameData(t, dir, manifestPath, resources)
			want := bldModule(dir, row.Pfb).dnsblBuildFromManifest(manifestPath)
			if want == nil {
				t.Fatalf("the file input builds nothing over Core's data; ledger %q", bldLedger(t, dir))
			}

			coreDir := t.TempDir()
			syncFromCore(t, coreDir, resources)
			m := bldModule(coreDir, row.Pfb)
			if m.pfb.pfbPyPsl != "" {
				m.pfb.pfbPyPsl = filepath.Join(coreDir, "dnsbl_psl")
			}
			got := m.dnsblBuildFromManifest(filepath.Join(coreDir, "pfb_py_sources.json"))
			if got == nil {
				t.Fatalf("the Core input builds nothing; ledger %q", bldLedger(t, coreDir))
			}
			for _, field := range buildDiffs(got, want) {
				t.Errorf("%s differs from the file input's", field)
			}
		})
	}
	if compared < 380 {
		t.Fatalf("compared %d rows, want the full matrix", compared)
	}
}

// sameData rewrites the file input staged in dir so that it holds the data Core publishes: each feed's raw file the
// feed's body, and TOP1M, inline or in its sidecar, the dnsbl/top1m body.
func sameData(t *testing.T, dir, manifestPath string, resources map[string]coretest.Resource) {
	t.Helper()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	feeds, _ := manifest["feeds"].([]any)
	for _, item := range feeds {
		row := item.(map[string]any)
		raw, _ := row["raw"].(string)
		feed, _ := row["feed"].(string)
		body, ok := resources["dnsbl/feed-"+feed]
		if !ok {
			t.Fatalf("no Core body for feed %q", feed)
		}
		path := raw
		if !filepath.IsAbs(raw) {
			path = filepath.Join(dir, raw)
		}
		if err := os.WriteFile(path, body.Body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	top1m, ok := resources["dnsbl/top1m"]
	if !ok {
		return
	}
	config, _ := manifest["config"].(map[string]any)
	if _, inline := config["top1m_list"]; inline {
		lines := strings.Split(strings.TrimSuffix(string(top1m.Body), "\n"), "\n")
		if len(top1m.Body) == 0 {
			lines = []string{}
		}
		config["top1m_list"] = lines
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_top1m.txt"), top1m.Body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildDiffs names every field of got that differs from want; the PSL rule lists are compared as sets.
func buildDiffs(got, want *buildResult) []string {
	g, w := *got, *want
	var diffs []string
	for _, pair := range [][3]any{
		{"psl_rules.icann_exact", g.pslRules.icannExact, w.pslRules.icannExact},
		{"psl_rules.icann_wildcard", g.pslRules.icannWildcard, w.pslRules.icannWildcard},
		{"psl_rules.icann_exception", g.pslRules.icannException, w.pslRules.icannException},
		{"psl_rules.private_exact", g.pslRules.privateExact, w.pslRules.privateExact},
		{"psl_rules.private_wildcard", g.pslRules.privateWildcard, w.pslRules.privateWildcard},
		{"psl_rules.private_exception", g.pslRules.privateException, w.pslRules.privateException},
	} {
		a, b := slices.Sorted(slices.Values(pair[1].([]string))), slices.Sorted(slices.Values(pair[2].([]string)))
		if !slices.Equal(a, b) {
			diffs = append(diffs, pair[0].(string))
		}
	}
	g.pslRules, w.pslRules = pslRules{}, pslRules{}
	for _, pair := range [][3]any{
		{"data_db", g.dataDB, w.dataDB}, {"zone_db", g.zoneDB, w.zoneDB},
		{"feed_group_index_db", g.feedGroupIndexDB, w.feedGroupIndexDB}, {"white_db", g.whiteDB, w.whiteDB},
		{"counts", g.counts, w.counts}, {"user_regex_db", g.userRegexDB, w.userRegexDB},
		{"user_allow_regex_db", g.userAllowRegexDB, w.userAllowRegexDB}, {"regex_db", g.regexDB, w.regexDB},
		{"allow_regex_db", g.allowRegexDB, w.allowRegexDB}, {"important_rules", g.importantRules, w.importantRules},
		{"regex_count", g.regexCount, w.regexCount}, {"rejects", g.rejects, w.rejects},
		{"builtin_log_flag", g.builtinLogFlag, w.builtinLogFlag},
	} {
		if !reflect.DeepEqual(pair[1], pair[2]) {
			diffs = append(diffs, pair[0].(string))
		}
	}
	if !reflect.DeepEqual(g, w) && len(diffs) == 0 {
		diffs = append(diffs, "a field buildDiffs does not name")
	}
	return diffs
}
