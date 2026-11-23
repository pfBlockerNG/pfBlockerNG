package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// continentCorpus is tests/geoip/fixtures/continents/continent_sets.json, frozen through today's continent block by
// tests/php/GeoipContinentSetCorpusTest.php.
type continentCorpus struct {
	Cases []struct {
		ID     string `json:"id"`
		Groups []struct {
			Name        string   `json:"name"`
			Action      string   `json:"action"`
			ListClass   string   `json:"listClass"`
			CountriesV4 []string `json:"countriesV4"`
			CountriesV6 []string `json:"countriesV6"`
		} `json:"groups"`
		CC           map[string]string `json:"cc"`
		Before       map[string]string `json:"before"`
		GeoIPChanged bool              `json:"geoipChanged"`
		Force        bool              `json:"force"`
		Enabled      *bool             `json:"enabled"`
		Expect       struct {
			Files   map[string]string `json:"files"`
			Changed []string          `json:"changed"`
			Log     []string          `json:"log"`
		} `json:"expect"`
	} `json:"cases"`
}

var listClasses = []string{"deny", "permit", "match", "native"}

// geoTree lays out a country folder, the baselines folder and the list folders under a temporary root.
func geoTree(t *testing.T) (root string, g GeoSets) {
	t.Helper()
	root = t.TempDir()
	g = GeoSets{CCDir: filepath.Join(root, "cc"), OrigDir: filepath.Join(root, "db", "original"), Folders: map[string]string{},
		Enabled: true}
	for _, c := range listClasses {
		g.Folders[c] = filepath.Join(root, "db", c)
	}
	for _, d := range append([]string{g.CCDir, g.OrigDir}, mapValues(g.Folders)...) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A country folder the conversion published holds its ISO list; without it Build builds nothing.
	if err := os.WriteFile(filepath.Join(g.CCDir, ".geoip_isos"), []byte("ZA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, g
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// geoFiles is every file of the baselines and list folders, by path relative to db.
func geoFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range append([]string{"original"}, listClasses...) {
		entries, err := os.ReadDir(filepath.Join(root, "db", c))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(root, "db", c, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[c+"/"+e.Name()] = string(b)
		}
	}
	return out
}

// projection is the case's continents as settings/feeds/geoip holds them.
func geoProjection(groups []map[string]any) map[string]any {
	list := make([]any, len(groups))
	for i, g := range groups {
		list[i] = g
	}
	return map[string]any{"groups": list}
}

func codes(cs []string) []any {
	out := []any{}
	for _, c := range cs {
		out = append(out, map[string]any{"code": c})
	}
	return out
}

// Feature: stage 11 builds each enabled continent's set from the country lists
//
//	Scenario Outline: a corpus case gives the files, the sets rebuilt and the lines logged that the corpus expects
func TestContinentSetCorpus(t *testing.T) {
	b, err := os.ReadFile("../../../tests/geoip/fixtures/continents/continent_sets.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus continentCorpus
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("the corpus holds no case")
	}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			root, g := geoTree(t)
			for name, content := range c.CC {
				if err := os.WriteFile(filepath.Join(g.CCDir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for path, content := range c.Before {
				if err := os.WriteFile(filepath.Join(root, "db", path), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var groups []map[string]any
			for _, gr := range c.Groups {
				groups = append(groups, map[string]any{"name": gr.Name, "action": gr.Action, "listClass": gr.ListClass,
					"countriesV4": codes(gr.CountriesV4), "countriesV6": codes(gr.CountriesV6)})
			}
			var log bytes.Buffer
			g.Log, g.Force, g.GeoIPChanged = &log, c.Force, c.GeoIPChanged
			if c.Enabled != nil {
				g.Enabled = *c.Enabled
			}

			sets, err := g.Build(context.Background(), geoProjection(groups))
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			changed := []string{}
			for _, s := range sets {
				if s.Changed {
					changed = append(changed, s.Alias)
				}
			}
			if !slices.Equal(changed, c.Expect.Changed) {
				t.Errorf("sets rebuilt = %q, want %q", changed, c.Expect.Changed)
			}
			want := c.Expect.Files
			if want == nil {
				want = map[string]string{}
			}
			if got := geoFiles(t, root); !mapsEqual(got, want) {
				t.Errorf("files =\n%q\nwant\n%q", got, want)
			}
			logged := []string{}
			for _, line := range strings.Split(log.String(), "\n") {
				if strings.HasPrefix(line, "Could not open ISO") {
					logged = append(logged, line)
				}
			}
			if !slices.Equal(logged, c.Expect.Log) {
				t.Errorf("logged %q, want %q", logged, c.Expect.Log)
			}
		})
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func africa(countries ...string) map[string]any {
	return geoProjection([]map[string]any{{"name": "pfB_Africa", "action": "Deny_Inbound", "listClass": "deny",
		"countriesV4": codes(countries), "countriesV6": codes(nil)}})
}

// A built set names its group as the resource id takes it, its family and its action, for the publisher (sub-slice 9h).
func TestABuiltSetNamesItsGroupFamilyAndAction(t *testing.T) {
	_, g := geoTree(t)
	if err := os.WriteFile(filepath.Join(g.CCDir, "ZA_v4.txt"), []byte("41.0.0.0/11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sets, err := g.Build(context.Background(), africa("ZA"))
	if err != nil {
		t.Fatal(err)
	}
	want := []GeoSet{{Alias: "pfB_Africa_v4", Group: "Africa", Family: "ipv4", Action: "Deny_Inbound", ListClass: "deny",
		Path: filepath.Join(g.Folders["deny"], "pfB_Africa_v4.txt"), Changed: true}}
	if !slices.Equal(sets, want) {
		t.Errorf("sets = %+v, want %+v", sets, want)
	}
}

// Hostile: a publication without disk room. The baseline and the list change together or not at all: a write that fails
// for want of space keeps the previous generation of both, leaves no temporary file and is reported.
func TestASetWithoutDiskRoomKeepsThePreviousBaselineAndList(t *testing.T) {
	for _, failing := range []string{".orig", ".txt"} {
		t.Run(failing, func(t *testing.T) {
			root, g := geoTree(t)
			if err := os.WriteFile(filepath.Join(g.CCDir, "ZA_v4.txt"), []byte("41.0.0.0/11\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{"original/pfB_Africa_v4.orig": "1.0.0.0/8\n", "deny/pfB_Africa_v4.txt": "1.0.0.0/8\n"}
			for p, content := range before {
				if err := os.WriteFile(filepath.Join(root, "db", p), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			saved := geoWrite
			t.Cleanup(func() { geoWrite = saved })
			geoWrite = func(f *os.File, b []byte) error {
				if strings.Contains(filepath.Base(f.Name()), failing) {
					return syscall.ENOSPC
				}
				return saved(f, b)
			}

			sets, err := g.Build(context.Background(), africa("ZA"))
			if err == nil {
				t.Error("a set that could not be written was not reported")
			}
			for _, s := range sets {
				if s.Changed {
					t.Errorf("%s is reported rebuilt", s.Alias)
				}
			}
			if got := geoFiles(t, root); !mapsEqual(got, before) {
				t.Errorf("files = %q, want the previous generation %q", got, before)
			}
		})
	}
}

// A killed run's staged files are removed by the next Build, which rolls the set forward from the country lists.
func TestAKilledRunsStagedFilesAreRemovedAndTheSetRollsForward(t *testing.T) {
	root, g := geoTree(t)
	if err := os.WriteFile(filepath.Join(g.CCDir, "ZA_v4.txt"), []byte("41.0.0.0/11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A run killed between the list's rename and the baseline's: the new list, the old baseline, a staged baseline.
	for p, content := range map[string]string{
		"original/pfB_Africa_v4.orig":            "1.0.0.0/8\n",
		"original/.pfB_Africa_v4.orig.123456789": "41.0.0.0/11\n",
		"deny/pfB_Africa_v4.txt":                 "41.0.0.0/11\n",
		"deny/.pfB_Africa_v4.txt.987654321":      "partial",
	} {
		if err := os.WriteFile(filepath.Join(root, "db", p), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Build(context.Background(), africa("ZA")); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"original/pfB_Africa_v4.orig": "41.0.0.0/11\n", "deny/pfB_Africa_v4.txt": "41.0.0.0/11\n"}
	if got := geoFiles(t, root); !mapsEqual(got, want) {
		t.Errorf("files = %q, want %q", got, want)
	}
}

// Feature: the geo-catalog body carries the country folder's catalog and the ASN choices
//
//	Scenario: the body is the .geo_catalog rows and an asn row per line of the ASN table, in byte order, and the store
//	  takes it as a canonical body
func TestTheGeoCatalogCarriesTheCountryCatalogAndTheASNChoices(t *testing.T) {
	dir := t.TempDir()
	cc, table := filepath.Join(dir, "cc"), filepath.Join(dir, "pfblockerng_asn.txt")
	if err := os.Mkdir(cc, 0o755); err != nil {
		t.Fatal(err)
	}
	page := `{"kind":"page","page":"Africa","continent":"Afrika"}`
	country := `{"kind":"country","page":"Africa","family":4,"position":1,"iso":"ZA","country":"Südafrika","networks":2}`
	if err := os.WriteFile(filepath.Join(cc, ".geo_catalog"), []byte(country+"\n"+page+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	asn := strings.Join([]string{
		"AS1 [ Level 3 Parent ]",
		"AS13335 [ Cloudflare ]",
		"AS4294967295 [ the last ]",
		"AS2 [  ]",             // an empty name is a choice as today's table offers it
		"AS3 [ Ctl\x7fName ]",  // DEL is a control character no member holds: escaped
		"AS4 [ Bad\xffByte ]",  // not UTF-8: the byte becomes U+FFFD
		"AS007 [ zeros ]",      // the number would not read back as written: left out
		"AS4294967296 [ big ]", // over 32 bits: left out
		"ASx [ not a number ]", // left out
		"junk",                 // left out
		"",
	}, "\n")
	if err := os.WriteFile(table, []byte(asn), 0o644); err != nil {
		t.Fatal(err)
	}

	members, err := GeoCatalog(cc, table)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"kind":"asn","asn":1,"name":"Level 3 Parent"}`,
		`{"kind":"asn","asn":13335,"name":"Cloudflare"}`,
		`{"kind":"asn","asn":2,"name":""}`,
		`{"kind":"asn","asn":3,"name":"Ctl\u007fName"}`,
		`{"kind":"asn","asn":4,"name":"Bad` + "�" + `Byte"}`,
		`{"kind":"asn","asn":4294967295,"name":"the last"}`,
		country,
		page,
	}
	if !slices.Equal(members, want) {
		t.Errorf("members =\n%s\nwant\n%s", strings.Join(members, "\n"), strings.Join(want, "\n"))
	}
	store := resources.Open(filepath.Join(dir, "store"))
	if _, err := store.Publish("geo-catalog", slices.Clone(members), nil); err != nil {
		t.Errorf("the store refuses the body: %v", err)
	}
}

// Without an ASN table the catalog is the country rows alone; without the country folder's catalog there is none.
func TestTheGeoCatalogWithoutAnASNTableOrWithoutTheCountryCatalog(t *testing.T) {
	dir := t.TempDir()
	cc := filepath.Join(dir, "cc")
	if err := os.Mkdir(cc, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := GeoCatalog(cc, filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("a catalog was made without the country folder's .geo_catalog")
	}
	page := `{"kind":"page","page":"Africa","continent":"Africa"}`
	if err := os.WriteFile(filepath.Join(cc, ".geo_catalog"), []byte(page+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	members, err := GeoCatalog(cc, filepath.Join(dir, "absent.txt"))
	if err != nil || !slices.Equal(members, []string{page}) {
		t.Errorf("GeoCatalog = %q, %v; want the country rows alone", members, err)
	}
}

func writeAll(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Scenario Outline: without country data (no ISO list in the country folder, or no country folder) no set is built,
// as today's pass stops before the continent block when MaxMind processing failed (apply.inc:3445-3460): every set
// keeps its baseline and list, and the caller is told.
func TestWithoutCountryDataNoSetIsBuilt(t *testing.T) {
	for name, remove := range map[string]string{"no ISO list": ".geoip_isos", "no country folder": ""} {
		t.Run(name, func(t *testing.T) {
			root, g := geoTree(t)
			before := map[string]string{"cc/ZA_v4.txt": "41.0.0.0/11\n", "db/original/pfB_Africa_v4.orig": "1.0.0.0/8\n",
				"db/deny/pfB_Africa_v4.txt": "1.0.0.0/8\n"}
			writeAll(t, root, before)
			if err := os.RemoveAll(filepath.Join(g.CCDir, remove)); err != nil {
				t.Fatal(err)
			}
			sets, err := g.Build(context.Background(), africa("ZA"))
			if !errors.Is(err, ErrNoCountryData) || len(sets) != 0 {
				t.Errorf("Build = %+v, %v; want no set and ErrNoCountryData", sets, err)
			}
			want := map[string]string{"original/pfB_Africa_v4.orig": "1.0.0.0/8\n", "deny/pfB_Africa_v4.txt": "1.0.0.0/8\n"}
			if got := geoFiles(t, root); !mapsEqual(got, want) {
				t.Errorf("files = %q, want %q", got, want)
			}
		})
	}
}

// Scenario: the list is renamed before its baseline. When the second rename fails, the new list is published, the old
// baseline stays, the set is not reported rebuilt and the error is; the next Build finds the baseline behind and
// republishes both.
func TestTheListIsRenamedBeforeItsBaseline(t *testing.T) {
	root, g := geoTree(t)
	writeAll(t, root, map[string]string{"cc/ZA_v4.txt": "41.0.0.0/11\n", "db/original/pfB_Africa_v4.orig": "1.0.0.0/8\n",
		"db/deny/pfB_Africa_v4.txt": "1.0.0.0/8\n"})
	saved := geoRename
	t.Cleanup(func() { geoRename = saved })
	renames := 0
	geoRename = func(from, to string) error {
		if renames++; renames == 2 {
			return syscall.EIO
		}
		return saved(from, to)
	}
	sets, err := g.Build(context.Background(), africa("ZA"))
	if err == nil || len(sets) != 1 || sets[0].Changed {
		t.Errorf("Build = %+v, %v; want the set not rebuilt and an error", sets, err)
	}
	want := map[string]string{"original/pfB_Africa_v4.orig": "1.0.0.0/8\n", "deny/pfB_Africa_v4.txt": "41.0.0.0/11\n"}
	if got := geoFiles(t, root); !mapsEqual(got, want) {
		t.Errorf("after the failed rename, files = %q, want the new list and the old baseline %q", got, want)
	}

	geoRename = saved
	sets, err = g.Build(context.Background(), africa("ZA"))
	if err != nil || len(sets) != 1 || !sets[0].Changed {
		t.Errorf("the next Build = %+v, %v; want the set rebuilt", sets, err)
	}
	want["original/pfB_Africa_v4.orig"] = "41.0.0.0/11\n"
	if got := geoFiles(t, root); !mapsEqual(got, want) {
		t.Errorf("after the next Build, files = %q, want %q", got, want)
	}
}

// Scenario: an interrupted publication whose country data then returns to the old baseline heals: the list is compared
// with the set too.
func TestAListLeftByAnInterruptedPublicationHeals(t *testing.T) {
	root, g := geoTree(t)
	// Killed after the list's rename: the new list (102/8), the old baseline (41/11); the country data is 41/11 again.
	writeAll(t, root, map[string]string{"cc/ZA_v4.txt": "41.0.0.0/11\n", "db/original/pfB_Africa_v4.orig": "41.0.0.0/11\n",
		"db/deny/pfB_Africa_v4.txt": "102.0.0.0/8\n"})
	sets, err := g.Build(context.Background(), africa("ZA"))
	if err != nil || len(sets) != 1 || !sets[0].Changed {
		t.Errorf("Build = %+v, %v; want the set rebuilt", sets, err)
	}
	want := map[string]string{"original/pfB_Africa_v4.orig": "41.0.0.0/11\n", "deny/pfB_Africa_v4.txt": "41.0.0.0/11\n"}
	if got := geoFiles(t, root); !mapsEqual(got, want) {
		t.Errorf("files = %q, want %q", got, want)
	}
}

// Scenario: a cancelled Update builds no further set and reports the cancellation.
func TestACancelledBuildPublishesNothing(t *testing.T) {
	root, g := geoTree(t)
	writeAll(t, root, map[string]string{"cc/ZA_v4.txt": "41.0.0.0/11\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sets, err := g.Build(ctx, africa("ZA"))
	if !errors.Is(err, context.Canceled) || len(sets) != 0 {
		t.Errorf("Build = %+v, %v; want no set and context.Canceled", sets, err)
	}
	if got := geoFiles(t, root); len(got) != 0 {
		t.Errorf("files = %q, want none", got)
	}
}

// Scenario Outline: a country code outside the projection's pattern ((A[12]_)?[A-Z][A-Z0-9](_rep)?) names no file: it is
// never joined into a path, so ../../x reads nothing outside the country folder.
func TestACountryCodeOutsideThePatternIsRefused(t *testing.T) {
	for _, code := range []string{"../../x", "../x", "x", "ZAA", "Z", "za", "ZA/../ZA", "A3_ZA", "ZA_rep_rep"} {
		t.Run(code, func(t *testing.T) {
			root, g := geoTree(t)
			g.CCDir = filepath.Join(root, "a", "b", "cc")
			writeAll(t, root, map[string]string{"a/b/cc/.geoip_isos": "ZA\n", "a/b/cc/ZA_v4.txt": "41.0.0.0/11\n",
				"a/x_v4.txt": "6.6.6.0/24\n", "a/b/x_v4.txt": "6.6.6.0/24\n", "a/b/cc/" + strings.ReplaceAll(code, "/", "_") + "_v4.txt": "6.6.6.0/24\n"})
			if _, err := g.Build(context.Background(), africa(code, "ZA")); err != nil {
				t.Fatal(err)
			}
			if got := geoFiles(t, root)["deny/pfB_Africa_v4.txt"]; got != "41.0.0.0/11\n" {
				t.Errorf("the list = %q, want ZA's networks alone", got)
			}
		})
	}
	// The codes the pattern takes are read.
	root, g := geoTree(t)
	writeAll(t, root, map[string]string{"cc/A1_v4.txt": "1.0.0.0/24\n", "cc/A2_US_rep_v4.txt": "2.0.0.0/24\n", "cc/US_rep_v4.txt": "3.0.0.0/24\n"})
	if _, err := g.Build(context.Background(), africa("A1", "A2_US_rep", "US_rep")); err != nil {
		t.Fatal(err)
	}
	if got := geoFiles(t, root)["deny/pfB_Africa_v4.txt"]; got != "1.0.0.0/24\n2.0.0.0/24\n3.0.0.0/24\n" {
		t.Errorf("the list = %q", got)
	}
}

// Scenario: the catalog's reads are bounded. An ASN row longer than a resource member is left out; a body over the
// Outpost's bound (PFB_GEOIP_CATALOG_MAX, 16 MiB) is refused, whether the country rows or the ASN rows make it so.
func TestTheGeoCatalogIsBounded(t *testing.T) {
	dir := t.TempDir()
	cc, table := filepath.Join(dir, "cc"), filepath.Join(dir, "asn.txt")
	page := `{"kind":"page","page":"Africa","continent":"Africa"}`
	writeAll(t, dir, map[string]string{"cc/.geo_catalog": page + "\n",
		"asn.txt": "AS1 [ " + strings.Repeat("n", resources.MaxMemberLength) + " ]\nAS2 [ ok ]\n"})
	members, err := GeoCatalog(cc, table)
	if err != nil || !slices.Equal(members, []string{`{"kind":"asn","asn":2,"name":"ok"}`, page}) {
		t.Errorf("GeoCatalog = %d members, %v; want the long row left out", len(members), err)
	}

	if geoCatalogMax != 16<<20 {
		t.Errorf("the bound is %d, want PFB_GEOIP_CATALOG_MAX (16 MiB)", geoCatalogMax)
	}
	saved := geoCatalogMax
	t.Cleanup(func() { geoCatalogMax = saved })
	geoCatalogMax = len(page) + 1 + len(`{"kind":"asn","asn":2,"name":"ok"}`) + 1 // exactly the body above
	if _, err := GeoCatalog(cc, table); err != nil {
		t.Errorf("a body at the bound is refused: %v", err)
	}
	geoCatalogMax--
	if _, err := GeoCatalog(cc, table); err == nil {
		t.Error("a body the ASN rows take over the bound is not refused")
	}
	geoCatalogMax = len(page) // the country rows alone are over it
	if _, err := GeoCatalog(cc, filepath.Join(dir, "absent")); err == nil {
		t.Error("a .geo_catalog over the bound is not refused")
	}
}
