package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The PHP comparisons the port reproduces, against the table today's PHP answers (tests/php/GeoipConversionCorpusTest.php
// holds the table to PHP).
func TestPHPSemanticsMatchTheTable(t *testing.T) {
	raw, err := os.ReadFile("testdata/php_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		NatCmp [][3]any `json:"natcmp"`
		Equal  [][3]any `json:"equal"`
		IsOne  [][2]any `json:"is_one"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.NatCmp) == 0 || len(table.Equal) == 0 || len(table.IsOne) == 0 {
		t.Fatal("empty table")
	}
	for _, r := range table.NatCmp {
		a, b, want := r[0].(string), r[1].(string), int(r[2].(float64))
		if got := natCompare(a, b); got != want {
			t.Errorf("natCompare(%q, %q) = %d, PHP %d", a, b, got, want)
		}
	}
	for _, r := range table.Equal {
		a, b, want := r[0].(string), r[1].(string), r[2].(bool)
		if got := equal(a, b); got != want {
			t.Errorf("equal(%q, %q) = %v, PHP %v", a, b, got, want)
		}
	}
	for _, r := range table.IsOne {
		s, want := r[0].(string), r[1].(bool)
		if got := isOne(s); got != want {
			t.Errorf("isOne(%q) = %v, PHP %v", s, got, want)
		}
	}
}

const (
	testLocations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
		"6252001,en,NA,\"North America\",US,\"United States\",0\n1814991,en,AS,Asia,CN,China,0\n"
	testBlocks = "network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast\n" +
		"3.0.0.0/15,6252001,6252001,,0,0,\n"
)

// previousGeneration is the generation conversionRoot publishes before the run, as a conversion names it.
const previousGeneration = ".cc.1.00000000"

// conversionRoot is a share with the given IPv4 Blocks file and a previous generation the country folder links to.
func conversionRoot(t *testing.T, blocksV4 string) (Conversion, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	share := filepath.Join(root, "share")
	for name, content := range map[string]string{
		"share/GeoLite2-Country-Locations-en.csv": testLocations,
		"share/GeoLite2-Country-Blocks-IPv4.csv":  blocksV4,
		"share/GeoLite2-Country-Blocks-IPv6.csv":  testBlocks,
		previousGeneration + "/US_v4.txt":         "192.0.2.0/24\n",
		previousGeneration + "/.geoip_isos":       "previous\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(previousGeneration, filepath.Join(root, "cc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "log"), 0o700); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	return Conversion{Share: share, CCDir: filepath.Join(root, "cc"), LogDir: filepath.Join(root, "log"), Locale: "en",
		Now: time.Date(2026, 11, 20, 9, 15, 0, 0, time.FixedZone("x", 3600)), Log: &log}, &log
}

// assertPrevious checks the country folder still links to the previous generation, unchanged, and nothing staged is
// left beside it.
func assertPrevious(t *testing.T, c Conversion) {
	t.Helper()
	if to, err := os.Readlink(c.CCDir); err != nil || to != previousGeneration {
		t.Errorf("cc links to %q, %v; want %s", to, err, previousGeneration)
	}
	if b, err := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); err != nil || string(b) != "192.0.2.0/24\n" {
		t.Errorf("US_v4.txt = %q, %v; want the previous list", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(c.CCDir, ".geoip_isos")); err != nil || string(b) != "previous\n" {
		t.Errorf(".geoip_isos = %q, %v; want the previous list", b, err)
	}
	assertBeside(t, c, previousGeneration)
}

// assertBeside checks the country folder's parent holds the share, the log, the link and the named generations, and
// nothing else (the lock file aside).
func assertBeside(t *testing.T, c Conversion, generations ...string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(c.CCDir))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if e.Name() != ".cc.lock" {
			got = append(got, e.Name())
		}
	}
	want := append([]string{"cc", "log", "share"}, generations...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("beside the country folder: %v, want %v", got, want)
	}
}

func TestARunWhoseContextEndedPublishesNothing(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Run(ctx) {
		t.Fatal("a run whose context ended succeeded")
	}
	assertPrevious(t, c)
}

// Where today's PHP dies with an Error (a Blocks row naming a Top Spammers key as its country: PHP's in_array() on its
// string ISO), the conversion stops and the previous generation stays.
func TestATopSpammersKeyAsACountryStopsTheConversion(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks+"4.0.0.0/8,A00000,A00000,,0,0,\n")
	if c.Run(context.Background()) {
		t.Fatal("the conversion went on past PHP's fatal error")
	}
	assertPrevious(t, c)
}

func TestTheContinentFilesCarryTheRunsLocalTime(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	b, err := os.ReadFile(filepath.Join(c.CCDir, "North_America_v4.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "# Generated from MaxMind Inc. on: 2026-11-20 09:15:00\n# Continent IPv4: North America\n"; !strings.HasPrefix(string(b), want) {
		t.Errorf("North_America_v4.txt starts %.120q, want %q", b, want)
	}
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n" {
		t.Errorf("US_v4.txt = %q", b)
	}
}

// The log lines pfblockerng_uc_countries() writes, as it writes them.
func TestTheLogIsTodays(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if want := "Country code update Start\n Processing ISO IPv4 Continent/Country Data\n Processing ISO IPv6 Continent/Country Data\n"; log.String() != want {
		t.Errorf("log = %q, want %q", log, want)
	}

	c, log = conversionRoot(t, testBlocks)
	c.Locale = "fr"
	if c.Run(context.Background()) {
		t.Fatal("a missing Locations file converted")
	}
	if want := "Country code update Start\n [ MAXMIND UPDATE FAIL, Language File Missing, using previous Country code database ]\n"; log.String() != want {
		t.Errorf("log = %q, want %q", log, want)
	}

	c, log = conversionRoot(t, testBlocks)
	os.Remove(filepath.Join(c.Share, "GeoLite2-Country-Blocks-IPv6.csv"))
	if c.Run(context.Background()) {
		t.Fatal("a missing Blocks file converted")
	}
	if want := " Processing ISO IPv6 Continent/Country Data\n\n Failed to load file: " + filepath.Join(c.Share, "GeoLite2-Country-Blocks-IPv6.csv") + "\n"; !strings.HasSuffix(log.String(), want) {
		t.Errorf("log = %q, want it to end %q", log, want)
	}
}

// Under a locale other than English, PHP passes the continent code to escapeshellarg(), which throws on a NUL: the
// conversion dies and publishes nothing.
func TestANULInTheContinentCodeStopsTheConversion(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	c.Locale = "fr"
	fr := "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
		"6252001,fr,\"N\x00A\",\"Amérique du Nord\",US,\"États-Unis\",0\n"
	if err := os.WriteFile(filepath.Join(c.Share, "GeoLite2-Country-Locations-fr.csv"), []byte(fr), 0o600); err != nil {
		t.Fatal(err)
	}
	if c.Run(context.Background()) {
		t.Fatal("the conversion went on past PHP's fatal error")
	}
	assertPrevious(t, c)
}

// "Continent data [ X ] not found" is logged as pfblockerng_get_countries() logs it: once the continent's name has been
// read from either family's file, a missing file of the other family is not reported. A forged header in Africa's IPv6
// file removes Asia_v6.txt before its pass (the conversion refuses a share that could forge one, #4127; the split keeps
// today's answer).
func TestAMissingContinentFileIsLoggedAsToday(t *testing.T) {
	var log bytes.Buffer
	Conversion{Log: &log}.split(stage{
		"Asia_v4.txt":   []byte("# Continent IPv4: Asia\n"),
		"Asia_v6.txt":   []byte("# Continent IPv6: Asia\n"),
		"Africa_v4.txt": []byte("# Continent IPv4: Africa\n"),
		"Africa_v6.txt": []byte("# Continent IPv6: Africa\n# ISO Code: Asia\n2c0f::/32\n"),
	})
	if strings.Contains(log.String(), "Continent data [ Asia ]") || strings.Contains(log.String(), "Continent data [ Africa ]") {
		t.Errorf("log = %q, want no missing-continent line for Asia or Africa", log.String())
	}
}
