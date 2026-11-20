package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// conversionRoot is a share with the given IPv4 Blocks file and a previous generation in the country folder.
func conversionRoot(t *testing.T, blocksV4 string) (Conversion, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	share := filepath.Join(root, "share")
	for name, content := range map[string]string{
		"share/GeoLite2-Country-Locations-en.csv": testLocations,
		"share/GeoLite2-Country-Blocks-IPv4.csv":  blocksV4,
		"share/GeoLite2-Country-Blocks-IPv6.csv":  testBlocks,
		"cc/US_v4.txt":                            "192.0.2.0/24\n",
		"db/geoip.txt":                            "previous\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var log bytes.Buffer
	return Conversion{Share: share, CCDir: filepath.Join(root, "cc"), ISOs: filepath.Join(root, "db", "geoip.txt"),
		LogDir: filepath.Join(root, "log"), Locale: "en", Now: time.Date(2026, 11, 20, 9, 15, 0, 0, time.FixedZone("x", 3600)),
		Log: &log}, &log
}

// assertPrevious checks the previous generation stands and nothing staged or set aside is left beside it.
func assertPrevious(t *testing.T, c Conversion) {
	t.Helper()
	if b, err := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); err != nil || string(b) != "192.0.2.0/24\n" {
		t.Errorf("US_v4.txt = %q, %v; want the previous list", b, err)
	}
	if b, err := os.ReadFile(c.ISOs); err != nil || string(b) != "previous\n" {
		t.Errorf("geoip.txt = %q, %v; want the previous list", b, err)
	}
	for _, pattern := range []string{c.CCDir + ".*", c.ISOs + ".*"} {
		if left, _ := filepath.Glob(pattern); len(left) != 0 {
			t.Errorf("left behind: %v", left)
		}
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

// The publication lock is exclusive: held elsewhere, a publication waits for it and gives up when its context ends.
func TestAHeldPublicationLockEndsWithTheContext(t *testing.T) {
	dir := t.TempDir()
	held, err := os.OpenFile(filepath.Join(dir, ".pfb_generation.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f, ok := publicationLock(ctx, dir); ok {
		f.Close()
		t.Fatal("took the lock a reader holds")
	}
	syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
	f, ok := publicationLock(context.Background(), dir)
	if !ok {
		t.Fatal("a free lock was not taken")
	}
	f.Close()
}
