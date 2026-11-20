package geoip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const frenchLocations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
	"6252001,fr,NA,\"Amérique du Nord\",US,\"États-Unis\",0\n1814991,fr,AS,Asie,CN,Chine,0\n"

// frenchRoot is conversionRoot under the French locale, with the given English Locations file ("" removes it).
func frenchRoot(t *testing.T, english string) (Conversion, *strings.Builder) {
	t.Helper()
	c, _ := conversionRoot(t, testBlocks)
	c.Locale = "fr"
	var log strings.Builder
	c.Log = &log
	if err := os.WriteFile(filepath.Join(c.Share, "GeoLite2-Country-Locations-fr.csv"), []byte(frenchLocations), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Share, "GeoLite2-Country-Locations-en.csv")
	if english == "" {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(path, []byte(english), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, &log
}

// Without the English Locations file no MaxMind country has a continent file to go in (#4125): the conversion fails and
// the previous generation stays, as it does when the configured locale's own Locations file is missing.
func TestAConversionThatPlacesNoMaxMindCountryKeepsThePreviousGeneration(t *testing.T) {
	c, log := frenchRoot(t, "")
	if c.Run(context.Background()) {
		t.Fatalf("a conversion that placed no MaxMind country published:\n%s", log)
	}
	assertPrevious(t, c)
	if want := " [ MAXMIND UPDATE FAIL, no MaxMind country has a continent, using previous Country code database ]\n"; !strings.HasSuffix(log.String(), want) {
		t.Errorf("log = %q, want it to end %q", log, want)
	}
}

// One MaxMind country with a continent is enough: the conversion publishes, the others are logged as today.
func TestOneMaxMindCountryWithAContinentPublishes(t *testing.T) {
	c, log := frenchRoot(t, "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n"+
		"6252001,en,NA,\"North America\",US,\"United States\",0\n")
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n" {
		t.Errorf("US_v4.txt = %q", b)
	}
	if !strings.Contains(log.String(), "Failed to create Continent file: Asie") {
		t.Errorf("log = %q, want China's continent reported", log)
	}
}
