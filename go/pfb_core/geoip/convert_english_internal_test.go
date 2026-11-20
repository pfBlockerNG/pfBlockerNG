package geoip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	locationsHeader = "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n"
	frenchLocations = locationsHeader +
		"6252001,fr,NA,\"Amérique du Nord\",US,\"États-Unis\",0\n1814991,fr,AS,Asie,CN,Chine,0\n"
)

// frenchRoot is conversionRoot under the French locale, with the given English Locations file ("" removes it).
func frenchRoot(t *testing.T, english string) (Conversion, *bytes.Buffer) {
	t.Helper()
	c, log := conversionRoot(t, testBlocks)
	c.Locale = "fr"
	writeShare(t, c, "GeoLite2-Country-Locations-fr.csv", frenchLocations)
	if english == "" {
		if err := os.Remove(filepath.Join(c.Share, "GeoLite2-Country-Locations-en.csv")); err != nil {
			t.Fatal(err)
		}
	} else {
		writeShare(t, c, "GeoLite2-Country-Locations-en.csv", english)
	}
	return c, log
}

func writeShare(t *testing.T, c Conversion, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(c.Share, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const noContinent = " [ MAXMIND UPDATE FAIL, no MaxMind country has a continent file, using previous Country code database ]\n"

// assertNoContinent checks the run failed for want of a continent and kept the previous generation.
func assertNoContinent(t *testing.T, c Conversion, log *bytes.Buffer) {
	t.Helper()
	if c.Run(context.Background()) {
		t.Fatalf("a conversion that placed no MaxMind country published:\n%s", log)
	}
	assertPrevious(t, c)
	if !strings.HasSuffix(log.String(), noContinent) {
		t.Errorf("log = %q, want it to end %q", log, noContinent)
	}
}

// Without the English Locations file no MaxMind country has a continent file to go in (#4125): the conversion fails and
// the previous generation stays, as it does when the configured locale's own Locations file is missing.
func TestAConversionThatPlacesNoMaxMindCountryKeepsThePreviousGeneration(t *testing.T) {
	c, log := frenchRoot(t, "")
	assertNoContinent(t, c, log)
}

// A country is placed only when its list lands in a continent file the split reads.
func TestACountryWhoseListReachesNoContinentFileIsNotPlaced(t *testing.T) {
	for name, rows := range map[string]string{
		"continent not a word":      "6252001,en,NA,North-America,US,\"United States\",0\n",
		"continent of no file":      "6252001,en,NA,NorthAmerica,US,\"United States\",0\n",
		"ISO not a word":            "6252001,en,NA,\"North America\",\"U S\",\"United States\",0\n",
		"beside a Top Spammers key": "6252001,en,NA,North-America,US,\"United States\",0\n9A0001,en,EU,Europe,QQ,Q,0\n",
		"a later row unplaces it":   "6252001,en,NA,\"North America\",US,\"United States\",0\n6252001,en,NA,North-America,US,\"United States\",0\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks)
			writeShare(t, c, "GeoLite2-Country-Locations-en.csv", locationsHeader+rows)
			assertNoContinent(t, c, log)
		})
	}
}

// A country's last row is the one converted: a later row with a continent places it.
func TestALaterRowOfTheSameCountryPlacesIt(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	writeShare(t, c, "GeoLite2-Country-Locations-en.csv", locationsHeader+
		"6252001,en,NA,North-America,US,\"United States\",0\n6252001,en,NA,\"North America\",US,\"United States\",0\n")
	if !c.Run(context.Background()) || strings.Contains(log.String(), noContinent) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n" {
		t.Errorf("US_v4.txt = %q", b)
	}
}

// A Locations file that lists no MaxMind country leaves every country to the built-in table, which places them all: a
// file without rows, or whose only row is a Top Spammers key or a key a built-in entry replaces.
func TestALocationsFileWithoutCountriesPublishes(t *testing.T) {
	for name, rows := range map[string]string{
		"no rows":          "",
		"Top Spammers key": "9A0001,en,EU,Europe,QQ,Q,0\n",
		"built-in key":     "6255147,en,AS,Asia,XX,Forged,0\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks)
			writeShare(t, c, "GeoLite2-Country-Locations-en.csv", locationsHeader+rows)
			if !c.Run(context.Background()) {
				t.Fatalf("conversion failed:\n%s", log)
			}
			if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n" {
				t.Errorf("US_v4.txt = %q", b)
			}
		})
	}
}

// One MaxMind country with a continent is enough: the conversion publishes, the others are logged as today.
func TestOneMaxMindCountryWithAContinentPublishes(t *testing.T) {
	c, log := frenchRoot(t, locationsHeader+"6252001,en,NA,\"North America\",US,\"United States\",0\n")
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
