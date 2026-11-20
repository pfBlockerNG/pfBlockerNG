package geoip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A row whose network is not one network, or whose header fields span lines, would forge or break the continent files
// split() reads line by line (#4127): the conversion refuses the share and the previous generation stays.
func TestAMalformedRowKeepsThePreviousGeneration(t *testing.T) {
	for name, tc := range map[string]struct{ file, content string }{
		"network with a line break": {"GeoLite2-Country-Blocks-IPv4.csv", testBlocks + "\"7.0.0.0/8\n# ISO Code: CN\",6252001,6252001,,0,0,\n"},
		"network that is not one":   {"GeoLite2-Country-Blocks-IPv4.csv", testBlocks + "banana,6252001,6252001,,0,0,\n"},
		"IPv6 network with a CR":    {"GeoLite2-Country-Blocks-IPv6.csv", blocksHeader + "\"2600::/12\r9.9.9.9/32\",6252001,6252001,,0,0,\n"},
		"header row after a BOM":    {"GeoLite2-Country-Blocks-IPv4.csv", "\ufeff" + testBlocks},
		"country name with a LF": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"6252001,en,NA,\"North America\",US,\"United\nStates\",0\n"},
		"continent name with a CR": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"6252001,en,NA,\"North\rAmerica\",US,\"United States\",0\n"},
		"geoname id with a LF": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"\"6252001\n# ISO Code: CN\",en,NA,\"North America\",US,\"United States\",0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks)
			writeShare(t, c, tc.file, tc.content)
			if c.Run(context.Background()) {
				t.Fatalf("a malformed row published:\n%s", log)
			}
			assertPrevious(t, c)
			want := " [ MAXMIND UPDATE FAIL, malformed row in " + tc.file + ", using previous Country code database ]\n"
			if !strings.HasSuffix(log.String(), want) {
				t.Errorf("log = %q, want it to end %q", log, want)
			}
		})
	}
}

// White space around a network is not part of it: the split trims every line, so the list holds the network alone.
func TestANetworkWithSurroundingSpaceIsListed(t *testing.T) {
	c, log := conversionRoot(t, testBlocks+" 4.0.0.0/8\t,6252001,6252001,,0,0,\n")
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if b, _ := os.ReadFile(filepath.Join(c.CCDir, "US_v4.txt")); string(b) != "3.0.0.0/15\n4.0.0.0/8\n" {
		t.Errorf("US_v4.txt = %q", b)
	}
}

// A country name that holds header text on one line forges no header: the split matches a header only at the start of
// its line, so no list is emptied (#4127). Today's PHP matches it anywhere in a '#' line.
func TestACountryNameHoldingHeaderTextEmptiesNoList(t *testing.T) {
	for name, tc := range map[string]struct{ row, list, want string }{
		// The country's _rep header follows its own, so the name's line ends the country's list.
		"continent file": {"6300000,en,NA,\"North America\",CA,\"Total Networks: 0\",0\n", "CA_v4.txt", "4.0.0.0/8\n"},
		// Russia follows China in Top Spammers.
		"Top Spammers": {"2017370,en,EU,Europe,RU,\"Total Networks: NA\",0\n", "CN_v4.txt", "1.0.1.0/24\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks+"4.0.0.0/8,6300000,6300000,,0,0,\n1.0.1.0/24,1814991,1814991,,0,0,\n")
			writeShare(t, c, "GeoLite2-Country-Locations-en.csv", testLocations+tc.row)
			if !c.Run(context.Background()) {
				t.Fatalf("conversion failed:\n%s", log)
			}
			if b, _ := os.ReadFile(filepath.Join(c.CCDir, tc.list)); string(b) != tc.want {
				t.Errorf("%s = %q, want %q", tc.list, b, tc.want)
			}
		})
	}
}
