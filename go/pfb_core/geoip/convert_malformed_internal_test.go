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
	const blocksHeader = "network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast\n"
	for name, tc := range map[string]struct{ file, content string }{
		"network with a line break": {"GeoLite2-Country-Blocks-IPv4.csv", testBlocks + "\"7.0.0.0/8\n# ISO Code: CN\",6252001,6252001,,0,0,\n"},
		"network that is not one":   {"GeoLite2-Country-Blocks-IPv4.csv", testBlocks + "banana,6252001,6252001,,0,0,\n"},
		"IPv6 network with a CR":    {"GeoLite2-Country-Blocks-IPv6.csv", blocksHeader + "\"2600::/12\r9.9.9.9/32\",6252001,6252001,,0,0,\n"},
		"country name with a LF": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"6252001,en,NA,\"North America\",US,\"United\nStates\",0\n"},
		"continent name with a CR": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"6252001,en,NA,\"North\rAmerica\",US,\"United States\",0\n"},
		"geoname id with a LF": {"GeoLite2-Country-Locations-en.csv", locationsHeader +
			"\"6252001\n# ISO Code: CN\",en,NA,\"North America\",US,\"United States\",0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c, log := conversionRoot(t, testBlocks)
			if err := os.WriteFile(filepath.Join(c.Share, tc.file), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
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
