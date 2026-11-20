package geoip

import (
	"bytes"
	"strings"
	"testing"
)

// pfblockerng_get_countries() tests empty($continent), which is also true for "0": a continent file whose name reads
// "0" is reported missing (here a forged "# Continent IPv4: 0" line in North America's file, which the conversion
// refuses to write since #4127; the split keeps today's answer).
func TestAContinentNamedZeroIsLoggedMissing(t *testing.T) {
	var log bytes.Buffer
	Conversion{Log: &log}.split(stage{
		"North_America_v4.txt": []byte("# Continent IPv4: North America\n# Continent IPv4: 0\n"),
		"North_America_v6.txt": []byte("# Continent IPv6: North America\n"),
	})
	if want := "Continent data [ North America ] not found\n"; !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to hold %q", log.String(), want)
	}
}
