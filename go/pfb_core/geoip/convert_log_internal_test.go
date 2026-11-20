package geoip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pfblockerng_get_countries() tests empty($continent), which is also true for "0": a continent file whose name reads
// "0" is reported missing (here a forged "# Continent IPv4: 0" line in North America's file).
func TestAContinentNamedZeroIsLoggedMissing(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	blocks := testBlocks + "\"4.0.0.0/8\n# Continent IPv4: 0\",6252001,6252001,,0,0,\n"
	if err := os.WriteFile(filepath.Join(c.Share, "GeoLite2-Country-Blocks-IPv4.csv"), []byte(blocks), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if want := "Continent data [ North America ] not found\n"; !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to hold %q", log, want)
	}
}
