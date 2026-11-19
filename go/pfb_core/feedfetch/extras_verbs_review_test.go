package feedfetch

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dcc with no row to download still runs pfblockerng_download_extras() over an empty table, then the conversion and
// the exit formula (pfblockerng.php:374-386): a pending geoip.update makes a scheduled run exit 2 (#4119 review).
func TestADccWithNoRowStillConvertsAndReportsTheGeoIPChange(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "geoip.update"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("a dcc with no row resolved a host")
		return nil, errors.New("no such host")
	}
	converted := false
	var log strings.Builder
	code, _ := f.RunExtras(context.Background(), ExtrasVerb{Name: "dcc", Args: []string{"scheduled"}, GeoIPShare: t.TempDir(),
		DBDir: db, Settings: ExtrasSettings{Top1MProvider: "tranco"}, Log: &log,
		Convert: func(context.Context) bool { converted = true; return true }})
	if code != 2 || !converted || !strings.Contains(log.String(), "Download Process Starting") {
		t.Errorf("(exit, converted) = (%d, %v), log %q; want (2, true) and the download's start", code, converted, log.String())
	}
}

// The archive's name is the base of the feed's path as written, as pathinfo() takes it: a percent-encoded character
// stays encoded (#4119 review).
func TestABlacklistArchiveNameKeepsItsEncoding(t *testing.T) {
	s := verbSettings()
	s.Providers[1].Feed = "https://lists.example/cat/my%20list.tar.gz?key=k"
	rows := ExtrasVerb{Name: "bl", Args: []string{"ex"}, DBDir: "/db", Settings: s}.plan(func(string) {})
	if len(rows) != 1 || rows[0].Download != "my%20list.tar.gz" || rows[0].File != "my%20list.tar.gz" {
		t.Errorf("rows = %+v, want the one row named my%%20list.tar.gz", rows)
	}
}
