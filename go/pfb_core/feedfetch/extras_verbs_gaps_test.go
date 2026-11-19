package feedfetch

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// A run's configuration carries every setting the transfers need: the MaxMind credentials, the IPinfo and TOP1M tokens,
// the database folder for the update markers, the ASN table hook, and the change detector for dcc alone (#4119 review).
func TestAVerbsConfigurationCarriesItsSettings(t *testing.T) {
	s := verbSettings()
	s.Top1MToken = "tt"
	for verb, detect := range map[string]bool{"dcc": true, "dc": false, "al": false, "bl": false} {
		ran := false
		c := ExtrasVerb{Name: verb, GeoIPShare: "/share", DBDir: "/db", Settings: s,
			ASNTable: func(context.Context) { ran = true }}.config()
		if c.DBDir != "/db" || c.MaxMindAccount != "1" || c.MaxMindKey != "mk" || c.ASNToken != "it" || c.Top1MToken != "tt" ||
			c.Detect != detect || c.ASNTable == nil {
			t.Errorf("%s: config = %+v, want every setting and detect %v", verb, c, detect)
			continue
		}
		if c.ASNTable(context.Background()); !ran {
			t.Errorf("%s: the ASN table hook is not the verb's", verb)
		}
	}
}

// A feed path ending in "." or ".." names no file: the row would download beside the database folder (#4119 review).
func TestAFeedEndingInADotNamesNoFile(t *testing.T) {
	for _, feed := range []string{"https://lists.example/a/..", "https://lists.example/a/.", "https://lists.example/.."} {
		s := verbSettings()
		s.Providers[1].Feed = feed
		var log strings.Builder
		rows := ExtrasVerb{Name: "bl", Args: []string{"ex"}, DBDir: "/db", Settings: s}.plan(func(m string) { log.WriteString(m) })
		if len(rows) != 0 || log.String() != "\nBlacklist provider [ ex ] skipped: its feed names no file\n" {
			t.Errorf("%s: rows %+v, log %q; want none and the skip", feed, rows, log.String())
		}
	}
}

// bl logs no Blacklist report (only bls prints it, pfblockerng.php:442-448); an unknown id is logged once, an empty one
// never (#4119 review).
func TestTheBlacklistVerbsLogs(t *testing.T) {
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	var log strings.Builder
	f.RunExtras(context.Background(), ExtrasVerb{Name: "bl", Args: []string{",gone,ex,gone,"}, GeoIPShare: t.TempDir(),
		DBDir: t.TempDir(), Settings: verbSettings(), Log: &log})
	if strings.Contains(log.String(), "... Failed") {
		t.Errorf("bl logged the Blacklist report:\n%s", log.String())
	}
	if n := strings.Count(log.String(), "skipped"); n != 1 || !strings.Contains(log.String(), "[ gone ] skipped") {
		t.Errorf("skip lines = %d, want one for gone:\n%s", n, log.String())
	}
}
