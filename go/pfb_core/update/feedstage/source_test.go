package feedstage

import (
	"context"
	"path/filepath"
	"testing"
)

// Scenario: a GeoIP feed is parsed as today parses it.
// Given a GeoIP feed, whose source is a country code with its name, when it is transferred and when it is parsed again from
// its download, then the parser is chosen from the country list the feed reads, as today's feed block chooses it once it
// has replaced the source with that list's path (pfblockerng_apply.inc, "Adjust 'geoip' format"): a .txt file reads as auto,
// which takes the first address of a line, never as regex, which takes every one.
func TestGeoIPFeedIsParsedAsItsCountryList(t *testing.T) {
	stage, feed, source := localStage(t)
	stage.Paths.GeoIPDir = filepath.Dir(source)
	feed.Format, feed.Source = "geoip", "XX Nowhere"
	writeFile(t, filepath.Join(stage.Paths.GeoIPDir, "XX_v4.txt"), "198.51.100.7 203.0.113.9\n")
	for _, force := range []string{"none", "parse"} {
		if got := run(stage, feed, force); got.Disposition == "failed" {
			t.Fatalf("force %s: run = %+v", force, got)
		}
		if list := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); list != "198.51.100.7\n" {
			t.Fatalf("force %s: the list = %q, want the first address of the line only, as the auto parser takes it", force, list)
		}
	}
}

// Scenario: an ASN feed's source carries the network's name.
// Given an ASN feed whose source is "AS64500 Example Network", as the Groups editor stores a source with its description,
// when it runs, then the AS number alone is looked up, as today's feed block cuts an asn source at its first space.
func TestASNFeedSourceIsCutAtItsFirstSpace(t *testing.T) {
	stage := testStage(t)
	csv := filepath.Join(t.TempDir(), "asn.csv")
	writeFile(t, csv, "198.51.100.0,198.51.100.255,AS64500,Example Network,example.net\n")
	stage.Fetcher.ASNCSV = csv
	got := stage.Run(context.Background(), testFeed("ipv4", "enabled", "asn", "AS64500 Example Network"), Change{Force: "none"})
	if got.Disposition != "changed" {
		t.Fatalf("an ASN feed with its description = %+v, want changed", got)
	}
	if list := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); list != "198.51.100.0/24\n" {
		t.Fatalf("the list = %q, want the ranges of AS64500", list)
	}
}
