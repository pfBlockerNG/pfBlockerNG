package feedstage

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Scenario: a whois list resolves only in part, and its run then fails.
// Given a custom Domain/AS list with one AS number that resolves and one that is no AS number, and a pre-script that
// fails, when the feed runs, then it fails at the pre-script and the feed folder gains the failure marker the partial
// whois left, as whoisconvert() leaves it whatever the run does next; the resolved copy is not published.
func TestAPartialWhoisKeepsItsMarkerWhenTheRunFailsLater(t *testing.T) {
	stage, feed, _ := localStage(t)
	stage.Fetcher.ASNCSV = filepath.Join(t.TempDir(), "asn.csv")
	writeFile(t, stage.Fetcher.ASNCSV, "198.51.100.0,198.51.100.255,AS64500,Example\n")
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "pre.sh"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed.Custom, feed.WhoisConvert, feed.CustomText, feed.Source, feed.PreScript = true, true, "AS64500\nASxyz\n", "", "pre.sh"
	got := stage.Run(context.Background(), feed, Change{Force: "none"})
	if got.Disposition != "failed" || got.Stage != "script" || !got.PreScriptFailed {
		t.Fatalf("the run = %+v, want failed at the pre-script", got)
	}
	dir := stage.Paths.FeedDir
	if !regularExists(filepath.Join(dir, "feed_v4.fail")) {
		t.Error("the failure marker of the partial whois is gone, want it published")
	}
	if _, err := os.Lstat(filepath.Join(dir, "feed_v4.orig")); !os.IsNotExist(err) {
		t.Errorf("the failed run published the resolved copy (%v), want the feed folder as it was", err)
	}
}

// Scenario: a feed that once failed its download downloads again.
// Given a published feed with its failure marker, when a run transfers the source (a URL feed's download, or a whois
// feed's resolution, as today's pfb_download() call), then the marker is removed with the run's publication, as today's
// feed block unlinks "{header}.fail" on a successful download. A run that transfers nothing (a Reload, a custom list) or
// whose transfer fails leaves the marker as it stands.
func TestASuccessfulTransferRemovesTheFailMarker(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, stage *Stage, feed *Feed, source string)
		force string
		want  bool // the marker stands after the run
	}{
		{"a changed download", func(t *testing.T, _ *Stage, _ *Feed, source string) {
			writeFile(t, source, "198.51.100.2\n")
		}, "none", false},
		{"a forced download", func(t *testing.T, _ *Stage, _ *Feed, source string) {
			writeFile(t, source, "198.51.100.1\n")
		}, "download", false},
		{"a whois feed that resolves", func(_ *testing.T, stage *Stage, feed *Feed, _ string) {
			stage.Fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
			}
			feed.Format, feed.Source = "whois", "one.example"
		}, "none", false},
		{"a Reload", func(*testing.T, *Stage, *Feed, string) {}, "parse", true},
		{"a custom whois list that resolves", func(_ *testing.T, stage *Stage, feed *Feed, _ string) {
			stage.Fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
			}
			feed.Custom, feed.WhoisConvert, feed.CustomText, feed.Source = true, true, "one.example\n", ""
		}, "none", true},
		{"a failed transfer", func(*testing.T, *Stage, *Feed, string) {}, "none", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, feed, source := localStage(t)
			writeFile(t, source, "198.51.100.1\n")
			if r := run(stage, feed, "none"); r.Disposition != "changed" {
				t.Fatalf("the baseline run = %+v", r)
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")
			writeFile(t, marker, "")
			tc.setup(t, stage, &feed, source)
			r := run(stage, feed, tc.force)
			if (r.Disposition == "failed") != (tc.name == "a failed transfer") {
				t.Fatalf("the run = %+v", r)
			}
			if got := regularExists(marker); got != tc.want {
				t.Errorf("after the run the marker stands: %v, want %v", got, tc.want)
			}
		})
	}
}
