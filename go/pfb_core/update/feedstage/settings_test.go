package feedstage

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

// Run reads the verdict only for a transferred feed: a disabled feed, a Hold feed with its list, a custom list and a
// whois feed run without one.
func TestVerdictIsReadOnlyForATransfer(t *testing.T) {
	for _, tc := range []struct {
		name string
		feed func(stage *Stage) Feed
		want string
	}{
		{"disabled", func(*Stage) Feed { return testFeed("ipv4", "disabled", "auto", "http://feed.example/list") }, "held"},
		{"hold with a list", func(stage *Stage) Feed {
			writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip"), "203.0.113.6\n")
			return testFeed("ipv4", "hold", "auto", "http://feed.example/list")
		}, "held"},
		{"custom list", func(*Stage) Feed {
			return Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled", Format: "auto",
				Custom: true, CustomText: "203.0.113.21\n"}
		}, "changed"},
		{"whois", func(stage *Stage) Feed {
			stage.Fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
			}
			return testFeed("ipv4", "enabled", "whois", "one.example")
		}, "changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := testStage(t)
			if got := stage.Run(context.Background(), tc.feed(stage), Change{Force: "none"}); got.Disposition != tc.want {
				t.Fatalf("Run without a verdict = %+v, want %s", got, tc.want)
			}
		})
	}
}

// A kind or a state Run does not know is a settings failure that touches nothing, never run as another. A format is read
// as today reads it (TestFormatIsReadAsTodayReadsIt).
func TestUnknownKindOrStateIsRefused(t *testing.T) {
	for _, tc := range []struct {
		kind, state, format, reason string
	}{
		{"ipv5", "enabled", "auto", "feed_kind_invalid"},
		{"", "enabled", "auto", "feed_kind_invalid"},
		{"ipv4", "paused", "auto", "feed_state_invalid"},
		{"ipv4", "", "auto", "feed_state_invalid"},
	} {
		stage := testStage(t)
		feed := Feed{ID: "custom:ipv4:Test", Kind: tc.kind, Name: "Test_custom_v4", State: tc.state, Format: tc.format,
			Custom: true, CustomText: "203.0.113.21\n"}
		got := stage.Run(context.Background(), feed, Change{Force: "download"})
		if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != tc.reason {
			t.Errorf("Run(kind %q, state %q, format %q) = %+v, want a settings failure %s", tc.kind, tc.state, tc.format, got, tc.reason)
		}
		if entries, _ := os.ReadDir(stage.Paths.FeedDir); len(entries) != 0 {
			t.Errorf("Run(kind %q, state %q, format %q) left %d files in the feed folder", tc.kind, tc.state, tc.format, len(entries))
		}
	}
}

// Scenario: a parse setting changes while the source does not.
// Given a feed published from an unchanged source, when a setting the parse reads changes (suppression and the CIDR
// floors, the group's Suppression CIDR, the DNSBL IP switch, the parse mode, the PSL's ICANN TLDs, the format, the list type), then the next run parses
// the download again with it instead of reusing the list, and the run after that reuses the new list.
func TestParseSettingsReachTheReuseRecord(t *testing.T) {
	otherICANN := icannOf(t, "com", "org") // the ICANN row's set, in place of each run's icannOf(t, "com")
	for _, tc := range []struct {
		name, kind, source string
		suppression        bool // Suppression is on from the first run, so that the change is the one floor alone
		change             func(*Stage, *Feed)
	}{
		{"the IPv4 floor", "ipv4", "198.51.0.0/16\n", true, func(s *Stage, _ *Feed) { s.Config.FloorV4 = 24 }},
		{"the IPv6 floor", "ipv6", "2001:db8::/32\n", true, func(s *Stage, _ *Feed) { s.Config.FloorV6 = 48 }},
		{"the group's Suppression CIDR", "ipv4", "198.51.0.0/16\n", true, func(_ *Stage, f *Feed) { f.SuppressionCIDR = 24 }},
		{"suppression", "dnsbl", "a.example\n", false, func(s *Stage, _ *Feed) { s.Config.Suppression = true }},
		{"the DNSBL IP switch", "dnsbl", "a.example\n198.51.100.1\n", false, func(s *Stage, _ *Feed) { s.Config.DNSBLIP = true }},
		{"parse mode", "dnsbl", "a.example\n", false, func(s *Stage, _ *Feed) { s.Config.ParseMode = feedparse.ParseLenient }},
		{"the ICANN TLDs", "dnsbl", "a.example\n", false, func(s *Stage, _ *Feed) { s.Config.ICANN = otherICANN }},
		{"the format", "ipv4", "198.51.100.1\n", false, func(_ *Stage, f *Feed) { f.Format = "regex" }},
		{"the list type", "ipv4", "198.51.100.1\n", false, func(_ *Stage, f *Feed) { f.Custom = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, _, source := localStage(t)
			stage.Config.Suppression = tc.suppression
			stage.Config.ICANN = icannOf(t, "com") // a set the ICANN row replaces with another
			feed := testFeed(tc.kind, "enabled", "auto", "file://"+source)
			writeFile(t, source, tc.source)
			if got := run(stage, feed, "none"); got.Disposition != "changed" {
				t.Fatalf("the first run = %+v", got)
			}
			if got := run(stage, feed, "none"); got.Disposition != "unchanged" {
				t.Fatalf("the run with the same settings = %+v, want unchanged", got)
			}
			tc.change(stage, &feed)
			if feed.Custom {
				// A custom list's text is its source: the same text as the download.
				feed.CustomText, feed.Source = tc.source, ""
			}
			if got := run(stage, feed, "none"); got.Disposition != "reparsed" {
				t.Fatalf("the run after the setting changed = %+v, want reparsed", got)
			}
			if got := run(stage, feed, "none"); got.Disposition != "unchanged" {
				t.Fatalf("the next run = %+v, want unchanged", got)
			}
		})
	}
}

// icannOf is the ICANN TLD set of a PSL whose ICANN section holds the rules given.
func icannOf(t *testing.T, rules ...string) *feedparse.ICANNTLDs {
	t.Helper()
	psl := filepath.Join(t.TempDir(), "dnsbl_psl")
	text := "// ===BEGIN ICANN DOMAINS===\n" + strings.Join(rules, "\n") + "\n// ===END ICANN DOMAINS===\n"
	if err := os.WriteFile(psl, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	icann, err := feedparse.LoadICANNTLDs(psl)
	if err != nil {
		t.Fatal(err)
	}
	return icann
}
