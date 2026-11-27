package feedstage

import (
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

// Scenario: an Adblock feed is parsed as Adblock (issue #4272).
// Given an Adblock-headed DNSBL feed holding EasyPrivacy's path rule '.imgur.com/lumbar.gif', a bare hostname and an anchored
// rule, when the stage parses it in Lenient mode, then the path rule blocks nothing, the hostname and the rule stay, and the
// same lines without the header (no Adblock rule left either) keep Lenient's host cut.
func TestAnAdblockFeedIsParsedAsAdblock(t *testing.T) {
	icann, err := feedparse.LoadICANNTLDs("../../../../src/usr/local/pkg/pfblockerng/dnsbl_psl")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, source, want string }{
		{"with the header", "[Adblock Plus 2.0]\n.imgur.com/lumbar.gif\nimgur.com\n||mp.imgur.com^\n",
			"[\"d\",\"imgur.com\"]\n[\"a\",\"||mp.imgur.com^\"]\n"},
		{"by an Adblock rule", ".imgur.com/lumbar.gif\nexample.org\n||mp.imgur.com^\n",
			"[\"d\",\"example.org\"]\n[\"a\",\"||mp.imgur.com^\"]\n"},
		{"neither", ".imgur.com/lumbar.gif\nexample.org\n", "[\"d\",\"imgur.com\"]\n[\"d\",\"example.org\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, _, source := localStage(t)
			stage.Config.ParseMode, stage.Config.ICANN = feedparse.ParseLenient, icann
			feed := testFeed("dnsbl", "enabled", "auto", "file://"+source)
			writeFile(t, source, tc.source)
			if got := run(stage, feed, "none"); got.Disposition != "changed" {
				t.Fatalf("Run = %+v", got)
			}
			if got := readFile(t, filepath.Join(stage.Paths.FeedDir, feed.Name+".parsed.ndjson")); got != tc.want {
				t.Errorf("rows = %q, want %q", got, tc.want)
			}
		})
	}
}
