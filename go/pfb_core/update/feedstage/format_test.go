package feedstage

import (
	"os"
	"path/filepath"
	"testing"
)

// formatOutcome runs a fresh IP feed of format over a local .txt source whose one line holds two addresses (auto reads the
// first, regex both) and returns its result and published list.
func formatOutcome(t *testing.T, format string) (Result, string) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"orig", "db", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.7 203.0.113.9\n")
	stage, feed := killStage(root)
	feed.Format = format
	r := run(stage, feed, "none")
	list, err := os.ReadFile(filepath.Join(root, "orig", "Feed_v4.parsed.ip"))
	if err != nil {
		return r, "<missing>"
	}
	return r, string(list)
}

// Scenario: a stored format is read as today's per-feed blocks read it.
// Given an IP feed, when its format is a spelling today's code compares as no format it knows (pfblockerng_apply.inc and
// pfb_download() compare the lowercase names case-sensitively, so "Auto", the category editor's placeholder, an empty
// format, "Regex", "RSync" or an unknown name all fall through to auto), then the feed runs as an auto feed, never refused;
// and the lowercase names keep their own handling.
func TestFormatIsReadAsTodayReadsIt(t *testing.T) {
	auto, autoList := formatOutcome(t, "auto")
	regex, regexList := formatOutcome(t, "regex")
	if auto.Disposition != "changed" || regex.Disposition != "changed" || autoList == regexList {
		t.Fatalf("the oracle: auto = %+v (%q), regex = %+v (%q), want both published and different", auto, autoList,
			regex, regexList)
	}
	for _, format := range []string{"Auto", "AUTO", "", "Regex", "RSync", "GeoIP", "xml"} {
		got, list := formatOutcome(t, format)
		if got != auto || list != autoList {
			t.Errorf("format %q ran as %+v (%q), want what auto does: %+v (%q)", format, got, list, auto, autoList)
		}
	}
	if got, _ := formatOutcome(t, "rsync"); got.Reason != "rsync_unavailable" {
		t.Errorf("format rsync without an rsync binary = %+v, want rsync_unavailable", got)
	}
}
