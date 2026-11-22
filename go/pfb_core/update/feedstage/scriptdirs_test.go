package feedstage

import (
	"os"
	"path/filepath"
	"testing"
)

// Scenario: the list-script folders hold an unset entry.
// Given list-script folders whose first entry is empty and whose second holds the feed's pre-script, when the feed runs,
// then the empty entry is skipped, as the script lookup skips it, and the pre-script's output is published; a relative
// entry is still refused.
func TestAnEmptyScriptFolderEntryIsSkipped(t *testing.T) {
	stage, feed, source := localStage(t)
	scripts := stage.Paths.ScriptDirs[0]
	if err := os.WriteFile(filepath.Join(scripts, "pre.sh"), []byte("#!/bin/sh\nprintf '203.0.113.88\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "198.51.100.1\n")
	feed.PreScript = "pre.sh"
	stage.Paths.ScriptDirs = []string{"", scripts}
	if got := run(stage, feed, "none"); got.Disposition != "changed" || got.PreScriptFailed {
		t.Fatalf("the run = %+v, want the pre-script's output published", got)
	}
	if got := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); got != "203.0.113.88\n" {
		t.Errorf("the list is %q, want the pre-script's output", got)
	}
	stage.Paths.ScriptDirs = []string{"scripts", scripts}
	if got := run(stage, feed, "none"); got.Disposition != "failed" || got.Reason != "script_directory_invalid" {
		t.Errorf("a relative script folder: the run = %+v, want failed with script_directory_invalid", got)
	}
}
