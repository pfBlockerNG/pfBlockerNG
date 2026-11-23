package update

import (
	"os"
	"path/filepath"
	"testing"
)

// GIVEN a feed whose source is gone and an apply that refuses
// WHEN an Update fails at its apply
// THEN the failed download is already counted in the Updater's state: a count kept only by the settle would let every
// failing Update retry the feed without end.
func TestAFailedDownloadIsCountedThoughTheUpdateFailsLater(t *testing.T) {
	fx := newLoopFixture(t)
	if err := os.Remove(filepath.Join(fx.src, "A.txt")); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.applyDir, "exit"), "2")
	if _, err := fx.run(t, manual()); err == nil {
		t.Fatal("the Update succeeded, want the apply's refusal")
	}
	if got := readUpdaterState(fx.state).Failures["A_v4"]; got != 1 {
		t.Errorf("A_v4's failed downloads = %d, want 1", got)
	}
}

// GIVEN a group whose pre-script fails after its feeds' transfers succeeded
// WHEN an Update runs
// THEN the feeds fail at their script and nothing is counted: only a failed transfer counts against the retry cap, as only
// pfb_download_failure() logs the FAIL line today's count greps.
func TestAFeedThatFailsAfterItsTransferIsNotCounted(t *testing.T) {
	fx := newLoopFixture(t)
	scripts := filepath.Join(fx.root, "scripts")
	mkdirs(t, scripts)
	script(t, filepath.Join(scripts, "fail.sh"), "exit 1")
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["preScript"] = "fail.sh"
	fx.reply(t)
	loop := fx.loop()
	loop.ScriptDirs = []string{scripts}
	if _, err := fx.runLoop(t, loop, manual()); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(fx.state).Failures; len(got) != 0 {
		t.Errorf("failed downloads %v, want none: every transfer succeeded", got)
	}
}
