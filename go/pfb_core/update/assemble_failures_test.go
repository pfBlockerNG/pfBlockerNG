package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
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

// WHEN a transfer is cancelled THEN it does not count against the retry cap: the feed did not fail, as a cancelled run neither
// creates nor removes its fail marker. Only a failed transfer counts.
func TestACancelledTransferIsNotCounted(t *testing.T) {
	for _, c := range []struct {
		r    feedstage.Result
		want bool
	}{
		{feedstage.Result{Disposition: "failed", Stage: "fetch", Reason: "feed_fetch_failed"}, true},
		{feedstage.Result{Disposition: "failed", Stage: "fetch", Reason: "cancelled"}, false},
		{feedstage.Result{Disposition: "failed", Stage: "script", Reason: "script_failed"}, false},
		{feedstage.Result{Disposition: "changed", Stage: "parse"}, false},
	} {
		if got := failedTransfer(c.r); got != c.want {
			t.Errorf("failedTransfer(%+v) = %v, want %v", c.r, got, c.want)
		}
	}
}

// GIVEN a retry cap of 1, the scheduler's zone 14 hours ahead of UTC, and a feed whose source is gone
// WHEN a second Update runs on the same UTC day but on the next local day
// THEN the feed is retried: the count starts again at local midnight, as pfb_failures() reads date() in the box's zone.
func TestTheRetryCapsDayIsTheSchedulersLocalDay(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["ingest"]["skipFeedLimit"] = 1
	fx.reply(t)
	if err := os.Remove(filepath.Join(fx.src, "A.txt")); err != nil {
		t.Fatal(err)
	}
	loop := fx.loop()
	loop.Zoneinfo = "/usr/share/zoneinfo/Pacific/Kiritimati"
	prev := loopNow
	t.Cleanup(func() { loopNow = prev })
	now := time.Date(2026, 11, 23, 5, 0, 0, 0, time.UTC) // 19:00 on 23 November in Kiritimati
	loopNow = func() time.Time { return now }
	named := Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}
	for i, want := range []string{"", "retry-cap-reached"} {
		res, err := fx.runLoop(t, loop, named)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Outcomes["ipv4:A_v4"]; got != want {
			t.Fatalf("Update %d on the first local day: A's outcome %q, want %q", i+1, got, want)
		}
	}
	now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) // 02:00 on 24 November in Kiritimati, same UTC day
	res, err := fx.runLoop(t, loop, named)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Outcomes["ipv4:A_v4"]; got == "retry-cap-reached" {
		t.Error("the next local day: A is still past the cap, want the count to start again at local midnight")
	}
}
