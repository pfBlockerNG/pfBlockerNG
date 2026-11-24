package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The loop's inputs that no projection carried before issue #4038: the retry cap (ingest.skipFeedLimit) with the failed
// downloads the Updater counts itself, the feed sanity switch (ingest.feedSanity) and the pending apply
// (platform.pendingApply).

// replyPending writes the adapter's answer from fx.settings and fx.token, with platform.pendingApply.
func (fx *loopFixture) replyPending(t *testing.T, pending bool) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 1, "revision": 3, "settings": fx.settings,
		"platform": map[string]any{"pendingToken": fx.token, "pendingApply": pending}})
	if err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.adapterDir, "reply"), string(b))
}

// GIVEN a retry cap of 2 and a feed whose source is gone
// WHEN scheduled Updates name it on one day
// THEN the third finds two failed downloads today and stops the feed's retries (retry-cap-reached), as pfb_update_check()
// does on the error log's FAIL lines; on the next day the count starts again and the feed is retried.
func TestTheRetryCapCountsTheDaysFailedDownloadsFromTheUpdatersOwnState(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["ingest"]["skipFeedLimit"] = 2
	fx.reply(t)
	if err := os.Remove(filepath.Join(fx.src, "A.txt")); err != nil {
		t.Fatal(err)
	}
	prev := loopNow
	t.Cleanup(func() { loopNow = prev })
	day := time.Date(2026, 11, 23, 10, 0, 0, 0, time.Local)
	loopNow = func() time.Time { return day }
	named := Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}} // only a named feed reports an outcome
	for i := 1; i <= 2; i++ {
		res, err := fx.run(t, named)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Outcomes["ipv4:A_v4"]; got == "retry-cap-reached" {
			t.Fatalf("Update %d: A is past the cap after %d failed downloads, want it retried", i, i-1)
		}
	}
	res, err := fx.run(t, named)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Outcomes["ipv4:A_v4"]; got != "retry-cap-reached" {
		t.Errorf("third Update: A's outcome %q, want retry-cap-reached after two failed downloads today", got)
	}

	day = day.Add(24 * time.Hour)
	res, err = fx.run(t, named)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Outcomes["ipv4:A_v4"]; got == "retry-cap-reached" {
		t.Error("next day: A is still past the cap, want the day's count to start again")
	}
}

// GIVEN ingest.feedSanity on, then off
// WHEN the loop builds its stages
// THEN the fetcher every per-feed stage uses runs the ADR-49 sanity scan exactly when the switch is on.
func TestTheFeedSanitySwitchReachesTheFetcher(t *testing.T) {
	for _, on := range []bool{true, false} {
		fx := newLoopFixture(t)
		fx.settings["ingest"]["feedSanity"] = on
		fx.reply(t)
		u := fx.updater(t, manual())
		if err := u.snapshot(); err != nil {
			t.Fatal(err)
		}
		if err := u.workList(); err != nil {
			t.Fatal(err)
		}
		for kind, stage := range u.stages {
			if stage.Fetcher.Sanity != on {
				t.Errorf("feedSanity %v: the %s stage's fetcher has Sanity %v", on, kind, stage.Fetcher.Sanity)
			}
		}
	}
}

// GIVEN a published feed that has not changed, and an apply window that does not hold now
// WHEN a scheduled Update names it, without and then with a change the Outpost holds for an apply
// THEN without one the Update runs today's no-update pass; with one the pass waits for the window and the apply only records
// the pending work (pendingOutsideWindow), as pfb_core_update_pending_apply() makes today's pass wait.
func TestAChangeTheOutpostHoldsWaitsForTheApplyWindow(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	fx.settings["ingest"]["applyWindow"] = outsideWindow(t)
	for _, pending := range []bool{false, true} {
		fx.replyPending(t, pending)
		if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}); err != nil {
			t.Fatal(err)
		}
		if got := fx.request(t)["pendingOutsideWindow"] == true; got != pending {
			t.Errorf("pendingApply %v: the apply's pendingOutsideWindow is %v, request %v", pending, got, fx.request(t))
		}
	}
}
