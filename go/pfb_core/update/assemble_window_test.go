package update

import (
	"fmt"
	"testing"
	"time"
)

// CodeRabbit r4671035943 (loop.go:103): the window is read again right before the apply of what the store holds
// unrequested, not taken from the change detection, so an Update that crosses the window's end applies nothing.
//
// GIVEN a published generation no apply took, and a window that holds now at the change detection
// WHEN the window has closed by the time the apply stage runs
// THEN no apply runs.
func TestTheWindowIsReadAgainBeforeTheApplyOfUnrequestedGenerations(t *testing.T) {
	fx := newLoopFixture(t)
	deferredActionEdit(t, fx)
	start := time.Date(2026, 11, 23, 10, 30, 0, 0, time.Local)
	fx.settings["ingest"]["applyWindow"] = fmt.Sprintf("%02d:00-%02d:00", start.Hour(), start.Hour()+1)
	fx.reply(t)
	prevNow, prevBoundary := loopNow, boundary
	t.Cleanup(func() { loopNow, boundary = prevNow, prevBoundary })
	loopNow = func() time.Time { return start }
	boundary = func(name string) {
		if name == "apply" {
			loopNow = func() time.Time { return start.Add(2 * time.Hour) } // the window has closed
		}
	}
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatal(err)
	}
	if fx.applyRuns(t) != runs {
		t.Errorf("apply runs %d, want %d: the window closed before the apply", fx.applyRuns(t), runs)
	}
}
