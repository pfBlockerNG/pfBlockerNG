package update

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Exit status 75 (EX_TEMPFAIL) is how the program says it chose not to run now (a lock held, the schedule switched off): an
// Update that was deferred, not one that failed.
func TestAnExitOf75IsErrDeferredAndReportsNothing(t *testing.T) {
	payload := `{"version":1,"outcomes":{"ipv4:a_v4":"success"},"attempted":["ipv4:a_v4"],"geoipReady":true}`
	res, err := runCmd(t, withResult(t, payload, 75), Request{Trigger: "scheduled"}, newLog(t))
	if !errors.Is(err, ErrDeferred) {
		t.Errorf("Run = %v, want ErrDeferred", err)
	}
	if !reflect.DeepEqual(res, Result{}) {
		t.Errorf("Run returned %s for a deferred Update, want nothing reported", jsonOf(t, res))
	}
}

func TestOtherNonZeroExitsAreNotDeferred(t *testing.T) {
	for _, status := range []int{1, 2, 74, 76, 127} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			_, err := runCmd(t, withResult(t, "", status), Request{Trigger: "scheduled"}, newLog(t))
			if err == nil || errors.Is(err, ErrDeferred) {
				t.Errorf("exit status %d: Run = %v, want a failure that is not ErrDeferred", status, err)
			}
		})
	}
}

func TestADeferredUpdateEndsSkippedAndDoneSeesTheDeferral(t *testing.T) {
	seen := make(chan error, 1)
	h := newHold()
	g := newGate(t, h.run, func(_ Request, _ Result, err error) { seen <- err })
	if err := g.Start(Request{Trigger: "scheduled"}); err != nil {
		t.Fatal(err)
	}
	h.finish(t, fmt.Errorf("the update program deferred: %w", ErrDeferred))
	if err := recv(t, seen, "done to be called"); !errors.Is(err, ErrDeferred) {
		t.Errorf("done was called with %v, want ErrDeferred", err)
	}
	settle(t, g)
	v := g.View(0, 0)
	if v.Running || v.Update == nil || v.Update.Result != "skipped" || v.Update.FinishedAt == nil {
		t.Errorf("View = %s, want a finished Update whose result is skipped", jsonOf(t, v))
	}
}
