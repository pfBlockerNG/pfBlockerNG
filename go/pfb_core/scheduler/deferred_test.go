package scheduler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// A deferred Update (the program chose not to run now) ran nothing: whatever it reported is not recorded, not even the GeoIP
// readiness, and the log does not call it a failure.
func TestADeferredUpdateRecordsNothing(t *testing.T) {
	f := newFixture(t, allEntries(), quiet)
	f.removeFile()
	deferred := fmt.Errorf("the update program deferred: %w", update.ErrDeferred)
	res := update.Result{Outcomes: map[string]string{feedA: "success"}, Attempted: []string{dcc}, GeoIPReady: new(false)}

	f.s.Done(update.Request{Trigger: "scheduled"}, res, deferred)

	f.noFile()
	if text := f.logText(); strings.Contains(text, "failed") || !strings.Contains(text, "deferred") {
		t.Errorf("the log = %q, want the deferral named and no failure", text)
	}
	if err := f.s.Tick(); err != nil { // a GeoIP report of not-ready would make dcc due
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d Updates requested after a deferred one that reported GeoIP not ready, want 0: the report is not recorded", n)
	}
}
