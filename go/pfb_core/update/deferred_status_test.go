package update

import (
	"errors"
	"reflect"
	"testing"
)

// WHEN the program reports outcomes and then exits with status 75 THEN the status the worker publishes holds an empty
// result: a deferred Update reports nothing, to Core or to a Core that reads the receipt later.
func TestADeferredUpdatePublishesAnEmptyResultInItsStatus(t *testing.T) {
	payload := `{"version":1,"outcomes":{"ipv4:a_v4":"success"},"attempted":["ipv4:a_v4"],"geoipReady":true}`
	log := newLog(t)
	if _, err := runCmd(t, withResult(t, payload, 75), Request{Trigger: "scheduled"}, log); !errors.Is(err, ErrDeferred) {
		t.Fatalf("Run = %v, want ErrDeferred", err)
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil || state.ExitCode == nil || *state.ExitCode != deferredStatus {
		t.Fatalf("status = %+v, %v; want exit status 75", state, err)
	}
	if !reflect.DeepEqual(state.Result, Result{}) {
		t.Errorf("the published result = %s, want empty for a deferred Update", jsonOf(t, state.Result))
	}
}
