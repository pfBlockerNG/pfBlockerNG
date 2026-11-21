package update

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The version 1 requests of tests/core/fixtures/update_request_v1.json, which the Outpost worker's tests feed to
// pfb_core_update_request() (tests/php/CoreUpdateServeTest.php): WHEN Core writes each one THEN it holds exactly the members
// the fixture names, so a member renamed or added on one side fails a test on the other (issue #4035: the worker refused
// lifecycle and pkgOp once).
func TestCoreWritesTheVersion1RequestsTheWorkerAccepts(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/core/fixtures/update_request_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Description string            `json:"description"`
		Requests    []json.RawMessage `json:"requests"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Requests) == 0 {
		t.Fatal("the fixture names no request")
	}
	for _, want := range fixture.Requests {
		dec := json.NewDecoder(bytes.NewReader(want))
		dec.DisallowUnknownFields()
		var req struct {
			Version int `json:"version"`
			Request
		}
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("%s: not a Request: %v", want, err)
		}
		if req.Version != protocolVersion {
			t.Fatalf("%s: version %d, not %d", want, req.Version, protocolVersion)
		}
		got, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		var g, w map[string]any
		if err := json.Unmarshal(got, &g); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("Core writes %s, the fixture says %s", got, want)
		}
	}
}
