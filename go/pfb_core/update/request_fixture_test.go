package update

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// requestFixture is tests/core/fixtures/update_request_v1.json: the version 1 requests Core writes to an Update program run
// without the loop, which only the test binary does since #3977 (the Outpost serves version 2 alone), and members, the names
// a request may hold. A member Core adds, drops or renames fails TestTheFixtureListsEveryMemberOfTheVersion1Request until
// members changes.
type requestFixture struct {
	Requests []json.RawMessage `json:"requests"`
	Members  []string          `json:"members"`
}

func readRequestFixture(t *testing.T) requestFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../tests/core/fixtures/update_request_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture requestFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// WHEN Core writes each request of the fixture THEN it holds exactly the members the fixture names.
func TestCoreWritesTheVersion1RequestsTheWorkerAccepts(t *testing.T) {
	fixture := readRequestFixture(t)
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

// WHEN the members of a version 1 request are listed from Request's JSON names plus version THEN they are exactly the
// fixture's members.
func TestTheFixtureListsEveryMemberOfTheVersion1Request(t *testing.T) {
	members := []string{"version"}
	request := reflect.TypeFor[Request]()
	for i := range request.NumField() {
		name, _, _ := strings.Cut(request.Field(i).Tag.Get("json"), ",")
		members = append(members, name)
	}
	slices.Sort(members)
	if listed := slices.Sorted(slices.Values(readRequestFixture(t).Members)); !slices.Equal(members, listed) {
		t.Errorf("a version 1 request holds %q, the fixture lists %q", members, listed)
	}
}
