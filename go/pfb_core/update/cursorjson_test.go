package update

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

// A browser or a PHP float holds integers exactly only up to 2^53, and a cursor passes it at generation 8192.
func TestACursorPastTwoToThe53IsAJSONStringThatRoundTripsExactly(t *testing.T) {
	for _, next := range []int64{0, 4, 1<<53 - 1, 1<<53 + 1, 8192<<40 | 12345, math.MaxInt64} {
		raw := jsonOf(t, View{Next: next})
		if want := `"next":"` + strconv.FormatInt(next, 10) + `"`; !strings.Contains(raw, want) {
			t.Errorf("a View with next %d is %s, want %s: a JSON string", next, raw, want)
		}
		var back View
		if err := json.Unmarshal([]byte(raw), &back); err != nil || back.Next != next {
			t.Errorf("decoding %s = next %d (%v), want %d back exactly", raw, back.Next, err, next)
		}
	}
}

func TestAGateAtGeneration8192HandsOutACursorPast2To53AsAString(t *testing.T) {
	g := newGate(t, writes, nil)
	g.gen = 8192 // 8192<<40 is 2^53: the first generation a float cannot tell its offsets apart in
	if err := g.Start(Request{Trigger: "some log\n"}); err != nil {
		t.Fatal(err)
	}
	settle(t, g)
	v := g.View(0, 0)
	if v.Log != "some log\n" || v.Next <= 1<<53 {
		t.Fatalf("View(0) = log %q next %d, want the log and a cursor past 2^53", v.Log, v.Next)
	}
	var wire map[string]any
	if err := json.Unmarshal([]byte(jsonOf(t, v)), &wire); err != nil {
		t.Fatal(err)
	}
	s, ok := wire["next"].(string)
	if !ok {
		t.Fatalf("next on the wire is %T, want a string", wire["next"])
	}
	cursor, err := strconv.ParseInt(s, 10, 64)
	if err != nil || cursor != v.Next {
		t.Fatalf("next on the wire is %q, want the cursor %d exactly (%v)", s, v.Next, err)
	}
	if again := g.View(cursor, 0); again.Log != "" || again.Next != v.Next {
		t.Errorf("View from the cursor read back off the wire = log %q next %d, want nothing new and %d", again.Log, again.Next, v.Next)
	}
}
