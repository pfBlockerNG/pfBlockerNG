package apply_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// The request the hostile result lines below answer: two ip-sets, the geo-catalog, and one removal.
var answered = apply.Request{Trigger: "scheduled", Scope: "both",
	Resources: []apply.Resource{
		{ID: "ip-set/Abuse/ipv4", Generation: 42, Action: "deny", Direction: []string{"ingress"}, Entries: 3},
		{ID: "ip-set/Top/ipv6", Generation: 7, Action: "alias_only"},
		{ID: "geo-catalog", Generation: 3},
	},
	Removed: []string{"ip-set/Old/ipv4"},
}

func read(t *testing.T, file string) (apply.Result, error) {
	t.Helper()
	return apply.ReadResult(strings.NewReader(file), answered)
}

// A line of exactly n bytes, its newline included: one failure of id whose message pads it.
func lineOf(t *testing.T, id string, n int) string {
	t.Helper()
	head, tail := `{"version":2,"failed":[{"id":"`+id+`","stage":"apply","message":"`, "\"}]}\n"
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}

// WHEN the result lines of one apply are read THEN they add up: applied ids, removals, failures and aliases of every line, and
// a flag true when any line says so.
func TestTheLinesOfOneApplyAddUp(t *testing.T) {
	got, err := read(t, `{"version":2,"applied":{"ip-set/Abuse/ipv4":"42"},"changedAliases":["pfB_Abuse_v4"],"ipChanged":true}`+"\n"+
		`{"version":2,"applied":{"geo-catalog":"3"},"removed":["ip-set/Old/ipv4"],"changedAliases":["pfB_Old_v4","pfB_Abuse_v4"],`+
		`"ipChanged":false,"reloadLaunched":true,"failed":[{"id":"ip-set/Top/ipv6","stage":"fetch","message":"GetResources: unavailable"}]}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	want := apply.Result{
		Applied:        map[string]uint64{"ip-set/Abuse/ipv4": 42, "geo-catalog": 3},
		Removed:        []string{"ip-set/Old/ipv4"},
		ChangedAliases: []string{"pfB_Abuse_v4", "pfB_Old_v4"},
		IPChanged:      true,
		ReloadLaunched: true,
		Failed:         []apply.Failure{{ID: "ip-set/Top/ipv6", Stage: "fetch", Message: "GetResources: unavailable"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Core reads %+v, the lines hold %+v", got, want)
	}
}

// WHEN the apply wrote nothing THEN nothing was applied, and that is no error.
func TestAnEmptyResultIsNothingApplied(t *testing.T) {
	got, err := read(t, "")
	if err != nil || !reflect.DeepEqual(got, apply.Result{}) {
		t.Errorf("an empty result reads as %+v, %v", got, err)
	}
}

// WHEN a line is the hostile input of a row below THEN the result is refused whole: nothing of it is settled.
func TestAHostileResultLineIsRefused(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	for name, file := range map[string]string{
		"another version":                   `{"version":1,"applied":{"geo-catalog":"3"}}` + "\n",
		"version 3":                         `{"version":3}` + "\n",
		"no version":                        `{"applied":{"geo-catalog":"3"}}` + "\n",
		"an unknown field":                  `{"version":2,"outcomes":{}}` + "\n",
		"an unknown field of a failure":     `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"m","code":"x"}]}` + "\n",
		"a line one byte over its bound":    lineOf(t, "geo-catalog", apply.MaxLine+1),
		"an id outside the request":         `{"version":2,"applied":{"ip-set/Other/ipv4":"1"}}` + "\n",
		"a failure outside the request":     `{"version":2,"failed":[{"id":"ip-set/Other/ipv4","stage":"apply","message":"m"}]}` + "\n",
		"a removal the request did not ask": `{"version":2,"removed":["ip-set/Abuse/ipv4"]}` + "\n",
		"an applied removal":                `{"version":2,"applied":{"ip-set/Old/ipv4":"1"}}` + "\n",
		"an alias outside the request":      `{"version":2,"changedAliases":["pfB_Other_v4"]}` + "\n",
		"another generation":                `{"version":2,"applied":{"ip-set/Abuse/ipv4":"41"}}` + "\n",
		"a generation of 21 digits":         `{"version":2,"applied":{"ip-set/Abuse/ipv4":"000000000000000000042"}}` + "\n",
		"a generation with a sign":          `{"version":2,"applied":{"ip-set/Abuse/ipv4":"+42"}}` + "\n",
		"an id applied on two lines":        ok + ok,
		"an id applied and failed":          ok + `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"m"}]}` + "\n",
		"an alias twice on a line":          `{"version":2,"changedAliases":["pfB_Abuse_v4","pfB_Abuse_v4"]}` + "\n",
		"a byte that is not printable":      `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"caf` + "\xc3\xa9" + `"}]}` + "\n",
		"a null flag":                       `{"version":2,"reloadLaunched":null}` + "\n",
		"a failure without a message":       `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply"}]}` + "\n",
		"a failure of another stage":        `{"version":2,"failed":[{"id":"geo-catalog","stage":"parse","message":"m"}]}` + "\n",
		"data after the object":             `{"version":2} {"version":2}` + "\n",
		"a bad line before a good one":      "{\n" + ok,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := read(t, file); err == nil || !reflect.DeepEqual(got, apply.Result{}) {
				t.Errorf("Core reads %+v (%v), it must refuse the result whole", got, err)
			}
		})
	}
}

// WHEN a line is at its bound THEN it is read; WHEN the file is 1 MiB THEN it is read, and one byte more is refused.
func TestTheBoundsOfALineAndOfTheFile(t *testing.T) {
	file := lineOf(t, "geo-catalog", apply.MaxLine) + lineOf(t, "ip-set/Top/ipv6", apply.MaxLine)
	if len(file) != apply.MaxResult {
		t.Fatalf("the probe is %d bytes", len(file))
	}
	if got, err := read(t, file); err != nil || len(got.Failed) != 2 {
		t.Errorf("two lines of exactly %d bytes are refused: %v", apply.MaxLine, err)
	}
	if got, err := read(t, file+"\n"); err == nil || !strings.Contains(err.Error(), "1 MiB") || !reflect.DeepEqual(got, apply.Result{}) {
		t.Errorf("a result of %d bytes is read: %+v %v", len(file)+1, len(got.Failed), err)
	}
}

// WHEN the last line is bad and unterminated (the apply died writing it) THEN the lines before it count, with the error.
func TestALineCutShortByDeathKeepsTheLinesBeforeIt(t *testing.T) {
	got, err := read(t, `{"version":2,"applied":{"geo-catalog":"3"}}`+"\n"+`{"version":2,"applied":{"ip-set/Ab`)
	if err == nil {
		t.Error("a cut line is no error")
	}
	if want := (apply.Result{Applied: map[string]uint64{"geo-catalog": 3}}); !reflect.DeepEqual(got, want) {
		t.Errorf("Core keeps %+v, the complete line holds %+v", got, want)
	}
}

// WHEN the apply exits THEN its status means what the contract says: 0 and failure keep the result lines, 75 and 2 discard them.
func TestTheExitStatusOfTheApply(t *testing.T) {
	for status, want := range map[int]apply.Exit{0: apply.Succeeded, 75: apply.Deferred, 2: apply.Refused, 1: apply.Failed, 3: apply.Failed,
		74: apply.Failed, 76: apply.Failed, -1: apply.Failed, 255: apply.Failed} {
		if got := apply.ExitOf(status); got != want {
			t.Errorf("exit %d means %v, want %v", status, got, want)
		}
	}
	for e, counts := range map[apply.Exit]bool{apply.Succeeded: true, apply.Failed: true, apply.Deferred: false, apply.Refused: false} {
		if e.Counts() != counts {
			t.Errorf("%v: the result lines count %v, want %v", e, e.Counts(), counts)
		}
	}
}

// WHEN the result is read from a large file THEN only the first 1 MiB and one byte are read.
func TestTheReaderStopsAtItsBound(t *testing.T) {
	var reads countingReader
	reads.r = bytes.NewReader(make([]byte, 64<<20))
	if _, err := apply.ReadResult(&reads, answered); err == nil {
		t.Error("64 MiB of NUL is read")
	}
	if reads.n > apply.MaxResult+1 {
		t.Errorf("%d bytes read, at most %d", reads.n, apply.MaxResult+1)
	}
}

type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += n
	return n, err
}
