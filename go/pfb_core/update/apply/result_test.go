package apply_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
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
		"an escaped control character":      `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"\u001b[31m\u0000x"}]}` + "\n",
		"an escaped C1 control":             `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"a\u0085b"}]}` + "\n",
		"an escaped line separator":         `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"a\u2028b"}]}` + "\n",
		"an escaped tab":                    `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"a\tb"}]}` + "\n",
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
	if got, err := read(t, file+"\n"); !errors.Is(err, apply.ErrCut) || len(got.Failed) != 2 {
		t.Errorf("a result of %d bytes whose first 1 MiB is two complete lines: %d failures, %v", len(file)+1, len(got.Failed), err)
	}
}

// WHEN the result is over 1 MiB THEN the complete lines inside the first 1 MiB count and the rest is reported as cut (ErrCut);
// WHEN a line inside the bound is refused THEN the result is refused whole, as it is within the bound.
func TestAResultOverItsBoundKeepsTheCompleteLinesInsideIt(t *testing.T) {
	a, b, c := lineOf(t, "geo-catalog", apply.MaxLine), lineOf(t, "ip-set/Top/ipv6", 300000), lineOf(t, "ip-set/Abuse/ipv4", 300000)
	got, err := read(t, a+b+c)
	if !errors.Is(err, apply.ErrCut) || len(got.Failed) != 2 || got.Failed[0].ID != "geo-catalog" || got.Failed[1].ID != "ip-set/Top/ipv6" {
		t.Errorf("%d bytes, the third line crossing 1 MiB: %d failures kept (%v), want the first two and ErrCut", len(a+b+c), len(got.Failed), err)
	}
	removal := `{"version":2,"removed":["ip-set/Old/ipv4"]}` + "\n"
	pad := lineOf(t, "ip-set/Top/ipv6", apply.MaxResult-len(a)-len(removal))
	if got, err := read(t, a+pad+removal+c); !errors.Is(err, apply.ErrCut) || len(got.Failed) != 2 || !reflect.DeepEqual(got.Removed, []string{"ip-set/Old/ipv4"}) {
		t.Errorf("a line ending at 1 MiB exactly: %+v (%v), want it kept", trim(got), err)
	}
	// the invalid line ends inside the first MaxResult bytes of a file that is over MaxResult: the kept prefix holds it
	for name, invalid := range map[string]string{
		"another version":           `{"version":1}` + "\n",
		"an id outside the request": `{"version":2,"applied":{"ip-set/Other/ipv4":"1"}}` + "\n",
		"an unknown field":          `{"version":2,"outcomes":{}}` + "\n",
	} {
		file := a + invalid + b + c
		if len(file) <= apply.MaxResult || len(a+invalid) > apply.MaxResult {
			t.Fatalf("%s: the probe is %d bytes and its invalid line ends at %d, want over %d and inside %d", name, len(file), len(a+invalid), apply.MaxResult, apply.MaxResult)
		}
		if got, err := read(t, file); err == nil || errors.Is(err, apply.ErrCut) || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("%s inside the bound of a result over it: %+v (%v), want it refused whole", name, trim(got), err)
		}
	}
}

// WHEN the work of reading a hostile result is measured THEN it grows with the lines read, never with the ids already read
// times the lines: no copy of what is read per line, no slice of every line. Bytes allocated stand for the work: they do not
// depend on the machine.
func TestTheWorkOfReadingAResultIsBounded(t *testing.T) {
	req := apply.Request{Trigger: "scheduled", Scope: "ip"}
	var applied strings.Builder
	for i := range apply.MaxIDs {
		id := fmt.Sprintf("ip-set/G%d/ipv4", i)
		req.Resources = append(req.Resources, apply.Resource{ID: id, Generation: 1, Action: "alias_only"})
		fmt.Fprintf(&applied, `,%q:"1"`, id)
	}
	head := `{"version":2,"applied":{` + applied.String()[1:] + "}}\n"
	fill := func(unit string) string { return head + strings.Repeat(unit, (apply.MaxResult-len(head))/len(unit)) }
	for name, c := range map[string]struct {
		file  string
		lines int // the non-empty lines read
	}{
		"2048 applied ids, then 60000 empty lines": {head + strings.Repeat("\n", 60000), 1},
		"only newlines":                        {strings.Repeat("\n", apply.MaxResult), 0},
		"2048 applied ids, then empty objects": {fill(`{"version":2}` + "\n"), (apply.MaxResult-len(head))/14 + 1},
	} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got, err := apply.ReadResult(strings.NewReader(c.file), req)
		runtime.ReadMemStats(&after)
		if err != nil || (c.lines > 0) != (len(got.Applied) == apply.MaxIDs) {
			t.Fatalf("%s: %d applied, %v", name, len(got.Applied), err)
		}
		// the file read once, the ids of the request and of one line held, and a few KiB per line decoded
		if bound := uint64(4<<20 + 3<<10*c.lines); after.TotalAlloc-before.TotalAlloc > bound {
			t.Errorf("%s: %d bytes allocated for %d lines, over %d", name, after.TotalAlloc-before.TotalAlloc, c.lines, bound)
		}
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

// WHEN a line is blank THEN it is skipped, but its bytes still count against the line bound, as a line of content does: past
// the bound the result is refused whole, terminated or not, with the line before it not kept.
func TestABlankLineKeepsToTheLineBound(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	if got, err := read(t, ok+strings.Repeat(" ", apply.MaxLine-1)+"\n"); err != nil || !reflect.DeepEqual(got.Applied, map[string]uint64{"geo-catalog": 3}) {
		t.Errorf("a blank line of exactly %d bytes: %+v (%v), want it skipped", apply.MaxLine, got, err)
	}
	for name, blank := range map[string]string{"terminated": strings.Repeat(" ", apply.MaxLine) + "\n", "unterminated": strings.Repeat(" ", apply.MaxLine)} {
		if got, err := read(t, ok+blank); err == nil || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("a %s blank line one byte over its bound: %+v (%v), want the result refused whole", name, got, err)
		}
	}
}

// WHEN a line is empty or holds only spaces THEN it is skipped; WHEN it holds any other whitespace THEN it is a line like any
// other and its byte that is not a space is refused, the result whole.
func TestOnlyEmptyAndSpaceLinesAreSkipped(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	if got, err := read(t, ok+"\n   \n\n"); err != nil || !reflect.DeepEqual(got.Applied, map[string]uint64{"geo-catalog": 3}) {
		t.Errorf("empty and space lines: %+v (%v), want them skipped", got, err)
	}
	for name, blank := range map[string]string{"CR": "\r", "tab": "\t", "vertical tab": "\v", "form feed": "\f", "no-break space": "\u00a0"} {
		if got, err := read(t, ok+blank+"\n"); err == nil || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("a line of a %s: %+v (%v), want the result refused whole", name, got, err)
		}
	}
}

// WHEN the last line is unterminated THEN only a proper prefix of one JSON value, shorter than the line bound, is a line the
// apply's death cut short and leaves the lines before it; any other bad last line refuses the result whole.
func TestAnUnterminatedLastLineIsKeptOnlyWhenCutShort(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	for name, last := range map[string]string{
		"a complete invalid value":          `{"version":1}`,
		"data after a complete value":       `{"version":2} {"version":2}`,
		"a stray byte after a value":        `{"version":1}x`,
		"content over the line bound":       `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"` + strings.Repeat("a", 600000),
		"spaces over the line bound":        strings.Repeat(" ", 600000),
		"a stray byte that starts no value": "x",
		"a syntax error no byte can repair": `{"version":2,}`,
	} {
		if got, err := read(t, ok+last); err == nil || errors.Is(err, apply.ErrCut) || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("%s as an unterminated last line: %+v (%v), want the result refused whole", name, trim(got), err)
		}
	}
	if got, err := read(t, ok+`{"version":2,"appl`); err == nil || !reflect.DeepEqual(got.Applied, map[string]uint64{"geo-catalog": 3}) {
		t.Errorf("a truncated last line: %+v (%v), want the first line's values and an error", got, err)
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

// WHEN one line is longer than the bound of the whole file, with or without its newline, THEN the writer broke the contract: the
// result is refused whole, as a line over MaxLine is, and it is no cut.
func TestALineLongerThanTheFileBoundIsRefusedNotCut(t *testing.T) {
	line := `{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"` + strings.Repeat("a", 2<<20)
	for name, file := range map[string]string{"without a newline": line, "with a newline at the end": line + "\"}]}\n"} {
		if got, err := read(t, file); err == nil || errors.Is(err, apply.ErrCut) || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("a line of 2 MiB %s: %+v (%v), want it refused whole and no ErrCut", name, trim(got), err)
		}
	}
}

// WHEN a result is over 1 MiB and what follows its last newline inside the first 1 MiB is MaxLine bytes or more THEN a line
// broke the line bound: the result is refused whole, with no ErrCut and no earlier line kept.
func TestACutTailOverTheLineBoundIsRefusedNotCut(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	long := lineOf(t, "geo-catalog", 1200<<10)
	for name, file := range map[string]string{"after a line": ok + long, "alone after a newline": "\n" + long} {
		if got, err := read(t, file); err == nil || errors.Is(err, apply.ErrCut) || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("a 1.2 MiB line %s: %+v (%v), want it refused whole and no ErrCut", name, trim(got), err)
		}
	}
}

// WHEN an empty result is read THEN the work does not depend on the bound: bytes allocated stay far under 1 MiB.
func TestReadingAnEmptyResultAllocatesLittle(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := read(t, ""); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 64<<10 {
		t.Errorf("an empty result allocates %d bytes, over 64 KiB", n)
	}
}

// WHEN a result of 1 MiB and one byte ends in a line of exactly MaxLine bytes, its newline the byte past the bound THEN
// the file is cut, not refused: no line of it is over the line bound, and the complete lines inside the first 1 MiB count.
func TestALegalLineEndingPastTheFileBoundIsCutNotRefused(t *testing.T) {
	first := lineOf(t, "ip-set/Abuse/ipv4", 1000)
	second := lineOf(t, "ip-set/Top/ipv6", apply.MaxLine+1-len(first))
	file := first + second + lineOf(t, "geo-catalog", apply.MaxLine)
	if len(file) != apply.MaxResult+1 {
		t.Fatalf("the probe is %d bytes, want %d", len(file), apply.MaxResult+1)
	}
	got, err := read(t, file)
	if !errors.Is(err, apply.ErrCut) || len(got.Failed) != 2 {
		t.Errorf("a legal last line ending past the bound: %+v (%v), want ErrCut and the two complete lines", trim(got), err)
	}
	// the same tail one byte longer and without its newline is a line over the bound: the writer broke it
	if got, err := read(t, first+second+strings.Repeat("a", apply.MaxLine)); err == nil || errors.Is(err, apply.ErrCut) ||
		!reflect.DeepEqual(got, apply.Result{}) {
		t.Errorf("a tail of MaxLine bytes without a newline: %+v (%v), want it refused whole", trim(got), err)
	}
}

// WHEN the unterminated last line is exactly at the line bound, starts no object or holds a byte the contract forbids
// THEN the apply's death did not cut it short: the result is refused whole. One byte under the bound it still counts as cut.
func TestAnUnterminatedLastLineIsCutShortOnlyAsAPrefixOfALine(t *testing.T) {
	ok := `{"version":2,"applied":{"geo-catalog":"3"}}` + "\n"
	open := `{"version":2,"failed":[{"id":"ip-set/Top/ipv6","stage":"apply","message":"`
	for name, last := range map[string]string{
		"a prefix of MaxLine bytes":  open + strings.Repeat("a", apply.MaxLine-len(open)),
		"a prefix of a list":         `[1,2,`,
		"a prefix with a UTF-8 byte": open + "café",
		"a tab":                      "\t",
		"a CR":                       "\r",
	} {
		if got, err := read(t, ok+last); err == nil || !reflect.DeepEqual(got, apply.Result{}) {
			t.Errorf("%s as an unterminated last line: %+v (%v), want the result refused whole", name, trim(got), err)
		}
	}
	under := open + strings.Repeat("a", apply.MaxLine-1-len(open))
	if got, err := read(t, ok+under); err == nil || !reflect.DeepEqual(got.Applied, map[string]uint64{"geo-catalog": 3}) {
		t.Errorf("a prefix of MaxLine-1 bytes: %+v (%v), want the first line's values and an error", trim(got), err)
	}
}
