package apply_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// WHEN Core writes a request with the settings read's pending token THEN the token's JSON value reaches the request byte for
// byte, whatever it holds, and no member is written for no token: the token is the platform's and Core never looks inside it.
func TestThePendingTokenReachesTheRequestUnchanged(t *testing.T) {
	for name, token := range map[string]json.RawMessage{
		"a string with escapes":   json.RawMessage(`"a\"b\\c\u0001\n\u00e9"`),
		"non-ASCII":               json.RawMessage(`"tökén 😀"`),
		"64 characters":           json.RawMessage(`"` + strings.Repeat("a", 64) + `"`),
		"65 characters":           json.RawMessage(`"` + strings.Repeat("a", 65) + `"`),
		"an empty string":         json.RawMessage(`""`),
		"a number, uninspected":   json.RawMessage(`12`),
		"null, as the read gave":  json.RawMessage(`null`),
		"none":                    nil,
		"an empty value, as none": {},
	} {
		t.Run(name, func(t *testing.T) {
			written, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", PendingToken: token})
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(written, &m); err != nil {
				t.Fatal(err)
			}
			got, present := m["pendingToken"]
			if present != (len(token) > 0) || string(got) != string(token) {
				t.Errorf("Core writes %s, the token is %q: want it byte for byte, and no member for none", written, token)
			}
		})
	}
}

// WHEN the token is not a JSON value THEN Encode fails, as for any value it cannot marshal: it writes no broken request.
func TestATokenThatIsNotJSONIsNotWritten(t *testing.T) {
	for _, token := range []string{`abc`, `"unterminated`, `{`, `"a" "b"`} {
		if written, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", PendingToken: json.RawMessage(token)}); err == nil {
			t.Errorf("%q: Core writes %s", token, written)
		}
	}
}

// WHEN the token is large THEN the 1 MiB bound holds for the request with the token in it: a token that alone fills it refuses
// the request, and beside a large token the issues that do not fit are left out.
func TestTheRequestBoundCountsTheToken(t *testing.T) {
	huge := json.RawMessage(`"` + strings.Repeat("a", apply.MaxRequest) + `"`)
	if _, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", PendingToken: huge}); err == nil {
		t.Error("Core writes a request whose token alone is over 1 MiB")
	}
	big := json.RawMessage(`"` + strings.Repeat("a", apply.MaxRequest-4096) + `"`)
	req := apply.Request{Trigger: "manual", Scope: "both", PendingToken: big}
	for range 100 {
		req.Issues = append(req.Issues, apply.Issue{Resource: "feed/ipv4:Foo_v4", Stage: "parse", Code: "x", Message: strings.Repeat("m", 1000)})
	}
	written, err := apply.Encode(req)
	if err != nil || len(written) > apply.MaxRequest {
		t.Fatalf("Core writes %d bytes (%v), want at most %d", len(written), err, apply.MaxRequest)
	}
	var m struct {
		PendingToken json.RawMessage `json:"pendingToken"`
		Issues       []apply.Issue   `json:"issues"`
	}
	if err := json.Unmarshal(written, &m); err != nil {
		t.Fatal(err)
	}
	if string(m.PendingToken) != string(big) || len(m.Issues) == 0 || len(m.Issues) > 4 || m.Issues[len(m.Issues)-1].Code != "issues_left_out" {
		t.Errorf("Core writes the token of %d bytes and %d issues, want the token whole and the issues that fit, then issues_left_out",
			len(m.PendingToken), len(m.Issues))
	}
}

// WHEN Core writes a narrower scope THEN a dnsbl scope lists no IP resource, removal or geo-catalog and an ip scope carries
// no dnsbl object (C row 13 of the #4038 plan).
func TestTheScopeRule(t *testing.T) {
	ipSet := apply.Resource{ID: "ip-set/Abuse/ipv4", Generation: 1, Action: "alias_only"}
	dnsbl := &apply.DNSBL{Generation: 1}
	for _, c := range []struct {
		name   string
		req    apply.Request
		writes bool
	}{
		{"dnsbl scope, dnsbl only", apply.Request{Scope: "dnsbl", DNSBL: dnsbl}, true},
		{"dnsbl scope, nothing", apply.Request{Scope: "dnsbl"}, true},
		{"dnsbl scope, an ip-set", apply.Request{Scope: "dnsbl", Resources: []apply.Resource{ipSet}}, false},
		{"dnsbl scope, the geo-catalog", apply.Request{Scope: "dnsbl", Resources: []apply.Resource{{ID: "geo-catalog", Generation: 1}}}, false},
		{"dnsbl scope, a removal", apply.Request{Scope: "dnsbl", Removed: []string{"ip-set/Old/ipv4"}}, false},
		{"ip scope, IP only", apply.Request{Scope: "ip", Resources: []apply.Resource{ipSet}, Removed: []string{"geo-catalog"}}, true},
		{"ip scope, a dnsbl object", apply.Request{Scope: "ip", DNSBL: dnsbl}, false},
		{"both, everything", apply.Request{Scope: "both", Resources: []apply.Resource{ipSet}, DNSBL: dnsbl}, true},
		{"no scope", apply.Request{}, false},
	} {
		c.req.Trigger = "manual"
		if _, err := apply.Encode(c.req); (err == nil) != c.writes {
			t.Errorf("%s: written %v (%v), want %v", c.name, err == nil, err, c.writes)
		}
	}
}

// WHEN a count is negative THEN Core refuses to write it; the largest int is written as it is (the validator's 2^63-1).
func TestTheEntriesBound(t *testing.T) {
	res := func(n int) apply.Request {
		return apply.Request{Trigger: "manual", Scope: "both", Resources: []apply.Resource{{ID: "ip-set/A/ipv4", Generation: 1, Action: "alias_only", Entries: n}}}
	}
	grp := func(n int) apply.Request {
		return apply.Request{Trigger: "manual", Scope: "both", DNSBL: &apply.DNSBL{Generation: 1, Groups: []apply.Group{{Name: "Ads", Entries: n}}}}
	}
	for _, r := range []apply.Request{res(-1), grp(-1)} {
		if _, err := apply.Encode(r); err == nil {
			t.Errorf("a negative count is written: %+v", r)
		}
	}
	if b, err := apply.Encode(res(9223372036854775807)); err != nil || !strings.Contains(string(b), `"entries":9223372036854775807`) {
		t.Errorf("the largest count: %s %v", b, err)
	}
}

// WHEN an issue is written THEN each field is written in the normal form the apply keeps unchanged, never refused: issues are
// informational, and one noisy feed must not stop every table from loading. The message is BoundedText; the resource and the
// code are 1 to 256 printable ASCII characters, any other byte written as "?" and an empty one as "unknown".
func TestIssueFieldsAreWrittenInTheirNormalForm(t *testing.T) {
	issue := func(resource, code, message string) apply.Issue {
		return apply.Issue{Resource: resource, Stage: "parse", Code: code, Message: message}
	}
	for name, c := range map[string]struct{ in, want apply.Issue }{
		"plain":                              {issue("feed/ipv4:Foo_v4", "exit_1", "the script exited 1"), issue("feed/ipv4:Foo_v4", "exit_1", "the script exited 1")},
		"an empty message":                   {issue("r", "c", ""), issue("r", "c", "")},
		"a message of 1024 bytes":            {issue("r", "c", strings.Repeat("a", 1024)), issue("r", "c", strings.Repeat("a", 1024))},
		"a message of 1025 bytes":            {issue("r", "c", strings.Repeat("a", 1025)), issue("r", "c", strings.Repeat("a", 1024))},
		"a message with a line break":        {issue("r", "c", "one\ntwo"), issue("r", "c", "one two")},
		"a message with a tab":               {issue("r", "c", "one\ttwo"), issue("r", "c", "one two")},
		"a message with a leading space":     {issue("r", "c", " m"), issue("r", "c", "m")},
		"a message with a trailing space":    {issue("r", "c", "m "), issue("r", "c", "m")},
		"a message not ASCII":                {issue("r", "c", "café au lait"), issue("r", "c", "caf  au lait")},
		"a resource not ASCII":               {issue("café", "c", "m"), issue("caf??", "c", "m")},
		"a resource of 256 bytes":            {issue(strings.Repeat("r", 256), "c", "m"), issue(strings.Repeat("r", 256), "c", "m")},
		"a resource of 257 bytes":            {issue(strings.Repeat("r", 257), "c", "m"), issue(strings.Repeat("r", 256), "c", "m")},
		"a resource with spaces at the ends": {issue(" r ", "c", "m"), issue(" r ", "c", "m")},
		"an empty resource":                  {issue("", "c", "m"), issue("unknown", "c", "m")},
		"an empty code":                      {issue("r", "", "m"), issue("r", "unknown", "m")},
		"a code with DEL and a tab":          {issue("r", "c\x7f\tc", "m"), issue("r", "c??c", "m")},
		"a code of 300 bytes not ASCII":      {issue("r", strings.Repeat("é", 150), "m"), issue("r", strings.Repeat("?", 256), "m")},
	} {
		b, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", Issues: []apply.Issue{c.in}})
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if got := issuesOf(t, b); !reflect.DeepEqual(got, []apply.Issue{c.want}) {
			t.Errorf("%s: Core writes %+q, want %+q", name, got, c.want)
		}
	}
	if _, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", Issues: []apply.Issue{{Resource: "r", Stage: "fetch", Code: "c"}}}); err == nil {
		t.Error("an issue of another stage is written: the stage is Core's own word, not the feed's")
	}
}

func issuesOf(t *testing.T, written []byte) []apply.Issue {
	t.Helper()
	var w struct{ Issues []apply.Issue }
	if err := json.Unmarshal(written, &w); err != nil {
		t.Fatal(err)
	}
	return w.Issues
}

// WHEN a message is made bounded text THEN the apply keeps it unchanged (pfb_core_update_v2_message() is the identity on it):
// each run of bytes outside printable ASCII is one space, no space at either end, at most 1024 bytes.
func TestBoundedText(t *testing.T) {
	for in, want := range map[string]string{
		"":                                   "",
		"plain":                              "plain",
		" \t\r\n ":                           "",
		"a\x00\x01\x1f\x7fb":                 "a b",
		"a \x00 b":                           "a   b",
		"one\u2028two\u2029three":            "one two three",
		"zero\u200bwidth":                    "zero width",
		"bad \xff\xfe utf8":                  "bad   utf8",
		"\xc3":                               "",
		`"<i>" &amp; \`:                      `"<i>" &amp; \`,
		strings.Repeat("a", 1023) + " b":     strings.Repeat("a", 1023),
		strings.Repeat("a", 1024) + "b":      strings.Repeat("a", 1024),
		strings.Repeat("\xff", 5000) + "x":   "x",
		strings.Repeat("ab\x00", 1000):       strings.Repeat("ab ", 341) + "a",
		" " + strings.Repeat("a", 1100):      strings.Repeat("a", 1024), // trimmed before the cut, as the apply does
		"\x00\t" + strings.Repeat("a", 1100): strings.Repeat("a", 1024),
	} {
		if got := apply.BoundedText(in); got != want {
			t.Errorf("%+.80q: %+.80q, want %+.80q", in, got, want)
		}
	}
	// generated strings of every byte class: the result is text the apply keeps, and BoundedText keeps it too
	for _, s := range generatedText() {
		got := apply.BoundedText(s)
		if len(got) > 1024 || !printable([]byte(got)) || strings.TrimSpace(got) != got || apply.BoundedText(got) != got {
			t.Fatalf("%+q makes %+q: not bounded text the apply keeps", s, got)
		}
	}
}

// generatedText is 2000 strings of up to 1400 parts from every byte class: printable ASCII, white space, C0 and DEL, C1 and
// lone continuation bytes, invalid and truncated UTF-8, a surrogate, line separators and valid non-ASCII text.
func generatedText() []string {
	classes := []string{"a", " ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f", "\x80", "\xff", "\xc3", "é", "\u2028", "\u200b",
		"\xed\xa0\x80", `"`, `\`, "~", "<i>"}
	seed := uint32(1)
	next := func(n int) int { seed = seed*1664525 + 1013904223; return int(seed>>8) % n }
	var out []string
	for range 2000 {
		var b strings.Builder
		for range next(1400) {
			b.WriteString(classes[next(len(classes))])
		}
		out = append(out, b.String())
	}
	return out
}

// WHEN the issues push a request over 4096 entries or 1 MiB THEN Core keeps the first issues that fit beside every resource
// and adds one issue saying how many were left out; WHEN everything fits THEN nothing is left out.
func TestIssuesOverTheBoundsAreLeftOutAndCounted(t *testing.T) {
	req := apply.Request{Trigger: "scheduled", Scope: "both", Resources: []apply.Resource{{ID: "ip-set/Abuse/ipv4", Generation: 1, Action: "alias_only"}}}
	for i := range 5000 {
		req.Issues = append(req.Issues, apply.Issue{Resource: fmt.Sprintf("feed/ipv4:Quotes%d_v4", i), Stage: "parse", Code: "quotes", Message: strings.Repeat(`"`, 1024)})
	}
	b, err := apply.Encode(req)
	if err != nil || len(b) > apply.MaxRequest {
		t.Fatalf("5000 issues of 1 KiB of quotes: %d bytes, %v", len(b), err)
	}
	got := issuesOf(t, b)
	kept := len(got) - 1
	if kept < 400 || !reflect.DeepEqual(got[:kept], req.Issues[:kept]) || !strings.Contains(string(b), `"resources":[{"id":"ip-set/Abuse/ipv4"`) {
		t.Fatalf("Core keeps %d issues, not the first ones in order beside the resource", kept)
	}
	if want := summary(5000 - kept); got[kept] != want {
		t.Errorf("the last issue is %+v, want %+v", got[kept], want)
	}
	if next, _ := json.Marshal(req.Issues[kept]); len(b)+len(next)+1 <= apply.MaxRequest {
		t.Errorf("issue %d is left out, although it fits beside the summary", kept)
	}

	small := apply.Request{Trigger: "manual", Scope: "both"}
	for i := range 4097 {
		small.Issues = append(small.Issues, apply.Issue{Resource: fmt.Sprint(i), Stage: "parse", Code: "c", Message: "m"})
	}
	b, err = apply.Encode(small)
	if got := issuesOf(t, b); err != nil || len(got) != 4096 || got[4094].Resource != "4094" || got[4095] != summary(2) {
		t.Errorf("4097 issues: %d written (%v)", len(got), err)
	}
	small.Issues = small.Issues[:4096]
	if b, err = apply.Encode(small); err != nil || len(issuesOf(t, b)) != 4096 || issuesOf(t, b)[4095].Resource != "4095" {
		t.Errorf("4096 issues are not written whole: %v", err)
	}
}

func summary(n int) apply.Issue {
	return apply.Issue{Resource: "core-updater", Stage: "apply", Code: "issues_left_out",
		Message: fmt.Sprintf("%d more issues were left out to fit the request", n)}
}

// WHEN the resources alone are over 1 MiB THEN Core refuses the request: issues are left out, resources never.
func TestARequestWhoseResourcesDoNotFitIsRefused(t *testing.T) {
	r := apply.Request{Trigger: "scheduled", Scope: "both", DNSBL: &apply.DNSBL{Generation: 1}}
	for i := range apply.MaxIDs {
		r.Resources = append(r.Resources, apply.Resource{ID: fmt.Sprintf("ip-set/G%023d/ipv4", i), Generation: 18446744073709551615,
			Action: "permit", Direction: []string{"ingress", "egress"}, Entries: 9223372036854775807})
	}
	for i := range 4096 {
		r.DNSBL.Groups = append(r.DNSBL.Groups, apply.Group{Name: fmt.Sprintf("G%0127d", i), Entries: 9223372036854775807})
	}
	if b, err := apply.Encode(r); err == nil || !strings.Contains(err.Error(), "1048576") {
		t.Errorf("resources over 1 MiB: %d bytes written (%v)", len(b), err)
	}
	r.DNSBL.Groups = r.DNSBL.Groups[:3000]
	r.Issues = []apply.Issue{{Resource: "r", Stage: "parse", Code: "c", Message: strings.Repeat("m", 1024)}}
	if b, err := apply.Encode(r); err != nil || len(b) > apply.MaxRequest || len(issuesOf(t, b)) != 1 {
		t.Errorf("resources that fit beside an issue: %d bytes (%v)", len(b), err)
	}
}

// WHEN a request would be over the apply's bounds THEN Core refuses to write it over 2048 ids, and cuts its issues to fit 1 MiB.
func TestTheBoundsOfARequest(t *testing.T) {
	ids := func(n int) apply.Request {
		r := apply.Request{Trigger: "scheduled", Scope: "ip"}
		for i := range n {
			r.Resources = append(r.Resources, apply.Resource{ID: fmt.Sprintf("ip-set/G%d/ipv4", i), Generation: 1, Action: "alias_only"})
		}
		return r
	}
	if _, err := apply.Encode(ids(apply.MaxIDs)); err != nil {
		t.Errorf("%d ids are refused: %v", apply.MaxIDs, err)
	}
	over := ids(apply.MaxIDs - 1)
	over.Removed = []string{"ip-set/Gx/ipv4", "ip-set/Gy/ipv4"}
	if _, err := apply.Encode(over); err == nil {
		t.Errorf("%d ids are written", apply.MaxIDs+1)
	}
	big := apply.Request{Trigger: "scheduled", Scope: "both"}
	for i := range 4096 {
		big.Issues = append(big.Issues, apply.Issue{Resource: fmt.Sprint(i), Stage: "parse", Code: "c", Message: strings.Repeat("m", 1024)})
	}
	b, err := apply.Encode(big)
	if err != nil || len(b) > apply.MaxRequest {
		t.Fatalf("4096 issues of 1 KiB: %d bytes written (%v)", len(b), err)
	}
	// the largest prefix that fits, in order, then the count of the rest: dropping every issue or too many must fail
	got := issuesOf(t, b)
	kept := len(got) - 1
	if kept < 1 || kept >= 4096 || !reflect.DeepEqual(got[:kept], big.Issues[:kept]) || got[kept] != summary(4096-kept) {
		t.Fatalf("Core writes %d issues, want a non-empty prefix of the 4096 in order and a summary of the rest", len(got))
	}
	// the estimate ignores the summary count's digits and HTML escaping, which the probe's issues do not exercise
	if next, _ := json.Marshal(big.Issues[kept]); len(b)+len(next)+1 <= apply.MaxRequest {
		t.Errorf("issue %d is left out, although it fits beside the summary", kept)
	}
}

// WHEN a group's ip-set id is asked for THEN it is ip-set/<group>/<family> when that id maps to an alias, and none otherwise:
// a group with a dash, too long for a pf table name, or taking an aggregate's reserved alias cannot be published.
func TestTheIdOfAGroup(t *testing.T) {
	for _, c := range []struct{ group, family, id string }{
		{"Abuse", "ipv4", "ip-set/Abuse/ipv4"},
		{"Africa", "ipv6", "ip-set/Africa/ipv6"},
		{"DNSBLIP", "ipv4", "ip-set/DNSBLIP/ipv4"},
		{"ABCDEFGHIJKLMNOPQRSTUVWX", "ipv4", "ip-set/ABCDEFGHIJKLMNOPQRSTUVWX/ipv4"},
		{"deny_Aggregated", "ipv4", "ip-set/deny_Aggregated/ipv4"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXY", "ipv4", ""},
		{"Deny_Aggregated", "ipv4", ""},
		{"Native_Aggregated", "ipv6", ""},
		{"Foo-Bar", "ipv4", ""},
		{"Foo/Bar", "ipv4", ""},
		{"", "ipv4", ""},
		{"Abuse", "v4", ""},
	} {
		id, ok := apply.SetID(c.group, c.family)
		if id != c.id || ok != (c.id != "") {
			t.Errorf("%q %q: %q (%v), want %q", c.group, c.family, id, ok, c.id)
		}
		if ok {
			if alias, _ := apply.Alias(id); alias != "pfB_"+c.group+"_v"+c.family[3:] {
				t.Errorf("%s maps to %q", id, alias)
			}
		}
	}
}

// WHEN a hundred thousand issues are given THEN the left-out count is the number given minus the number kept, and the work stays
// proportional to what is kept: about 4096 issues are normalised and encoded, never all of them.
func TestTheWorkOfEncodingIssuesIsBoundedByWhatIsKept(t *testing.T) {
	const given = 100000
	req := apply.Request{Trigger: "scheduled", Scope: "both"}
	for i := range given {
		req.Issues = append(req.Issues, apply.Issue{Resource: fmt.Sprint(i), Stage: "parse", Code: "c", Message: strings.Repeat("m", 1024)})
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	b, err := apply.Encode(req)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	got := issuesOf(t, b)
	kept := len(got) - 1
	if kept < 400 || got[kept] != summary(given-kept) {
		t.Errorf("%d issues written, the last is %+v: want the count of %d given minus %d kept", len(got), got[kept], given, kept)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 128<<20 {
		t.Errorf("%d issues of 1 KiB allocate %d bytes, over 128 MiB", given, n)
	}
}
