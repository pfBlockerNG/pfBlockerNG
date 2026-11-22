package apply_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// WHEN a marker's text is checked against the apply's rule THEN only 1 to 64 printable ASCII characters without the space pass:
// the Updater fails an Update at the snapshot on any other, naming the marker (C row 12 of the #4038 plan).
func TestThePendingTokenRule(t *testing.T) {
	for token, valid := range map[string]bool{
		"0123456789abcdef": true, "~": true, "!": true, strings.Repeat("a", 64): true,
		"": false, strings.Repeat("a", 65): false, "a b": false, "abc\n": false, "a\x00b": false, "café": false, "a\x7fb": false,
	} {
		if got := apply.ValidToken(token); got != valid {
			t.Errorf("%q: %v, want %v", token, got, valid)
		}
		_, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "both", PendingToken: token})
		if (err == nil) != (valid || token == "") {
			t.Errorf("%q: Core writes it: %v, its rule says %v", token, err == nil, valid)
		}
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

// WHEN an issue is written THEN its fields are printable ASCII as the apply takes them, or Core refuses to write it.
func TestIssueFieldsArePrintableAscii(t *testing.T) {
	issue := func(resource, code, message string) apply.Request {
		return apply.Request{Trigger: "manual", Scope: "both", Issues: []apply.Issue{{Resource: resource, Stage: "parse", Code: code, Message: message}}}
	}
	for name, c := range map[string]struct {
		req    apply.Request
		writes bool
	}{
		"plain":                           {issue("feed/ipv4:Foo_v4", "exit_1", "the script exited 1"), true},
		"an empty message":                {issue("r", "c", ""), true},
		"a message of 1024 bytes":         {issue("r", "c", strings.Repeat("a", 1024)), true},
		"a message of 1025 bytes":         {issue("r", "c", strings.Repeat("a", 1025)), false},
		"a message with a line break":     {issue("r", "c", "one\ntwo"), false},
		"a message with a tab":            {issue("r", "c", "one\ttwo"), false},
		"a message with a leading space":  {issue("r", "c", " m"), false},
		"a message with a trailing space": {issue("r", "c", "m "), false},
		"a message not ASCII":             {issue("r", "c", "café"), false},
		"a resource not ASCII":            {issue("café", "c", "m"), false},
		"a resource of 256 bytes":         {issue(strings.Repeat("r", 256), "c", "m"), true},
		"a resource of 257 bytes":         {issue(strings.Repeat("r", 257), "c", "m"), false},
		"an empty code":                   {issue("r", "", "m"), false},
		"a code with DEL":                 {issue("r", "c\x7f", "m"), false},
		"another stage":                   {apply.Request{Trigger: "manual", Scope: "both", Issues: []apply.Issue{{Resource: "r", Stage: "fetch", Code: "c"}}}, false},
	} {
		if _, err := apply.Encode(c.req); (err == nil) != c.writes {
			t.Errorf("%s: written %v (%v), want %v", name, err == nil, err, c.writes)
		}
	}
}

// WHEN a request would be over the apply's bounds THEN Core refuses to write it: over 2048 ids, or over 1 MiB.
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
	if b, err := apply.Encode(big); err == nil {
		t.Errorf("a request of %d bytes is written", len(b))
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
