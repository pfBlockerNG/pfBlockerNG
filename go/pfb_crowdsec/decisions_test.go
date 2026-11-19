package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func banDecision(id int64, scope, value string) decision {
	return decision{ID: id, Origin: "crowdsec", Type: "ban", Scope: scope, Value: value, Scenario: "test/scenario",
		Duration: "4h"}
}

func TestParseBanNormalisesUsableValues(t *testing.T) {
	cases := []struct {
		scope, value string
		key          string
		fam          family
		single       bool
	}{
		{"ip", "198.51.100.10", "198.51.100.10", inet, true},
		{"Ip", "2001:db8::1", "2001:db8::1", inet6, true},
		{"IP", "2001:0db8:0000::0001", "2001:db8::1", inet6, true},
		{"range", "203.0.113.0/24", "203.0.113.0/24", inet, false},
		{"Range", "203.0.113.77/24", "203.0.113.0/24", inet, false},
		{"range", "2001:db8:beef::/48", "2001:db8:beef::/48", inet6, false},
		{"range", "198.51.100.1/32", "198.51.100.1", inet, true},
		{"range", "2001:db8::5/128", "2001:db8::5", inet6, true},
		{"ip", "::ffff:198.51.100.20", "198.51.100.20", inet, true},
		{"ip", "198.51.100.0/24", "198.51.100.0/24", inet, false},
	}
	for _, tc := range cases {
		b, use, err := parseBan(banDecision(1, tc.scope, tc.value))
		if err != nil || !use {
			t.Errorf("parseBan(%s %q) = use %v, err %v; want a usable ban", tc.scope, tc.value, use, err)
			continue
		}
		if b.key != tc.key || b.fam != tc.fam || b.single != tc.single {
			t.Errorf("parseBan(%s %q) = key %q fam %d single %v; want %q %d %v", tc.scope, tc.value, b.key, b.fam,
				b.single, tc.key, tc.fam, tc.single)
		}
		if tc.single && b.addr.String() != tc.key {
			t.Errorf("parseBan(%s %q).addr = %v; want %s", tc.scope, tc.value, b.addr, tc.key)
		}
	}
}

func TestParseBanCaseInsensitiveType(t *testing.T) {
	d := banDecision(1, "ip", "198.51.100.10")
	d.Type = "BAN"
	if _, use, err := parseBan(d); !use || err != nil {
		t.Fatalf("parseBan(type BAN) = %v, %v; want usable", use, err)
	}
}

// Decisions the bouncer does not enforce are skipped silently: other types and other scopes.
func TestParseBanSkipsOtherTypesAndScopes(t *testing.T) {
	cases := []decision{
		{ID: 1, Type: "captcha", Scope: "ip", Value: "198.51.100.10"},
		{ID: 2, Type: "throttle", Scope: "ip", Value: "198.51.100.10"},
		{ID: 3, Type: "", Scope: "ip", Value: "198.51.100.10"},
		{ID: 4, Type: "ban", Scope: "username", Value: "root"},
		{ID: 5, Type: "ban", Scope: "country", Value: "FR"},
		{ID: 6, Type: "ban", Scope: "as", Value: "64496"},
		{ID: 7, Type: "ban", Scope: "", Value: "198.51.100.10"},
	}
	for _, d := range cases {
		if _, use, err := parseBan(d); use || err != nil {
			t.Errorf("parseBan(%+v) = use %v, err %v; want skipped without error", d, use, err)
		}
	}
}

func TestParseBanRejectsBadValues(t *testing.T) {
	for _, value := range []string{
		"", "1.2.3", "256.1.1.1", "198.51.100.1/33", "2001:db8::/129", "fe80::1%em0", "198.51.100.1 ",
		" 198.51.100.1", "198.51.100.1\n198.51.100.2", "-f", "../../etc/passwd", "198.51.100.1;rm -rf /",
		"example.com", "0x7f.1", "198.51.100.1/24/8", strings.Repeat("1", 5000),
	} {
		for _, scope := range []string{"ip", "range"} {
			if b, use, err := parseBan(banDecision(1, scope, value)); err == nil {
				t.Errorf("parseBan(%s %q) = %+v use %v; want an error", scope, value, b, use)
			}
		}
	}
}

func TestDecodeStreamReadsBothLists(t *testing.T) {
	r, err := decodeStream(strings.NewReader(`{"new":[{"id":7,"origin":"cscli","type":"ban","scope":"Ip",
		"value":"198.51.100.10","duration":"4h","scenario":"manual","extra":"ignored"}],
		"deleted":[{"id":3,"origin":"crowdsec","type":"ban","scope":"Range","value":"203.0.113.0/24",
		"duration":"-1s","scenario":"x"}]}`))
	if err != nil {
		t.Fatalf("decodeStream(valid) = %v", err)
	}
	if len(r.New) != 1 || r.New[0].ID != 7 || r.New[0].Value != "198.51.100.10" || r.New[0].Origin != "cscli" {
		t.Fatalf("new = %+v", r.New)
	}
	if len(r.Deleted) != 1 || r.Deleted[0].ID != 3 || r.Deleted[0].Scope != "Range" {
		t.Fatalf("deleted = %+v", r.Deleted)
	}
}

func TestDecodeStreamAcceptsNullLists(t *testing.T) {
	r, err := decodeStream(strings.NewReader(`{"new":null,"deleted":null}`))
	if err != nil || len(r.New) != 0 || len(r.Deleted) != 0 {
		t.Fatalf("decodeStream(null lists) = %+v, %v; want empty lists", r, err)
	}
}

func TestDecodeStreamRejectsMalformedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":        `{"new": [`,
		"trailing garbage": `{"new":[],"deleted":[]} {"new":[]}`,
		"top-level array":  `[]`,
		"string id":        `{"new":[{"id":"7","type":"ban","scope":"ip","value":"198.51.100.1"}]}`,
		"new not a list":   `{"new":{"id":7}}`,
		"html":             `<html>bad gateway</html>`,
		"empty":            ``,
		"null":             `null`,
	} {
		if r, err := decodeStream(strings.NewReader(body)); err == nil {
			t.Errorf("%s: decodeStream(%q) = %+v, nil; want an error", name, body, r)
		}
	}
}

func keysOf(bans []ban) []string {
	out := make([]string, 0, len(bans))
	for _, b := range bans {
		out = append(out, b.key)
	}
	return out
}

func assertChange(t *testing.T, what string, got applyResult, add4, add6, del4, del6 []string) {
	t.Helper()
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"add v4", keysOf(got.add[inet]), add4},
		{"add v6", keysOf(got.add[inet6]), add6},
		{"del v4", keysOf(got.del[inet]), del4},
		{"del v6", keysOf(got.del[inet6]), del6},
	} {
		if !slices.Equal(c.got, c.want) && !(len(c.got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: %s = %v; want %v", what, c.name, c.got, c.want)
		}
	}
}

// Scenario: a value banned by two decisions.
// Given decisions 1 and 2 both banning 198.51.100.10, when decision 1 is deleted the value stays,
// and when decision 2 is deleted too the value goes.
func TestBanSetKeepsAValueUntilItsLastDecisionIsDeleted(t *testing.T) {
	s := newBanSet()
	r := s.apply(&streamResponse{New: []decision{banDecision(1, "ip", "198.51.100.10")}})
	assertChange(t, "first decision", r, []string{"198.51.100.10"}, nil, nil, nil)
	r = s.apply(&streamResponse{New: []decision{banDecision(2, "ip", "198.51.100.10")}})
	assertChange(t, "second decision", r, nil, nil, nil, nil)
	r = s.apply(&streamResponse{Deleted: []decision{banDecision(1, "ip", "198.51.100.10")}})
	assertChange(t, "first deleted", r, nil, nil, nil, nil)
	if got := s.keys(inet); !slices.Equal(got, []string{"198.51.100.10"}) {
		t.Fatalf("after deleting one of two decisions keys = %v; want the value kept", got)
	}
	r = s.apply(&streamResponse{Deleted: []decision{banDecision(2, "ip", "198.51.100.10")}})
	assertChange(t, "second deleted", r, nil, nil, []string{"198.51.100.10"}, nil)
	if got := s.keys(inet); len(got) != 0 {
		t.Fatalf("after deleting both decisions keys = %v; want none", got)
	}
}

func TestBanSetMatchesValuesByTheirNormalForm(t *testing.T) {
	s := newBanSet()
	s.apply(&streamResponse{New: []decision{banDecision(1, "range", "203.0.113.9/24")}})
	r := s.apply(&streamResponse{Deleted: []decision{banDecision(1, "range", "203.0.113.0/24")}})
	assertChange(t, "delete by another spelling", r, nil, nil, []string{"203.0.113.0/24"}, nil)
}

func TestBanSetIgnoresDuplicateIDsAndUnknownDeletes(t *testing.T) {
	s := newBanSet()
	r := s.apply(&streamResponse{New: []decision{
		banDecision(5, "ip", "198.51.100.10"), banDecision(5, "ip", "198.51.100.10"),
	}})
	assertChange(t, "duplicate id", r, []string{"198.51.100.10"}, nil, nil, nil)
	r = s.apply(&streamResponse{Deleted: []decision{banDecision(99, "ip", "198.51.100.10"),
		banDecision(5, "ip", "198.51.100.77")}})
	assertChange(t, "unknown deletes", r, nil, nil, nil, nil)
	r = s.apply(&streamResponse{Deleted: []decision{banDecision(5, "ip", "198.51.100.10")}})
	assertChange(t, "the one id deleted", r, nil, nil, []string{"198.51.100.10"}, nil)
}

// The same id banning two values is two bans: deleting it for one value leaves the other.
func TestBanSetKeysDecisionIDsPerValue(t *testing.T) {
	s := newBanSet()
	s.apply(&streamResponse{New: []decision{banDecision(5, "ip", "198.51.100.10"), banDecision(5, "ip", "198.51.100.11")}})
	r := s.apply(&streamResponse{Deleted: []decision{banDecision(5, "ip", "198.51.100.10")}})
	assertChange(t, "delete for one value", r, nil, nil, []string{"198.51.100.10"}, nil)
	if got := s.keys(inet); !slices.Equal(got, []string{"198.51.100.11"}) {
		t.Fatalf("keys = %v; want the other value kept", got)
	}
}

// Deleted is applied before new, and the change is the net one: a value deleted and re-banned in one pull
// stays in place without a delete and an add.
func TestBanSetReportsTheNetChangeOfAPull(t *testing.T) {
	s := newBanSet()
	s.apply(&streamResponse{New: []decision{banDecision(1, "ip", "198.51.100.10")}})
	r := s.apply(&streamResponse{
		Deleted: []decision{banDecision(1, "ip", "198.51.100.10")},
		New:     []decision{banDecision(2, "ip", "198.51.100.10")},
	})
	assertChange(t, "delete and re-ban", r, nil, nil, nil, nil)
	if got := s.keys(inet); !slices.Equal(got, []string{"198.51.100.10"}) {
		t.Fatalf("keys = %v; want the value kept", got)
	}
}

func TestBanSetSplitsFamiliesAndSkipsWhatItCannotUse(t *testing.T) {
	s := newBanSet()
	captcha := banDecision(9, "ip", "198.51.100.99")
	captcha.Type = "captcha"
	r := s.apply(&streamResponse{New: []decision{
		banDecision(1, "ip", "198.51.100.11"),
		banDecision(2, "ip", "2001:db8:dead::1"),
		banDecision(3, "range", "203.0.113.0/24"),
		banDecision(4, "range", "2001:db8:beef::/48"),
		banDecision(5, "ip", "198.51.100.10"),
		banDecision(6, "ip", "not-an-ip"),
		banDecision(7, "ip", "198.51.100.300"),
		banDecision(8, "username", "root"),
		captcha,
	}})
	assertChange(t, "mixed", r, []string{"198.51.100.10", "198.51.100.11", "203.0.113.0/24"},
		[]string{"2001:db8:beef::/48", "2001:db8:dead::1"}, nil, nil)
	if !slices.Equal(r.invalid, []string{"not-an-ip", "198.51.100.300"}) {
		t.Errorf("invalid = %q; want the two bad values in arrival order", r.invalid)
	}
	if r.skipped != 2 {
		t.Errorf("skipped = %d; want 2 (the username scope and the captcha)", r.skipped)
	}
}

// A value counts under the origin of its lowest-numbered decision.
func TestBanSetCountsValuesPerOrigin(t *testing.T) {
	s := newBanSet()
	mk := func(id int64, origin, scope, value string) decision {
		d := banDecision(id, scope, value)
		d.Origin = origin
		return d
	}
	s.apply(&streamResponse{New: []decision{
		mk(10, "crowdsec", "ip", "198.51.100.10"),
		mk(4, "cscli", "ip", "198.51.100.10"),
		mk(11, "CAPI", "ip", "198.51.100.11"),
		mk(12, "crowdsec", "range", "203.0.113.0/24"),
		mk(13, "lists", "ip", "2001:db8::1"),
	}})
	if got, want := s.origins(inet), map[string]int{"cscli": 1, "CAPI": 1, "crowdsec": 1}; !maps.Equal(got, want) {
		t.Errorf("v4 origins = %v; want %v", got, want)
	}
	if got, want := s.origins(inet6), map[string]int{"lists": 1}; !maps.Equal(got, want) {
		t.Errorf("v6 origins = %v; want %v", got, want)
	}
	s.apply(&streamResponse{Deleted: []decision{mk(4, "cscli", "ip", "198.51.100.10")}})
	if got, want := s.origins(inet), map[string]int{"crowdsec": 2, "CAPI": 1}; !maps.Equal(got, want) {
		t.Errorf("v4 origins after the cscli decision went = %v; want %v", got, want)
	}
}

func TestBanSetHandlesALargePull(t *testing.T) {
	s := newBanSet()
	var news []decision
	for i := range 20000 {
		news = append(news, banDecision(int64(i+1), "ip", fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
	}
	r := s.apply(&streamResponse{New: news})
	if len(r.add[inet]) != 20000 || len(s.keys(inet)) != 20000 {
		t.Fatalf("added %d, kept %d; want 20000", len(r.add[inet]), len(s.keys(inet)))
	}
	if !slices.IsSorted(s.keys(inet)) {
		t.Fatal("keys are not sorted")
	}
}
