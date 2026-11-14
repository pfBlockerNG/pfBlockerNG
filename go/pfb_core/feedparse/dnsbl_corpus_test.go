package feedparse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// The corpus is testdata/dnsbl.json, schema in testdata/README.md. Any unknown or missing key and any duplicate id
// is a test error, never a skip.

type dnsblCorpusLine struct {
	raw    string
	expect DNSBLLine
}

type dnsblCorpusCase struct {
	id     string
	config DNSBLConfig
	lines  []dnsblCorpusLine
}

var dnsblHexRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)

// dnsblObject decodes a JSON object whose key set must be exactly keys.
func dnsblObject(raw json.RawMessage, where string, keys ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: object expected: %v", where, err)
	}
	have := make([]string, 0, len(m))
	for k := range m {
		have = append(have, k)
	}
	sort.Strings(have)
	want := append([]string(nil), keys...)
	sort.Strings(want)
	if !reflect.DeepEqual(have, want) {
		return nil, fmt.Errorf("%s: keys %v must be exactly %v", where, have, want)
	}
	return m, nil
}

func dnsblUnmarshal(raw json.RawMessage, where string, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %v", where, err)
	}
	return nil
}

func dnsblFeedBytes(m map[string]json.RawMessage, where string) (string, error) {
	if hx, ok := m["line_hex"]; ok {
		var s string
		if err := dnsblUnmarshal(hx, where+" line_hex", &s); err != nil {
			return "", err
		}
		b, err := hex.DecodeString(s)
		if !dnsblHexRE.MatchString(s) || err != nil || utf8.Valid(b) {
			return "", fmt.Errorf("%s: line_hex must be lower-case hex of bytes that are not UTF-8", where)
		}
		return string(b), nil
	}
	var s string
	if err := dnsblUnmarshal(m["line"], where+" line", &s); err != nil {
		return "", err
	}
	return s, nil
}

// dnsblExpect decodes one expect object: rows, ip4, ip6, fail, scheme_skipped and stop.
func dnsblExpect(t *testing.T, raw json.RawMessage, where string) DNSBLLine {
	t.Helper()
	em, err := dnsblObject(raw, where, "rows", "ip4", "ip6", "fail", "scheme_skipped", "stop")
	if err != nil {
		t.Fatal(err)
	}
	var rows [][2]string
	var failItems []json.RawMessage
	exp := DNSBLLine{}
	for k, dst := range map[string]any{"rows": &rows, "ip4": &exp.IP4, "ip6": &exp.IP6, "fail": &failItems, "scheme_skipped": &exp.SchemeSkipped, "stop": &exp.Stop} {
		if err := dnsblUnmarshal(em[k], where+"."+k, dst); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rows {
		switch r[0] {
		case "d", "a":
			exp.Rows = append(exp.Rows, DNSBLRow{ABP: r[0] == "a", Text: r[1]})
		default:
			t.Fatalf("%s: row kind %q must be d or a", where, r[0])
		}
	}
	for _, fi := range failItems {
		if len(fi) > 0 && fi[0] == '{' {
			fm, err := dnsblObject(fi, where+" fail item", "hex")
			if err != nil {
				t.Fatal(err)
			}
			var s string
			if err := dnsblUnmarshal(fm["hex"], where+" fail hex", &s); err != nil {
				t.Fatal(err)
			}
			b, err := hex.DecodeString(s)
			if !dnsblHexRE.MatchString(s) || err != nil || utf8.Valid(b) {
				t.Fatalf("%s: fail hex must be lower-case hex of bytes that are not UTF-8", where)
			}
			exp.Fail = append(exp.Fail, string(b))
			continue
		}
		var s string
		if err := dnsblUnmarshal(fi, where+" fail item", &s); err != nil {
			t.Fatal(err)
		}
		exp.Fail = append(exp.Fail, s)
	}
	return exp
}

func dnsblLoadCorpus(t *testing.T) []dnsblCorpusCase {
	t.Helper()
	data, err := os.ReadFile("testdata/dnsbl.json")
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Fatal("corpus is not UTF-8")
	}
	file, err := dnsblObject(data, "file", "schema", "cases")
	if err != nil {
		t.Fatal(err)
	}
	var schema int
	if err := dnsblUnmarshal(file["schema"], "schema", &schema); err != nil || schema != 1 {
		t.Fatalf("schema must be 1: %v", err)
	}
	var rawCases []json.RawMessage
	if err := dnsblUnmarshal(file["cases"], "cases", &rawCases); err != nil || len(rawCases) == 0 {
		t.Fatalf("cases must be a non-empty list: %v", err)
	}
	seen := map[string]bool{}
	out := make([]dnsblCorpusCase, 0, len(rawCases))
	for i, rc := range rawCases {
		where := fmt.Sprintf("case #%d", i)
		cm, err := dnsblObject(rc, where, "id", "description", "config", "lines")
		if err != nil {
			t.Fatal(err)
		}
		var id, desc string
		if err := dnsblUnmarshal(cm["id"], where+" id", &id); err != nil || id == "" {
			t.Fatalf("%s: id must be a non-empty string", where)
		}
		if err := dnsblUnmarshal(cm["description"], where+" description", &desc); err != nil || desc == "" {
			t.Fatalf("%s: description must be a non-empty string", where)
		}
		where = "case " + id
		if seen[id] {
			t.Fatalf("%s: duplicate id", where)
		}
		seen[id] = true
		cc := dnsblCorpusCase{id: id}
		cfg, err := dnsblObject(cm["config"], where+" config", "dnsbl_ip", "lenient", "custom", "suppression")
		if err != nil {
			t.Fatal(err)
		}
		for k, dst := range map[string]*bool{"dnsbl_ip": &cc.config.DNSBLIP, "lenient": &cc.config.Lenient, "custom": &cc.config.Custom, "suppression": &cc.config.Suppression} {
			if err := dnsblUnmarshal(cfg[k], where+" config."+k, dst); err != nil {
				t.Fatal(err)
			}
		}
		var rawLines []json.RawMessage
		if err := dnsblUnmarshal(cm["lines"], where+" lines", &rawLines); err != nil || len(rawLines) == 0 {
			t.Fatalf("%s: lines must be a non-empty list: %v", where, err)
		}
		for n, rl := range rawLines {
			lw := fmt.Sprintf("%s line %d", where, n)
			var lm map[string]json.RawMessage
			if err := json.Unmarshal(rl, &lm); err != nil {
				t.Fatalf("%s: object expected: %v", lw, err)
			}
			keys := []string{"line", "expect"}
			if _, ok := lm["line_hex"]; ok {
				keys[0] = "line_hex"
			}
			if _, ok := lm["appliance"]; ok { // the pfSense appliance's result; Core asserts it like any other line
				keys = append(keys, "appliance")
			}
			if _, ok := lm["old_expect"]; ok {
				keys = append(keys, "old_expect")
			}
			lm, err := dnsblObject(rl, lw, keys...)
			if err != nil {
				t.Fatal(err)
			}
			if ra, ok := lm["appliance"]; ok && string(ra) != "true" {
				t.Fatalf("%s: appliance, when present, must be true", lw)
			}
			raw, err := dnsblFeedBytes(lm, lw)
			if err != nil {
				t.Fatal(err)
			}
			exp := dnsblExpect(t, lm["expect"], lw+" expect")
			if oldRaw, ok := lm["old_expect"]; ok { // the old path's answer; the PHP runner asserts it, this runner only checks its shape
				if old := dnsblExpect(t, oldRaw, lw+" old_expect"); reflect.DeepEqual(dnsblNorm(old), dnsblNorm(exp)) {
					t.Fatalf("%s: old_expect equals expect; it is present only where Core differs from the old path", lw)
				}
			}
			if exp.Stop && n != len(rawLines)-1 {
				t.Fatalf("%s: nothing is read after a stop", lw)
			}
			cc.lines = append(cc.lines, dnsblCorpusLine{raw: raw, expect: exp})
		}
		out = append(out, cc)
	}
	return out
}

// dnsblNorm makes nil and empty slices compare equal, and leaves the notices out: they are pinned per feed, in feed.json.
func dnsblNorm(l DNSBLLine) DNSBLLine {
	l.Messages = nil
	if len(l.Rows) == 0 {
		l.Rows = nil
	}
	if len(l.IP4) == 0 {
		l.IP4 = nil
	}
	if len(l.IP6) == 0 {
		l.IP6 = nil
	}
	if len(l.Fail) == 0 {
		l.Fail = nil
	}
	return l
}

func dnsblShow(l DNSBLLine) string {
	var b strings.Builder
	rows := make([]string, 0, len(l.Rows))
	for _, r := range l.Rows {
		kind := "d"
		if r.ABP {
			kind = "a"
		}
		rows = append(rows, fmt.Sprintf("[%s %q]", kind, r.Text))
	}
	fmt.Fprintf(&b, "rows=%s ip4=%q ip6=%q fail=%q scheme_skipped=%d stop=%v", strings.Join(rows, ","), l.IP4, l.IP6, l.Fail, l.SchemeSkipped, l.Stop)
	return b.String()
}

func TestDNSBLCorpus(t *testing.T) {
	for _, c := range dnsblLoadCorpus(t) {
		c := c
		t.Run(c.id, func(t *testing.T) {
			p := NewDNSBLParser(c.config)
			for n, line := range c.lines {
				got := dnsblNorm(p.Line(line.raw))
				want := dnsblNorm(line.expect)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("line %d %q\n  expected %s\n  actual   %s", n, line.raw, dnsblShow(want), dnsblShow(got))
				}
			}
		})
	}
}
