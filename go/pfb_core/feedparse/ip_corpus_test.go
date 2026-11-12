package feedparse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The IP feed line corpus (testdata/ip.json, schema in testdata/README.md): the old path's results, replayed against Core.

type ipExpect struct {
	Entries     []string
	Line        string
	Suppressed  bool
	ParseFail   int
	Detailed    bool
	Messages    []string
	hasMessages bool
}

type ipRow struct {
	Line      string
	Appliance bool // the expectation is the pfSense appliance's; the Go runner asserts it like any other
	Expect    ipExpect
}

type ipCase struct {
	ID, Description string
	Config          IPConfig
	Rows            []ipRow
}

type ipType struct {
	ID, Description, Format, URL, Expect string
}

type ipCorpus struct {
	Cases []ipCase
	Types []ipType
}

// keysOf fails unless raw is a JSON object whose keys are the required ones, any of the optional ones and, per group,
// exactly one of its members.
func keysOf(raw json.RawMessage, what string, required, optional []string, oneOf ...[2]string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%s: not an object", what)
	}
	want := slices.Clone(required)
	for _, pair := range oneOf {
		_, a := m[pair[0]]
		_, b := m[pair[1]]
		if a == b {
			return nil, fmt.Errorf("%s: exactly one of %q, %q is required", what, pair[0], pair[1])
		}
		if a {
			want = append(want, pair[0])
		} else {
			want = append(want, pair[1])
		}
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("%s: missing key %q", what, k)
		}
	}
	for k := range m {
		if !slices.Contains(want, k) && !slices.Contains(optional, k) {
			return nil, fmt.Errorf("%s: unknown key %q", what, k)
		}
	}
	return m, nil
}

func strictInto(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// feedBytes reads x (text) or x_hex (lower-case hex) of an object whose key set was already checked.
func feedBytes(m map[string]json.RawMessage, key string) (string, error) {
	if raw, ok := m[key]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("%s: %v", key, err)
		}
		return s, nil
	}
	var h string
	if err := json.Unmarshal(m[key+"_hex"], &h); err != nil {
		return "", fmt.Errorf("%s_hex: %v", key, err)
	}
	if h != strings.ToLower(h) {
		return "", fmt.Errorf("%s_hex: not lower-case", key)
	}
	b, err := hex.DecodeString(h)
	return string(b), err
}

func parseIPCorpus(data []byte) (*ipCorpus, error) {
	top, err := keysOf(data, "corpus", []string{"schema", "cases", "types"}, nil)
	if err != nil {
		return nil, err
	}
	var schema int
	if json.Unmarshal(top["schema"], &schema) != nil || schema != 1 {
		return nil, fmt.Errorf("schema must be 1")
	}
	var cases, types []json.RawMessage
	if json.Unmarshal(top["cases"], &cases) != nil || len(cases) == 0 || json.Unmarshal(top["types"], &types) != nil || len(types) == 0 {
		return nil, fmt.Errorf("cases and types must be non-empty lists")
	}
	out := &ipCorpus{}
	seen := map[string]bool{}
	checkID := func(id, desc string) error {
		if id == "" || desc == "" {
			return fmt.Errorf("%q: id and description must be non-empty", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate id %q", id)
		}
		seen[id] = true
		return nil
	}
	for _, raw := range cases {
		c, err := parseIPCase(raw)
		if err != nil {
			return nil, err
		}
		if err := checkID(c.ID, c.Description); err != nil {
			return nil, err
		}
		out.Cases = append(out.Cases, *c)
	}
	seen = map[string]bool{}
	for _, raw := range types {
		if _, err := keysOf(raw, "type", []string{"id", "description", "format", "url", "expect"}, nil); err != nil {
			return nil, err
		}
		var t ipType
		if err := strictInto(raw, &struct {
			ID          *string `json:"id"`
			Description *string `json:"description"`
			Format      *string `json:"format"`
			URL         *string `json:"url"`
			Expect      *string `json:"expect"`
		}{&t.ID, &t.Description, &t.Format, &t.URL, &t.Expect}); err != nil {
			return nil, err
		}
		if err := checkID(t.ID, t.Description); err != nil {
			return nil, err
		}
		if t.Expect != "auto" && t.Expect != "regex" {
			return nil, fmt.Errorf("type %s: expect must be auto or regex", t.ID)
		}
		out.Types = append(out.Types, t)
	}
	return out, nil
}

func parseIPCase(raw json.RawMessage) (*ipCase, error) {
	m, err := keysOf(raw, "case", []string{"id", "description", "config", "rows"}, nil)
	if err != nil {
		return nil, err
	}
	var c ipCase
	if json.Unmarshal(m["id"], &c.ID) != nil || json.Unmarshal(m["description"], &c.Description) != nil {
		return nil, fmt.Errorf("case: id and description must be strings")
	}
	if _, err := keysOf(m["config"], c.ID+" config", []string{"vtype", "pftype", "custom", "cidr_floor_v4", "cidr_floor_v6", "suppression"}, nil); err != nil {
		return nil, err
	}
	if err := strictInto(m["config"], &struct {
		VType       *string `json:"vtype"`
		PFType      *string `json:"pftype"`
		Custom      *bool   `json:"custom"`
		FloorV4     *string `json:"cidr_floor_v4"`
		FloorV6     *string `json:"cidr_floor_v6"`
		Suppression *bool   `json:"suppression"`
	}{&c.Config.VType, &c.Config.PFType, &c.Config.Custom, &c.Config.FloorV4, &c.Config.FloorV6, &c.Config.Suppression}); err != nil {
		return nil, fmt.Errorf("%s config: %v", c.ID, err)
	}
	if (c.Config.VType != "_v4" && c.Config.VType != "_v6") || (c.Config.PFType != "auto" && c.Config.PFType != "regex") {
		return nil, fmt.Errorf("%s: vtype/pftype", c.ID)
	}
	var rows []json.RawMessage
	if json.Unmarshal(m["rows"], &rows) != nil || len(rows) == 0 {
		return nil, fmt.Errorf("%s: rows must be a non-empty list", c.ID)
	}
	for i, rr := range rows {
		what := fmt.Sprintf("%s row %d", c.ID, i)
		rm, err := keysOf(rr, what, []string{"expect"}, []string{"appliance"}, [2]string{"line", "line_hex"})
		if err != nil {
			return nil, err
		}
		row := ipRow{}
		if raw, ok := rm["appliance"]; ok {
			if json.Unmarshal(raw, &row.Appliance) != nil || !row.Appliance {
				return nil, fmt.Errorf("%s: appliance, if present, is true", what)
			}
		}
		if row.Line, err = feedBytes(rm, "line"); err != nil {
			return nil, fmt.Errorf("%s: %v", what, err)
		}
		em, err := keysOf(rm["expect"], what+" expect", []string{"entries", "suppressed", "parse_fail", "detailed_parse_fail"}, nil,
			[2]string{"line", "line_hex"}, [2]string{"messages", "messages_hex"})
		if err != nil {
			return nil, err
		}
		e := &row.Expect
		if err := strictInto(rm["expect"], &struct {
			Entries  *[]string `json:"entries"`
			Supp     *bool     `json:"suppressed"`
			Fail     *int      `json:"parse_fail"`
			Detailed *bool     `json:"detailed_parse_fail"`
			Line     any       `json:"line"`
			LineHex  any       `json:"line_hex"`
			Msgs     any       `json:"messages"`
			MsgsHex  any       `json:"messages_hex"`
		}{Entries: &e.Entries, Supp: &e.Suppressed, Fail: &e.ParseFail, Detailed: &e.Detailed}); err != nil {
			return nil, fmt.Errorf("%s: %v", what, err)
		}
		if e.Line, err = feedBytes(em, "line"); err != nil {
			return nil, fmt.Errorf("%s: %v", what, err)
		}
		if raw, ok := em["messages"]; ok {
			err = json.Unmarshal(raw, &e.Messages)
		} else {
			var hs []string
			if err = json.Unmarshal(em["messages_hex"], &hs); err == nil {
				for _, h := range hs {
					b, herr := hex.DecodeString(h)
					if herr != nil || h != strings.ToLower(h) {
						err = fmt.Errorf("bad hex %q", h)
						break
					}
					e.Messages = append(e.Messages, string(b))
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: messages: %v", what, err)
		}
		c.Rows = append(c.Rows, row)
	}
	return &c, nil
}

func loadIPCorpus(t *testing.T) *ipCorpus {
	t.Helper()
	data, err := os.ReadFile("testdata/ip.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseIPCorpus(data)
	if err != nil {
		t.Fatalf("testdata/ip.json: %v", err)
	}
	return c
}

func nilToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func describeIPLine(line string, e ipExpect) string {
	return fmt.Sprintf("line %q\n  entries=%q log=%q suppressed=%v parse_fail=%d detailed=%v messages=%q", line, nilToEmpty(e.Entries), e.Line, e.Suppressed, e.ParseFail, e.Detailed, nilToEmpty(e.Messages))
}

func TestIPCorpus(t *testing.T) {
	corpus := loadIPCorpus(t)
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			for i, row := range c.Rows {
				got := ParseIPLine(row.Line, c.Config)
				actual := ipExpect{Entries: got.Entries, Line: got.Line, Suppressed: got.Suppressed, ParseFail: got.ParseFail, Detailed: got.DetailedParseFail, Messages: got.Messages}
				if !reflect.DeepEqual(nilToEmpty(actual.Entries), nilToEmpty(row.Expect.Entries)) || actual.Line != row.Expect.Line || actual.Suppressed != row.Expect.Suppressed ||
					actual.ParseFail != row.Expect.ParseFail || actual.Detailed != row.Expect.Detailed || !reflect.DeepEqual(nilToEmpty(actual.Messages), nilToEmpty(row.Expect.Messages)) {
					t.Errorf("%s row %d (%s%s)\nexpected %s\nactual   %s", c.ID, i, c.Description, map[bool]string{true: "; appliance row", false: ""}[row.Appliance],
						describeIPLine(row.Line, row.Expect), describeIPLine(row.Line, actual))
				}
			}
		})
	}
}

func TestIPParseTypeCorpus(t *testing.T) {
	for _, ty := range loadIPCorpus(t).Types {
		t.Run(ty.ID, func(t *testing.T) {
			if got := IPParseType(ty.Format, ty.URL); got != ty.Expect {
				t.Errorf("%s (%s): IPParseType(%q, %q) = %q, want %q", ty.ID, ty.Description, ty.Format, ty.URL, got, ty.Expect)
			}
		})
	}
}

// The loader is strict: an unknown or missing key and a duplicate id are errors, never skips.
func TestIPCorpusLoaderIsStrict(t *testing.T) {
	row := `{"line": "1.2.3.4\n", "expect": {"entries": ["1.2.3.4"], "line": "1.2.3.4", "suppressed": false, "parse_fail": 0, "detailed_parse_fail": false, "messages": []}}`
	config := `{"vtype": "_v4", "pftype": "auto", "custom": false, "cidr_floor_v4": "Disabled", "cidr_floor_v6": "Disabled", "suppression": false}`
	kase := func(id, extra string) string {
		return `{"id": "` + id + `", "description": "d", "config": ` + config + `, "rows": [` + row + `]` + extra + `}`
	}
	corpus := func(cases, types string) string {
		return `{"schema": 1, "cases": [` + cases + `], "types": [` + types + `]}`
	}
	typ := `{"id": "t", "description": "d", "format": "auto", "url": "u", "expect": "auto"}`
	if _, err := parseIPCorpus([]byte(corpus(kase("a", ""), typ))); err != nil {
		t.Fatalf("control corpus rejected: %v", err)
	}
	applianceRow := strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"line": "1.2.3.4\n", "appliance": true,`, 1)
	if c, err := parseIPCorpus([]byte(corpus(applianceRow, typ))); err != nil || !c.Cases[0].Rows[0].Appliance {
		t.Fatalf("appliance row not accepted and read: %v", err)
	}
	bad := map[string]string{
		"unknown case key":    corpus(kase("a", `, "extra": 1`), typ),
		"duplicate id":        corpus(kase("a", "")+","+kase("a", ""), typ),
		"unknown config key":  corpus(strings.Replace(kase("a", ""), `"custom": false`, `"custom": false, "x": 1`, 1), typ),
		"missing config key":  corpus(strings.Replace(kase("a", ""), `"custom": false, `, "", 1), typ),
		"unknown expect key":  corpus(strings.Replace(kase("a", ""), `"parse_fail": 0`, `"parse_fail": 0, "x": 1`, 1), typ),
		"missing expect key":  corpus(strings.Replace(kase("a", ""), `"suppressed": false, `, "", 1), typ),
		"line and line_hex":   corpus(strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"line": "1.2.3.4\n", "line_hex": "00",`, 1), typ),
		"appliance false":     corpus(strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"line": "1.2.3.4\n", "appliance": false,`, 1), typ),
		"appliance a string":  corpus(strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"line": "1.2.3.4\n", "appliance": "yes",`, 1), typ),
		"unknown row key":     corpus(strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"x": 1, "line": "1.2.3.4\n",`, 1), typ),
		"unknown type key":    corpus(kase("a", ""), strings.Replace(typ, `"url": "u"`, `"url": "u", "x": 1`, 1)),
		"type duplicate id":   corpus(kase("a", ""), typ+","+typ),
		"unknown top key":     strings.Replace(corpus(kase("a", ""), typ), `"schema": 1`, `"schema": 1, "x": 1`, 1),
		"empty description":   corpus(strings.Replace(kase("a", ""), `"description": "d"`, `"description": ""`, 1), typ),
		"upper-case hex line": corpus(strings.Replace(kase("a", ""), `{"line": "1.2.3.4\n",`, `{"line_hex": "0A",`, 1), typ),
	}
	for name, doc := range bad {
		if _, err := parseIPCorpus([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
