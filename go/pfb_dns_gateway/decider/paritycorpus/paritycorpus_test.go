// Tests of the Go side of the parity corpus contract; the Python counterpart is tests/dns_proxy/test_parity_corpus.py.
package paritycorpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

// object is a JSON object that keeps its key order (encoding/json sorts a map's keys), as the loader's
// "first defect in file order" depends on it.
type object []member

type member struct {
	key   string
	value any
}

func obj(pairs ...any) *object {
	o := object{}
	for i := 0; i < len(pairs); i += 2 {
		o = append(o, member{pairs[i].(string), pairs[i+1]})
	}
	return &o
}

func (o *object) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, m := range *o {
		if i > 0 {
			out.WriteByte(',')
		}
		key, _ := json.Marshal(m.key)
		value, err := json.Marshal(m.value)
		if err != nil {
			return nil, err
		}
		out.Write(key)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func (o *object) set(key string, value any) {
	for i := range *o {
		if (*o)[i].key == key {
			(*o)[i].value = value
			return
		}
	}
	*o = append(*o, member{key, value})
}

func (o *object) del(key string) {
	*o = slices.DeleteFunc(*o, func(m member) bool { return m.key == key })
}

func (o *object) get(path ...string) *object {
	for _, key := range path {
		i := slices.IndexFunc(*o, func(m member) bool { return m.key == key })
		o = (*o)[i].value.(*object)
	}
	return o
}

func caseZero(d *object) *object {
	i := slices.IndexFunc(*d, func(m member) bool { return m.key == "cases" })
	return (*d)[i].value.([]any)[0].(*object)
}

// raw is a value written into the document as the text it holds: json.Marshal cannot write NaN or 1.0.
func raw(text string) string { return "@raw:" + text }

var rawValue = regexp.MustCompile(`"@raw:([^"]*)"`)

// good is the smallest valid scenario; each hostile row below breaks one thing in a fresh copy of it.
func good() *object {
	return obj(
		"schema", 3,
		"description", "one unlisted name",
		"module", obj(
			"ini", obj("MAIN", obj("python_enable", "true")),
			"manifest", obj("version", 1, "config", obj(), "feeds", []any{}),
			"files", obj("pfb_py_raw/feed.txt", []any{"listed.example"}),
		),
		"upstream", obj("allowed.example. A", []any{"allowed.example. 300 IN A 192.0.2.77"}),
		"cases", []any{
			obj(
				"id", "good",
				"family", "relay",
				"description", "an unlisted name is relayed unchanged",
				"query", obj("name", "allowed.example.", "type", "A"),
				"expect", obj(
					"decision", "relay",
					"forwards", []any{"allowed.example. A"},
					"rcode", "NOERROR",
					"answer", []any{"allowed.example. 300 IN A 192.0.2.77"},
					"authority", []any{},
				),
			),
		},
	)
}

func documentText(t *testing.T, d *object) string {
	t.Helper()
	text, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return rawValue.ReplaceAllString(string(text), "$1")
}

const badFile = "bad.json"

func realFamilies(t *testing.T) ([]string, map[string]string) {
	t.Helper()
	names, source, err := LoadFamilies(filepath.Join(Fixtures(), "families.json"))
	if err != nil {
		t.Fatal(err)
	}
	return names, source
}

func loadText(t *testing.T, text string) (*Scenario, error) {
	t.Helper()
	_, families := realFamilies(t)
	path := filepath.Join(t.TempDir(), badFile)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadScenario(path, families)
}

func refusalText(t *testing.T, err error) string {
	t.Helper()
	var refusal FixtureError
	if !errors.As(err, &refusal) {
		t.Fatalf("want a FixtureError, got %T: %v", err, err)
	}
	return refusal.Error()
}

func mustRR(t *testing.T, text string) dnswire.RR {
	t.Helper()
	rr, err := dnswire.RRFromText(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestAMinimalValidScenarioLoadsWithTheDefaultsFilledIn(t *testing.T) {
	s, err := loadText(t, documentText(t, good()))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != badFile || s.Description != "one unlisted name" || len(s.Cases) != 1 {
		t.Fatalf("scenario header: got %q %q with %d cases", s.Name, s.Description, len(s.Cases))
	}
	c := s.Cases[0]
	wantQuery := Query{Wire: query(t, "allowed.example.", dnswire.TYPE_A), Client: "192.0.2.10", Transport: "UDP"}
	if c.ID != "good" || c.Family != "relay" || !reflect.DeepEqual(c.Query, wantQuery) {
		t.Errorf("case: got %q %q %+v, want good relay %+v", c.ID, c.Family, c.Query, wantQuery)
	}
	rr := mustRR(t, "allowed.example. 300 IN A 192.0.2.77")
	if c.Expect.Decision != "relay" || c.Expect.Rcode != "NOERROR" || c.Expect.TC ||
		!reflect.DeepEqual(c.Expect.Forwards, []string{"allowed.example. A"}) ||
		!reflect.DeepEqual(c.Expect.Answer, []dnswire.RR{rr}) || len(c.Expect.Authority) != 0 {
		t.Errorf("expect: got %+v", c.Expect)
	}
	wantIni := []IniSection{{Name: "MAIN", Keys: [][2]string{{"python_enable", "true"}}}}
	if !reflect.DeepEqual(s.Module.Ini, wantIni) {
		t.Errorf("module.ini: got %+v, want %+v", s.Module.Ini, wantIni)
	}
	if got, want := string(s.Module.Manifest), `{"version":1,"config":{},"feeds":[]}`; got != want {
		t.Errorf("module.manifest: got %s, want %s", got, want)
	}
	wantFiles := []ModuleFile{{Path: "pfb_py_raw/feed.txt", Lines: []string{"listed.example"}}}
	if !reflect.DeepEqual(s.Module.Files, wantFiles) {
		t.Errorf("module.files: got %+v, want %+v", s.Module.Files, wantFiles)
	}
	wantUpstream := map[UpstreamKey][]string{{Name: "allowed.example.", Qtype: 1}: {"allowed.example. 300 IN A 192.0.2.77"}}
	if !reflect.DeepEqual(s.Upstream, wantUpstream) {
		t.Errorf("upstream: got %+v, want %+v", s.Upstream, wantUpstream)
	}
}

func loadGood(t *testing.T, mutate func(d *object)) *Scenario {
	t.Helper()
	d := good()
	mutate(d)
	s, err := loadText(t, documentText(t, d))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAWireHexQueryLoadsAsExactlyThoseBytesWithTheDefaults(t *testing.T) {
	q := loadGood(t, func(d *object) { caseZero(d).set("query", obj("wire_hex", "00ff10")) }).Cases[0].Query
	if !bytes.Equal(q.Wire, []byte{0x00, 0xff, 0x10}) || q.Client != DEFAULT_CLIENT || q.Transport != "UDP" {
		t.Errorf("got %x %q %q", q.Wire, q.Client, q.Transport)
	}
}

func TestAWireHexQueryTakesAClientAndATransportToo(t *testing.T) {
	q := loadGood(t, func(d *object) {
		caseZero(d).set("query", obj("wire_hex", "", "client", "2001:db8::1", "transport", "DoT"))
	}).Cases[0].Query
	if len(q.Wire) != 0 || q.Client != "2001:db8::1" || q.Transport != "DoT" {
		t.Errorf("got %x %q %q", q.Wire, q.Client, q.Transport)
	}
}

func TestAWireHexQueryOfTheLargestDNSMessageLoads(t *testing.T) {
	q := loadGood(t, func(d *object) { caseZero(d).set("query", obj("wire_hex", strings.Repeat("00", 0xFFFF))) }).Cases[0].Query
	if len(q.Wire) != 0xFFFF {
		t.Errorf("got %d bytes, want 65535", len(q.Wire))
	}
}

func TestADropExpectationLoadsWithNothingElse(t *testing.T) {
	e := loadGood(t, func(d *object) { caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{})) }).Cases[0].Expect
	if !reflect.DeepEqual(e, Expect{Decision: "drop"}) {
		t.Errorf("got %+v", e)
	}
}

func TestTCTrueLoads(t *testing.T) {
	if e := loadGood(t, func(d *object) { caseZero(d).get("expect").set("tc", true) }).Cases[0].Expect; !e.TC {
		t.Errorf("got %+v, want TC set", e)
	}
}

const signoff = "https://github.com/pfBlockerNG/pfBlockerNG/issues/3511#issuecomment-6757232482"

// withGoExpect gives good()'s case a go_expect that rewrites where its expect relays, without the keys drop, then
// applies change to it.
func withGoExpect(change func(g *object), drop ...string) func(d *object) {
	return func(d *object) {
		g := obj(
			"decision", "rewrite",
			"forwards", []any{"allowed.example. A"},
			"rcode", "NOERROR",
			"answer", []any{"allowed.example. 3600 IN A 0.0.0.0"},
			"authority", []any{},
			"signoff", signoff,
		)
		for _, key := range drop {
			g.del(key)
		}
		if change != nil {
			change(g)
		}
		caseZero(d).set("go_expect", g)
	}
}

func TestACaseWithoutAGoExpectHasNone(t *testing.T) {
	if c := loadGood(t, func(d *object) {}).Cases[0]; c.GoExpect != nil || c.Signoff != "" {
		t.Errorf("got go_expect %+v, signoff %q; want none", c.GoExpect, c.Signoff)
	}
}

func TestASignedGoExpectLoadsNextToAnUntouchedExpect(t *testing.T) {
	c := loadGood(t, withGoExpect(nil)).Cases[0]
	want := Expect{"rewrite", []string{"allowed.example. A"}, "NOERROR",
		[]dnswire.RR{mustRR(t, "allowed.example. 3600 IN A 0.0.0.0")}, nil, false}
	if c.GoExpect == nil || !reflect.DeepEqual(*c.GoExpect, want) {
		t.Errorf("go_expect: got %+v, want %+v", c.GoExpect, want)
	}
	if c.Signoff != signoff || c.Expect.Decision != "relay" {
		t.Errorf("got signoff %q and expect decision %q, want %q and relay", c.Signoff, c.Expect.Decision, signoff)
	}
}

func TestAnUpstreamNullLoadsAsNoReplyAndAnEmptyListAsNoRecords(t *testing.T) {
	s := loadGood(t, func(d *object) {
		d.get("upstream").set("silent.example. A", nil)
		d.get("upstream").set("empty.example. A", []any{})
	})
	if got, ok := s.Upstream[UpstreamKey{Name: "silent.example.", Qtype: 1}]; !ok || got != nil {
		t.Errorf("null: got %#v, present %v; want a nil list: Unbound gives no reply", got, ok)
	}
	if got, ok := s.Upstream[UpstreamKey{Name: "empty.example.", Qtype: 1}]; !ok || got == nil || len(got) != 0 {
		t.Errorf("[]: got %#v, present %v; want an empty list that is not nil: NOERROR without records", got, ok)
	}
}

func TestTheManifestIsKeptExactlyAsTheFixtureWritesIt(t *testing.T) {
	text := documentText(t, good())
	const compact = `"manifest":{"version":1,"config":{},"feeds":[]}`
	spaced := "\"manifest\" :  { \"version\" :1,\n \"feeds\":[ ] } "
	if !strings.Contains(text, compact) {
		t.Fatalf("test document has no %s: %s", compact, text)
	}
	s, err := loadText(t, strings.Replace(text, compact, spaced, 1))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(s.Module.Manifest), "{ \"version\" :1,\n \"feeds\":[ ] }"; got != want {
		t.Errorf("module.manifest: got %q, want %q", got, want)
	}
}

type hostileRow struct {
	name   string
	mutate func(d *object)
	names  []string // what the message must name (the Python row's assertion)
	exact  string   // the message Python's loader gives for the row, where Go's is the same text
	prefix string   // the start of the message where the rest is the wording of a Python or a Go exception
}

var hostile = []hostileRow{
	{"schema 1, the old version", func(d *object) { d.set("schema", 1) }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got 1", ""},
	{"schema 2, the version before go_expect", func(d *object) { d.set("schema", 2) }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got 2", ""},
	{"schema 4", func(d *object) { d.set("schema", 4) }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got 4", ""},
	{"schema as a string", func(d *object) { d.set("schema", "3") }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got '3'", ""},
	{"schema missing", func(d *object) { d.del("schema") }, []string{badFile, "schema"},
		"bad.json: schema: missing", ""},
	{"schema true", func(d *object) { d.set("schema", true) }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got True", ""},
	{"schema 3.0", func(d *object) { d.set("schema", raw("3.0")) }, []string{badFile, "schema"},
		"bad.json: schema: must be the integer 3, got 3.0", ""},
	// Deviation: Python's json reads NaN and the loader refuses it by name; Go's decoder refuses it as a syntax error.
	{"NaN, which only Python reads", func(d *object) { d.get("module", "manifest").set("x", raw("NaN")) },
		[]string{badFile, "not a readable JSON document"}, "", "bad.json: not a readable JSON document: "},
	{"no cases", func(d *object) { d.set("cases", []any{}) }, []string{badFile, "cases"},
		"bad.json: cases: must be a non-empty list", ""},
	{"empty case id", func(d *object) { caseZero(d).set("id", "") }, []string{badFile, "cases[0]", "id"},
		"bad.json: cases[0]: id: must not be empty", ""},
	{"empty case description", func(d *object) { caseZero(d).set("description", "") }, []string{badFile, "'good'", "description"},
		"bad.json: case 'good': description: must say what behaviour is pinned", ""},
	{"client not an IP", func(d *object) { caseZero(d).get("query").set("client", "host.example") }, []string{"'good'", "query.client"},
		"bad.json: case 'good': query.client: not an IP address: 'host.example'", ""},
	{"client 0.0.0.0", func(d *object) { caseZero(d).get("query").set("client", "0.0.0.0") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '0.0.0.0' is not a canonical, specified address without a zone", ""},
	{"client ::", func(d *object) { caseZero(d).get("query").set("client", "::") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '::' is not a canonical, specified address without a zone", ""},
	{"client fe80::1%eth0", func(d *object) { caseZero(d).get("query").set("client", "fe80::1%eth0") }, []string{"query.client"},
		"bad.json: case 'good': query.client: 'fe80::1%eth0' is not a canonical, specified address without a zone", ""},
	{"client ::ffff:192.0.2.1", func(d *object) { caseZero(d).get("query").set("client", "::ffff:192.0.2.1") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '::ffff:192.0.2.1' is not a canonical, specified address without a zone", ""},
	{"client 2001:DB8::1", func(d *object) { caseZero(d).get("query").set("client", "2001:DB8::1") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '2001:DB8::1' is not a canonical, specified address without a zone", ""},
	{"client IPv6 not compressed", func(d *object) { caseZero(d).get("query").set("client", "2001:db8:0:0:0:0:0:1") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '2001:db8:0:0:0:0:0:1' is not a canonical, specified address without a zone", ""},
	{"client IPv4-compatible IPv6", func(d *object) { caseZero(d).get("query").set("client", "::1.2.3.4") }, []string{"query.client"},
		"bad.json: case 'good': query.client: '::1.2.3.4' is not a canonical, specified address without a zone", ""},
	{"client a number", func(d *object) { caseZero(d).get("query").set("client", 5) }, []string{"query.client"},
		"bad.json: case 'good': query.client: must be a string, got 5", ""},
	// Python's ipaddress refuses a second '%' and any '/' in an IPv6 text; net/netip takes both.
	{"client IPv6 with two zone separators", func(d *object) { caseZero(d).get("query").set("client", "fe80::1%a%b") }, []string{"'good'", "query.client"},
		"bad.json: case 'good': query.client: not an IP address: 'fe80::1%a%b'", ""},
	{"client IPv6 with a prefix length after an empty zone", func(d *object) { caseZero(d).get("query").set("client", "::%/64") }, []string{"'good'", "query.client"},
		"bad.json: case 'good': query.client: not an IP address: '::%/64'", ""},
	{"manifest that is not an object", func(d *object) { d.get("module").set("manifest", []any{}) }, []string{badFile, "module.manifest"},
		"bad.json: module.manifest: must be a JSON object", ""},
	{"unknown transport", func(d *object) { caseZero(d).get("query").set("transport", "QUIC") }, []string{"'good'", "query.transport"},
		"bad.json: case 'good': query.transport: unknown value 'QUIC', expected one of DoH DoQ DoT TCP UDP", ""},
	{"TYPE65536", func(d *object) { caseZero(d).get("query").set("type", "TYPE65536") }, []string{"'good'", "query.type"},
		"bad.json: case 'good': query.type: unknown query type 'TYPE65536'", ""},
	{"TYPE with 5000 digits", func(d *object) { caseZero(d).get("query").set("type", "TYPE"+strings.Repeat("9", 5000)) }, []string{"query.type"},
		"bad.json: case 'good': query.type: unknown query type 'TYPE" + strings.Repeat("9", 5000) + "'", ""},
	{"unknown rcode", func(d *object) { caseZero(d).get("expect").set("rcode", "NOPE") }, []string{"'good'", "expect.rcode"},
		"bad.json: case 'good': expect.rcode: unknown value 'NOPE', expected one of FORMERR NOERROR NOTIMP NXDOMAIN REFUSED SERVFAIL", ""},
	{"upstream name without the trailing dot", func(d *object) { d.set("upstream", obj("allowed.example A", []any{})) },
		[]string{badFile, "upstream['allowed.example A']"},
		"bad.json: upstream['allowed.example A']: name 'allowed.example' must be absolute (end with a dot)", ""},
	{"upstream name in upper case", func(d *object) { d.set("upstream", obj("Allowed.example. A", []any{})) },
		[]string{badFile, "upstream['Allowed.example. A']", "lower case"},
		"bad.json: upstream['Allowed.example. A']: the name must be lower case", ""},
	{"one upstream question under two spellings", func(d *object) { d.get("upstream").set("allowed.example. TYPE1", []any{}) },
		[]string{badFile, "upstream['allowed.example. TYPE1']", "already listed"},
		"bad.json: upstream['allowed.example. TYPE1']: the same question is already listed under another spelling", ""},
	{"ini value carrying a new section", func(d *object) { d.get("module", "ini", "MAIN").set("python_enable", "true\n[X]") },
		[]string{badFile, "module.ini.MAIN.python_enable"},
		`bad.json: module.ini.MAIN.python_enable: 'true\n[X]' must not contain any of '\r\n'`, ""},
	{"ini section name closing early", func(d *object) { d.get("module", "ini").set("A]\nB", obj()) },
		[]string{badFile, "module.ini.A]"},
		"bad.json: module.ini.A]\nB: " + `'A]\nB' must not contain any of '\r\n[]'`, ""},
	{"ini key carrying its own value", func(d *object) { d.get("module", "ini", "MAIN").set("a=b", "c") },
		[]string{badFile, "module.ini.MAIN.a=b"},
		`bad.json: module.ini.MAIN.a=b: 'a=b' must not contain any of '\r\n=:'`, ""},
	{"files under the shipped decider's link", func(d *object) { d.get("module", "files").set("pfb_unbound.py/x", []any{"x"}) },
		[]string{badFile, "module.files", "runner"},
		"bad.json: module.files: 'pfb_unbound.py/x' is written by the runner, never by a fixture", ""},
	{"files naming one file twice", func(d *object) { d.get("module", "files").set("./pfb_py_raw/feed.txt", []any{"x"}) },
		[]string{badFile, "module.files", "already listed"},
		"bad.json: module.files: './pfb_py_raw/feed.txt' names a file already listed", ""},
	{"files using a file as a directory", func(d *object) { d.get("module", "files").set("pfb_py_raw/feed.txt/x", []any{"x"}) },
		[]string{badFile, "module.files", "directory"},
		"bad.json: module.files: 'pfb_py_raw/feed.txt' is both a file and the directory of another listed file", ""},
	{"files path with a NUL", func(d *object) { d.get("module", "files").set("a\x00b", []any{"x"}) }, []string{badFile, "module.files"},
		`bad.json: module.files: unsafe path 'a\x00b': must be relative and stay inside the module directory`, ""},
	{"files path '.'", func(d *object) { d.get("module", "files").set(".", []any{"x"}) }, []string{badFile, "module.files"},
		"bad.json: module.files: unsafe path '.': must be relative and stay inside the module directory", ""},
	{"files path ''", func(d *object) { d.get("module", "files").set("", []any{"x"}) }, []string{badFile, "module.files"},
		"bad.json: module.files: unsafe path '': must be relative and stay inside the module directory", ""},
	{"unknown family", func(d *object) { caseZero(d).set("family", "nonesuch") }, []string{badFile, "'good'", "family"},
		"", "bad.json: case 'good': family: unknown value 'nonesuch', expected one of abp allow "},
	{"unknown top-level key", func(d *object) { d.set("extra", 1) }, []string{badFile, "extra"},
		"bad.json: extra: unknown key", ""},
	{"unknown key in a case", func(d *object) { caseZero(d).set("extra", 1) }, []string{badFile, "'good'", "extra"},
		"bad.json: case 'good': extra: unknown key", ""},
	{"missing expect.decision", func(d *object) { caseZero(d).get("expect").del("decision") }, []string{badFile, "'good'", "expect.decision"},
		"bad.json: case 'good': expect.decision: missing", ""},
	{"decision 'block'", func(d *object) { caseZero(d).get("expect").set("decision", "block") }, []string{badFile, "'good'", "expect.decision"},
		"bad.json: case 'good': expect.decision: unknown value 'block', expected one of answer drop relay rewrite", ""},
	{"query type BOGUS", func(d *object) { caseZero(d).get("query").set("type", "BOGUS") }, []string{badFile, "'good'", "query.type"},
		"bad.json: case 'good': query.type: unknown query type 'BOGUS'", ""},
	{"files path climbing out", func(d *object) { d.get("module", "files").set("../x", []any{"x"}) }, []string{badFile, "module.files", "../x"},
		"bad.json: module.files: unsafe path '../x': must be relative and stay inside the module directory", ""},
	{"files absolute path", func(d *object) { d.get("module", "files").set("/etc/x", []any{"x"}) }, []string{badFile, "module.files", "/etc/x"},
		"bad.json: module.files: unsafe path '/etc/x': must be relative and stay inside the module directory", ""},
	{"files overwriting the shipped decider", func(d *object) { d.get("module", "files").set("pfb_unbound.py", []any{"x"}) },
		[]string{badFile, "module.files", "pfb_unbound.py", "runner"},
		"bad.json: module.files: 'pfb_unbound.py' is written by the runner, never by a fixture", ""},
	{"files overwriting the manifest through a dot path", func(d *object) { d.get("module", "files").set("./pfb_py_sources.json", []any{"x"}) },
		[]string{badFile, "module.files", "pfb_py_sources.json", "runner"},
		"bad.json: module.files: './pfb_py_sources.json' is written by the runner, never by a fixture", ""},
	{"ini value that is not a string", func(d *object) { d.get("module", "ini", "MAIN").set("python_enable", true) },
		[]string{badFile, "module.ini.MAIN.python_enable"},
		"bad.json: module.ini.MAIN.python_enable: must be a string, got True", ""},
	{"duplicate case id", func(d *object) { d.set("cases", []any{caseZero(good()), caseZero(good())}) },
		[]string{badFile, "'good'", "id", "duplicate"},
		"bad.json: case 'good': id: duplicate within the file", ""},
	{"answer text rr_from_text rejects", func(d *object) {
		caseZero(d).get("expect").set("answer", []any{"allowed.example. 300 IN A not-an-address"})
	}, []string{badFile, "'good'", "expect.answer[0]"},
		"", "bad.json: case 'good': expect.answer[0]: rr_from_text rejects 'allowed.example. 300 IN A not-an-address': "},
	{"upstream text rr_from_text rejects", func(d *object) {
		d.get("upstream").set("allowed.example. A", []any{"allowed.example. 300 IN MX 10 mail.example."})
	}, []string{badFile, "upstream['allowed.example. A']"},
		"", "bad.json: upstream['allowed.example. A'][0]: rr_from_text rejects 'allowed.example. 300 IN MX 10 mail.example.': "},
	{"forward that is not '<name> <TYPE>'", func(d *object) { caseZero(d).get("expect").set("forwards", []any{"allowed.example."}) },
		[]string{badFile, "'good'", "expect.forwards[0]"},
		"bad.json: case 'good': expect.forwards[0]: expected '<name> <TYPE>', got 'allowed.example.'", ""},
	{"wire_hex with a name too", func(d *object) { caseZero(d).get("query").set("wire_hex", "00") }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: excludes query.name and query.type", ""},
	{"wire_hex with a type and no name", func(d *object) { caseZero(d).set("query", obj("wire_hex", "00", "type", "A")) },
		[]string{badFile, "'good'", "query"},
		"bad.json: case 'good': query.wire_hex: excludes query.name and query.type", ""},
	{"neither name nor wire_hex", func(d *object) { caseZero(d).set("query", obj()) }, []string{badFile, "'good'", "query", "wire_hex"},
		"bad.json: case 'good': query.name: missing: a query is a name and a type, or wire_hex", ""},
	{"name without type", func(d *object) { caseZero(d).get("query").del("type") }, []string{badFile, "'good'", "query.type"},
		"bad.json: case 'good': query.type: missing: a query is a name and a type, or wire_hex", ""},
	{"type without name", func(d *object) { caseZero(d).get("query").del("name") }, []string{badFile, "'good'", "query.name"},
		"bad.json: case 'good': query.name: missing: a query is a name and a type, or wire_hex", ""},
	{"wire_hex in upper case", func(d *object) { caseZero(d).set("query", obj("wire_hex", "AB")) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: 'AB' must be lower-case hex of whole bytes", ""},
	{"wire_hex of odd length", func(d *object) { caseZero(d).set("query", obj("wire_hex", "abc")) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: 'abc' must be lower-case hex of whole bytes", ""},
	{"wire_hex that is not hex", func(d *object) { caseZero(d).set("query", obj("wire_hex", "zz")) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: 'zz' must be lower-case hex of whole bytes", ""},
	{"wire_hex with a space", func(d *object) { caseZero(d).set("query", obj("wire_hex", "ab cd")) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: 'ab cd' must be lower-case hex of whole bytes", ""},
	{"wire_hex ending in a newline", func(d *object) { caseZero(d).set("query", obj("wire_hex", "ab\n")) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: " + `'ab\n'` + " must be lower-case hex of whole bytes", ""},
	{"wire_hex as a number", func(d *object) { caseZero(d).set("query", obj("wire_hex", 12)) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: must be a string, got 12", ""},
	{"wire_hex null", func(d *object) { caseZero(d).set("query", obj("wire_hex", nil)) }, []string{badFile, "'good'", "query.wire_hex"},
		"bad.json: case 'good': query.wire_hex: must be a string, got None", ""},
	{"wire_hex of 65536 bytes", func(d *object) { caseZero(d).set("query", obj("wire_hex", strings.Repeat("00", 65536))) },
		[]string{badFile, "'good'", "query.wire_hex", "65536"},
		"bad.json: case 'good': query.wire_hex: 65536 bytes: a DNS message has at most 65535", ""},
	{"drop with an rcode", func(d *object) {
		caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{}, "rcode", "NOERROR"))
	},
		[]string{badFile, "'good'", "expect.rcode"},
		"bad.json: case 'good': expect.rcode: unknown key: a drop has no ANSWER", ""},
	{"drop with answer", func(d *object) {
		caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{}, "answer", []any{}))
	},
		[]string{badFile, "'good'", "expect.answer"},
		"bad.json: case 'good': expect.answer: unknown key: a drop has no ANSWER", ""},
	{"drop with authority", func(d *object) {
		caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{}, "authority", []any{}))
	},
		[]string{badFile, "'good'", "expect.authority"},
		"bad.json: case 'good': expect.authority: unknown key: a drop has no ANSWER", ""},
	{"drop with tc", func(d *object) { caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{}, "tc", false)) },
		[]string{badFile, "'good'", "expect.tc"},
		"bad.json: case 'good': expect.tc: unknown key: a drop has no ANSWER", ""},
	{"drop with a forward", func(d *object) {
		caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{"allowed.example. A"}))
	},
		[]string{badFile, "'good'", "expect.forwards"},
		"bad.json: case 'good': expect.forwards: must be empty for a drop", ""},
	{"drop with a malformed forward", func(d *object) {
		caseZero(d).set("expect", obj("decision", "drop", "forwards", []any{"allowed.example."}))
	},
		[]string{badFile, "'good'", "expect.forwards[0]"},
		"bad.json: case 'good': expect.forwards[0]: expected '<name> <TYPE>', got 'allowed.example.'", ""},
	{"non-drop without an rcode", func(d *object) { caseZero(d).get("expect").del("rcode") }, []string{badFile, "'good'", "expect.rcode"},
		"bad.json: case 'good': expect.rcode: missing", ""},
	{"tc as a number", func(d *object) { caseZero(d).get("expect").set("tc", 1) }, []string{badFile, "'good'", "expect.tc"},
		"bad.json: case 'good': expect.tc: must be true or false, got 1", ""},
	{"tc as a string", func(d *object) { caseZero(d).get("expect").set("tc", "true") }, []string{badFile, "'good'", "expect.tc"},
		"bad.json: case 'good': expect.tc: must be true or false, got 'true'", ""},
	{"tc null", func(d *object) { caseZero(d).get("expect").set("tc", nil) }, []string{badFile, "'good'", "expect.tc"},
		"bad.json: case 'good': expect.tc: must be true or false, got None", ""},
	{"upstream value a string", func(d *object) { d.set("upstream", obj("allowed.example. A", "allowed.example. 300 IN A 192.0.2.77")) },
		[]string{badFile, "upstream['allowed.example. A']"},
		"bad.json: upstream['allowed.example. A']: must be a list, got 'allowed.example. 300 IN A 192.0.2.77'", ""},
	{"upstream value an object", func(d *object) { d.set("upstream", obj("allowed.example. A", obj())) },
		[]string{badFile, "upstream['allowed.example. A']"},
		"bad.json: upstream['allowed.example. A']: must be a list, got {}", ""},
	{"upstream value a number", func(d *object) { d.set("upstream", obj("allowed.example. A", 7)) },
		[]string{badFile, "upstream['allowed.example. A']"},
		"bad.json: upstream['allowed.example. A']: must be a list, got 7", ""},
	{"upstream value a list of numbers", func(d *object) { d.set("upstream", obj("allowed.example. A", []any{7})) },
		[]string{badFile, "upstream['allowed.example. A'][0]"},
		"bad.json: upstream['allowed.example. A'][0]: must be a string, got 7", ""},
	{"go_expect not an object", func(d *object) { caseZero(d).set("go_expect", "rewrite") },
		[]string{badFile, "'good'", "go_expect", "must be a JSON object"},
		"bad.json: case 'good': go_expect: must be a JSON object", ""},
	{"go_expect an empty object", func(d *object) { caseZero(d).set("go_expect", obj()) },
		[]string{badFile, "'good'", "go_expect.signoff", "missing"},
		"bad.json: case 'good': go_expect.signoff: missing", ""},
	{"go_expect with an unknown key", withGoExpect(func(g *object) { g.set("note", "x") }),
		[]string{badFile, "'good'", "go_expect.note", "unknown key"},
		"bad.json: case 'good': go_expect.note: unknown key", ""},
	{"go_expect without a signoff", withGoExpect(nil, "signoff"),
		[]string{badFile, "'good'", "go_expect.signoff", "missing"},
		"bad.json: case 'good': go_expect.signoff: missing", ""},
	{"signoff a number", withGoExpect(func(g *object) { g.set("signoff", 7) }),
		[]string{badFile, "'good'", "go_expect.signoff", "must be a string"},
		"bad.json: case 'good': go_expect.signoff: must be a string, got 7", ""},
	{"signoff empty", withGoExpect(func(g *object) { g.set("signoff", "") }),
		[]string{badFile, "'good'", "go_expect.signoff", "must not be empty"},
		"bad.json: case 'good': go_expect.signoff: must not be empty", ""},
	{"signoff on another site", withGoExpect(func(g *object) { g.set("signoff", "https://example.com/x") }),
		[]string{badFile, "'good'", "go_expect.signoff"},
		"bad.json: case 'good': go_expect.signoff: must start with 'https://github.com/pfBlockerNG/pfBlockerNG/issues/', got 'https://example.com/x'", ""},
	{"signoff over http", withGoExpect(func(g *object) { g.set("signoff", "http://github.com/pfBlockerNG/pfBlockerNG/issues/1") }),
		[]string{badFile, "'good'", "go_expect.signoff"},
		"bad.json: case 'good': go_expect.signoff: must start with 'https://github.com/pfBlockerNG/pfBlockerNG/issues/', got 'http://github.com/pfBlockerNG/pfBlockerNG/issues/1'", ""},
	{"signoff in another repository", withGoExpect(func(g *object) { g.set("signoff", "https://github.com/other/repo/issues/1") }),
		[]string{badFile, "'good'", "go_expect.signoff"},
		"bad.json: case 'good': go_expect.signoff: must start with 'https://github.com/pfBlockerNG/pfBlockerNG/issues/', got 'https://github.com/other/repo/issues/1'", ""},
	{"signoff a relative path", withGoExpect(func(g *object) { g.set("signoff", "issues/3511") }),
		[]string{badFile, "'good'", "go_expect.signoff"},
		"bad.json: case 'good': go_expect.signoff: must start with 'https://github.com/pfBlockerNG/pfBlockerNG/issues/', got 'issues/3511'", ""},
	{"go_expect equal to expect", func(d *object) {
		g := append(slices.Clone(*caseZero(d).get("expect")), member{"signoff", signoff})
		caseZero(d).set("go_expect", &g)
	}, []string{badFile, "'good'", "go_expect:", "equals expect"},
		"bad.json: case 'good': go_expect: equals expect, so it pins no Go-specific decision: remove it", ""},
	{"go_expect equal to expect once parsed (tc spelled out)", func(d *object) {
		g := append(slices.Clone(*caseZero(d).get("expect")), member{"tc", false}, member{"signoff", signoff})
		caseZero(d).set("go_expect", &g)
	}, []string{badFile, "'good'", "go_expect:", "equals expect"},
		"bad.json: case 'good': go_expect: equals expect, so it pins no Go-specific decision: remove it", ""},
	{"go_expect without a decision", withGoExpect(nil, "decision"),
		[]string{badFile, "'good'", "go_expect.decision", "missing"},
		"bad.json: case 'good': go_expect.decision: missing", ""},
	{"go_expect with decision 'block'", withGoExpect(func(g *object) { g.set("decision", "block") }),
		[]string{badFile, "'good'", "go_expect.decision"},
		"bad.json: case 'good': go_expect.decision: unknown value 'block', expected one of answer drop relay rewrite", ""},
	{"go_expect drop with an rcode", withGoExpect(func(g *object) { g.set("decision", "drop"); g.set("forwards", []any{}) }),
		[]string{badFile, "'good'", "go_expect.rcode", "a drop has no ANSWER"},
		"bad.json: case 'good': go_expect.rcode: unknown key: a drop has no ANSWER", ""},
	{"go_expect non-drop without an rcode", withGoExpect(nil, "rcode"),
		[]string{badFile, "'good'", "go_expect.rcode", "missing"},
		"bad.json: case 'good': go_expect.rcode: missing", ""},
	{"go_expect tc as a string", withGoExpect(func(g *object) { g.set("tc", "true") }),
		[]string{badFile, "'good'", "go_expect.tc"},
		"bad.json: case 'good': go_expect.tc: must be true or false, got 'true'", ""},
	{"go_expect answer not a record", withGoExpect(func(g *object) { g.set("answer", []any{"x"}) }),
		[]string{badFile, "'good'", "go_expect.answer[0]"},
		"", "bad.json: case 'good': go_expect.answer[0]: rr_from_text rejects 'x': "},
}

func TestTheLoaderRefusesABadScenarioNamingFileCaseAndField(t *testing.T) {
	for _, row := range hostile {
		t.Run(row.name, func(t *testing.T) {
			d := good()
			row.mutate(d)
			_, err := loadText(t, documentText(t, d))
			if err == nil {
				t.Fatal("the loader accepted the scenario")
			}
			message := refusalText(t, err)
			for _, name := range row.names {
				if !strings.Contains(message, name) {
					t.Errorf("%q must name %q", message, name)
				}
			}
			if row.exact != "" && message != row.exact {
				t.Errorf("message:\n got %q\nwant %q", message, row.exact)
			}
			if row.prefix != "" && !strings.HasPrefix(message, row.prefix) {
				t.Errorf("message:\n got %q\nwant it to start with %q", message, row.prefix)
			}
		})
	}
}

func TestTheLoaderAcceptsTheHighestNumberedQueryType(t *testing.T) {
	d := good()
	caseZero(d).get("query").set("type", "TYPE65535")
	s, err := loadText(t, documentText(t, d))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Cases[0].Query.Wire, query(t, "allowed.example.", 65535); !bytes.Equal(got, want) {
		t.Errorf("query.type TYPE65535: got wire %x, want %x", got, want)
	}
}

func TestTheUnknownFamilyMessageListsEveryFamilyInOrder(t *testing.T) {
	names, _ := realFamilies(t)
	d := good()
	caseZero(d).set("family", "nonesuch")
	_, err := loadText(t, documentText(t, d))
	want := "bad.json: case 'good': family: unknown value 'nonesuch', expected one of " + strings.Join(slices.Sorted(slices.Values(names)), " ")
	if got := refusalText(t, err); got != want {
		t.Errorf("message:\n got %q\nwant %q", got, want)
	}
}

func TestTheLoaderRefusesAnUnreadableDocumentAsAFixtureError(t *testing.T) {
	for name, row := range map[string]struct{ document, reason string }{
		"key written twice":                 {`{"schema": 1, "schema": 2}`, `duplicate JSON key 'schema'`},
		"nesting too deep to read":          {strings.Repeat("[", 100_000), depthReason},
		"empty file":                        {"", ""},
		"cut off":                           {`{"schema": `, ""},
		"text after the document":           {`{"schema": 1} {}`, ""},
		"infinity, which only Python reads": {`{"schema": Infinity}`, ""},
		"bytes that are not UTF-8":          {"{\"schema\": \"\xff\"}", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadText(t, row.document)
			message := refusalText(t, err)
			if !strings.HasPrefix(message, "bad.json: not a readable JSON document: ") || !strings.Contains(message, row.reason) {
				t.Errorf("message %q must be %q then a reason containing %q", message, "bad.json: not a readable JSON document: ", row.reason)
			}
		})
	}
}

// The cap is Python's floor through the loader: it reads 990 levels and refuses 1000 (the real limit is the recursion
// limit less the caller's stack). The numbers are written out here so a change of the constant turns these tests red.
const (
	depthCap    = 990
	depthReason = "nesting deeper than 990 levels"
)

// nestedSchema is a valid scenario whose "schema" holds arrays, so that the whole document nests `levels` deep (its own
// object is the first level) and the first thing refused, past the JSON stage, is the schema field.
func nestedSchema(t *testing.T, levels int) string {
	d := good()
	d.set("schema", raw(strings.Repeat("[", levels-1)+strings.Repeat("]", levels-1)))
	return documentText(t, d)
}

func TestTheLoaderRefusesADocumentNestedPastTheCapAndReadsOneAtTheCap(t *testing.T) {
	_, err := loadText(t, nestedSchema(t, depthCap+1))
	if got, want := refusalText(t, err), "bad.json: not a readable JSON document: "+depthReason; got != want {
		t.Errorf("one level past the cap:\n got %q\nwant %q", got, want)
	}

	_, err = loadText(t, nestedSchema(t, depthCap))
	got := refusalText(t, err)
	if strings.Contains(got, "not a readable JSON document") || !strings.HasPrefix(got, "bad.json: schema: must be the integer 3, got [[") {
		t.Errorf("at the cap the JSON stage must pass and the schema field be what is refused: got %.120q", got)
	}
}

// withEscape is the document with every "@@" replaced by the escape's text, which json.Marshal cannot write.
func withEscape(t *testing.T, d *object, escape string) string {
	t.Helper()
	return strings.ReplaceAll(documentText(t, d), "@@", escape)
}

func TestTheLoaderRefusesALoneSurrogateEscapeWhereverItStands(t *testing.T) {
	const escape = `\ud800`
	for _, position := range []struct {
		name   string
		mutate func(d *object)
	}{
		{"query.name", func(d *object) { caseZero(d).get("query").set("name", "@@.example.") }},
		{"an upstream key", func(d *object) { d.set("upstream", obj("@@.example. A", []any{})) }},
		{"a description", func(d *object) { d.set("description", "x@@y") }},
		{"an ini value", func(d *object) { d.get("module", "ini", "MAIN").set("python_enable", "@@") }},
		{"a files path", func(d *object) { d.get("module", "files").set("@@.txt", []any{"x"}) }},
		{"a files line", func(d *object) { d.get("module", "files").set("pfb_py_raw/feed.txt", []any{"@@"}) }},
		{"a manifest value", func(d *object) { d.get("module", "manifest").set("x", "@@") }},
	} {
		t.Run(position.name, func(t *testing.T) {
			d := good()
			position.mutate(d)
			text := withEscape(t, d, escape)
			_, err := loadText(t, text)
			want := fmt.Sprintf("bad.json: not a readable JSON document: lone surrogate %s at byte %d", escape, strings.Index(text, escape))
			if got := refusalText(t, err); got != want {
				t.Errorf("message:\n got %q\nwant %q", got, want)
			}
		})
	}
}

func TestTheLoaderRefusesEveryEscapeThatIsHalfOfNoSurrogatePairAndOnlyThose(t *testing.T) {
	// shortcut: Python takes a lone surrogate into a str and refuses it only where it must be encoded (a name, a file
	// the runner writes); the loader refuses it in every field, which is stricter on the ones Python never encodes.
	for name, escape := range map[string]string{
		"a high half":                           `\ud800`,
		"a high half in upper case":             `\uD800`,
		"the last high half":                    `\udbff`,
		"a low half":                            `\udc00`,
		"the last low half":                     `\udfff`,
		"a high half then another escape":       `\ud800\u0041`,
		"a high half then a plain character":    `\ud800x`,
		"a low half then a high half":           `\udc00\ud800`,
		"two high halves":                       `\ud800\ud800`,
		"a high half then an escaped backslash": `\ud800\\udc00`,
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			d := good()
			d.set("description", "x@@y")
			text := withEscape(t, d, escape)
			_, err := loadText(t, text)
			want := fmt.Sprintf("bad.json: not a readable JSON document: lone surrogate %s at byte %d", escape[:6], strings.Index(text, escape))
			if got := refusalText(t, err); got != want {
				t.Errorf("message:\n got %q\nwant %q", got, want)
			}
		})
	}
	for _, row := range []struct{ name, escape, want string }{
		{"a valid pair", `\ud83d\ude00`, "x\U0001F600y"},
		{"a valid pair in upper case", `\uD83D\uDE00`, "x\U0001F600y"},
		{"an escaped backslash then text that spells a surrogate", `\\ud800`, `x\ud800y`},
		{"the code point below the range", `\ud7ff`, "x\ud7ffy"},
		{"the code point above the range", `\ue000`, "x\ue000y"},
		{"the replacement character", `\ufffd`, "x\ufffdy"},
	} {
		t.Run("reads "+row.name, func(t *testing.T) {
			d := good()
			d.set("description", "x@@y")
			s, err := loadText(t, withEscape(t, d, row.escape))
			if err != nil {
				t.Fatal(err)
			}
			if s.Description != row.want {
				t.Errorf("description: got %q, want %q", s.Description, row.want)
			}
		})
	}
}

func TestTheLoaderRefusesABadFamiliesIndex(t *testing.T) {
	for _, row := range []struct{ name, document, want string }{
		{"schema 1", `{"schema": 1, "families": {"relay": "x"}}`, "families.json: schema: must be the integer 3, got 1"},
		{"schema 2", `{"schema": 2, "families": {"relay": "x"}}`, "families.json: schema: must be the integer 3, got 2"},
		{"source", `{"schema": 3, "families": {"relay": 7}}`, "families.json: families.relay: must be a string, got 7"},
		{"no family", `{"schema": 3, "families": {}}`, "families.json: families: must be a non-empty JSON object of family -> source branch"},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "families.json")
			if err := os.WriteFile(path, []byte(row.document), 0o644); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadFamilies(path)
			if got := refusalText(t, err); got != row.want {
				t.Errorf("message:\n got %q\nwant %q", got, row.want)
			}
		})
	}
}

func TestTheFamiliesComeBackInFileOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "families.json")
	if err := os.WriteFile(path, []byte(`{"schema": 3, "families": {"zeta": "z branch", "alpha": "a branch"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	names, source, err := LoadFamilies(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"zeta", "alpha"}) || !maps.Equal(source, map[string]string{"zeta": "z branch", "alpha": "a branch"}) {
		t.Errorf("got %v %v", names, source)
	}
}

func TestEveryFileInTheCorpusIsAJSONDocumentTheRunnerLoadsAndEveryFamilyHasCases(t *testing.T) {
	names, source := realFamilies(t)
	entries, err := os.ReadDir(Fixtures())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	total := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			t.Errorf("never loaded, so never run: %s", entry.Name())
			continue
		}
		if entry.Name() == "families.json" {
			continue
		}
		s, err := LoadScenario(filepath.Join(Fixtures(), entry.Name()), source)
		if err != nil {
			t.Error(err)
			continue
		}
		for _, c := range s.Cases {
			counts[c.Family]++
			total++
		}
	}
	for _, name := range names {
		t.Logf("family %s: %d cases", name, counts[name])
		if counts[name] == 0 {
			t.Errorf("family %s has no case", name)
		}
	}
	t.Logf("%d families, %d cases", len(names), total)
}

func TestWriteModuleWritesTheIniTheManifestAndTheFilesExactly(t *testing.T) {
	root := t.TempDir()
	m := Module{
		Ini: []IniSection{
			{Name: "MAIN", Keys: [][2]string{{"python_enable", "true"}, {"dnsbl_ipv4", "10.10.10.1"}}},
			{Name: "GROUP", Keys: [][2]string{{"mode", "x y"}}},
		},
		Manifest: []byte(`{"version": 1}`),
		Files: []ModuleFile{
			{Path: "pfb_py_raw/feed.txt", Lines: []string{"a.example", "b.example"}},
			{Path: "empty.txt"},
		},
	}
	if err := WriteModule(root, m); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		"pfb_unbound.ini":     "[MAIN]\npython_enable = true\ndnsbl_ipv4 = 10.10.10.1\n\n[GROUP]\nmode = x y\n\n",
		"pfb_py_sources.json": `{"version": 1}`,
		"pfb_py_raw/feed.txt": "a.example\nb.example\n",
		"empty.txt":           "\n",
	} {
		got, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Errorf("%s: %v", file, err)
		} else if string(got) != want {
			t.Errorf("%s:\n got %q\nwant %q", file, got, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "pfb_unbound.py")); !os.IsNotExist(err) {
		t.Errorf("the Go decider reads no Python, so WriteModule links none: Lstat gave %v", err)
	}
}

func TestBuildQueryIsOneRecursiveQuestionWithoutEDNS(t *testing.T) {
	got, err := BuildQuery("a.example.", dnswire.TYPE_A)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x07example\x00\x00\x01\x00\x01")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

var zone = map[UpstreamKey][]string{
	{Name: "allowed.example.", Qtype: dnswire.TYPE_A}: {"allowed.example. 300 IN A 192.0.2.77"},
	{Name: "empty.example.", Qtype: dnswire.TYPE_A}:   {},
	{Name: "silent.example.", Qtype: dnswire.TYPE_A}:  nil,
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	wire, err := BuildQuery(name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func answer(t *testing.T, u *FakeUnbound, wire []byte) (*dnswire.Message, []byte) {
	t.Helper()
	reply, err := u.Answer(wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dnswire.Parse(reply)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, reply
}

func TestFakeUnboundAnswersAListedQuestionNoerrorWithItsRecords(t *testing.T) {
	u := NewFakeUnbound(zone)
	wire := query(t, "Allowed.Example.", dnswire.TYPE_A) // the zone is looked up in lower case
	reply, _ := answer(t, u, wire)
	if reply.ID != 0x1234 || reply.Flags != dnswire.QR|dnswire.RA|dnswire.RD {
		t.Errorf("header: got id %#x flags %#x", reply.ID, reply.Flags)
	}
	if want := []dnswire.Question{{Name: "Allowed.Example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}}; !reflect.DeepEqual(reply.Questions, want) {
		t.Errorf("questions: got %+v, want %+v", reply.Questions, want)
	}
	if len(reply.Answers) != 1 || reply.Answers[0].Rtype != dnswire.TYPE_A || reply.Answers[0].TTL != 300 ||
		!bytes.Equal(reply.Answers[0].Rdata, []byte{192, 0, 2, 77}) {
		t.Errorf("answers: got %+v", reply.Answers)
	}
	if len(reply.Authority) != 0 || len(reply.Additional) != 0 {
		t.Errorf("only the answer section is filled: got %+v %+v", reply.Authority, reply.Additional)
	}
}

func TestFakeUnboundAnswersAListedEmptyQuestionNoerrorWithoutRecords(t *testing.T) {
	reply, _ := answer(t, NewFakeUnbound(zone), query(t, "empty.example.", dnswire.TYPE_A))
	if reply.Rcode() != 0 || reply.Flags != dnswire.QR|dnswire.RA|dnswire.RD || len(reply.Answers) != 0 {
		t.Errorf("got flags %#x with %d answers", reply.Flags, len(reply.Answers))
	}
}

func TestFakeUnboundAnswersAnUnlistedQuestionNxdomain(t *testing.T) {
	for name, wire := range map[string][]byte{
		"unknown name":            query(t, "unknown.example.", dnswire.TYPE_A),
		"listed name, other type": query(t, "allowed.example.", dnswire.TYPE_AAAA),
	} {
		reply, _ := answer(t, NewFakeUnbound(zone), wire)
		if reply.Flags != dnswire.QR|dnswire.RA|dnswire.RD|3 || len(reply.Answers) != 0 {
			t.Errorf("%s: got flags %#x with %d answers", name, reply.Flags, len(reply.Answers))
		}
	}
}

func TestFakeUnboundEchoesTheQueriesRecursionDesired(t *testing.T) {
	wire := query(t, "allowed.example.", dnswire.TYPE_A)
	wire[2] = 0 // flags 0x0000: RD clear
	reply, _ := answer(t, NewFakeUnbound(zone), wire)
	if reply.Flags != dnswire.QR|dnswire.RA {
		t.Errorf("got flags %#x, want QR|RA", reply.Flags)
	}
}

func TestFakeUnboundRecordsEveryQueryAndItsOwnCopyOfEveryReply(t *testing.T) {
	u := NewFakeUnbound(zone)
	wire := query(t, "allowed.example.", dnswire.TYPE_A)
	_, reply := answer(t, u, wire)
	if len(u.Queries) != 1 || !bytes.Equal(u.Queries[0], wire) || len(u.Replies) != 1 || !bytes.Equal(u.Replies[0], reply) {
		t.Fatalf("recorded %x and %x for %x and %x", u.Queries, u.Replies, wire, reply)
	}
	kept := bytes.Clone(reply)
	reply[0]++ // a decider that edits the reply it was handed must not change what Unbound is on record as having said
	wire[0]++
	if !bytes.Equal(u.Replies[0], kept) || bytes.Equal(u.Queries[0], wire) {
		t.Errorf("the records changed with the caller's slices: %x %x", u.Queries[0], u.Replies[0])
	}
}

func TestFakeUnboundRecordsNothingForAQueryItCannotParseOrThatAsksNothing(t *testing.T) {
	noQuestion := make([]byte, 12) // a well-formed header: the zone is keyed on the first question, and there is none
	for name, wire := range map[string][]byte{"not a message": {1, 2, 3}, "no question": noQuestion} {
		u := NewFakeUnbound(zone)
		if reply, err := u.Answer(wire); err == nil || reply != nil {
			t.Errorf("%s: got %x, %v; want an error and no reply", name, reply, err)
		}
		if len(u.Queries) != 0 || len(u.Replies) != 0 {
			t.Errorf("%s: recorded %d queries and %d replies, want none: the question is read before anything is kept", name, len(u.Queries), len(u.Replies))
		}
	}
}

func TestFakeUnboundGivesNoReplyForAQuestionTheZoneListsAsNull(t *testing.T) {
	u := NewFakeUnbound(zone)
	wire := query(t, "SILENT.example.", dnswire.TYPE_A)
	if reply, err := u.Answer(wire); err != nil || reply != nil {
		t.Errorf("got %x, %v; want no reply and no error", reply, err)
	}
	if len(u.Queries) != 1 || !bytes.Equal(u.Queries[0], wire) {
		t.Errorf("the query is on record: got %x", u.Queries)
	}
	if len(u.Replies) != 1 || len(u.Replies[0]) != 0 {
		t.Errorf("the empty REPLY is on record, so no ANSWER can be taken for Unbound's: got %x", u.Replies)
	}
}

func TestFakeUnboundKeysOnTheFirstQuestionIgnoresItsClassAndEchoesTheQuestionsAndTheID(t *testing.T) {
	questions := []dnswire.Question{
		{Name: "Allowed.example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_ANY},
		{Name: "unknown.example.", Qtype: dnswire.TYPE_AAAA, Qclass: dnswire.CLASS_IN},
	}
	wire, err := dnswire.Encode(&dnswire.Message{ID: 0xBEEF, Flags: dnswire.RD, Questions: questions})
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := answer(t, NewFakeUnbound(zone), wire)
	if reply.ID != 0xBEEF || reply.Flags != dnswire.QR|dnswire.RA|dnswire.RD || len(reply.Answers) != 1 {
		t.Errorf("first question listed, class ANY: got id %#x flags %#x with %d answers", reply.ID, reply.Flags, len(reply.Answers))
	}
	if !reflect.DeepEqual(reply.Questions, questions) {
		t.Errorf("questions: got %+v, want %+v", reply.Questions, questions)
	}

	swapped, err := dnswire.Encode(&dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: []dnswire.Question{questions[1], questions[0]}})
	if err != nil {
		t.Fatal(err)
	}
	reply, _ = answer(t, NewFakeUnbound(zone), swapped)
	if reply.Rcode() != 3 || len(reply.Answers) != 0 {
		t.Errorf("first question unlisted, second listed: got rcode %d with %d answers, want NXDOMAIN", reply.Rcode(), len(reply.Answers))
	}
}

func TestRRTextIsOwnerTTLClassTypeAndHexRdata(t *testing.T) {
	got := RRText(mustRR(t, "allowed.example. 300 IN A 192.0.2.77"))
	if want := "allowed.example. 300 class1 A c000024d"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := RRText(dnswire.RR{Name: "x.", Rtype: 4242, Rclass: 255, TTL: 7}), "x. 7 class255 TYPE4242 "; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecisionTellsAnswerRelayRewriteAndUnclassifiedApart(t *testing.T) {
	first := query(t, "allowed.example.", dnswire.TYPE_A)
	second := query(t, "unknown.example.", dnswire.TYPE_A)

	if got := Decision(first, NewFakeUnbound(zone), []byte("built by the decider")); got != "answer" {
		t.Errorf("no FORWARD: got %q, want answer", got)
	}

	u := NewFakeUnbound(zone)
	_, reply := answer(t, u, first)
	if got := Decision(first, u, reply); got != "relay" {
		t.Errorf("the client's own wire forwarded, Unbound's reply back: got %q, want relay", got)
	}
	if got := Decision(first, u, append(bytes.Clone(reply), 0)); got != "rewrite" {
		t.Errorf("an ANSWER that is none of Unbound's replies: got %q, want rewrite", got)
	}

	const unclassified = "unclassified: the ANSWER is an Unbound reply but not the one relayed FORWARD"
	if got := Decision(second, u, reply); got != unclassified {
		t.Errorf("another question forwarded: got %q, want %q", got, unclassified)
	}
	_, other := answer(t, u, second)
	if got := Decision(first, u, reply); got != unclassified {
		t.Errorf("two FORWARDs: got %q, want %q", got, unclassified)
	}
	if got := Decision(second, u, other); got != unclassified {
		t.Errorf("two FORWARDs, the second one's reply: got %q, want %q", got, unclassified)
	}
}

func TestDecisionIsDropWhenThereIsNoAnswerWhateverWasForwarded(t *testing.T) {
	wire := query(t, "allowed.example.", dnswire.TYPE_A)
	if got := Decision(wire, NewFakeUnbound(zone), nil); got != "drop" {
		t.Errorf("nothing forwarded: got %q, want drop", got)
	}
	u := NewFakeUnbound(zone)
	answer(t, u, wire)
	if got := Decision(wire, u, nil); got != "drop" {
		t.Errorf("forwarded first: got %q, want drop", got)
	}
}

func TestDecisionCountsTheServfailTheDeciderBuildsForUnboundsSilenceAsARewrite(t *testing.T) {
	wire := query(t, "silent.example.", dnswire.TYPE_A)
	u := NewFakeUnbound(zone)
	if _, err := u.Answer(wire); err != nil {
		t.Fatal(err)
	}
	servfail, err := dnswire.Encode(&dnswire.Message{
		ID: 0x1234, Flags: dnswire.QR | dnswire.RA | dnswire.RD | 2,
		Questions: []dnswire.Question{{Name: "silent.example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := Decision(wire, u, servfail); got != "rewrite" {
		t.Errorf("got %q, want rewrite", got)
	}
}

func TestMismatchesIsEmptyForTheExpectedExchangeAndNamesTheFieldThatDiffers(t *testing.T) {
	a := mustRR(t, "allowed.example. 300 IN A 192.0.2.77")
	other := mustRR(t, "x.example. 5 IN A 1.1.1.1")
	s := &Scenario{Name: "s.json"}
	base := Case{ID: "c", Expect: Expect{
		Decision: "relay", Forwards: []string{"allowed.example. A"}, Rcode: "NOERROR", Answer: []dnswire.RR{a},
	}}
	wire := query(t, "allowed.example.", dnswire.TYPE_A)
	u := NewFakeUnbound(zone)
	_, reply := answer(t, u, wire)

	if got := Mismatches(s, &base, wire, u, reply); len(got) != 0 {
		t.Fatalf("the expected exchange: got %q", got)
	}

	for _, row := range []struct {
		name   string
		expect func(e *Expect)
		want   []string
	}{
		{"decision", func(e *Expect) { e.Decision = "answer" },
			[]string{"s.json: case 'c': decision: expected 'answer', got 'relay'"}},
		{"forwards", func(e *Expect) { e.Forwards = []string{"other.example. A"} },
			[]string{"s.json: case 'c': forwards: expected ['other.example. A'], got ['allowed.example. A']"}},
		{"rcode", func(e *Expect) { e.Rcode = "NXDOMAIN" },
			[]string{"s.json: case 'c': rcode: expected 'NXDOMAIN', got 'NOERROR'"}},
		{"answer", func(e *Expect) { e.Answer = nil },
			[]string{"s.json: case 'c': answer: expected [], got ['allowed.example. 300 class1 A c000024d']"}},
		{"authority", func(e *Expect) { e.Authority = []dnswire.RR{other} },
			[]string{"s.json: case 'c': authority: expected ['x.example. 5 class1 A 01010101'], got []"}},
		{"two fields, in the contract's order", func(e *Expect) { e.Rcode = "SERVFAIL"; e.Decision = "rewrite" },
			[]string{
				"s.json: case 'c': decision: expected 'rewrite', got 'relay'",
				"s.json: case 'c': rcode: expected 'SERVFAIL', got 'NOERROR'",
			}},
	} {
		t.Run(row.name, func(t *testing.T) {
			c := base
			row.expect(&c.Expect)
			if got := Mismatches(s, &c, wire, u, reply); !slices.Equal(got, row.want) {
				t.Errorf("got %q\nwant %q", got, row.want)
			}
		})
	}
}

func TestMismatchesComparesTheAnswersIDAndTC(t *testing.T) {
	s := &Scenario{Name: "s.json"}
	a := mustRR(t, "allowed.example. 300 IN A 192.0.2.77")
	wire := query(t, "allowed.example.", dnswire.TYPE_A) // id 0x1234 = 4660
	u := NewFakeUnbound(zone)
	_, reply := answer(t, u, wire)
	otherID := bytes.Clone(reply)
	otherID[0] ^= 0xff // id 0xed34 = 60724
	truncated := bytes.Clone(reply)
	truncated[2] |= 0x02 // the TC bit
	rewrite := Expect{Decision: "rewrite", Forwards: []string{"allowed.example. A"}, Rcode: "NOERROR", Answer: []dnswire.RR{a}}
	relayTC := rewrite
	relayTC.Decision, relayTC.TC = "relay", true
	rewriteTC := rewrite
	rewriteTC.TC = true

	for _, row := range []struct {
		name   string
		expect Expect
		answer []byte
		want   []string
	}{
		{"the id differs", rewrite, otherID, []string{"s.json: case 'c': id: expected 4660, got 60724"}},
		{"TC set, not expected", rewrite, truncated, []string{"s.json: case 'c': tc: expected False, got True"}},
		{"TC expected, not set", relayTC, reply, []string{"s.json: case 'c': tc: expected True, got False"}},
		{"TC expected and set", rewriteTC, truncated, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := Mismatches(s, &Case{ID: "c", Expect: row.expect}, wire, u, row.answer); !slices.Equal(got, row.want) {
				t.Errorf("got %q\nwant %q", got, row.want)
			}
		})
	}

	answered := Case{ID: "c", Expect: Expect{Decision: "answer", Rcode: "NOERROR", Answer: []dnswire.RR{a}}}
	for name, row := range map[string]struct {
		wire []byte
		want string
	}{
		"a query of one byte": {[]byte{0x12}, "s.json: case 'c': id: expected 18, got 4660"},
		"a query of no bytes": {nil, "s.json: case 'c': id: expected 0, got 4660"},
	} {
		if got := Mismatches(s, &answered, row.wire, NewFakeUnbound(zone), reply); !slices.Equal(got, []string{row.want}) {
			t.Errorf("%s: got %q, want %q", name, got, row.want)
		}
	}
}

func TestMismatchesForADropComparesOnlyTheDecisionAndTheForwards(t *testing.T) {
	s := &Scenario{Name: "s.json"}
	a := mustRR(t, "allowed.example. 300 IN A 192.0.2.77")
	wire := query(t, "allowed.example.", dnswire.TYPE_A)
	forwarded := NewFakeUnbound(zone)
	_, reply := answer(t, forwarded, wire)
	drop := Case{ID: "c", Expect: Expect{Decision: "drop"}}
	relay := Case{ID: "c", Expect: Expect{Decision: "relay", Forwards: []string{"allowed.example. A"}, Rcode: "NOERROR", Answer: []dnswire.RR{a}}}

	for _, row := range []struct {
		name   string
		c      Case
		u      *FakeUnbound
		answer []byte
		want   []string
	}{
		{"a drop as expected", drop, NewFakeUnbound(zone), nil, nil},
		{"a drop after a FORWARD", drop, forwarded, nil,
			[]string{"s.json: case 'c': forwards: expected [], got ['allowed.example. A']"}},
		{"an ANSWER where a drop is expected", drop, NewFakeUnbound(zone), reply,
			[]string{"s.json: case 'c': decision: expected 'drop', got 'answer'"}},
		{"an ANSWER that is no DNS message where a drop is expected", drop, NewFakeUnbound(zone), []byte{1, 2, 3},
			[]string{"s.json: case 'c': decision: expected 'drop', got 'answer'"}},
		{"a drop where an ANSWER is expected", relay, forwarded, nil,
			[]string{"s.json: case 'c': decision: expected 'relay', got 'drop'"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := Mismatches(s, &row.c, wire, row.u, row.answer); !slices.Equal(got, row.want) {
				t.Errorf("got %q\nwant %q", got, row.want)
			}
		})
	}
}

func TestMismatchesReportsAnAnswerThatIsNotADNSMessageAsOneLine(t *testing.T) {
	s := &Scenario{Name: "s.json"}
	c := Case{ID: "c", Expect: Expect{Decision: "answer", Rcode: "NOERROR"}}
	for name, answer := range map[string][]byte{"garbage": {1, 2, 3}, "no bytes": {}} {
		got := Mismatches(s, &c, query(t, "a.example.", dnswire.TYPE_A), NewFakeUnbound(zone), answer)
		if len(got) != 1 || !strings.HasPrefix(got[0], "s.json: case 'c': answer: ") {
			t.Errorf("%s: got %q, want one line starting %q", name, got, "s.json: case 'c': answer: ")
		}
	}
}
