// Package paritycorpus is the Go side of the schema-1 parity corpus contract, so the Go decider runs the JSON scenarios
// the Python one passes. It translates tests/dns_proxy/test_parity_corpus.py (the loader, write_module, RecordingUnbound,
// _decision, _rr_text, _mismatches) and tests/dns_proxy/frontend_helpers.py (build_query, FakeUnbound without verdicts).
package paritycorpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const DEFAULT_CLIENT = "192.0.2.10"

var (
	RUNNER_WRITES = []string{"pfb_unbound.py", "pfb_dnsbl_regex_rules.py", "pfb_unbound.ini", "pfb_py_sources.json"}
	TRANSPORTS    = []string{"TCP", "UDP", "DoT", "DoH", "DoQ"} // the QUERY frame's transport byte is this index
	DECISIONS     = []string{"answer", "relay", "rewrite"}
	RCODES        = map[string]int{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
	QTYPES        = map[string]uint16{
		"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "SIG": 24, "AAAA": 28, "SRV": 33,
		"DNAME": 39, "SVCB": 64, "HTTPS": 65, "ANY": 255,
	}
)

// FixtureError is a parity fixture the loader refuses; the message names the file, the case (when there is one) and
// the field.
type FixtureError string

func (e FixtureError) Error() string { return string(e) }

type Query struct {
	Name      string
	Qtype     uint16
	Client    string
	Transport string
}

type Expect struct {
	Decision  string
	Forwards  []string
	Rcode     string
	Answer    []dnswire.RR
	Authority []dnswire.RR
}

type Case struct {
	ID, Family, Description string
	Query                   Query
	Expect                  Expect
}

type IniSection struct {
	Name string
	Keys [][2]string // key, value in file order
}

type ModuleFile struct {
	Path  string // as_posix-normalised
	Lines []string
}

type Module struct {
	Ini      []IniSection // file order
	Manifest []byte       // the fixture's JSON value as written
	Files    []ModuleFile
}

type UpstreamKey struct {
	Name  string
	Qtype uint16
}

type Scenario struct {
	Name, Description string
	Module            Module
	Upstream          map[UpstreamKey][]string // FakeUnbound's zone: (lower-case name, qtype) -> RR texts
	Cases             []Case
}

// Fixtures is the absolute path of tests/dns_proxy/fixtures/parity, found from this file so any package's test can use it.
func Fixtures() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "tests", "dns_proxy", "fixtures", "parity")
}

// --- the loader: every defect is one FixtureError ---------------------------------------------------------------

// fail panics with the FixtureError; the exported loaders turn it back into their error return.
func fail(where, field, why string) {
	panic(FixtureError(where + ": " + field + ": " + why))
}

func catch(run func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			refusal, ok := r.(FixtureError)
			if !ok {
				panic(r)
			}
			err = refusal
		}
	}()
	run()
	return nil
}

// orderedObject is a JSON object with its keys in file order and each member's value as written.
type orderedObject struct {
	keys []string
	vals map[string]any
	raw  map[string][]byte
}

// maxDepth: Python's json gives up on absurd nesting with a RecursionError; so does the loader.
const maxDepth = 512

func parseDocument(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := readValue(dec, data, 0)
	if err != nil {
		return nil, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("extra data after the document: %v", tok)
		}
		return nil, err
	}
	return value, nil
}

func readValue(dec *json.Decoder, data []byte, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, endOfInput(err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if depth >= maxDepth {
		return nil, fmt.Errorf("nesting deeper than %d levels", maxDepth)
	}
	if delim == '[' {
		return readArray(dec, data, depth+1)
	}
	return readObject(dec, data, depth+1)
}

func readArray(dec *json.Decoder, data []byte, depth int) (any, error) {
	items := []any{}
	for dec.More() {
		item, err := readValue(dec, data, depth)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if _, err := dec.Token(); err != nil {
		return nil, endOfInput(err)
	}
	return items, nil
}

func readObject(dec *json.Decoder, data []byte, depth int) (any, error) {
	object := &orderedObject{vals: map[string]any{}, raw: map[string][]byte{}}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, endOfInput(err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("object key %v is not a string", tok)
		}
		if _, seen := object.vals[key]; seen {
			return nil, fmt.Errorf("duplicate JSON key %s", pyRepr(key))
		}
		start := dec.InputOffset() // just after the key: the colon and any blanks come before the value
		value, err := readValue(dec, data, depth)
		if err != nil {
			return nil, err
		}
		object.keys = append(object.keys, key)
		object.vals[key] = value
		object.raw[key] = bytes.Trim(data[start:dec.InputOffset()], " \t\r\n:")
	}
	if _, err := dec.Token(); err != nil {
		return nil, endOfInput(err)
	}
	return object, nil
}

func endOfInput(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func readJSON(where string, data []byte) any {
	value, err := parseDocument(data)
	if err != nil {
		panic(FixtureError(where + ": not a readable JSON document: " + err.Error()))
	}
	return value
}

// objectOf is value as a JSON object with exactly the required keys plus any of the optional ones.
func objectOf(value any, where, field string, required []string, optional ...string) *orderedObject {
	object, ok := value.(*orderedObject)
	if !ok {
		shown := field
		if shown == "" {
			shown = "document"
		}
		fail(where, shown, "must be a JSON object")
	}
	prefix := field
	if prefix != "" {
		prefix += "."
	}
	for _, key := range object.keys {
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			fail(where, prefix+key, "unknown key")
		}
	}
	for _, key := range required {
		if _, ok := object.vals[key]; !ok {
			fail(where, prefix+key, "missing")
		}
	}
	return object
}

func stringValue(value any, where, field string) string {
	text, ok := value.(string)
	if !ok {
		fail(where, field, "must be a string, got "+pyRepr(value))
	}
	return text
}

func stringValues(value any, where, field string) []string {
	items, ok := value.([]any)
	if !ok {
		fail(where, field, "must be a list, got "+pyRepr(value))
	}
	out := make([]string, len(items))
	for index, item := range items {
		out[index] = stringValue(item, where, fmt.Sprintf("%s[%d]", field, index))
	}
	return out
}

func choice(value any, where, field string, allowed []string) string {
	text := stringValue(value, where, field)
	if !slices.Contains(allowed, text) {
		fail(where, field, fmt.Sprintf("unknown value %s, expected one of %s", pyRepr(text), strings.Join(slices.Sorted(slices.Values(allowed)), " ")))
	}
	return text
}

func iniText(text, where, field, forbidden string) string {
	if strings.ContainsAny(text, forbidden) {
		fail(where, field, fmt.Sprintf("%s must not contain any of %s", pyRepr(text), pyRepr(forbidden)))
	}
	return text
}

func schema(doc *orderedObject, where string) {
	if number, ok := doc.vals["schema"].(json.Number); !ok || number.String() != "1" { // a bool or 1.0 is not the integer 1
		fail(where, "schema", "must be the integer 1, got "+pyRepr(doc.vals["schema"]))
	}
}

var typeNumber = regexp.MustCompile(`^TYPE([0-9]{1,5})$`)

func qtype(text, where, field string) uint16 {
	if number, ok := QTYPES[text]; ok {
		return number
	}
	if numbered := typeNumber.FindStringSubmatch(text); numbered != nil {
		if number, _ := strconv.Atoi(numbered[1]); number <= 0xFFFF {
			return uint16(number)
		}
	}
	fail(where, field, "unknown query type "+pyRepr(text))
	return 0
}

func typeText(qtype uint16) string {
	for name, number := range QTYPES {
		if number == qtype {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func wireName(name, where, field string) string {
	if _, err := dnswire.NameToLabels(name); err != nil {
		fail(where, field, fmt.Sprintf("name %s cannot go on the wire: %v", pyRepr(name), err))
	}
	if !strings.HasSuffix(name, ".") {
		fail(where, field, fmt.Sprintf("name %s must be absolute (end with a dot)", pyRepr(name)))
	}
	return name
}

// question is "<name> <TYPE>" as the name and the numeric type.
func question(text, where, field string) (string, uint16) {
	name, kind, found := strings.Cut(text, " ")
	if !found {
		fail(where, field, "expected '<name> <TYPE>', got "+pyRepr(text))
	}
	return wireName(name, where, field), qtype(kind, where, field)
}

func rrFromText(text, where, field string, index int) dnswire.RR {
	rr, err := dnswire.RRFromText(text)
	if err != nil {
		fail(where, fmt.Sprintf("%s[%d]", field, index), fmt.Sprintf("rr_from_text rejects %s: %v", pyRepr(text), err))
	}
	return rr
}

func rrs(value any, where, field string) []dnswire.RR {
	var out []dnswire.RR
	for index, text := range stringValues(value, where, field) {
		out = append(out, rrFromText(text, where, field, index))
	}
	return out
}

// LoadFamilies reads families.json: the family names in file order and the source branch of each.
func LoadFamilies(path string) (names []string, source map[string]string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := catch(func() { names, source = familiesFrom(filepath.Base(path), data) }); err != nil {
		return nil, nil, err
	}
	return names, source, nil
}

func familiesFrom(where string, data []byte) ([]string, map[string]string) {
	doc := objectOf(readJSON(where, data), where, "", []string{"schema", "families"})
	schema(doc, where)
	families, ok := doc.vals["families"].(*orderedObject)
	if !ok || len(families.keys) == 0 {
		fail(where, "families", "must be a non-empty JSON object of family -> source branch")
	}
	source := map[string]string{}
	for _, name := range families.keys {
		source[name] = stringValue(families.vals[name], where, "families."+name)
	}
	return slices.Clone(families.keys), source
}

// posixParts is PurePosixPath(rel).parts without its root, and whether rel is absolute.
func posixParts(rel string) (parts []string, absolute bool) {
	for _, part := range strings.Split(rel, "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	return parts, strings.HasPrefix(rel, "/")
}

func module(value any, where string) Module {
	object := objectOf(value, where, "module", []string{"ini", "manifest", "files"})
	sections, ok := object.vals["ini"].(*orderedObject)
	if !ok {
		fail(where, "module.ini", "must be a JSON object of sections")
	}
	var ini []IniSection
	for _, section := range sections.keys {
		field := "module.ini." + section
		rows, ok := sections.vals[section].(*orderedObject)
		if !ok {
			fail(where, field, "must be a JSON object of key/value strings")
		}
		// A line break, or a bracket/separator in the wrong place, would write a different ini than the fixture says.
		iniText(section, where, field, "\r\n[]")
		ini = append(ini, IniSection{Name: section})
		for _, key := range rows.keys {
			iniText(key, where, field+"."+key, "\r\n=:")
			text := iniText(stringValue(rows.vals[key], where, field+"."+key), where, field+"."+key, "\r\n")
			ini[len(ini)-1].Keys = append(ini[len(ini)-1].Keys, [2]string{key, text})
		}
	}
	if _, ok := object.vals["manifest"].(*orderedObject); !ok {
		fail(where, "module.manifest", "must be a JSON object")
	}
	listed, ok := object.vals["files"].(*orderedObject)
	if !ok {
		fail(where, "module.files", "must be a JSON object of path -> lines")
	}
	var files []ModuleFile
	for _, rel := range listed.keys {
		parts, absolute := posixParts(rel)
		if len(parts) == 0 || absolute || slices.Contains(parts, "..") || strings.Contains(rel, "\x00") {
			fail(where, "module.files", fmt.Sprintf("unsafe path %s: must be relative and stay inside the module directory", pyRepr(rel)))
		}
		if slices.Contains(RUNNER_WRITES, parts[0]) { // a write would follow the shipped-code link into src/
			fail(where, "module.files", pyRepr(rel)+" is written by the runner, never by a fixture")
		}
		path := strings.Join(parts, "/")
		if slices.ContainsFunc(files, func(file ModuleFile) bool { return file.Path == path }) {
			fail(where, "module.files", pyRepr(rel)+" names a file already listed")
		}
		files = append(files, ModuleFile{path, stringValues(listed.vals[rel], where, fmt.Sprintf("module.files[%s]", pyRepr(rel)))})
	}
	folders := map[string]bool{}
	for _, file := range files {
		parts := strings.Split(file.Path, "/")
		for end := 1; end < len(parts); end++ {
			folders[strings.Join(parts[:end], "/")] = true
		}
	}
	for _, file := range files {
		if folders[file.Path] {
			fail(where, "module.files", pyRepr(file.Path)+" is both a file and the directory of another listed file")
		}
	}
	return Module{ini, slices.Clone(object.raw["manifest"]), files}
}

func upstream(value any, where string) map[UpstreamKey][]string {
	listed, ok := value.(*orderedObject)
	if !ok {
		fail(where, "upstream", "must be a JSON object of '<name> <TYPE>' -> RR texts")
	}
	zone := map[UpstreamKey][]string{}
	for _, key := range listed.keys {
		field := "upstream[" + pyRepr(key) + "]"
		name, kind := question(key, where, field)
		if name != strings.ToLower(name) {
			fail(where, field, "the name must be lower case")
		}
		texts := stringValues(listed.vals[key], where, field)
		for index, text := range texts {
			rrFromText(text, where, field, index) // rr_from_text must accept every record
		}
		if _, ok := zone[UpstreamKey{name, kind}]; ok {
			fail(where, field, "the same question is already listed under another spelling")
		}
		zone[UpstreamKey{name, kind}] = texts
	}
	return zone
}

func caseOf(item any, index int, where string, families map[string]string, seen map[string]bool) Case {
	whereCase := fmt.Sprintf("%s: cases[%d]", where, index)
	if listed, ok := item.(*orderedObject); ok {
		if id, ok := listed.vals["id"].(string); ok && id != "" {
			whereCase = where + ": case " + pyRepr(id) // every later error names the case
		}
	}
	object := objectOf(item, whereCase, "", []string{"id", "family", "description", "query", "expect"})
	id := stringValue(object.vals["id"], whereCase, "id")
	if id == "" {
		fail(whereCase, "id", "must not be empty")
	}
	if seen[id] {
		fail(whereCase, "id", "duplicate within the file")
	}
	seen[id] = true
	family := choice(object.vals["family"], whereCase, "family", slices.Collect(maps.Keys(families)))
	description := stringValue(object.vals["description"], whereCase, "description")
	if description == "" {
		fail(whereCase, "description", "must say what behaviour is pinned")
	}

	query := objectOf(object.vals["query"], whereCase, "query", []string{"name", "type"}, "client", "transport")
	name := wireName(stringValue(query.vals["name"], whereCase, "query.name"), whereCase, "query.name")
	kind := qtype(stringValue(query.vals["type"], whereCase, "query.type"), whereCase, "query.type")
	var client any = DEFAULT_CLIENT
	if given, ok := query.vals["client"]; ok {
		client = given
	}
	address := stringValue(client, whereCase, "query.client")
	if _, err := netip.ParseAddr(address); err != nil {
		fail(whereCase, "query.client", "not an IP address: "+pyRepr(address))
	}
	var transport any = "UDP"
	if given, ok := query.vals["transport"]; ok {
		transport = given
	}
	transportName := choice(transport, whereCase, "query.transport", TRANSPORTS)

	expect := objectOf(object.vals["expect"], whereCase, "expect", []string{"decision", "forwards", "rcode", "answer", "authority"})
	forwards := stringValues(expect.vals["forwards"], whereCase, "expect.forwards")
	for position, text := range forwards {
		question(text, whereCase, fmt.Sprintf("expect.forwards[%d]", position))
	}
	return Case{
		id,
		family,
		description,
		Query{name, kind, address, transportName},
		Expect{
			choice(expect.vals["decision"], whereCase, "expect.decision", DECISIONS),
			forwards,
			choice(expect.vals["rcode"], whereCase, "expect.rcode", slices.Collect(maps.Keys(RCODES))),
			rrs(expect.vals["answer"], whereCase, "expect.answer"),
			rrs(expect.vals["authority"], whereCase, "expect.authority"),
		},
	}
}

// LoadScenario reads one scenario file; families is the families.json index (name -> source branch).
func LoadScenario(path string, families map[string]string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s *Scenario
	if err := catch(func() { s = scenarioFrom(filepath.Base(path), data, families) }); err != nil {
		return nil, err
	}
	return s, nil
}

func scenarioFrom(where string, data []byte, families map[string]string) *Scenario {
	doc := objectOf(readJSON(where, data), where, "", []string{"schema", "description", "module", "upstream", "cases"})
	schema(doc, where)
	description := stringValue(doc.vals["description"], where, "description")
	mod := module(doc.vals["module"], where)
	zone := upstream(doc.vals["upstream"], where)
	items, ok := doc.vals["cases"].([]any)
	if !ok || len(items) == 0 {
		fail(where, "cases", "must be a non-empty list")
	}
	seen := map[string]bool{}
	cases := make([]Case, len(items))
	for index, item := range items {
		cases[index] = caseOf(item, index, where, families, seen)
	}
	return &Scenario{where, description, mod, zone, cases}
}

// --- the runner: the scenario's module directory, the queries and the verdict on each exchange ---------------------

// WriteModule writes the files PHP would write for the decider. It links no shipped code: the Go decider reads no Python.
func WriteModule(root string, m Module) error {
	var ini strings.Builder
	for _, section := range m.Ini {
		ini.WriteString("[" + section.Name + "]\n")
		for _, key := range section.Keys {
			ini.WriteString(key[0] + " = " + key[1] + "\n")
		}
		ini.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(root, "pfb_unbound.ini"), []byte(ini.String()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "pfb_py_sources.json"), m.Manifest, 0o644); err != nil {
		return err
	}
	for _, file := range m.Files {
		target := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte(strings.Join(file.Lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// BuildQuery is a one-question query: id 0x1234, RD set, no EDNS.
func BuildQuery(name string, qtype uint16) ([]byte, error) {
	return dnswire.Encode(&dnswire.Message{
		ID:        0x1234,
		Flags:     dnswire.RD,
		Questions: []dnswire.Question{{Name: name, Qtype: qtype, Qclass: dnswire.CLASS_IN}},
	})
}

// FakeUnbound stands in for Unbound behind the decider: it answers from a table and keeps every query it is sent and
// every reply it gave, so a relayed answer can be told from a rewritten one by its bytes.
type FakeUnbound struct {
	zone    map[UpstreamKey][]string
	Queries [][]byte
	Replies [][]byte
}

func NewFakeUnbound(zone map[UpstreamKey][]string) *FakeUnbound {
	return &FakeUnbound{zone: zone}
}

func (u *FakeUnbound) Answer(wire []byte) ([]byte, error) {
	// Copies, because Python's bytes cannot change under the record: the decider may edit the slice it is handed.
	u.Queries = append(u.Queries, bytes.Clone(wire))
	query, err := dnswire.Parse(wire)
	if err != nil {
		return nil, err
	}
	if len(query.Questions) == 0 {
		return nil, errors.New("the query has no question")
	}
	question := query.Questions[0]
	texts, listed := u.zone[UpstreamKey{strings.ToLower(question.Name), question.Qtype}]
	flags := dnswire.QR | dnswire.RA | (query.Flags & dnswire.RD)
	if !listed {
		flags |= 3
	}
	reply := &dnswire.Message{ID: query.ID, Flags: flags, Questions: query.Questions}
	for _, text := range texts {
		rr, err := dnswire.RRFromText(text)
		if err != nil {
			return nil, err
		}
		reply.Answers = append(reply.Answers, rr)
	}
	encoded, err := dnswire.Encode(reply)
	if err != nil {
		return nil, err
	}
	u.Replies = append(u.Replies, bytes.Clone(encoded))
	return encoded, nil
}

// Decision is how the exchange went, by the contract's definitions of answer, relay and rewrite.
func Decision(wire []byte, u *FakeUnbound, answer []byte) string {
	if len(u.Queries) == 0 {
		return "answer"
	}
	if len(u.Queries) == 1 && bytes.Equal(u.Queries[0], wire) && len(u.Replies) > 0 && bytes.Equal(answer, u.Replies[0]) {
		return "relay"
	}
	if !slices.ContainsFunc(u.Replies, func(reply []byte) bool { return bytes.Equal(reply, answer) }) {
		return "rewrite"
	}
	return "unclassified: the ANSWER is an Unbound reply but not the one relayed FORWARD"
}

func RRText(rr dnswire.RR) string {
	return fmt.Sprintf("%s %d class%d %s %x", rr.Name, rr.TTL, rr.Rclass, dnswire.TypeStr(rr.Rtype), rr.Rdata)
}

func rrTexts(rrs []dnswire.RR) []string {
	out := make([]string, len(rrs))
	for index, rr := range rrs {
		out[index] = RRText(rr)
	}
	return out
}

// Mismatches is one line per way the exchange differs from what the case expects; empty when it is the expected decision.
func Mismatches(s *Scenario, c *Case, wire []byte, u *FakeUnbound, answer []byte) []string {
	where := fmt.Sprintf("%s: case %s", s.Name, pyRepr(c.ID))
	reply, err := dnswire.Parse(answer)
	if err != nil {
		return []string{fmt.Sprintf("%s: answer: not a DNS message: %v", where, err)}
	}
	expect := c.Expect
	forwards := []string{}
	for _, sent := range u.Queries {
		parsed, err := dnswire.Parse(sent)
		if err != nil {
			return []string{fmt.Sprintf("%s: forwards: a FORWARD is not a DNS message: %v", where, err)}
		}
		for _, question := range parsed.Questions {
			forwards = append(forwards, question.Name+" "+typeText(question.Qtype))
		}
	}
	rcode := fmt.Sprintf("RCODE%d", reply.Rcode())
	for name, number := range RCODES {
		if number == reply.Rcode() {
			rcode = name
		}
	}
	var out []string
	for _, row := range []struct{ field, want, got string }{
		{"decision", pyRepr(expect.Decision), pyRepr(Decision(wire, u, answer))},
		{"forwards", pyRepr(expect.Forwards), pyRepr(forwards)},
		{"rcode", pyRepr(expect.Rcode), pyRepr(rcode)},
		{"answer", pyRepr(rrTexts(expect.Answer)), pyRepr(rrTexts(reply.Answers))},
		{"authority", pyRepr(rrTexts(expect.Authority)), pyRepr(rrTexts(reply.Authority))},
	} {
		if row.want != row.got {
			out = append(out, fmt.Sprintf("%s: %s: expected %s, got %s", where, row.field, row.want, row.got))
		}
	}
	return out
}

// --- Python's repr, so a refusal reads as the Python loader's --------------------------------------------------------

func pyRepr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case bool:
		if v {
			return "True"
		}
		return "False"
	case json.Number:
		return v.String()
	case string:
		return reprString(v)
	case []string:
		items := make([]string, len(v))
		for index, item := range v {
			items[index] = reprString(item)
		}
		return "[" + strings.Join(items, ", ") + "]"
	case []any:
		items := make([]string, len(v))
		for index, item := range v {
			items[index] = pyRepr(item)
		}
		return "[" + strings.Join(items, ", ") + "]"
	case *orderedObject:
		items := make([]string, len(v.keys))
		for index, key := range v.keys {
			items[index] = reprString(key) + ": " + pyRepr(v.vals[key])
		}
		return "{" + strings.Join(items, ", ") + "}"
	}
	return fmt.Sprint(value)
}

func reprString(text string) string {
	quote := '\''
	if strings.ContainsRune(text, '\'') && !strings.ContainsRune(text, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for _, r := range text {
		switch {
		case r == quote || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&out, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			out.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&out, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			fmt.Fprintf(&out, `\U%08x`, r)
		}
	}
	out.WriteRune(quote)
	return out.String()
}
