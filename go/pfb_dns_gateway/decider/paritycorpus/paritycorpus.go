// Package paritycorpus loads the decision parity corpus (issue #3772), schema 4: language-neutral JSON scenarios that the
// Go decider passes; it is the only runner (decider/corpus_test.go). A scenario is one module directory (the files PHP
// writes for the decider) plus ordered query cases, each with the decision as it appears on the decision protocol
// (docs/misc/dns-gateway-protocol.md, "One query"): which FORWARDs the decider sent, and the final ANSWER.
//
// The expectations in tests/dns_proxy/fixtures/parity are frozen literals derived from the source branch each family
// names in families.json, never captured from a run. Where the owner signed off a Go result that differs from the
// source's, expect holds the Go result and the case's description names the sign-off. A fixture the loader refuses is an
// error naming file, case and field.
//
// The schema (every key is required unless marked optional; any other key, a duplicate JSON key, NaN/Infinity, a wrong
// JSON type or an unknown value is a refusal, never a skip; every file in fixtures/parity is a .json document the runner
// loads; "schema" is the integer 4 in every file, 3, 2 and 1 are refused):
//
//	families.json  {"schema": 4, "families": {"<family>": "<source branch>", ...}}: the closed family list. Every
//	               family pins pfb_unbound.py except `frontend`, which pins Frontend.resolve in pfb_dns_proxy.py.
//	<scenario>.json  {"schema": 4, "description", "module", "upstream", "cases"}
//	  module.ini       {section: {key: value}}, every value a string, written as pfb_unbound.ini in file order; no line
//	                   break anywhere, no bracket in a section name, no "=" or ":" in a key.
//	  module.manifest  written verbatim as pfb_py_sources.json.
//	  module.files     {relative path: [lines]}, written joined by newlines plus a trailing one; no "..", NUL or
//	                   absolute path, no path listed twice ("./x" is "x"), no file that is also another one's directory,
//	                   and nothing at or under the names the runner writes (the shipped pfb_unbound.py and
//	                   pfb_dnsbl_regex_rules.py are linked in by the runner, never by a fixture).
//	  upstream         {"<lower-case absolute name> <TYPE>": [RR texts] or null}, Unbound's stand-in (FakeUnbound),
//	                   keyed on the FORWARD's first question, its name lower-cased; its class is ignored and the reply
//	                   carries the FORWARD's questions and id, RD copied, RA set. A listed question gets NOERROR with
//	                   those records (an empty list: none at all; null: no reply, which the runner gives as an empty
//	                   REPLY), any other NXDOMAIN; one question is listed once, whichever spelling of its type. So a
//	                   FORWARD must parse with at least one question: a relay of a wire that does not is not
//	                   expressible.
//	  cases            non-empty list, run IN FILE ORDER against one booted decider (its per-name memo carries over).
//	    id, description   non-empty strings; id unique within the file.
//	    family            a families.json key; every family's cases run, none is skipped.
//	    query             {"name": absolute name, "type": mnemonic or TYPE<n> (n <= 65535)}: one question, class IN,
//	                      RD set, no EDNS; or {"wire_hex": lower-case hex of at most 65535 bytes}: the QUERY frame's DNS
//	                      wire verbatim; never both, never half of the first. Either has "client": IP (optional,
//	                      192.0.2.10; canonical as the gateway sends it: no zone, not unspecified, IPv4-mapped IPv6
//	                      refused) and "transport": TCP|UDP|DoT|DoH|DoQ (optional, UDP).
//	    expect            {"decision": answer|relay|rewrite|drop, "forwards": ["<name> <TYPE>", ...], "rcode":
//	                      NOERROR|FORMERR|SERVFAIL|NXDOMAIN|NOTIMP|REFUSED, "answer": [RR texts], "authority": [RR
//	                      texts], "tc": true|false (optional, false)}. A drop is exactly {"decision": "drop",
//	                      "forwards": []}.
//
// RR texts are "name ttl IN TYPE rdata" for A, AAAA, CNAME, TXT and SOA (dnswire.RRFromText).
//
// Decisions: answer = no FORWARD, the decider built the ANSWER; relay = one FORWARD carrying the client's own wire and
// an ANSWER byte-identical to Unbound's reply; rewrite = FORWARDs, then an ANSWER that is none of Unbound's replies (the
// SERVFAIL the decider builds for Unbound's silence is one); drop = the decider's final frame is DROP, whatever it
// forwarded first. Any other outcome (an ANSWER equal to an Unbound reply other than a relay's) is always a mismatch.
// forwards lists every question of every FORWARD, in order. answer/authority compare in order as (owner, type, class,
// ttl, rdata) with the owner exactly as on the wire: the encoder compresses an owner equal to the question, case-blind,
// into the question, so a mixed-case query's answer carries the client's spelling. For every non-drop case the ANSWER's
// id (equal to the query's first two bytes), rcode and TC are compared too; its question section, other flags and
// additional section (EDNS included) are not. A drop has no ANSWER: only decision and forwards are compared.
// The frontend family's size rows sit on exact byte counts of the decider's encoding (dnswire.Encode): every owner name
// compressed against the names written before it, rdata names (a CNAME's target) never compressed. A decider whose
// encoder differs builds answers of other sizes and fails those rows.
package paritycorpus

import (
	"bytes"
	"encoding/hex"
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
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const DEFAULT_CLIENT = "192.0.2.10"

var (
	RUNNER_WRITES = []string{"pfb_unbound.py", "pfb_dnsbl_regex_rules.py", "pfb_unbound.ini", "pfb_py_sources.json"}
	TRANSPORTS    = []string{"TCP", "UDP", "DoT", "DoH", "DoQ"} // the QUERY frame's transport byte is this index
	DECISIONS     = []string{"answer", "relay", "rewrite", "drop"}
	RCODES        = map[string]int{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
	QTYPES        = map[string]uint16{
		"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "SIG": 24, "AAAA": 28, "SRV": 33,
		"DNAME": 39, "SVCB": 64, "HTTPS": 65, "ANY": 255,
	}
)

type FixtureError string

func (e FixtureError) Error() string { return string(e) }

type Query struct {
	Wire      []byte // the QUERY frame's DNS wire
	Client    string
	Transport string
}

type Expect struct {
	Decision  string
	Forwards  []string
	Rcode     string // the rest only for a non-drop decision: a drop has no ANSWER
	Answer    []dnswire.RR
	Authority []dnswire.RR
	TC        bool
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
	Upstream          map[UpstreamKey][]string // FakeUnbound's zone: (lower-case name, qtype) -> RR texts; nil: no reply
	Cases             []Case
}

// Fixtures is derived from this source file's location, so it does not work under -trimpath.
func Fixtures() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "tests", "dns_proxy", "fixtures", "parity")
}

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

// orderedObject keeps the file order a Go map loses, and each member's raw bytes: the manifest is written back as the
// fixture has it.
type orderedObject struct {
	keys []string
	vals map[string]any
	raw  map[string][]byte
}

// maxDepth: Python's json gives up on absurd nesting with a RecursionError; so does the loader. It reads 990 levels
// through the loader and refuses 1000.
// shortcut: Python's real limit is its recursion limit less the caller's stack, so it moves with the caller; 990 is the
// floor measured through the loader.
const maxDepth = 990

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
	if offset := loneSurrogate(data); offset >= 0 {
		return nil, fmt.Errorf("lone surrogate %s at byte %d", data[offset:offset+6], offset)
	}
	return value, nil
}

// loneSurrogate is the offset of the first \uD800-\uDFFF escape in a valid JSON document that is not half of a high then
// low pair, or -1. Go's decoder would turn it into U+FFFD, where Python keeps the surrogate in its str.
// shortcut: Python refuses a lone surrogate only where it must be encoded (a name, a file the runner writes); refusing it
// in every field is stricter on the ones Python never encodes.
func loneSurrogate(data []byte) int {
	inString := false
	for i := 0; i < len(data); i++ {
		switch {
		case !inString:
			inString = data[i] == '"'
		case data[i] == '"':
			inString = false
		case data[i] == '\\':
			if data[i+1] != 'u' {
				i++ // the escaped character: a quote or a backslash here ends no string and starts no escape
				continue
			}
			unit := utf16Unit(data[i+2 : i+6])
			switch {
			case unit >= 0xD800 && unit <= 0xDBFF:
				if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
					return i
				}
				if low := utf16Unit(data[i+8 : i+12]); low < 0xDC00 || low > 0xDFFF {
					return i
				}
				i += 11 // the whole pair
			case unit >= 0xDC00 && unit <= 0xDFFF:
				return i
			default:
				i += 5 // the whole escape
			}
		}
	}
	return -1
}

func utf16Unit(hex4 []byte) int {
	unit, _ := strconv.ParseUint(string(hex4), 16, 16) // the document is valid JSON: four hex digits
	return int(unit)
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
	if number, ok := doc.vals["schema"].(json.Number); !ok || number.String() != "4" { // a bool or 4.0 is not the integer 4
		fail(where, "schema", "must be the integer 4, got "+pyRepr(doc.vals["schema"]))
	}
}

var typeNumber = regexp.MustCompile(`^TYPE([0-9]{1,5})$`)

func qtype(text, where, field string) uint16 {
	if number, ok := QTYPES[text]; ok {
		return number
	}
	if numbered := typeNumber.FindStringSubmatch(text); numbered != nil {
		if number, err := strconv.ParseUint(numbered[1], 10, 16); err == nil { // TYPE65536 and above is a range error
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
		if name != pysem.Lower(name) {
			fail(where, field, "the name must be lower case")
		}
		var texts []string // nil for null: Unbound gives no reply
		if listed.vals[key] != nil {
			texts = stringValues(listed.vals[key], where, field)
			for index, text := range texts {
				rrFromText(text, where, field, index) // rr_from_text must accept every record
			}
		}
		if _, ok := zone[UpstreamKey{name, kind}]; ok {
			fail(where, field, "the same question is already listed under another spelling")
		}
		zone[UpstreamKey{name, kind}] = texts
	}
	return zone
}

func parseCase(item any, index int, where string, families map[string]string, seen map[string]bool) Case {
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
	return Case{
		ID:          id,
		Family:      family,
		Description: description,
		Query:       parseQuery(object.vals["query"], whereCase),
		Expect:      parseExpect(object.vals["expect"], whereCase, "expect"),
	}
}

var wholeHexBytes = regexp.MustCompile(`\A(?:[0-9a-f]{2})*\z`)

func wireHex(text, where, field string) []byte {
	if !wholeHexBytes.MatchString(text) { // hex.DecodeString alone takes upper case
		fail(where, field, pyRepr(text)+" must be lower-case hex of whole bytes")
	}
	if len(text) > 2*0xFFFF {
		fail(where, field, fmt.Sprintf("%d bytes: a DNS message has at most 65535", len(text)/2))
	}
	wire, err := hex.DecodeString(text)
	if err != nil {
		panic(err) // unreachable: the pattern above is whole bytes of hex
	}
	return wire
}

// canonicalClient is a client address as the gateway writes it: not unspecified, not IPv4-mapped (the gateway unmaps
// it) and spelled as Python's str(ip_address(text)); a zone never matches that spelling, because packed has none.
func canonicalClient(text string, packed []byte) bool {
	unspecified := !slices.ContainsFunc(packed, func(octet byte) bool { return octet != 0 })
	mapped := len(packed) == 16 && bytes.HasPrefix(packed, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
	if unspecified || mapped {
		return false
	}
	address, _ := netip.AddrFromSlice(packed)
	return address.String() == text // netip spells an IPv6 address as Python does, bar the mapped form refused above
}

func parseQuery(value any, where string) Query {
	object := objectOf(value, where, "query", nil, "name", "type", "wire_hex", "client", "transport")
	var wire []byte
	if given, ok := object.vals["wire_hex"]; ok {
		_, named := object.vals["name"]
		_, typed := object.vals["type"]
		if named || typed {
			fail(where, "query.wire_hex", "excludes query.name and query.type")
		}
		wire = wireHex(stringValue(given, where, "query.wire_hex"), where, "query.wire_hex")
	} else {
		for _, key := range []string{"name", "type"} {
			if _, ok := object.vals[key]; !ok {
				fail(where, "query."+key, "missing: a query is a name and a type, or wire_hex")
			}
		}
		name := wireName(stringValue(object.vals["name"], where, "query.name"), where, "query.name")
		built, err := BuildQuery(name, qtype(stringValue(object.vals["type"], where, "query.type"), where, "query.type"))
		if err != nil {
			panic(err) // unreachable: wireName accepted the name
		}
		wire = built
	}
	var client any = DEFAULT_CLIENT
	if given, ok := object.vals["client"]; ok {
		client = given
	}
	address := stringValue(client, where, "query.client")
	packed, err := pysem.IPAddress(address)
	if err != nil {
		fail(where, "query.client", "not an IP address: "+pyRepr(address))
	}
	if !canonicalClient(address, packed) {
		fail(where, "query.client", pyRepr(address)+" is not a canonical, specified address without a zone")
	}
	var transport any = "UDP"
	if given, ok := object.vals["transport"]; ok {
		transport = given
	}
	return Query{wire, address, choice(transport, where, "query.transport", TRANSPORTS)}
}

func parseExpect(value any, where, field string) Expect {
	object := objectOf(value, where, field, []string{"decision", "forwards"}, "rcode", "answer", "authority", "tc")
	decision := choice(object.vals["decision"], where, field+".decision", DECISIONS)
	forwards := stringValues(object.vals["forwards"], where, field+".forwards")
	for position, text := range forwards {
		question(text, where, fmt.Sprintf("%s.forwards[%d]", field, position))
	}
	if decision == "drop" {
		for _, key := range []string{"rcode", "answer", "authority", "tc"} {
			if _, ok := object.vals[key]; ok {
				fail(where, field+"."+key, "unknown key: a drop has no ANSWER")
			}
		}
		if len(forwards) > 0 {
			fail(where, field+".forwards", "must be empty for a drop")
		}
		return Expect{Decision: decision}
	}
	for _, key := range []string{"rcode", "answer", "authority"} {
		if _, ok := object.vals[key]; !ok {
			fail(where, field+"."+key, "missing")
		}
	}
	tc := false
	if given, ok := object.vals["tc"]; ok {
		if tc, ok = given.(bool); !ok {
			fail(where, field+".tc", "must be true or false, got "+pyRepr(given))
		}
	}
	return Expect{
		decision,
		forwards,
		choice(object.vals["rcode"], where, field+".rcode", slices.Collect(maps.Keys(RCODES))),
		rrs(object.vals["answer"], where, field+".answer"),
		rrs(object.vals["authority"], where, field+".authority"),
		tc,
	}
}

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
		cases[index] = parseCase(item, index, where, families, seen)
	}
	return &Scenario{where, description, mod, zone, cases}
}

// WriteModule links no shipped Python: the Go decider reads none.
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

func BuildQuery(name string, qtype uint16) ([]byte, error) {
	return dnswire.Encode(&dnswire.Message{
		ID:        0x1234,
		Flags:     dnswire.RD,
		Questions: []dnswire.Question{{Name: name, Qtype: qtype, Qclass: dnswire.CLASS_IN}},
	})
}

// FakeUnbound keeps each reply it gave, so a relayed ANSWER can be told from a rewritten one by its bytes. A question
// the zone lists as nil gets no reply: the empty one goes on record.
type FakeUnbound struct {
	zone    map[UpstreamKey][]string
	Queries [][]byte
	Replies [][]byte
}

func NewFakeUnbound(zone map[UpstreamKey][]string) *FakeUnbound {
	return &FakeUnbound{zone: zone}
}

func (u *FakeUnbound) Answer(wire []byte) ([]byte, error) {
	query, err := dnswire.Parse(wire)
	if err != nil {
		return nil, err
	}
	if len(query.Questions) == 0 {
		return nil, errors.New("the query has no question")
	}
	// Copies, because Python's bytes cannot change under the record: the decider may edit the slice it is handed.
	u.Queries = append(u.Queries, bytes.Clone(wire))
	question := query.Questions[0]
	texts, listed := u.zone[UpstreamKey{pysem.Lower(question.Name), question.Qtype}]
	if listed && texts == nil {
		u.Replies = append(u.Replies, []byte{})
		return nil, nil
	}
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

func Decision(wire []byte, u *FakeUnbound, answer []byte) string {
	if answer == nil {
		return "drop"
	}
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

type comparison struct{ field, want, got string }

func Mismatches(s *Scenario, c *Case, wire []byte, u *FakeUnbound, answer []byte) []string {
	where := fmt.Sprintf("%s: case %s", s.Name, pyRepr(c.ID))
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
	compared := []comparison{
		{"decision", pyRepr(expect.Decision), pyRepr(Decision(wire, u, answer))},
		{"forwards", pyRepr(expect.Forwards), pyRepr(forwards)},
	}
	if answer != nil && expect.Decision != "drop" { // a drop/non-drop disagreement is the decision's line
		reply, err := dnswire.Parse(answer)
		if err != nil {
			return []string{fmt.Sprintf("%s: answer: not a DNS message: %v", where, err)}
		}
		rcode := fmt.Sprintf("RCODE%d", reply.Rcode())
		for name, number := range RCODES {
			if number == reply.Rcode() {
				rcode = name
			}
		}
		queryID := 0 // int.from_bytes(wire[:2], "big"), whatever the length of wire
		for _, octet := range wire[:min(len(wire), 2)] {
			queryID = queryID<<8 | int(octet)
		}
		compared = append(compared,
			comparison{"id", pyRepr(queryID), pyRepr(int(reply.ID))},
			comparison{"rcode", pyRepr(expect.Rcode), pyRepr(rcode)},
			comparison{"answer", pyRepr(rrTexts(expect.Answer)), pyRepr(rrTexts(reply.Answers))},
			comparison{"authority", pyRepr(rrTexts(expect.Authority)), pyRepr(rrTexts(reply.Authority))},
			comparison{"tc", pyRepr(expect.TC), pyRepr(reply.Flags&dnswire.TC != 0)},
		)
	}
	var out []string
	for _, row := range compared {
		if row.want != row.got {
			out = append(out, fmt.Sprintf("%s: %s: expected %s, got %s", where, row.field, row.want, row.got))
		}
	}
	return out
}

// pyRepr formats a value as Python's repr, so a refusal reads as the Python loader's.
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
		return pysem.Repr(v)
	case []string:
		items := make([]string, len(v))
		for index, item := range v {
			items[index] = pysem.Repr(item)
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
			items[index] = pysem.Repr(key) + ": " + pyRepr(v.vals[key])
		}
		return "{" + strings.Join(items, ", ") + "}"
	}
	return fmt.Sprint(value)
}
