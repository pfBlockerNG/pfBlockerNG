package ipset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The IP set parity corpus (testdata/ipset.json, schema and comparison rules in testdata/README.md): today's shell and PHP
// results, replayed against this package. A group test fails a case when any asserted key differs; an unknown key, a missing
// key, a duplicate id or an unknown op fails the load, never skips a case.

const (
	corpusPath = "testdata/ipset.json"
	readmePath = "testdata/README.md"
	defaultPH  = "127.1.7.7"
)

var corpusOps = []string{"cidr_aggregate", "preprocess", "recompute", "pmax", "suppress", "remove", "closing", "canonical", "union", "dnsblip", "matrix", "pipeline"}

// ---- the expect table: which keys a runner asserts and which it leaves to the Core Updater ----

type tableRow struct{ group, key, status string }

const (
	asserted     = "asserted"
	presentation = "presentation"
)

func tableRows(group, status string, keys ...string) []tableRow {
	rows := make([]tableRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, tableRow{group, k, status})
	}
	return rows
}

var sanityKeys = []string{"original", "final", "verdict", "masterfile_count", "deny_count", "uniq_master", "uniq_deny", "empty_lists"}

// expectTable is the code side of README.md "What the Go runner asserts". A key with a "." or "[" is a nested key of a
// top-level key; every other key is a top-level expect key of its group.
var expectTable = slices.Concat(
	tableRows("cidr_aggregate", asserted, "members", "unchanged", "stats"),
	tableRows("cidr_aggregate", presentation, "rc", "log"),
	tableRows("preprocess", asserted, "args", "ran", "members", "match_rep"),
	tableRows("preprocess", presentation, "rc", "log"),
	tableRows("recompute", asserted, "deny", "master", "mastercat", "counts", "match", "processed", "log"),
	tableRows("recompute", presentation, "rc"),
	tableRows("pmax", asserted, "deny", "master", "mastercat"),
	tableRows("pmax", presentation, "rc", "log"),
	tableRows("suppress/v4", asserted, "members", "master", "stats", "log"),
	tableRows("suppress/v4", presentation, "rc"),
	tableRows("suppress/v6", asserted, "ok", "members", "log"),
	tableRows("suppress/v6", presentation, "leftover_tmp"),
	tableRows("remove", asserted, "files", "master", "mastercat", "messages"),
	tableRows("remove", presentation, "rc"),
	tableRows("closing", asserted, "deny", "master", "sanity"),
	tableRows("closing", asserted, prefixed("sanity.", sanityKeys)...),
	tableRows("closing", presentation, "rc", "log"),
	tableRows("canonical", asserted, "set"),
	tableRows("union", asserted, "kept", "aggregate", "consumer", "stats"),
	tableRows("union", presentation, "rc", "log"),
	tableRows("dnsblip", asserted, "content", "final_newline", "sources"),
	tableRows("dnsblip", presentation, "built"),
	tableRows("matrix/recompute_matrix", asserted, "invoke_v4", "invoke_v6", "dedup", "repmode", "legacy_pmax_followup"),
	tableRows("matrix/closing_pass_active", asserted, "invoke", "alias_arg"),
	tableRows("pipeline", asserted, "passes"),
	tableRows("pipeline", asserted, "passes[].matrix", "passes[].ran", "passes[].canonical", "passes[].aggregate", "passes[].closing", "passes[].deny_final"),
)

func prefixed(p string, keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = p + k
	}
	return out
}

// topKeys are the top-level expect keys of one group, asserted and presentation alike.
func topKeys(group string) []string {
	var keys []string
	for _, r := range expectTable {
		if r.group == group && !strings.ContainsAny(r.key, ".[") {
			keys = append(keys, r.key)
		}
	}
	return keys
}

// inputKeys are the required and optional input keys of each group.
var inputKeys = map[string][2][]string{
	"cidr_aggregate":             {{"members"}, nil},
	"preprocess":                 {{"members", "dup", "agg", "rep", "max", "drep", "cc", "ccwhite", "ccblack", "geo"}, nil},
	"recompute":                  {{"members", "dedup", "repmode", "max", "cc", "ccwhite", "ccblack", "geo"}, {"master", "deny_pre", "match_pre", "ph"}},
	"pmax":                       {{"deny", "max", "geo"}, {"master"}},
	"suppress/v4":                {{"members", "suppression", "dedup"}, {"master"}},
	"suppress/v6":                {{"members", "suppression"}, nil},
	"remove":                     {{"headers"}, {"deny", "original", "match", "matchgen", "permit", "native", "master"}},
	"closing":                    {{"dedup", "deny"}, {"master", "orig", "ph"}},
	"canonical":                  {{"members"}, nil},
	"union":                      {{"type", "members", "collapsed"}, {"ph"}},
	"dnsblip":                    {{"ip_files"}, {"ip_ph"}},
	"matrix/recompute_matrix":    {{"fn", "dedup_on", "rep_trigger", "drep_on", "prep_on"}, nil},
	"matrix/closing_pass_active": {{"fn", "dup_on", "ran_v4"}, nil},
	"pipeline":                   {{"switches", "feeds", "suppression", "passes"}, {"agg_types"}},
}

// ---- strict JSON objects ----

// obj reads the keys of a JSON object whose key set was checked; the first decoding error is kept in err.
type obj struct {
	what string
	m    map[string]json.RawMessage
	err  error
}

func objOf(raw json.RawMessage, what string, required, optional []string) (*obj, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%s: not an object", what)
	}
	if _, _, err := orderedObject(raw); err != nil {
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("%s: missing key %q", what, k)
		}
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return nil, fmt.Errorf("%s: unknown key %q", what, k)
		}
	}
	return &obj{what: what, m: m}, nil
}

func (o *obj) fail(k string, err error) {
	if o.err == nil && err != nil {
		o.err = fmt.Errorf("%s.%s: %v", o.what, k, err)
	}
}

func (o *obj) has(k string) bool { _, ok := o.m[k]; return ok }

func (o *obj) isNull(k string) bool { return bytes.Equal(bytes.TrimSpace(o.m[k]), []byte("null")) }

func (o *obj) str(k string) string {
	var s string
	if !o.has(k) {
		return ""
	}
	o.fail(k, json.Unmarshal(o.m[k], &s))
	return s
}

func (o *obj) flag(k string) bool {
	var b bool
	o.fail(k, json.Unmarshal(o.m[k], &b))
	return b
}

func (o *obj) num(k string) int {
	var n int
	o.fail(k, json.Unmarshal(o.m[k], &n))
	return n
}

func (o *obj) onOff(k string) bool {
	switch s := o.str(k); s {
	case "on":
		return true
	case "off":
		return false
	default:
		o.fail(k, fmt.Errorf("must be on or off, got %q", s))
		return false
	}
}

func (o *obj) strs(k string) []string {
	var s []string
	if o.has(k) {
		o.fail(k, json.Unmarshal(o.m[k], &s))
	}
	return s
}

// text reads a required text object.
func (o *obj) text(k string) *textObj {
	t, err := parseText(o.m[k], o.what+"."+k)
	o.fail(k, err)
	return t
}

// nullText reads a text object that may be absent or null (no file).
func (o *obj) nullText(k string) *textObj {
	if !o.has(k) || o.isNull(k) {
		return nil
	}
	return o.text(k)
}

func (o *obj) texts(k string) []namedText {
	if !o.has(k) {
		return nil
	}
	nt, err := parseTexts(o.m[k], o.what+"."+k)
	o.fail(k, err)
	return nt
}

func (o *obj) geo(k string) geoTable {
	if o.isNull(k) {
		return geoTable{}
	}
	g := geoTable{ok: true, m: map[string]string{}}
	o.fail(k, json.Unmarshal(o.m[k], &g.m))
	return g
}

// orderedObject returns the keys and values of a JSON object in document order.
func orderedObject(raw json.RawMessage) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, fmt.Errorf("not an object")
	}
	var keys []string
	var vals []json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k := tok.(string)
		if slices.Contains(keys, k) {
			return nil, nil, fmt.Errorf("duplicate key %q", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, err
		}
		keys, vals = append(keys, k), append(vals, v)
	}
	return keys, vals, nil
}

// ---- text objects and the generator recipes ----

type namedText struct {
	name string
	text *textObj
}

type geoTable struct {
	ok bool
	m  map[string]string
}

// lookup is the GeoLookup of the case's GeoIP stub: nil when there is no mmdblookup at all.
func (g geoTable) lookup() GeoLookup {
	if !g.ok {
		return nil
	}
	return func(octets string) string { return g.m[octets] }
}

type recipe struct {
	kind         string
	start, count uint64
	step         uint64
	suffix       string
	base         [16]byte
}

type textPart struct {
	lit string
	gen *recipe
}

// textObj is a member list text: one literal, or parts to concatenate; recipes expand only when the text is read.
type textObj struct{ parts []textPart }

var textKeys = []string{"text", "text_hex", "parts"}

func parseText(raw json.RawMessage, what string) (*textObj, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%s: not a text object", what)
	}
	return parseTextMap(m, what, nil)
}

// parseTextMap reads the text object held in m once the keys of skip are set aside.
func parseTextMap(m map[string]json.RawMessage, what string, skip []string) (*textObj, error) {
	var have []string
	for k := range m {
		if slices.Contains(skip, k) {
			continue
		}
		if !slices.Contains(textKeys, k) {
			return nil, fmt.Errorf("%s: unknown key %q", what, k)
		}
		have = append(have, k)
	}
	if len(have) != 1 {
		return nil, fmt.Errorf("%s: exactly one of text, text_hex, parts is required, got %v", what, have)
	}
	switch have[0] {
	case "text":
		var s string
		if err := json.Unmarshal(m["text"], &s); err != nil {
			return nil, fmt.Errorf("%s.text: %v", what, err)
		}
		return &textObj{parts: []textPart{{lit: s}}}, nil
	case "text_hex":
		var h string
		if err := json.Unmarshal(m["text_hex"], &h); err != nil {
			return nil, fmt.Errorf("%s.text_hex: %v", what, err)
		}
		if h != strings.ToLower(h) {
			return nil, fmt.Errorf("%s.text_hex: not lower-case", what)
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("%s.text_hex: %v", what, err)
		}
		return &textObj{parts: []textPart{{lit: string(b)}}}, nil
	}
	var rawParts []json.RawMessage
	if err := json.Unmarshal(m["parts"], &rawParts); err != nil {
		return nil, fmt.Errorf("%s.parts: %v", what, err)
	}
	t := &textObj{}
	for i, rp := range rawParts {
		var s string
		if json.Unmarshal(rp, &s) == nil {
			t.parts = append(t.parts, textPart{lit: s})
			continue
		}
		g, err := objOf(rp, fmt.Sprintf("%s.parts[%d]", what, i), []string{"generate"}, nil)
		if err != nil {
			return nil, err
		}
		r, err := parseRecipe(g.m["generate"], fmt.Sprintf("%s.parts[%d].generate", what, i))
		if err != nil {
			return nil, err
		}
		t.parts = append(t.parts, textPart{gen: r})
	}
	return t, nil
}

func parseRecipe(raw json.RawMessage, what string) (*recipe, error) {
	var probe struct{ Kind string }
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	var o *obj
	var err error
	switch probe.Kind {
	case "v4_seq":
		o, err = objOf(raw, what, []string{"kind", "start", "count", "step", "suffix"}, nil)
	case "v6_seq":
		o, err = objOf(raw, what, []string{"kind", "base", "count", "step", "suffix"}, nil)
	default:
		return nil, fmt.Errorf("%s: unknown generator kind %q", what, probe.Kind)
	}
	if err != nil {
		return nil, err
	}
	r := &recipe{kind: probe.Kind, suffix: o.str("suffix")}
	u := func(k string) uint64 {
		var n uint64
		o.fail(k, json.Unmarshal(o.m[k], &n))
		return n
	}
	r.count, r.step = u("count"), u("step")
	if r.kind == "v4_seq" {
		r.start = u("start")
		if r.start+r.count*r.step > 1<<32 {
			o.fail("start", fmt.Errorf("the sequence leaves the IPv4 space"))
		}
	} else {
		a, perr := netip.ParseAddr(o.str("base"))
		if perr != nil || !a.Is6() {
			o.fail("base", fmt.Errorf("not an IPv6 address"))
		} else {
			r.base = a.As16()
		}
	}
	return r, o.err
}

func parseTexts(raw json.RawMessage, what string) ([]namedText, error) {
	keys, vals, err := orderedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	out := make([]namedText, 0, len(keys))
	for i, k := range keys {
		t, err := parseText(vals[i], what+"."+k)
		if err != nil {
			return nil, err
		}
		out = append(out, namedText{k, t})
	}
	return out, nil
}

// String is the text. The recipes of the README, byte for byte: a line per i from 0 to count-1, each ended by "\n".
func (t *textObj) String() string {
	if len(t.parts) == 1 && t.parts[0].gen == nil {
		return t.parts[0].lit
	}
	var b []byte
	for _, p := range t.parts {
		if p.gen == nil {
			b = append(b, p.lit...)
		} else {
			b = p.gen.appendTo(b)
		}
	}
	return string(b)
}

func (r *recipe) appendTo(b []byte) []byte {
	b = slices.Grow(b, int(r.count)*(16+len(r.suffix)))
	for i := uint64(0); i < r.count; i++ {
		if r.kind == "v4_seq" {
			n := uint32(r.start + i*r.step)
			b = netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}).AppendTo(b)
		} else {
			a := r.base
			binary.BigEndian.PutUint64(a[8:], binary.BigEndian.Uint64(r.base[8:])+i*r.step)
			b = appendNtop6(b, a)
		}
		b = append(b, r.suffix...)
		b = append(b, '\n')
	}
	return b
}

// appendNtop6 writes inet_ntop(AF_INET6): lower case, the first longest run of two or more zero groups compressed, a dotted
// IPv4 tail for the IPv4-mapped and IPv4-compatible ranges (the algorithm of the C library's inet_ntop6).
func appendNtop6(b []byte, a [16]byte) []byte {
	var w [8]uint16
	for i := range w {
		w[i] = uint16(a[2*i])<<8 | uint16(a[2*i+1])
	}
	best, cur := [2]int{-1, 0}, [2]int{-1, 0}
	for i := 0; i < 8; i++ {
		if w[i] == 0 {
			if cur[0] == -1 {
				cur = [2]int{i, 1}
			} else {
				cur[1]++
			}
		} else if cur[0] != -1 {
			if best[0] == -1 || cur[1] > best[1] {
				best = cur
			}
			cur[0] = -1
		}
	}
	if cur[0] != -1 && (best[0] == -1 || cur[1] > best[1]) {
		best = cur
	}
	if best[0] != -1 && best[1] < 2 {
		best[0] = -1
	}
	for i := 0; i < 8; i++ {
		if best[0] != -1 && i >= best[0] && i < best[0]+best[1] {
			if i == best[0] {
				b = append(b, ':')
			}
			continue
		}
		if i != 0 {
			b = append(b, ':')
		}
		if i == 6 && best[0] == 0 && (best[1] == 6 || (best[1] == 7 && w[7] != 1) || (best[1] == 5 && w[5] == 0xffff)) {
			return netip.AddrFrom4([4]byte(a[12:16])).AppendTo(b)
		}
		b = strconv.AppendUint(b, uint64(w[i]), 16)
	}
	if best[0] != -1 && best[0]+best[1] == 8 {
		b = append(b, ':')
	}
	return b
}

// splitLines is a file's text as the corpus records it: split at "\n", a final unterminated line counts, "\r" stays.
func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// joinLines is the file text of lines: each ended by "\n".
func joinLines(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// ---- expected member lists ----

type digestExp struct {
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

// listExp is an expected member list: null (no file), lines, or the digest of a large case.
type listExp struct {
	null   bool
	lines  []string
	digest *digestExp
}

func (l *listExp) UnmarshalJSON(b []byte) error {
	s := bytes.TrimSpace(b)
	switch {
	case bytes.Equal(s, []byte("null")):
		l.null = true
	case len(s) > 0 && s[0] == '[':
		l.lines = []string{}
		return json.Unmarshal(s, &l.lines)
	case len(s) > 0 && s[0] == '{':
		dec := json.NewDecoder(bytes.NewReader(s))
		dec.DisallowUnknownFields()
		l.digest = &digestExp{}
		if err := dec.Decode(l.digest); err != nil {
			return err
		}
		if keys, _, err := orderedObject(s); err != nil || len(keys) != 2 || len(l.digest.SHA256) != 64 {
			return fmt.Errorf("a digest is exactly a count and a sha256")
		}
	default:
		return fmt.Errorf("not a member list: %s", s)
	}
	return nil
}

// digestOf is the digest of the README: the count and the SHA-256 of the lines sorted bytewise and joined with "\n".
func digestOf(lines []string) digestExp {
	sorted := lines
	if !slices.IsSorted(lines) {
		sorted = slices.Clone(lines)
		slices.Sort(sorted)
	}
	h := sha256.New()
	for i, l := range sorted {
		if i > 0 {
			io.WriteString(h, "\n")
		}
		io.WriteString(h, l)
	}
	return digestExp{len(lines), hex.EncodeToString(h.Sum(nil))}
}

// listDiff is empty when the lists agree, else says how they differ: the counts and the first differing members.
func listDiff(want, got []string, ordered bool) string {
	if ordered {
		if slices.Equal(want, got) {
			return ""
		}
		i := 0
		for i < len(want) && i < len(got) && want[i] == got[i] {
			i++
		}
		return fmt.Sprintf("lists differ in order: expected %d rows, actual %d; first difference at row %d: expected %s, actual %s",
			len(want), len(got), i, rowAt(want, i), rowAt(got, i))
	}
	a, b := slices.Clone(want), slices.Clone(got)
	slices.Sort(a)
	slices.Sort(b)
	if slices.Equal(a, b) {
		return ""
	}
	var onlyWant, onlyGot []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j == len(b) || (i < len(a) && a[i] < b[j]):
			onlyWant = append(onlyWant, a[i])
			i++
		case i == len(a) || b[j] < a[i]:
			onlyGot = append(onlyGot, b[j])
			j++
		default:
			i, j = i+1, j+1
		}
	}
	return fmt.Sprintf("lists differ as multisets: expected %d rows, actual %d; %d only in expected, first %q; %d only in actual, first %q",
		len(want), len(got), len(onlyWant), first(onlyWant, 5), len(onlyGot), first(onlyGot, 5))
}

func rowAt(l []string, i int) string {
	if i < len(l) {
		return strconv.Quote(l[i])
	}
	return "(none)"
}

func first(l []string, n int) []string { return l[:min(n, len(l))] }

// problem is empty when got agrees with the expectation, else says how it differs: lines (a multiset unless ordered), a digest,
// or null for no file.
func (l listExp) problem(got []string, ordered bool) string {
	switch {
	case l.null:
		if len(got) != 0 {
			return fmt.Sprintf("expected no file, actual %d rows, first %q", len(got), first(got, 5))
		}
	case l.digest != nil:
		if len(got) != l.digest.Count {
			return fmt.Sprintf("expected a list of %d rows (sha256 %s), actual %d rows, first %q", l.digest.Count, l.digest.SHA256, len(got), first(got, 3))
		}
		if d := digestOf(got); d.SHA256 != l.digest.SHA256 {
			return fmt.Sprintf("%d rows as expected but the digest differs: expected sha256 %s, actual %s; first rows %q", d.Count, l.digest.SHA256, d.SHA256, first(got, 3))
		}
	default:
		return listDiff(l.lines, got, ordered)
	}
	return ""
}

func (l listExp) check(t *testing.T, name string, got []string, ordered bool) {
	t.Helper()
	if msg := l.problem(got, ordered); msg != "" {
		t.Errorf("%s: %s", name, msg)
	}
}

// dirExp is the expected {file name: list} of a folder; PHP encodes an empty one as [].
type dirExp map[string]listExp

func (d *dirExp) UnmarshalJSON(b []byte) error {
	if s := bytes.TrimSpace(b); bytes.Equal(s, []byte("[]")) {
		*d = dirExp{}
		return nil
	}
	m := map[string]listExp{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*d = m
	return nil
}

// check compares a folder: the same file names, then each file's list.
func (d dirExp) check(t *testing.T, name string, got map[string][]string, ordered bool) {
	t.Helper()
	var want, have []string
	for k := range d {
		want = append(want, k)
	}
	for k := range got {
		have = append(have, k)
	}
	slices.Sort(want)
	slices.Sort(have)
	if !slices.Equal(want, have) {
		t.Errorf("%s: expected files %q, actual files %q", name, first(want, 20), first(have, 20))
	}
	for _, k := range want {
		if g, ok := got[k]; ok {
			d[k].check(t, name+"/"+k, g, ordered)
		}
	}
}

// ---- the corpus ----

type corpusCase struct {
	ID, Description, Op, Family string
	Digest                      bool
	Variant                     string // the key of inputKeys and of the expect table
	In                          any
	Expect                      *obj
}

type corpusDoc struct{ Cases []*corpusCase }

func variantOf(op, family string, in map[string]json.RawMessage) (string, error) {
	switch op {
	case "suppress":
		return "suppress/" + family, nil
	case "matrix":
		var fn string
		if json.Unmarshal(in["fn"], &fn) != nil {
			return "", fmt.Errorf("matrix input has no fn")
		}
		return "matrix/" + fn, nil
	}
	return op, nil
}

// loadCorpus is the strict schema of the README: an unknown or missing key, a duplicate id, an unknown op or an expect key
// absent from the asserted/presentation table is an error.
func loadCorpus(data []byte) (*corpusDoc, error) {
	top, err := objOf(data, "corpus", []string{"schema", "cases"}, nil)
	if err != nil {
		return nil, err
	}
	var schema int
	var cases []json.RawMessage
	if json.Unmarshal(top.m["schema"], &schema) != nil || schema != 1 {
		return nil, fmt.Errorf("schema must be 1")
	}
	if json.Unmarshal(top.m["cases"], &cases) != nil || len(cases) == 0 {
		return nil, fmt.Errorf("cases must be a non-empty list")
	}
	doc := &corpusDoc{}
	seen := map[string]bool{}
	for n, raw := range cases {
		c, err := loadCase(raw, n)
		if err != nil {
			return nil, err
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("duplicate id %q", c.ID)
		}
		seen[c.ID] = true
		doc.Cases = append(doc.Cases, c)
	}
	return doc, nil
}

func loadCase(raw json.RawMessage, n int) (*corpusCase, error) {
	o, err := objOf(raw, fmt.Sprintf("case %d", n), []string{"id", "description", "op", "family", "input", "expect"}, []string{"digest"})
	if err != nil {
		return nil, err
	}
	c := &corpusCase{ID: o.str("id"), Description: o.str("description"), Op: o.str("op"), Family: o.str("family")}
	if o.err != nil {
		return nil, o.err
	}
	if c.ID == "" || c.Description == "" {
		return nil, fmt.Errorf("case %d: id and description must be non-empty", n)
	}
	o.what = c.ID
	if !slices.Contains(corpusOps, c.Op) {
		return nil, fmt.Errorf("%s: unknown op %q", c.ID, c.Op)
	}
	if c.Family != "v4" && c.Family != "v6" {
		return nil, fmt.Errorf("%s: family must be v4 or v6, got %q", c.ID, c.Family)
	}
	if o.has("digest") {
		if c.Digest = o.flag("digest"); !c.Digest {
			return nil, fmt.Errorf("%s: digest is only ever true", c.ID)
		}
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(o.m["input"], &in) != nil || in == nil {
		return nil, fmt.Errorf("%s: input is not an object", c.ID)
	}
	if c.Variant, err = variantOf(c.Op, c.Family, in); err != nil {
		return nil, fmt.Errorf("%s: %v", c.ID, err)
	}
	keys, ok := inputKeys[c.Variant]
	if !ok {
		return nil, fmt.Errorf("%s: no input schema for %q", c.ID, c.Variant)
	}
	inObj, err := objOf(o.m["input"], c.ID+".input", keys[0], keys[1])
	if err != nil {
		return nil, err
	}
	if c.In, err = decodeInput(c, inObj); err != nil {
		return nil, err
	}
	c.Expect, err = objOf(o.m["expect"], c.ID+".expect", topKeys(c.Variant), nil)
	if err != nil {
		if strings.Contains(err.Error(), "unknown key") {
			err = fmt.Errorf("%v: not in the asserted or presentation table of README.md", err)
		}
		return nil, err
	}
	return c, nil
}

var (
	corpusOnce sync.Once
	corpusDocV *corpusDoc
	corpusErr  error
)

// theCorpus loads testdata/ipset.json once.
func theCorpus(t *testing.T) *corpusDoc {
	t.Helper()
	corpusOnce.Do(func() {
		data, err := os.ReadFile(corpusPath)
		if err != nil {
			corpusErr = err
			return
		}
		corpusDocV, corpusErr = loadCorpus(data)
	})
	if corpusErr != nil {
		t.Fatalf("corpus: %v", corpusErr)
	}
	return corpusDocV
}

// runGroup replays every case of one op as a subtest named by its id.
func runGroup(t *testing.T, op string, run func(t *testing.T, c *corpusCase)) {
	t.Helper()
	n := 0
	for _, c := range theCorpus(t).Cases {
		if c.Op != op {
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) { run(t, c) })
	}
	if n == 0 {
		t.Fatalf("op %s has no case in the corpus", op)
	}
}

// rcOK holds the exit status mirror to its one meaning: no Go function has an error path, so a status other than 0 or null
// needs a new return value first.
func rcOK(t *testing.T, e *obj) {
	t.Helper()
	if raw, ok := e.m["rc"]; ok {
		if s := string(bytes.TrimSpace(raw)); s != "null" && s != "0" {
			t.Errorf("rc: expected status %s has no Go counterpart; an error return is needed first", s)
		}
	}
}

// ---- tests of the runner itself ----

func TestCorpusRouting(t *testing.T) {
	doc := theCorpus(t)
	perOp := map[string]int{}
	for _, c := range doc.Cases {
		perOp[c.Op]++
	}
	for _, op := range corpusOps {
		if perOp[op] == 0 {
			t.Errorf("op %s has no case", op)
		}
	}
	if len(doc.Cases) != 433 {
		t.Errorf("the corpus holds %d cases, expected 433", len(doc.Cases))
	}
}

// Every op is replayed by exactly one group test: runGroup(t, "<op>", ...) appears once per op in the test sources, so no case
// is left without a runner and none runs twice.
func TestEveryOpHasOneGroupTest(t *testing.T) {
	files, err := parser.ParseDir(token.NewFileSet(), ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	for _, pkg := range files {
		for name, f := range pkg.Files {
			if !strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "runGroup" {
					if lit, ok := call.Args[1].(*ast.BasicLit); ok {
						calls[strings.Trim(lit.Value, `"`)]++
					}
				}
				return true
			})
		}
	}
	for _, op := range corpusOps {
		if calls[op] != 1 {
			t.Errorf("op %s is replayed by %d group tests, expected exactly 1", op, calls[op])
		}
	}
	if len(calls) != len(corpusOps) {
		t.Errorf("group tests name %d ops, the corpus has %d", len(calls), len(corpusOps))
	}
}

func TestExpectTableMatchesReadme(t *testing.T) {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(data), "\n## What the Go runner asserts\n")
	if !found {
		t.Fatal(`README.md has no "What the Go runner asserts" section`)
	}
	if i := strings.Index(section, "\n## "); i >= 0 {
		section = section[:i]
	}
	var readme []string
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if !strings.HasPrefix(line, "|") || len(cells) != 4 || strings.Trim(cells[0], " -") == "" || strings.TrimSpace(cells[0]) == "Group" {
			continue
		}
		cell := func(i int) string { return strings.Trim(strings.TrimSpace(cells[i]), "`") }
		if cell(3) == "" {
			t.Errorf("README row %q has no reason", line)
		}
		readme = append(readme, cell(0)+"|"+cell(1)+"|"+cell(2))
	}
	var code []string
	for _, r := range expectTable {
		code = append(code, r.group+"|"+r.key+"|"+r.status)
	}
	if msg := listDiff(code, readme, false); msg != "" {
		t.Errorf("the runner's expect table and README.md disagree: %s", msg)
	}
}

// A valid corpus of one case, the base of the hostile loader rows.
const minimalCorpus = `{"schema":1,"cases":[{"id":"c1","description":"d","op":"canonical","family":"v4","input":{"members":{"text":"1.1.1.1\n"}},"expect":{"set":["1.1.1.1"]}}]}`

func TestLoaderRejectsHostileCorpus(t *testing.T) {
	if _, err := loadCorpus([]byte(minimalCorpus)); err != nil {
		t.Fatalf("the base corpus must load: %v", err)
	}
	cases := []struct{ name, old, new, want string }{
		{"unknown case key", `"op":"canonical",`, `"op":"canonical","extra":1,`, `unknown key "extra"`},
		{"missing expect", `,"expect":{"set":["1.1.1.1"]}`, ``, `missing key "expect"`},
		{"missing input", `"input":{"members":{"text":"1.1.1.1\n"}},`, ``, `missing key "input"`},
		{"unknown op", `"op":"canonical"`, `"op":"bogus"`, `unknown op "bogus"`},
		{"unknown top-level key", `{"schema":1,`, `{"schema":1,"note":"x",`, `unknown key "note"`},
		{"wrong schema", `"schema":1`, `"schema":2`, `schema must be 1`},
		{"bad family", `"family":"v4"`, `"family":"v5"`, `family must be v4 or v6`},
		{"empty description", `"description":"d"`, `"description":""`, `non-empty`},
		{"digest false", `"op":"canonical",`, `"op":"canonical","digest":false,`, `digest is only ever true`},
		{"unknown input key", `"input":{"members"`, `"input":{"note":1,"members"`, `unknown key "note"`},
		{"text and parts", `{"text":"1.1.1.1\n"}`, `{"text":"x","parts":["y"]}`, `exactly one of text, text_hex, parts`},
		{"no text key", `{"text":"1.1.1.1\n"}`, `{}`, `exactly one of text, text_hex, parts`},
		{"upper-case hex", `{"text":"1.1.1.1\n"}`, `{"text_hex":"0A"}`, `not lower-case`},
		{"unknown generator kind", `{"text":"1.1.1.1\n"}`, `{"parts":[{"generate":{"kind":"v5_seq"}}]}`, `unknown generator kind "v5_seq"`},
		{"generator without count", `{"text":"1.1.1.1\n"}`, `{"parts":[{"generate":{"kind":"v4_seq","start":1,"step":1,"suffix":""}}]}`, `missing key "count"`},
		{"generator with an unknown key", `{"text":"1.1.1.1\n"}`, `{"parts":[{"generate":{"kind":"v4_seq","start":1,"count":1,"step":1,"suffix":"","base":"::"}}]}`, `unknown key "base"`},
		{"expect key in neither list", `"expect":{"set"`, `"expect":{"note":1,"set"`, `not in the asserted or presentation table`},
		{"expect key missing", `"expect":{"set":["1.1.1.1"]}`, `"expect":{}`, `missing key "set"`},
		{"duplicate key", `"expect":{"set":["1.1.1.1"]}`, `"expect":{"set":[],"set":["1.1.1.1"]}`, `duplicate key "set"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.Count(minimalCorpus, c.old) != 1 {
				t.Fatalf("the mutation target %q is not unique in the base corpus", c.old)
			}
			_, err := loadCorpus([]byte(strings.Replace(minimalCorpus, c.old, c.new, 1)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("expected an error containing %q, got %v", c.want, err)
			}
		})
	}
	t.Run("duplicate id", func(t *testing.T) {
		one := minimalCorpus[strings.Index(minimalCorpus, `[`)+1 : len(minimalCorpus)-2]
		_, err := loadCorpus([]byte(`{"schema":1,"cases":[` + one + `,` + one + `]}`))
		if err == nil || !strings.Contains(err.Error(), `duplicate id "c1"`) {
			t.Errorf("expected a duplicate id error, got %v", err)
		}
	})
}

// The real corpus with one unknown key added to a case must not load.
func TestLoaderRejectsMutatedRealCorpus(t *testing.T) {
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(doc["cases"], &cases); err != nil {
		t.Fatal(err)
	}
	cases[0]["surprise"] = json.RawMessage(`true`)
	doc["cases"], _ = json.Marshal(cases)
	mutated, _ := json.Marshal(doc)
	if _, err := loadCorpus(mutated); err == nil || !strings.Contains(err.Error(), `unknown key "surprise"`) {
		t.Errorf("expected the unknown key to fail the load, got %v", err)
	}
}

func TestNtop6MatchesInetNtop(t *testing.T) {
	// Vectors from PHP's inet_ntop().
	for hexa, want := range map[string]string{
		"00000000000000000000000000000000": "::",
		"00000000000000000000000000000001": "::1",
		"00000000000000000000000001020304": "::1.2.3.4",
		"0000000000000000000000000000ff01": "::ff01",
		"00000000000000000000ffff01020304": "::ffff:1.2.3.4",
		"20010db8000000000000000000000001": "2001:db8::1",
		"20010db8000000010000000000000000": "2001:db8:0:1::",
		"00010000000000020000000000000003": "1:0:0:2::3",
		"00000000000000000000000100000001": "::1:0:1",
		"00000000000000000001000000000000": "::1:0:0:0",
		"fe800000000000000000000000000001": "fe80::1",
		"00000000000000010000000000000001": "::1:0:0:0:1",
		"00000000000000000000000000000100": "::100",
	} {
		b, _ := hex.DecodeString(hexa)
		if got := string(appendNtop6(nil, [16]byte(b))); got != want {
			t.Errorf("%s: expected %s, actual %s", hexa, want, got)
		}
	}
}

func TestTextObjects(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"text":     {`{"text":"a\r\nb"}`, "a\r\nb"},
		"hex":      {`{"text_hex":"ff0a"}`, "\xff\n"},
		"parts":    {`{"parts":["a\n",{"generate":{"kind":"v4_seq","start":16777216,"count":2,"step":2,"suffix":"/32"}}]}`, "a\n1.0.0.0/32\n1.0.0.2/32\n"},
		"v6":       {`{"parts":[{"generate":{"kind":"v6_seq","base":"2001:db8::","count":2,"step":3,"suffix":""}}]}`, "2001:db8::\n2001:db8::3\n"},
		"v6 carry": {`{"parts":[{"generate":{"kind":"v6_seq","base":"2001:db8::ffff:ffff:ffff:ffff","count":2,"step":1,"suffix":""}}]}`, "2001:db8::ffff:ffff:ffff:ffff\n2001:db8::\n"},
	} {
		x, err := parseText(json.RawMessage(tc.raw), name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := x.String(); got != tc.want {
			t.Errorf("%s: expected %q, actual %q", name, tc.want, got)
		}
	}
}

// A failing comparison says what differed, never a bare false.
func TestListFailuresNameTheDifference(t *testing.T) {
	good := digestOf([]string{"a", "b"})
	for name, tc := range map[string]struct {
		want    listExp
		got     []string
		ordered bool
		in      []string
	}{
		"order":      {listExp{lines: []string{"a", "b"}}, []string{"b", "a"}, true, []string{"first difference at row 0", `"a"`, `"b"`}},
		"multiset":   {listExp{lines: []string{"a", "b", "b"}}, []string{"a", "c"}, false, []string{"expected 3 rows, actual 2", `only in expected, first ["b" "b"]`, `only in actual, first ["c"]`}},
		"duplicates": {listExp{lines: []string{"a"}}, []string{"a", "a"}, false, []string{"expected 1 rows, actual 2"}},
		"null":       {listExp{null: true}, []string{"a"}, false, []string{"expected no file", `["a"]`}},
		"count":      {listExp{digest: &good}, []string{"a"}, false, []string{"expected a list of 2 rows", "actual 1 rows"}},
		"hash":       {listExp{digest: &good}, []string{"a", "c"}, false, []string{"digest differs", good.SHA256}},
	} {
		msg := tc.want.problem(tc.got, tc.ordered)
		for _, frag := range tc.in {
			if !strings.Contains(msg, frag) {
				t.Errorf("%s: the message %q lacks %q", name, msg, frag)
			}
		}
	}
	for name, tc := range map[string]struct {
		want listExp
		got  []string
	}{
		"same multiset": {listExp{lines: []string{"a", "b", "a"}}, []string{"a", "a", "b"}},
		"digest":        {listExp{digest: &good}, []string{"b", "a"}},
		"null":          {listExp{null: true}, nil},
	} {
		if msg := tc.want.problem(tc.got, false); msg != "" {
			t.Errorf("%s: expected agreement, got %q", name, msg)
		}
	}
}

func TestSplitLinesAndDigest(t *testing.T) {
	for in, want := range map[string][]string{"": {}, "a": {"a"}, "a\n": {"a"}, "a\n\n": {"a", ""}, "a\r\nb": {"a\r", "b"}} {
		if got := splitLines(in); !slices.Equal(got, want) {
			t.Errorf("splitLines(%q): expected %q, actual %q", in, want, got)
		}
	}
	if d := digestOf(nil); d.Count != 0 || d.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("the digest of no rows is the hash of the empty string, got %+v", d)
	}
	if a, b := digestOf([]string{"b", "a"}), digestOf([]string{"a", "b"}); a != b {
		t.Errorf("a digest is order-insensitive: %+v against %+v", a, b)
	}
}

// The corpus records a few large lists whose output equals their input; regenerating the input proves the recipes and the
// digest rule against the appliance's frozen hashes, with no package code involved.
func TestGeneratorsReproduceFrozenDigests(t *testing.T) {
	doc := theCorpus(t)
	byID := map[string]*corpusCase{}
	for _, c := range doc.Cases {
		byID[c.ID] = c
	}
	input := func(id string) []string {
		switch in := byID[id].In.(type) {
		case cidrIn:
			return splitLines(in.members.String())
		case recIn:
			return splitLines(in.members[0].text.String())
		}
		t.Fatalf("%s: no input to regenerate", id)
		return nil
	}
	var want listExp
	if err := json.Unmarshal(byID["agg_large_2m_step2"].Expect.m["members"], &want); err != nil {
		t.Fatal(err)
	}
	want.check(t, "agg_large_2m_step2.members", input("agg_large_2m_step2"), false)
	var deny dirExp
	if err := json.Unmarshal(byID["rec_v6_large_2m"].Expect.m["deny"], &deny); err != nil {
		t.Fatal(err)
	}
	deny["X_v6.txt"].check(t, "rec_v6_large_2m.deny", input("rec_v6_large_2m"), false)
}
