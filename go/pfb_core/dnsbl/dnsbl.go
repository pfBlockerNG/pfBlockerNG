// Package dnsbl assembles the DNSBL data pfB-DNS builds from into dnsbl/* resources (issue #4036, spec section 9): the
// data today's pfb_unbound_python_sources() writes as the manifest pfb_py_sources.json and its raw feed files, the TOP1M
// sidecar, the SafeSearch table and the PSL authority. Publish writes the bodies first and dnsbl/manifest last; the
// manifest names the generation and digest of each body it goes with.
//
//	dnsbl/manifest     JSON Lines: one config row; one whitelist, unlock, tld_blacklist or tld_exclusion row per entry;
//	                   one feed row per feed (position, attributes, and its body's resource, generation, digest and
//	                   entries); one member row per other body. Metadata: the per-group entry counts.
//	dnsbl/feed-<name>  plain text: the feed's rows, each a domain or a verbatim ABP rule, as a .raw file holds them.
//	dnsbl/top1m        plain text: the TOP1M whitelist, one domain per line.
//	dnsbl/safesearch   JSON Lines: {"host", "a", "aaaa", "v4", "v6"}, v4 and v6 only on a CNAME row.
//	dnsbl/psl          JSON Lines: {"section": "icann" or "private", "rule"}.
//
// The store keeps only a body's current generation and its applied baseline, so a body can move on between a client's
// read of the manifest and its fetch of the body: the client then keeps the set it serves and retries on its next poll.
//
// A body is a sorted set (owner, 2026-11-23): a feed's rows lose their order and repeats, which changes no block or
// allow decision; the departures are pinned in tests/core/fixtures/dnsbl_resources_parity.json.
package dnsbl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// The resource ids. A feed's is FeedPrefix followed by its name.
const (
	ManifestID   = "dnsbl/manifest"
	Top1mID      = "dnsbl/top1m"
	SafeSearchID = "dnsbl/safesearch"
	PSLID        = "dnsbl/psl"
	FeedPrefix   = "dnsbl/feed-"
)

// maxStagedLine bounds a staged NDJSON line: a member's 1 MiB, escaped at most twice over, plus the row's other fields.
const maxStagedLine = 2*resources.MaxMemberLength + 4096

// Feed is one feed, in the order the build reads the feeds: the order decides which feed a domain listed twice belongs to.
type Feed struct {
	Name       string // the feed header: letters, digits and underscores (PFB_FILTER_WORD)
	Group      string
	LogFlag    string
	Provenance string   // "user" for a Custom_List; anything else is "feed"
	Mode       string   // "permit" for a permit feed; anything else is "deny"
	Top1m      bool     // the group's "TOP1M Whitelist" box
	Rows       []string // domains and verbatim ABP rules, in any order; Publish filters and sorts them in place
}

// SafeSearch is one row of the SafeSearch table: an A and AAAA rewrite, or a CNAME redirect with its baked addresses.
type SafeSearch struct {
	Host string `json:"host"`
	A    string `json:"a"`
	AAAA string `json:"aaaa"`
	V4   string `json:"v4,omitempty"`
	V6   string `json:"v6,omitempty"`
}

// Set is everything Publish writes. A nil SafeSearch or PSL publishes no body for it.
type Set struct {
	BuiltinLogFlag string
	Top1mEnabled   bool     // dnsbl/top1m is published exactly while it is on, and then Top1m must not be nil
	Top1m          []string // filtered and sorted in place
	Whitelist      []string
	Unlock         []string
	TLDWildcard    bool     // dns.tldWildcard: both TLD lists are published only while it is on
	TLDBlacklist   []string // what policy/dnsbl lists, whether TLDWildcard is on or not
	TLDExclusions  []string
	Feeds          []Feed       // two feeds of one name share one body holding the rows of both
	SafeSearch     []SafeSearch // a host listed twice keeps its last row
	PSL            []byte       // the PSL text with its four section markers
}

// Result is what Publish did.
type Result struct {
	Generation uint64         // dnsbl/manifest's: the apply request's dnsbl.generation
	Dropped    map[string]int // resource id: rows left out because the store cannot hold them
	Refused    []string       // feeds left out: a name today's writer refuses, or one too long for a resource id
}

// The PSL authority's section markers, as the decider matches them (decider/pfb_unbound_psl.go).
var pslMarkers = [4]string{
	"// ===BEGIN ICANN DOMAINS===", "// ===END ICANN DOMAINS===",
	"// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS===",
}

// ReadStaged reads a feed's staged NDJSON rows and returns their texts. It takes what pfb_dnsbl_ndjson_parse_row()
// takes: ["d",domain] and ["a",rule], and the schema-v1 objects {"kind":"domain","domain","log","feed","group"} and
// {"kind":"abp","raw"}. A line of any other shape, not UTF-8, holding a lone UTF-16 surrogate escape, or longer than
// maxStagedLine, is skipped and counted in invalid; blank lines are skipped uncounted. A long line is never held whole.
func ReadStaged(r io.Reader) (rows []string, invalid int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, long, err := readLine(br)
		switch {
		case long:
			invalid++
		case len(bytes.TrimSpace(line)) == 0:
		default:
			if text, ok := parseRow(line); ok {
				rows = append(rows, text)
			} else {
				invalid++
			}
		}
		if errors.Is(err, io.EOF) {
			return rows, invalid, nil
		}
		if err != nil {
			return nil, 0, err
		}
	}
}

// readLine reads up to the next newline; past maxStagedLine it drains the line and returns long instead of it.
func readLine(br *bufio.Reader) (line []byte, long bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !long && len(line)+len(chunk) > maxStagedLine {
			line, long = nil, true
		}
		if !long {
			line = append(line, chunk...)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, long, err
		}
	}
}

// parseRow is pfb_dnsbl_ndjson_parse_row(): the text of a row, and whether the line is one.
func parseRow(line []byte) (string, bool) {
	// json_decode() refuses what is not UTF-8 and a lone surrogate escape, where encoding/json substitutes U+FFFD.
	if !utf8.Valid(line) || loneSurrogate(line) {
		return "", false
	}
	var v any
	if json.Unmarshal(line, &v) != nil {
		return "", false
	}
	trimmed := bytes.TrimLeft(line, " \t\n\r\x00\x0b") // ltrim()
	if trimmed[0] == '[' {
		a, _ := v.([]any)
		if len(a) != 2 {
			return "", false
		}
		tag, _ := a[0].(string)
		text, _ := a[1].(string)
		return text, text != "" && (tag == "d" || tag == "a")
	}
	o, _ := v.(map[string]any)
	if trimmed[0] != '{' || o == nil {
		return "", false
	}
	kind, _ := o["kind"].(string)
	required := map[string][]string{"domain": {"domain", "log", "feed", "group"}, "abp": {"raw"}}[kind]
	for _, key := range required {
		if s, _ := o[key].(string); s == "" {
			return "", false
		}
	}
	if required == nil {
		return "", false
	}
	return o[required[0]].(string), true
}

// loneSurrogate reports a \uD800-\uDFFF escape that is not a high surrogate followed by a low one.
func loneSurrogate(b []byte) bool {
	hex4 := func(i int) int {
		if i+4 > len(b) {
			return -1
		}
		n, err := strconv.ParseUint(string(b[i:i+4]), 16, 16)
		if err != nil {
			return -1
		}
		return int(n)
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++ // the escaped character, a backslash included
		if i >= len(b) || b[i] != 'u' {
			continue
		}
		r := hex4(i + 1)
		switch {
		case r >= 0xDC00 && r <= 0xDFFF:
			return true
		case r >= 0xD800 && r <= 0xDBFF:
			if i+10 >= len(b) || b[i+5] != '\\' || b[i+6] != 'u' {
				return true
			}
			if low := hex4(i + 7); low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 10
		}
	}
	return false
}

// body is one body Publish writes, and what the store answered for it.
type body struct {
	id    string
	rows  []string
	reply resources.Reply
}

// Publish writes set into store: each body, then dnsbl/manifest naming them, then it removes every other dnsbl/* id the
// store holds. Publishing the same set again advances no generation. TOP1M on without a list, a PSL text without its
// markers, or a manifest row longer than a member may be, refuses the whole set before anything is written.
func Publish(store *resources.Store, set Set) (Result, error) {
	res := Result{Dropped: map[string]int{}}
	var feeds []Feed
	var bodies []*body
	byName := map[string]*body{}
	for _, f := range set.Feeds {
		// PFB_FILTER_WORD, read through empty(): the header "0" is refused too.
		if !wordName(f.Name) || f.Name == "0" || !resources.ValidID(FeedPrefix+f.Name) {
			res.Refused = append(res.Refused, f.Name)
			continue
		}
		feeds = append(feeds, f)
		if b := byName[f.Name]; b != nil {
			b.rows = append(b.rows, f.Rows...)
			continue
		}
		byName[f.Name] = &body{id: FeedPrefix + f.Name, rows: slices.Clip(f.Rows)}
		bodies = append(bodies, byName[f.Name])
	}
	if set.Top1mEnabled {
		if set.Top1m == nil {
			return res, errors.New("TOP1M is on but no TOP1M list is given")
		}
		bodies = append(bodies, &body{id: Top1mID, rows: set.Top1m})
	}
	if set.SafeSearch != nil {
		last := map[string]SafeSearch{}
		for _, row := range set.SafeSearch {
			last[row.Host] = row
		}
		rows := make([]string, 0, len(last))
		for _, row := range last {
			rows = append(rows, jsonLine(row))
		}
		bodies = append(bodies, &body{id: SafeSearchID, rows: rows})
	}
	if set.PSL != nil {
		rows, err := pslRows(set.PSL)
		if err != nil {
			return res, err
		}
		bodies = append(bodies, &body{id: PSLID, rows: rows})
	}

	// The rows with the longest generation, digest and entries a body can have: when they are members, so is the manifest.
	widest := resources.Reply{Generation: math.MaxUint64, Digest: strings.Repeat("f", 32), Entries: math.MaxInt}
	for _, b := range bodies {
		b.reply = widest
	}
	if _, err := resources.Canonical(manifestRows(set, feeds, byName, bodies)); err != nil {
		return res, fmt.Errorf("%s: %w", ManifestID, err)
	}

	for _, b := range bodies {
		kept := b.rows[:0]
		for i := range b.rows {
			if _, err := resources.Canonical(b.rows[i : i+1]); err != nil {
				res.Dropped[b.id]++
				continue
			}
			kept = append(kept, b.rows[i])
		}
		if _, err := store.Publish(b.id, kept, nil); err != nil {
			return res, err
		}
		reply, err := store.Get(b.id, nil)
		if err != nil {
			return res, err
		}
		b.reply = reply
	}

	type group struct {
		Name    string `json:"name"`
		Entries int    `json:"entries"`
	}
	groups := []group{}
	groupAt := map[string]int{}
	total := 0
	for _, f := range feeds {
		entries := byName[f.Name].reply.Entries
		total += entries
		at, ok := groupAt[f.Group]
		if !ok {
			at, groupAt[f.Group] = len(groups), len(groups)
			groups = append(groups, group{Name: f.Group})
		}
		groups[at].Entries += entries
	}
	var err error
	meta := map[string]any{"groups": groups, "feeds": len(feeds), "entries": total}
	if res.Generation, err = store.Publish(ManifestID, manifestRows(set, feeds, byName, bodies), meta); err != nil {
		return res, err
	}

	held, err := store.IDs("dnsbl/")
	if err != nil {
		return res, err
	}
	current := map[string]bool{ManifestID: true}
	for _, b := range bodies {
		current[b.id] = true
	}
	for _, id := range held {
		if !current[id] {
			if err := store.Remove(id); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// domainRow is a manifest row that names a domain: whitelist, unlock or tld_exclusion.
type domainRow struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

// memberRow names the body a manifest row belongs with.
type memberRow struct {
	Resource   string `json:"resource"`
	Generation string `json:"generation"`
	Digest     string `json:"digest"`
	Entries    int    `json:"entries"`
}

func member(b *body) memberRow {
	return memberRow{b.id, strconv.FormatUint(b.reply.Generation, 10), b.reply.Digest, b.reply.Entries}
}

// manifestRows is the manifest's rows, each body described by its reply.
func manifestRows(set Set, feeds []Feed, byName map[string]*body, bodies []*body) []string {
	var rows []string
	add := func(v any) { rows = append(rows, jsonLine(v)) }
	add(struct {
		Kind           string `json:"kind"`
		BuiltinLogFlag string `json:"builtinLogFlag"`
		Top1mEnabled   bool   `json:"top1mEnabled"`
	}{"config", set.BuiltinLogFlag, set.Top1mEnabled})
	exclusions := set.TLDExclusions
	if !set.TLDWildcard {
		exclusions = nil
	}
	for _, list := range []struct {
		kind   string
		values []string
	}{{"whitelist", set.Whitelist}, {"unlock", set.Unlock}, {"tld_exclusion", exclusions}} {
		for _, v := range list.values {
			add(domainRow{list.kind, v})
		}
	}
	if set.TLDWildcard {
		for _, v := range set.TLDBlacklist {
			add(struct {
				Kind string `json:"kind"`
				TLD  string `json:"tld"`
			}{"tld_blacklist", v})
		}
	}
	for i, f := range feeds {
		mode, provenance := "deny", "feed"
		if f.Mode == "permit" {
			mode = "permit"
		}
		if f.Provenance == "user" {
			provenance = "user"
		}
		add(struct {
			Kind       string `json:"kind"`
			Position   int    `json:"position"`
			Feed       string `json:"feed"`
			Group      string `json:"group"`
			LogFlag    string `json:"logFlag"`
			Provenance string `json:"provenance"`
			Mode       string `json:"mode"`
			Top1m      bool   `json:"top1m"`
			memberRow
		}{"feed", i + 1, f.Name, f.Group, f.LogFlag, provenance, mode, f.Top1m, member(byName[f.Name])})
	}
	for _, b := range bodies {
		if !strings.HasPrefix(b.id, FeedPrefix) {
			add(struct {
				Kind string `json:"kind"`
				memberRow
			}{"member", member(b)})
		}
	}
	return rows
}

// wordName is PFB_FILTER_WORD, the rule today's manifest writer applies to a feed header.
func wordName(s string) bool {
	for _, c := range []byte(s) {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return s != ""
}

// jsonLine is v as one JSON object that is a valid member: the control characters encoding/json leaves raw (U+007F and
// the C1 range) are escaped too.
func jsonLine(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // only strings, ints and bools reach it
	}
	line := strings.TrimSuffix(b.String(), "\n")
	if strings.IndexFunc(line, unicode.IsControl) < 0 {
		return line
	}
	var out strings.Builder
	for _, r := range line {
		if unicode.IsControl(r) {
			fmt.Fprintf(&out, `\u%04x`, r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// pySpace is str.isspace(), what the decider's pyStrip strips.
func pySpace(r rune) bool { return unicode.IsSpace(r) || 0x1C <= r && r <= 0x1F }

// pslLines breaks the text where str.splitlines() does, as the decider's pslSplitlines reads the authority; a CRLF gives
// an extra blank line, which pslRows skips like any blank line.
func pslLines(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029", r)
	})
}

// pslRows is the rules of the PSL text's ICANN and PRIVATE sections as rows. Blank and comment lines go; each of the
// four markers must stand once, in order, on a line of its own, and the text must be UTF-8 without NUL, as the decider
// requires of its authority file.
func pslRows(text []byte) ([]string, error) {
	if !utf8.Valid(text) || bytes.IndexByte(text, 0) >= 0 {
		return nil, errors.New("PSL text is not UTF-8 without NUL")
	}
	lines := pslLines(string(text))
	at := [4]int{-1, -1, -1, -1}
	for i, line := range lines {
		for m, marker := range pslMarkers {
			if strings.TrimFunc(line, pySpace) == marker {
				if at[m] >= 0 {
					return nil, errors.New("PSL text holds a section marker twice")
				}
				at[m] = i
			}
		}
	}
	if !(at[0] >= 0 && at[0] < at[1] && at[1] < at[2] && at[2] < at[3]) {
		return nil, errors.New("PSL text lacks its section markers, or holds them out of order")
	}
	rows := []string{}
	for _, s := range []struct {
		name     string
		from, to int
	}{{"icann", at[0], at[1]}, {"private", at[2], at[3]}} {
		for _, line := range lines[s.from+1 : s.to] {
			rule := strings.TrimFunc(line, pySpace)
			if rule == "" || strings.HasPrefix(rule, "#") || strings.HasPrefix(rule, "//") {
				continue
			}
			rows = append(rows, jsonLine(struct {
				Section string `json:"section"`
				Rule    string `json:"rule"`
			}{s.name, rule}))
		}
	}
	return rows, nil
}
