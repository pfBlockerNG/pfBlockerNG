// Package dnsbl assembles the DNSBL data pfB-DNS builds from into dnsbl/* resources (issue #4036, spec section 9): the
// data today's pfb_unbound_python_sources() writes as the manifest pfb_py_sources.json and its raw feed files, the TOP1M
// sidecar, the SafeSearch table and the PSL authority. Publish writes them into the resource store, the members first
// and dnsbl/manifest last, so the manifest is the one commit point: a consumer that reads it finds every body it names.
//
//	dnsbl/manifest     JSON Lines: one config row; one whitelist, unlock, tld_blacklist or tld_exclusion row per entry;
//	                   one feed row per feed (position, attributes, and its body's resource, generation, digest and
//	                   entries); one member row per other body. Metadata: the per-group entry counts.
//	dnsbl/feed-<name>  plain text: the feed's rows, each a domain or a verbatim ABP rule, as a .raw file holds them.
//	dnsbl/top1m        plain text: the TOP1M whitelist, one domain per line.
//	dnsbl/safesearch   JSON Lines: {"host", "a", "aaaa", "v4", "v6"}, v4 and v6 only on a CNAME row.
//	dnsbl/psl          JSON Lines: {"section": "icann" or "private", "rule"}.
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

// Feed is one feed, in the order the build reads the feeds: the order decides which feed a domain listed twice belongs to.
type Feed struct {
	Name       string // the feed header: letters, digits and underscores (PFB_FILTER_WORD)
	Group      string
	LogFlag    string
	Provenance string   // "user" for a Custom_List; anything else is "feed"
	Mode       string   // "permit" for a permit feed; anything else is "deny"
	Top1m      bool     // the group's "TOP1M Whitelist" box
	Rows       []string // domains and verbatim ABP rules, in any order; Publish sorts them in place
}

// SafeSearch is one row of the SafeSearch table: an A and AAAA rewrite, or a CNAME redirect with its baked addresses.
type SafeSearch struct {
	Host string `json:"host"`
	A    string `json:"a"`
	AAAA string `json:"aaaa"`
	V4   string `json:"v4,omitempty"`
	V6   string `json:"v6,omitempty"`
}

// Set is everything Publish writes. A nil Top1m, SafeSearch or PSL publishes no body for it.
type Set struct {
	BuiltinLogFlag string
	Top1mEnabled   bool
	Whitelist      []string
	Unlock         []string
	TLDWildcard    bool     // dns.tldWildcard
	TLDBlacklist   []string // published by the caller only while dns.tldWildcard is on, as today
	TLDExclusions  []string
	Feeds          []Feed
	Top1m          []string
	SafeSearch     []SafeSearch // a host listed twice keeps its last row
	PSL            []byte       // the PSL text with its four section markers
}

// Result is what Publish did.
type Result struct {
	Generation uint64         // dnsbl/manifest's: the apply request's dnsbl.generation
	Dropped    map[string]int // resource id: rows left out because the store cannot hold them
	Refused    []string       // feeds left out because their name is not letters, digits and underscores
}

// The PSL authority's section markers, as the decider matches them (decider/pfb_unbound_psl.go).
var pslMarkers = [4]string{
	"// ===BEGIN ICANN DOMAINS===", "// ===END ICANN DOMAINS===",
	"// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS===",
}

// ReadStaged reads a feed's staged NDJSON rows, ["d",domain] or ["a",rule] as pfb_dnsbl_ndjson_emit_row() and
// feedparse write them, and returns their texts. A row of any other shape is skipped and counted in invalid, as
// pfb_dnsbl_ndjson_parse_row() skips it; blank lines are skipped uncounted.
func ReadStaged(r io.Reader) (rows []string, invalid int, err error) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var row []string
			if json.Unmarshal(line, &row) != nil || len(row) != 2 || row[1] == "" || (row[0] != "d" && row[0] != "a") {
				invalid++
			} else {
				rows = append(rows, row[1])
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

// Publish writes set into store: each body, then dnsbl/manifest naming them, then it removes every dnsbl/* body the
// previous manifest named and this one does not. Publishing the same set again advances no generation. A feed named
// twice, a PSL text without its markers, or a manifest row longer than a member may be, refuses the whole set; a body
// already written then stays unnamed until the next Publish, which writes or removes it.
func Publish(store *resources.Store, set Set) (Result, error) {
	res := Result{Dropped: map[string]int{}}
	previous, err := manifestResources(store)
	if err != nil {
		return res, err
	}
	var feeds []Feed
	seen := map[string]bool{}
	for _, f := range set.Feeds {
		if seen[f.Name] {
			return res, fmt.Errorf("feed %q is named twice", f.Name)
		}
		seen[f.Name] = true
		if !wordName(f.Name) || !resources.ValidID(FeedPrefix+f.Name) {
			res.Refused = append(res.Refused, f.Name)
			continue
		}
		feeds = append(feeds, f)
	}
	var psl []string
	if set.PSL != nil {
		if psl, err = pslRows(set.PSL); err != nil {
			return res, err
		}
	}

	var manifest []string
	add := func(v any) { manifest = append(manifest, jsonLine(v)) }
	add(struct {
		Kind           string `json:"kind"`
		BuiltinLogFlag string `json:"builtinLogFlag"`
		Top1mEnabled   bool   `json:"top1mEnabled"`
	}{"config", set.BuiltinLogFlag, set.Top1mEnabled})
	type domainRow struct {
		Kind   string `json:"kind"`
		Domain string `json:"domain"`
	}
	for _, list := range []struct {
		kind   string
		values []string
	}{{"whitelist", set.Whitelist}, {"unlock", set.Unlock}, {"tld_exclusion", set.TLDExclusions}} {
		for _, v := range list.values {
			add(domainRow{list.kind, v})
		}
	}
	for _, v := range set.TLDBlacklist {
		add(struct {
			Kind string `json:"kind"`
			TLD  string `json:"tld"`
		}{"tld_blacklist", v})
	}

	type group struct {
		Name    string `json:"name"`
		Entries int    `json:"entries"`
	}
	groups := []group{}
	groupAt := map[string]int{}
	total := 0
	current := map[string]bool{ManifestID: true}
	for i, f := range feeds {
		id := FeedPrefix + f.Name
		reply, err := publishRows(store, id, f.Rows, res.Dropped)
		if err != nil {
			return res, err
		}
		current[id] = true
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
		}{"feed", i + 1, f.Name, f.Group, f.LogFlag, provenance, mode, f.Top1m, member(id, reply)})
		total += reply.Entries
		at, ok := groupAt[f.Group]
		if !ok {
			at, groupAt[f.Group] = len(groups), len(groups)
			groups = append(groups, group{Name: f.Group})
		}
		groups[at].Entries += reply.Entries
	}

	var safeSearch []string
	if set.SafeSearch != nil {
		last := map[string]SafeSearch{}
		for _, row := range set.SafeSearch {
			last[row.Host] = row
		}
		safeSearch = make([]string, 0, len(last))
		for _, row := range last {
			safeSearch = append(safeSearch, jsonLine(row))
		}
	}
	for _, m := range []struct {
		id   string
		rows []string
	}{{Top1mID, set.Top1m}, {SafeSearchID, safeSearch}, {PSLID, psl}} {
		if m.rows == nil {
			continue
		}
		reply, err := publishRows(store, m.id, m.rows, res.Dropped)
		if err != nil {
			return res, err
		}
		current[m.id] = true
		add(struct {
			Kind string `json:"kind"`
			memberRow
		}{"member", member(m.id, reply)})
	}

	if res.Generation, err = store.Publish(ManifestID, manifest, map[string]any{"groups": groups, "feeds": len(feeds), "entries": total}); err != nil {
		return res, err
	}
	for _, id := range previous {
		if !current[id] {
			if err := store.Remove(id); err != nil && !errors.Is(err, resources.ErrNotFound) {
				return res, err
			}
		}
	}
	return res, nil
}

// memberRow names the body a manifest row belongs with.
type memberRow struct {
	Resource   string `json:"resource"`
	Generation string `json:"generation"`
	Digest     string `json:"digest"`
	Entries    int    `json:"entries"`
}

func member(id string, r resources.Reply) memberRow {
	return memberRow{id, strconv.FormatUint(r.Generation, 10), r.Digest, r.Entries}
}

// publishRows publishes the rows the store can hold as id's body, counting the others in dropped, and describes it.
func publishRows(store *resources.Store, id string, rows []string, dropped map[string]int) (resources.Reply, error) {
	kept := rows[:0]
	for i := range rows {
		if _, err := resources.Canonical(rows[i : i+1]); err != nil {
			dropped[id]++
			continue
		}
		kept = append(kept, rows[i])
	}
	if _, err := store.Publish(id, kept, nil); err != nil {
		return resources.Reply{}, err
	}
	return store.Get(id, nil)
}

// manifestResources is every body the current dnsbl/manifest names, none when there is no manifest.
func manifestResources(store *resources.Store) ([]string, error) {
	reply, err := store.Get(ManifestID, nil)
	if errors.Is(err, resources.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	body, _, err := store.Body(ManifestID, reply.Generation, resources.PartMembers, 0)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var ids []string
	sc := bufio.NewScanner(body)
	sc.Buffer(nil, resources.MaxMemberLength+1)
	for sc.Scan() {
		var row struct{ Resource string }
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("%s: %w", ManifestID, err)
		}
		if row.Resource != "" {
			ids = append(ids, row.Resource)
		}
	}
	return ids, sc.Err()
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

// pslRows is the rules of the PSL text's ICANN and PRIVATE sections as rows. Blank and comment lines go; each of the
// four markers must stand once, in order, on a line of its own, and the text must be UTF-8 without NUL, as the decider
// requires of its authority file.
func pslRows(text []byte) ([]string, error) {
	if !utf8.Valid(text) || bytes.IndexByte(text, 0) >= 0 {
		return nil, errors.New("PSL text is not UTF-8 without NUL")
	}
	lines := strings.Split(string(text), "\n")
	at := [4]int{-1, -1, -1, -1}
	for i, line := range lines {
		for m, marker := range pslMarkers {
			if strings.TrimSpace(line) == marker {
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
			rule := strings.TrimSpace(line)
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
