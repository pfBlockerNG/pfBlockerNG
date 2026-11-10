// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the Public Suffix List section: PslRules ..
// _load_psl_authority (117-376), _selected_tld_roots (1336-1343), tld_wildcard_classify and _dnsbl_suffix_feed_policy
// (5174-5229) and _psl_normalize_query (7346-7368).
//
// IDNA is not Python's. label.encode("idna") and .decode("idna") are the IDNA2003 codec (RFC 3490: nameprep over
// Unicode 3.2 tables, no unassigned-code-point check, case folding and NFKC from Python's unicodedata); pslIdna is
// golang.org/x/net/idna's UTS #46 non-transitional processing over the Unicode version the Go toolchain ships (owner
// decision, #3779). Where the two answer differently the Go answer stands. pfb_unbound_psl_test.go pins the
// differences in pslIdnaDivergences; the #3779 handoff tabulates them over the shipped authority, the parity corpus
// names and an exhaustive code-point scan.
package decider

import (
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// pslIdna stands in for the idna codec: UTS #46 non-transitional mapping and validation with the bidi rule (what
// nameprep's bidi check approximates) and the 1..63 octet label gate RFC 3490 puts in ToASCII. It is the Lookup
// profile, not Registration: Python's codec maps (case folds, NFKC) and never refuses an input for not being
// canonical already, which is what Registration does. Lookup's two strictness defaults that nameprep does not have
// are switched off: STD3 ASCII rules (an underscore label must survive the lenient query path, and the strict path
// has its own charset check) and the hyphen rules (Python encodes "ab--ü" and "-ü"; browsers set CheckHyphens
// false too). Scanning every code point alone and as "a"+c+"b", this leaves the fewest differences from Python of the
// configurations tried (Lookup, Lookup without the hyphen rules, Transitional, Registration).
var pslIdna = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false), idna.CheckHyphens(false), idna.VerifyDNSLength(true))

// pslRules is the frozen, source-ordered rule set; its zero value is Python's PslRules(), the empty set.
type pslRules struct {
	icannExact, icannWildcard, icannException       []string
	privateExact, privateWildcard, privateException []string
	// cachedIndex is Python's _index: set by parsePslRules and shared by every copy of the value. A hand-built
	// pslRules has none and rebuilds the sets on each use.
	cachedIndex *atomic.Pointer[[2]pslSets]
}

// pslSets is the (exact, wildcard, exception) membership sets of one section view.
type pslSets struct{ exact, wildcard, exception map[string]struct{} }

// pslResolution is the public-suffix resolution of one normalized DNS name.
type pslResolution struct {
	icannSuffix, publicSuffix, registrableDomain string
	privateActive                                bool
}

const (
	PSL_ICANN_BEGIN   = "// ===BEGIN ICANN DOMAINS==="
	PSL_ICANN_END     = "// ===END ICANN DOMAINS==="
	PSL_PRIVATE_BEGIN = "// ===BEGIN PRIVATE DOMAINS==="
	PSL_PRIVATE_END   = "// ===END PRIVATE DOMAINS==="
	PSL_LABEL_CHARS   = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// index is the (ICANN-only, ICANN+PRIVATE) membership sets, built on first use and kept on the rules. Racing
// goroutines each build an equal value and the last store wins, as with Python's unlocked check-then-set.
func (r pslRules) index() (pslSets, pslSets) {
	if r.cachedIndex == nil {
		return pslBuildIndex(r)
	}
	idx := r.cachedIndex.Load()
	if idx == nil {
		icann, combined := pslBuildIndex(r)
		idx = &[2]pslSets{icann, combined}
		r.cachedIndex.Store(idx)
	}
	return idx[0], idx[1]
}

func pslIsASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// pslRefusedCategory is unicodedata.category(char) in {"Cc", "Cf", "Cn"}; Cn is the code points no category table
// holds.
func pslRefusedCategory(char rune) bool {
	return unicode.In(char, unicode.Cc, unicode.Cf) ||
		!unicode.In(char, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Co, unicode.Cs)
}

func pslNormalizeName(name string) (string, error) {
	labels := strings.Split(name, ".")
	// Python's str cannot hold invalid UTF-8 (a lone surrogate raises UnicodeEncodeError, a ValueError, at the
	// len(name.encode("utf-8")) below); a Go string can, and is refused the same way.
	if name == "" || slices.Contains(labels, "") || len(name) > 253 || !utf8.ValidString(name) {
		return "", &valueError{"invalid DNS name"}
	}
	normalized := make([]string, 0, len(labels))
	for _, label := range labels {
		if strings.ContainsAny(label, "*!") {
			return "", &valueError{"invalid DNS label"}
		}
		var encoded string
		if pslIsASCII(label) && !strings.HasPrefix(pysem.Lower(label), "xn--") {
			// Plain-ASCII fast path (the overwhelming hot-path case): the idna codec accepts any non-empty ASCII
			// label up to 63 octets, so the charset/length/hyphen checks below reproduce codec+checks exactly.
			encoded = pysem.Lower(label)
		} else {
			for _, char := range label {
				if pysem.IsSpace(char) || pslRefusedCategory(char) {
					return "", &valueError{"invalid DNS label"}
				}
			}
			var ascii string
			var err error
			if pslIsASCII(label) {
				// The codec passes ASCII through unmapped (an xn-- label is judged as given by the round trip below,
				// not re-encoded first) and only gates its length.
				if ascii = label; len(label) > 63 {
					err = &valueError{"label too long"}
				}
			} else {
				ascii, err = pslIdna.ToASCII(label)
			}
			if err == nil {
				encoded = pysem.Lower(ascii)
				if strings.HasPrefix(encoded, "xn--") {
					var unicodeLabel, canonical string
					if unicodeLabel, err = pslIdna.ToUnicode(encoded); err == nil {
						if canonical, err = pslIdna.ToASCII(unicodeLabel); err == nil && pysem.Lower(canonical) != encoded {
							err = &valueError{"non-canonical IDNA label"}
						}
					}
				}
			}
			if err != nil {
				return "", &valueError{"invalid IDNA label"}
			}
		}
		if encoded == "" || len(encoded) > 63 || encoded[0] == '-' || encoded[len(encoded)-1] == '-' || !pslLabelChars(encoded) {
			return "", &valueError{"invalid DNS label"}
		}
		normalized = append(normalized, encoded)
	}
	result := strings.Join(normalized, ".")
	if len(result) > 253 {
		return "", &valueError{"invalid DNS name"}
	}
	return result, nil
}

func pslLabelChars(encoded string) bool {
	for i := range len(encoded) {
		if strings.IndexByte(PSL_LABEL_CHARS, encoded[i]) < 0 {
			return false
		}
	}
	return true
}

// pslRuleToken is _psl_rule_token: the rule's kind ("exact", "wildcard" or "exception") and its normalized name.
func pslRuleToken(raw string) (string, string, error) {
	token := ""
	if stripped := pyStrip(raw); stripped != "" {
		token = pysem.SplitWhitespace(stripped, 1)[0]
	}
	if token == "" || strings.HasPrefix(token, "#") || strings.HasPrefix(token, "//") {
		return "", "", &valueError{"not a rule"}
	}
	kind := "exact"
	if strings.HasPrefix(token, "!") {
		kind, token = "exception", token[1:]
	} else if strings.HasPrefix(token, "*.") {
		kind, token = "wildcard", token[2:]
	} else if strings.ContainsAny(token, "*!") {
		return "", "", &valueError{"invalid PSL rule"}
	}
	if token == "" || strings.HasPrefix(token, ".") || strings.HasSuffix(token, ".") || strings.Contains(token, "..") {
		return "", "", &valueError{"invalid PSL rule"}
	}
	name, err := pslNormalizeName(token)
	return kind, name, err
}

func pslSection(lines []string) (exact, wildcard, exception []string, err error) {
	for _, line := range lines {
		stripped := pyStrip(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, "//") {
			continue
		}
		kind, token, err := pslRuleToken(stripped)
		if err != nil {
			return nil, nil, nil, err
		}
		switch kind {
		case "exact":
			exact = append(exact, token)
		case "wildcard":
			wildcard = append(wildcard, token)
		default:
			exception = append(exception, token)
		}
	}
	wildcardSet := pslSet(wildcard)
	for _, rule := range exception {
		_, parent, dotted := strings.Cut(rule, ".")
		if _, inFamily := wildcardSet[parent]; !dotted || !inFamily {
			return nil, nil, nil, &valueError{"PSL exception has no wildcard family"}
		}
	}
	return exact, wildcard, exception, nil
}

// parsePslRules parses the self-describing PSL authority, retaining source order.
func parsePslRules(text string) (pslRules, error) {
	lines := pslSplitlines(text)
	var positions []int
	for _, marker := range []string{PSL_ICANN_BEGIN, PSL_ICANN_END, PSL_PRIVATE_BEGIN, PSL_PRIVATE_END} {
		var found []int
		for index, line := range lines {
			if pyStrip(line) == marker {
				found = append(found, index)
			}
		}
		if len(found) != 1 {
			return pslRules{}, &valueError{"PSL authority markers missing or duplicated"}
		}
		positions = append(positions, found[0])
	}
	begin, end, privateBegin, privateEnd := positions[0], positions[1], positions[2], positions[3]
	if !(begin < end && end < privateBegin && privateBegin < privateEnd) {
		return pslRules{}, &valueError{"PSL authority markers out of order"}
	}
	rules := pslRules{cachedIndex: new(atomic.Pointer[[2]pslSets])}
	var err error
	if rules.icannExact, rules.icannWildcard, rules.icannException, err = pslSection(lines[begin+1 : end]); err != nil {
		return pslRules{}, err
	}
	if rules.privateExact, rules.privateWildcard, rules.privateException, err = pslSection(lines[privateBegin+1 : privateEnd]); err != nil {
		return pslRules{}, err
	}
	return rules, nil
}

// pslSplitlines is str.splitlines(): it breaks at \n, \r\n, \r, \v, \f, \x1c-\x1e, \x85, \u2028 and \u2029, and a
// trailing break does not open an empty last line.
func pslSplitlines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); {
		r, width := utf8.DecodeRuneInString(text[i:])
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		case '\r':
			if strings.HasPrefix(text[i+1:], "\n") {
				lines = append(lines, text[start:i])
				i, start = i+2, i+2
				continue
			}
		default:
			i += width
			continue
		}
		lines = append(lines, text[start:i])
		i, start = i+width, i+width
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

func pslSet(rules ...[]string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, list := range rules {
		for _, rule := range list {
			set[rule] = struct{}{}
		}
	}
	return set
}

// pslBuildIndex builds the (ICANN-only, ICANN+PRIVATE) (exact, wildcard, exception) sets, once per pslRules via
// pslRules.index(), so each resolution costs O(name labels) rather than a scan over the ~10k shipped rules.
func pslBuildIndex(rules pslRules) (pslSets, pslSets) {
	icann := pslSets{pslSet(rules.icannExact), pslSet(rules.icannWildcard), pslSet(rules.icannException)}
	combined := pslSets{
		pslSet(rules.icannExact, rules.privateExact),
		pslSet(rules.icannWildcard, rules.privateWildcard),
		pslSet(rules.icannException, rules.privateException),
	}
	return icann, combined
}

// pslPrevailing is the (ICANN-only, ICANN+PRIVATE) prevailing suffixes from ONE walk of labels (issue #3061). An
// exception rule beats an ordinary match at ANY depth, so its carve-out is tracked alongside the ordinary match.
func pslPrevailing(labels []string, icannSets, combinedSets pslSets) (string, string) {
	// Every dotted suffix of labels, longest first (tails[i] == labels[i:]), grown one label at a time from the right.
	tails := []string{labels[len(labels)-1]}
	for index := len(labels) - 2; index >= 0; index-- {
		tails = append(tails, labels[index]+"."+tails[len(tails)-1])
	}
	slices.Reverse(tails)
	count := len(tails)
	var icannSuffix, publicSuffix string
	var icannFound, publicFound, icannCarved, publicCarved bool
	for start, tail := range tails {
		if _, ok := combinedSets.exception[tail]; ok {
			// Exception output drops the rule's leftmost label. Longest-first makes the first hit the longest, so
			// later ones are ignored.
			carved := ""
			if start+1 < count {
				carved = tails[start+1]
			}
			if !publicCarved {
				publicSuffix, publicFound, publicCarved = carved, true, true
			}
			if _, inIcann := icannSets.exception[tail]; !icannCarved && inIcann {
				icannSuffix, icannFound, icannCarved = carved, true, true
			}
		}
		// Longest surviving suffix wins. A wildcard base at start yields the suffix labels[start-1:], one label longer
		// than an exact rule at start and the SAME string an exact rule at start-1 would yield -- so the longest-first
		// walk needs no cross-kind tie-breaking.
		if !icannFound {
			if _, wild := icannSets.wildcard[tail]; start > 0 && wild {
				icannSuffix, icannFound = tails[start-1], true
			} else if _, exact := icannSets.exact[tail]; exact {
				icannSuffix, icannFound = tail, true
			}
		}
		if !publicFound {
			if _, wild := combinedSets.wildcard[tail]; start > 0 && wild {
				publicSuffix, publicFound = tails[start-1], true
			} else if _, exact := combinedSets.exact[tail]; exact {
				publicSuffix, publicFound = tail, true
			}
		}
	}
	if !icannFound {
		icannSuffix = tails[count-1]
	}
	if !publicFound {
		publicSuffix = tails[count-1]
	}
	return icannSuffix, publicSuffix
}

// resolvePublicSuffix applies PSL prevailing-rule semantics for the ICANN and combined sections.
func resolvePublicSuffix(name string, rules pslRules) (pslResolution, error) {
	normalized, err := pslNormalizeName(name)
	if err != nil {
		return pslResolution{}, err
	}
	labels := strings.Split(normalized, ".")
	icannSets, combinedSets := rules.index()
	icannSuffix, publicSuffix := pslPrevailing(labels, icannSets, combinedSets)
	suffixLabels := strings.Split(publicSuffix, ".")
	registrable := ""
	if len(labels) > len(suffixLabels) {
		registrable = strings.Join(labels[len(labels)-len(suffixLabels)-1:], ".")
	}
	return pslResolution{
		icannSuffix:       icannSuffix,
		publicSuffix:      publicSuffix,
		registrableDomain: registrable,
		privateActive:     len(suffixLabels) > len(strings.Split(icannSuffix, ".")),
	}, nil
}

// loadPslAuthority loads one shipped PSL authority, or returns empty rules while disabled.
// shortcut: Python's OSError text ("[Errno 2] No such file or directory: 'p'") and UnicodeDecodeError text differ
// from Go's, and os.access(R_OK) is not called (open refuses an unreadable file the same way). The refusal is the
// same ValueError carrying the path; only the logged message differs.
func loadPslAuthority(path string, enabled bool) (pslRules, error) {
	if !enabled {
		return pslRules{}, nil
	}
	rules, err := func() (pslRules, error) {
		info, err := os.Stat(path)
		if err != nil {
			return pslRules{}, err
		}
		if !info.Mode().IsRegular() {
			return pslRules{}, &valueError{"authority is not a readable regular file"}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return pslRules{}, err
		}
		if !utf8.Valid(data) {
			return pslRules{}, &valueError{"'utf-8' codec can't decode the authority: invalid data"}
		}
		text := string(data)
		if strings.Contains(text, "\x00") {
			return pslRules{}, &valueError{"authority contains NUL"}
		}
		return parsePslRules(text)
	}()
	if err != nil {
		return pslRules{}, &valueError{"PSL authority '" + path + "': " + err.Error()}
	}
	return rules, nil
}

// selectedTldRoots freezes the configured TLD-Allow selections for one matcher snapshot.
func selectedTldRoots(values []string) []string {
	var roots []string
	for _, value := range values {
		root := pysem.Lower(strings.Trim(pyStrip(value), "."))
		if root != "" && !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
	}
	return roots
}

// tldWildcardClassify returns (DNSBL_CLASS_ZONE, registrable-domain) or exact DATA. blacklist is already dot-stripped
// TLD roots -- the contract exclusion also carries -- normalized ONCE by build() at the config boundary (#3050).
func tldWildcardClassify(domain string, rules pslRules, exclusion map[string]struct{}, includePrivate bool, blacklist map[string]struct{}) (string, string) {
	if len(rules.icannExact)+len(rules.icannWildcard)+len(rules.icannException)+
		len(rules.privateExact)+len(rules.privateWildcard)+len(rules.privateException) == 0 {
		return DNSBL_CLASS_DATA, domain
	}
	resolution, err := resolvePublicSuffix(domain, rules)
	if err != nil {
		return DNSBL_CLASS_DATA, domain
	}
	suffix := resolution.icannSuffix
	if includePrivate {
		suffix = resolution.publicSuffix
	}
	root := suffix[strings.LastIndex(suffix, ".")+1:]
	_, suffixBlacklisted := blacklist[suffix]
	_, rootBlacklisted := blacklist[root]
	_, suffixExcluded := exclusion[suffix]
	_, rootExcluded := exclusion[root]
	_, domainExcluded := exclusion[domain]
	if suffixBlacklisted || rootBlacklisted || suffixExcluded || rootExcluded || domainExcluded {
		return DNSBL_CLASS_DATA, domain
	}
	labels := strings.Split(domain, ".")
	suffixLabels := strings.Split(suffix, ".")
	registrable := ""
	if len(labels) > len(suffixLabels) {
		registrable = strings.Join(labels[len(labels)-len(suffixLabels)-1:], ".")
	}
	if domain == suffix || registrable == "" {
		return DNSBL_CLASS_DATA, domain
	}
	if domain == registrable {
		return DNSBL_CLASS_ZONE, domain
	}
	return DNSBL_CLASS_DATA, domain
}

// dnsblSuffixFeedPolicy is issue #2371's feed-at-suffix policy governing name, or nil when name is not exactly its own
// winning public suffix (normal handling). The section is PRIVATE iff the winning rule's privateActive is true, else
// ICANN.
func dnsblSuffixFeedPolicy(name string, rules pslRules, privatePolicy, icannPolicy string) *string {
	resolution, err := resolvePublicSuffix(name, rules)
	if err != nil || name != resolution.publicSuffix {
		return nil
	}
	if resolution.privateActive {
		return &privatePolicy
	}
	return &icannPolicy
}

// pslNormalizeQuery is the lenient label normalization for LIVE QUERY names (the TLD-Allow check). Rules are strictly
// validated at parse time; queries are whatever the resolver was actually asked -- underscore service labels
// (_dmarc.*, _sip._tcp.*, _acme-challenge.*) are legitimate DNS names whose suffix must still be judged. A label the
// codec refuses stays lowercased raw and simply never matches a (strictly validated) rule label. Only structural
// emptiness is an error.
func pslNormalizeQuery(name string) ([]string, error) {
	labels := strings.Split(name, ".")
	if name == "" || slices.Contains(labels, "") {
		return nil, &valueError{"invalid DNS name"}
	}
	normalized := make([]string, 0, len(labels))
	for _, label := range labels {
		if pslIsASCII(label) {
			normalized = append(normalized, pysem.Lower(label))
		} else if ascii, err := pslIdna.ToASCII(label); err == nil {
			normalized = append(normalized, pysem.Lower(ascii))
		} else {
			normalized = append(normalized, pysem.Lower(label))
		}
	}
	return normalized, nil
}
