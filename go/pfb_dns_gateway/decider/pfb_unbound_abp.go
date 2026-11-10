// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py lines 4425-4457 (entry kinds, rule targets and
// provenances, the label alphabet), 4460-4522 (Rule, ParsedEntry), 4680-4720 (_dnsbl_is_ipv4,
// _dnsbl_is_numeric_host), 4725-5100 (the ABP option and regex classifiers, _dnsbl_is_abp_rule_line, parse_abp,
// _dnsbl_strip_hosts_prefix, parse), 5104-5171 (_tally_reject, the wire caps, _normalise_verdict, normalise),
// 5250-5514 (the regex reduction, the band, the Stage-B rule types and reconcile) and 5517-5562
// (_dnsbl_normalise_whitelist).
//
// Python's parse() is parseEntry: pfb_dns_proxy_test.go already holds the name parse. Python's None is nil for a
// pointer, ok == false for a (value, ok) pair, and "" for normaliseVerdict's domain and bucket (an accepted domain is
// never empty, and a reject always has a bucket). Python's keyword defaults (provenance=feed, feed="", group="",
// log="", tally=None) are passed explicitly. _DNSBL_DNS_RELEVANT_OPTS is not translated: nothing reads it.
//
// Python indexes a str by character and Go a string by byte. Every slice below cuts at an ASCII marker or counts with
// utf8.RuneCountInString, so the two agree.
package decider

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const (
	DNSBL_KIND_BLOCK = "block"
	DNSBL_KIND_ALLOW = "allow"
	DNSBL_KIND_REGEX = "regex"
)

const (
	DNSBL_CLASS_DATA = "data" // exact match (loaded into dataDB)
	DNSBL_CLASS_ZONE = "zone" // wildcard-incl-self match (loaded into zoneDB)
)

const (
	RULE_TARGET_DOMAIN = "domain"
	RULE_TARGET_REGEX  = "regex"
)

const (
	RULE_PROV_USER = "user"
	RULE_PROV_FEED = "feed"
)

// DNSBL_LABEL_CHARS is the lower-cased label alphabet of the domain-shape gate (#723: underscore is deliberate).
const DNSBL_LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_"

// ruleSignature is Python's (key_or_pattern, tuple(sorted DNS options)). Go cannot compare a tuple holding a slice, so
// dnsOpts is the option names joined by ",": only "important" can occur in it, so the join is injective.
type ruleSignature struct {
	keyOrPattern string
	dnsOpts      string
}

type rule struct {
	kind         string
	target       string
	keyOrPattern string
	important    bool
	badfilter    bool
	provenance   string
	feed         string
	group        string
	log          string
	signature    ruleSignature
	wildcard     bool
}

type parsedEntry struct {
	kind  string
	value string
	feed  string
	group string
	log   string
}

func dnsblIsIpv4(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		// the ASCII-decimal test and the length cap come first: Python's int() must never see anything else (#1071)
		if !pysem.IsASCIIDigits(p) || len(p) > 3 {
			return false
		}
		if n, _ := strconv.Atoi(p); n > 255 || len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	return true
}

func dnsblIsNumericHost(token string) bool {
	if strings.Contains(token, ":") {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if pysem.IsASCIIDigits(last) {
		return true
	}
	if len(last) < 2 || pysem.Lower(last[:2]) != "0x" {
		return false
	}
	for i := 2; i < len(last); i++ {
		if strings.IndexByte("0123456789abcdefABCDEF", last[i]) < 0 {
			return false
		}
	}
	return true
}

// DNSBL_PAGE_CONTEXT_OPTS and DNSBL_NON_DNS_MODIFIERS are Python frozensets.
var DNSBL_PAGE_CONTEXT_OPTS = []string{
	"third-party",
	"~third-party",
	"domain",
	"script",
	"image",
	"stylesheet",
	"object",
	"subdocument",
	"document",
	"xmlhttprequest",
	"websocket",
	"ping",
	"media",
	"font",
	"popup",
	"csp",
	"elemhide",
	"generichide",
	"genericblock",
	"rewrite",
}

var DNSBL_NON_DNS_MODIFIERS = []string{"dnsrewrite", "dnstype", "client", "ctag"}

func dnsblOptName(opt string) string {
	name, _, _ := strings.Cut(opt, "=")
	return strings.TrimFunc(name, pysem.IsSpace)
}

// dnsblClassifyOptions returns ok == false where Python returns None.
func dnsblClassifyOptions(optsStr string) (dnsOpts []string, important, badfilter, ok bool) {
	var kept []string
	for _, raw := range strings.Split(optsStr, ",") {
		raw = strings.TrimFunc(raw, pysem.IsSpace)
		if raw == "" {
			continue
		}
		name := dnsblOptName(raw)
		if slices.Contains(DNSBL_PAGE_CONTEXT_OPTS, name) || slices.Contains(DNSBL_NON_DNS_MODIFIERS, name) {
			return nil, false, false, false
		}
		if name == "important" {
			important = true
			kept = append(kept, name)
			continue
		}
		if name == "badfilter" {
			badfilter = true
			continue // excluded from the signature by design
		}
		return nil, false, false, false
	}
	slices.Sort(kept)
	return kept, important, badfilter, true
}

var DNSBL_ELEMENT_HIDING_MARKERS = []string{"##", "#@#", "#?#", "#%#", "#$#"}

func dnsblParseAbpRegex(stripped string) (kind, inner, optsStr string, ok bool) {
	var body string
	if strings.HasPrefix(stripped, "@@/") {
		kind, body = DNSBL_KIND_ALLOW, stripped[2:]
	} else if strings.HasPrefix(stripped, "/") {
		kind, body = DNSBL_KIND_BLOCK, stripped
	} else {
		return "", "", "", false
	}
	if strings.HasSuffix(body, "/") {
		if len(body) < 2 { // body == "/": Python's body[1:-1] is empty
			return "", "", "", false
		}
		inner, optsStr = body[1:len(body)-1], ""
	} else {
		marker := strings.LastIndex(body, "/$")
		if marker <= 0 {
			return "", "", "", false
		}
		inner, optsStr = body[1:marker], body[marker+2:]
	}
	if inner == "" {
		return "", "", "", false
	}
	return kind, inner, optsStr, true
}

const DNSBL_ABP_COSMETIC_PREFIX_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._,~*-"

func dnsblIsAbpRuleLine(line string) bool {
	if strings.HasPrefix(line, ",") {
		return false
	}
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") {
		return true
	}
	if strings.Contains(line, "#") {
		first, markerLen := -1, 0
		for _, m := range DNSBL_ELEMENT_HIDING_MARKERS {
			if p := strings.Index(line, m); p != -1 && (first == -1 || p < first || p == first && len(m) < markerLen) {
				first, markerLen = p, len(m)
			}
		}
		if first != -1 {
			if first == 0 {
				if markerLen < len(line) {
					if after, _ := utf8.DecodeRuneInString(line[markerLen:]); !pysem.IsSpace(after) {
						return true
					}
				}
			} else if !strings.ContainsFunc(line[:first], func(c rune) bool { return strings.IndexRune(DNSBL_ABP_COSMETIC_PREFIX_CHARS, c) < 0 }) {
				return true
			}
		}
	}
	if strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "//") {
		if strings.HasSuffix(line, "/") && len(line) > 1 {
			return true
		}
		marker := strings.LastIndex(line, "/$")
		return marker != -1 && marker > 0
	}
	return false
}

func parseAbp(line, provenance, feed, group, log string, tally rejectTally) *rule {
	s := strings.TrimFunc(line, pysem.IsSpace)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "!") || strings.HasPrefix(s, "[") {
		return nil
	}
	if strings.HasPrefix(s, "#") {
		return nil
	}
	if strings.Contains(s, "#") && slices.ContainsFunc(DNSBL_ELEMENT_HIDING_MARKERS, func(marker string) bool { return strings.Contains(s, marker) }) {
		return nil
	}

	if kind, inner, optsStr, ok := dnsblParseAbpRegex(s); ok {
		var dnsOpts []string
		var important, badfilter bool
		if optsStr != "" {
			dnsOpts, important, badfilter, ok = dnsblClassifyOptions(optsStr)
			if !ok {
				return nil
			}
		}
		return &rule{
			kind:         kind,
			target:       RULE_TARGET_REGEX,
			keyOrPattern: inner,
			important:    important,
			badfilter:    badfilter,
			provenance:   provenance,
			feed:         feed,
			group:        group,
			log:          log,
			signature:    ruleSignature{inner, strings.Join(dnsOpts, ",")},
			wildcard:     false,
		}
	}

	isAllow := strings.HasPrefix(s, "@@||")
	isBlock := strings.HasPrefix(s, "||")
	if isAllow || isBlock {
		rest := s[2:]
		if isAllow {
			rest = s[4:]
		}
		anchor, optsStr, _ := strings.Cut(rest, "$")
		host, tail, _ := strings.Cut(anchor, "^")
		if strings.Contains(host, "/") || strings.Contains(host, "*") || strings.Contains(tail, "/") || strings.Trim(tail, "^") != "" {
			return nil
		}
		if dnsblIsNumericHost(host) {
			return nil
		}
		dom, bucket := normaliseVerdict(host, false)
		if dom == "" {
			if tally != nil && bucket != "" {
				tallyReject(tally, feed, group, bucket)
			}
			return nil
		}
		var dnsOpts []string
		var important, badfilter bool
		if optsStr != "" {
			var ok bool
			dnsOpts, important, badfilter, ok = dnsblClassifyOptions(optsStr)
			if !ok {
				return nil
			}
		}
		kind := DNSBL_KIND_BLOCK
		if isAllow {
			kind = DNSBL_KIND_ALLOW
		}
		return &rule{
			kind:         kind,
			target:       RULE_TARGET_DOMAIN,
			keyOrPattern: dom,
			important:    important,
			badfilter:    badfilter,
			provenance:   provenance,
			feed:         feed,
			group:        group,
			log:          log,
			signature:    ruleSignature{dom, strings.Join(dnsOpts, ",")},
			wildcard:     true, // ||domain^ / @@||domain^ cover the domain + subdomains
		}
	}

	parts := pysem.SplitWhitespace(s, 1)
	if len(parts) == 2 {
		first, target := parts[0], strings.TrimFunc(parts[1], pysem.IsSpace)
		if !dnsblIsIpv4(first) {
			return nil // not a hosts line (a real ABP line never has a bare space)
		}
		if dnsblIsNumericHost(target) {
			return nil // "<ip> <ip>" -> firewall path
		}
		dom, bucket := normaliseVerdict(target, false)
		if dom == "" {
			if tally != nil && bucket != "" {
				tallyReject(tally, feed, group, bucket)
			}
			return nil
		}
		return &rule{
			kind:         DNSBL_KIND_BLOCK,
			target:       RULE_TARGET_DOMAIN,
			keyOrPattern: dom,
			important:    false,
			badfilter:    false,
			provenance:   provenance,
			feed:         feed,
			group:        group,
			log:          log,
			signature:    ruleSignature{dom, ""},
			wildcard:     true, // plain/hosts cover the domain + subdomains (reference oracle)
		}
	}

	if strings.Contains(s, "/") || strings.Contains(s, "*") {
		return nil
	}
	dom, bucket := normaliseVerdict(s, false)
	if dom == "" {
		if tally != nil && bucket != "" {
			tallyReject(tally, feed, group, bucket)
		}
		return nil
	}
	return &rule{
		kind:         DNSBL_KIND_BLOCK,
		target:       RULE_TARGET_DOMAIN,
		keyOrPattern: dom,
		important:    false,
		badfilter:    false,
		provenance:   provenance,
		feed:         feed,
		group:        group,
		log:          log,
		signature:    ruleSignature{dom, ""},
		wildcard:     true,
	}
}

func dnsblStripHostsPrefix(line string) string {
	if first, rest, found := strings.Cut(line, " "); found {
		rest = strings.TrimFunc(rest, pysem.IsSpace)
		if dnsblIsIpv4(first) {
			return rest
		}
		return first
	}
	return line
}

func parseEntry(line string) *parsedEntry {
	stripped := strings.TrimFunc(line, pysem.IsSpace)
	if stripped == "" {
		return nil
	}

	if strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, "!") {
		return nil
	}
	token := dnsblStripHostsPrefix(stripped)
	token = strings.Trim(strings.TrimFunc(token, pysem.IsSpace), ".")
	if token == "" {
		return nil
	}
	// Bare IP -> firewall path (PHP); skipped from the domain build.
	if dnsblIsIpv4(token) {
		return nil
	}
	return &parsedEntry{kind: DNSBL_KIND_BLOCK, value: token, feed: "", group: "", log: ""}
}

func tallyReject(tally rejectTally, feed, group, bucket string) {
	key := [2]string{feed, group}
	counts, ok := tally[key]
	if !ok {
		counts = map[string]int{"shape": 0, "wire_cap": 0}
		tally[key] = counts
	}
	counts[bucket]++
}

// dnsblWithinWireCaps counts characters as Python's len() does: it runs before the charset check, so a non-ASCII
// label must count the same here for its reject to land in the same bucket.
func dnsblWithinWireCaps(host string) bool {
	if utf8.RuneCountInString(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if utf8.RuneCountInString(label) > 63 {
			return false
		}
	}
	return true
}

func normaliseVerdict(value string, singleLabelOk bool) (domain, bucket string) {
	host := pysem.Lower(strings.Trim(strings.TrimFunc(value, pysem.IsSpace), "."))
	if !strings.Contains(host, ".") && !singleLabelOk || dnsblIsNumericHost(host) && !dnsblIsIpv4(host) {
		// A numeric last label makes clients parse the name as an IPv4 literal. Canonical quads
		// stay accepted here: parseEntry owns the bare-IP skip.
		return "", "shape"
	}
	if !dnsblWithinWireCaps(host) {
		return "", "wire_cap"
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "shape"
		}
		for i := range len(label) {
			if strings.IndexByte(DNSBL_LABEL_CHARS, label[i]) < 0 {
				return "", "shape"
			}
		}
	}
	return host, ""
}

func normalise(value string) (string, bool) {
	domain, _ := normaliseVerdict(value, false)
	return domain, domain != ""
}

// DNSBL_RX_DOMAIN_LITERAL is Python's re.compile(r"^[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+$"). Python's "$" also
// matches just before a trailing newline, which RE2's does not: the optional \n and \z spell it out.
var DNSBL_RX_DOMAIN_LITERAL = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+\n?\z`)

var DNSBL_RX_WILDCARD_PREFIXES = []string{`^(.+\.)?`, `(^|\.)`, `^(?:.+\.)?`}

var DNSBL_RX_EXACT_PREFIXES = []string{`^`}

const DNSBL_RX_WWW_OPT = `(www\.)?`

func dnsblReduceRegex(inner string) (wildcard bool, domain string, ok bool) {
	if !strings.HasSuffix(inner, "$") {
		return false, "", false
	}
	body := inner[:len(inner)-1]
	for _, pre := range DNSBL_RX_WILDCARD_PREFIXES {
		if strings.HasPrefix(body, pre) {
			lit := body[len(pre):]
			if DNSBL_RX_DOMAIN_LITERAL.MatchString(lit) {
				return true, pysem.Lower(strings.ReplaceAll(lit, `\.`, ".")), true
			}
			return false, "", false
		}
	}
	for _, pre := range DNSBL_RX_EXACT_PREFIXES {
		if strings.HasPrefix(body, pre) {
			lit := body[len(pre):]
			if len(lit) >= len(DNSBL_RX_WWW_OPT) && pysem.Lower(lit[:len(DNSBL_RX_WWW_OPT)]) == DNSBL_RX_WWW_OPT {
				lit = lit[len(DNSBL_RX_WWW_OPT):]
			}
			if DNSBL_RX_DOMAIN_LITERAL.MatchString(lit) {
				return false, pysem.Lower(strings.ReplaceAll(lit, `\.`, ".")), true
			}
			return false, "", false
		}
	}
	return false, "", false
}

func dnsblRuleBand(r rule) int {
	user := r.provenance == RULE_PROV_USER
	if r.kind == DNSBL_KIND_ALLOW {
		return allowPriority(r.important, user)
	}
	return blockPriority(r.important, user)
}

type blockDomainRule struct {
	cls        string
	key        string
	band       int
	important  bool
	provenance string
	feed       string
	group      string
	log        string
}

type allowDomainRule struct {
	domain     string
	wildcard   bool
	band       int
	important  bool
	provenance string
}

type regexRule struct {
	pattern    string
	kind       string
	band       int
	important  bool
	provenance string
	feed       string
	group      string
	log        string
}

type reconcileResult struct {
	blockDomains          []blockDomainRule
	allowDomains          []allowDomainRule
	blockRegexIrreducible []regexRule
	allowRegexIrreducible []regexRule
	importantRules        bool
	pruned                int
	reduced               int
	skippedBadfilter      int
}

// reconcile never reads tlds (Python keeps it for signature stability) and mutates no argument.
func reconcile(rules []rule, tlds map[string]map[string]string, exclusion map[string]struct{}, tally rejectTally) reconcileResult {
	// --- Step 1: feed-only $badfilter prune
	badSigs := map[ruleSignature]struct{}{}
	for _, r := range rules {
		if r.badfilter && r.provenance == RULE_PROV_FEED {
			badSigs[r.signature] = struct{}{}
		}
	}
	var result reconcileResult
	var survivors []rule
	for _, r := range rules {
		if r.badfilter {
			result.skippedBadfilter++
			continue // the $badfilter rule itself never emits a decision
		}
		if _, pruned := badSigs[r.signature]; r.provenance == RULE_PROV_FEED && pruned {
			result.pruned++
			continue // pruned by a feed $badfilter (USER rules are never here)
		}
		survivors = append(survivors, r)
	}

	// --- Steps 2-4: reduce, classify, band
	for _, r := range survivors {
		// A surviving rule engages the numeric 6-band branch (vs today's fast path)
		// whenever it is $important, or a feed ALLOW (@@), or a feed regex.
		if r.important || r.provenance == RULE_PROV_FEED && r.kind == DNSBL_KIND_ALLOW {
			result.importantRules = true
		}

		var wildcard bool
		var domain string
		switch r.target {
		case RULE_TARGET_REGEX:
			var reduced bool
			wildcard, domain, reduced = dnsblReduceRegex(r.keyOrPattern)
			if !reduced {
				// Irreducible -> hand the RAW pattern through as a compile candidate.
				if r.provenance == RULE_PROV_FEED {
					result.importantRules = true // any feed regex engages numeric path
				}
				rr := regexRule{
					pattern:    r.keyOrPattern,
					kind:       r.kind,
					band:       dnsblRuleBand(r),
					important:  r.important,
					provenance: r.provenance,
					feed:       r.feed,
					group:      r.group,
					log:        r.log,
				}
				if r.kind == DNSBL_KIND_ALLOW {
					result.allowRegexIrreducible = append(result.allowRegexIrreducible, rr)
				} else {
					result.blockRegexIrreducible = append(result.blockRegexIrreducible, rr)
				}
				continue
			}
			// #753: the folded literal is an exact/wildcard match KEY -- an over-cap key can never match a
			// queryable qname, so drop the rule outright.
			if !dnsblWithinWireCaps(domain) {
				if tally != nil {
					tallyReject(tally, r.feed, r.group, "wire_cap")
				}
				continue
			}
			result.reduced++
		case RULE_TARGET_DOMAIN:
			wildcard, domain = r.wildcard, r.keyOrPattern
		default: // defensive; parseAbp only emits domain/regex
			continue
		}

		band := dnsblRuleBand(r)
		if r.kind == DNSBL_KIND_ALLOW {
			result.allowDomains = append(result.allowDomains, allowDomainRule{
				domain:     domain,
				wildcard:   wildcard,
				band:       band,
				important:  r.important,
				provenance: r.provenance,
			})
		} else {
			// ||host^ (and a wildcard-shaped regex fold) emits a ZONE keyed at the anchor at any depth (#718); a TLD
			// exclusion still opts a domain out of wildcarding, and a wildcard=False fold stays DATA.
			cls := DNSBL_CLASS_DATA
			if _, excluded := exclusion[domain]; wildcard && !excluded {
				cls = DNSBL_CLASS_ZONE
			}
			result.blockDomains = append(result.blockDomains, blockDomainRule{
				cls:        cls,
				key:        domain,
				band:       band,
				important:  r.important,
				provenance: r.provenance,
				feed:       r.feed,
				group:      r.group,
				log:        r.log,
			})
		}
	}

	return result
}

// dnsblNormaliseWhitelist returns an unordered map where Python returns an insertion-ordered dict.
func dnsblNormaliseWhitelist(userWhitelist []string, tally rejectTally, source string) map[string]whiteEntry {
	whiteDB := map[string]whiteEntry{}
	for _, raw := range userWhitelist {
		line := strings.TrimFunc(raw, pysem.IsSpace)
		if line == "" {
			continue
		}
		body, wwwStripped := line, false
		if len(line) >= 4 && pysem.Lower(line[:4]) == "www." {
			body, wwwStripped = line[4:], true
		}
		domain, bucket := normaliseVerdict(body, strings.HasPrefix(body, "."))
		if domain == "" && wwwStripped {
			// `www.com`: the remainder is one label but the whole name is valid; the query-time
			// lookup matches it exactly. `line` starts with "www." here, so it is never a wildcard.
			body = line
			domain, bucket = normaliseVerdict(line, false)
		}
		if domain == "" {
			if tally != nil && bucket != "" {
				tallyReject(tally, source, "DNSBL", bucket)
			}
			continue
		}
		wildcard := strings.HasPrefix(body, ".")
		newEntry := whiteEntry{wildcard: wildcard, important: true, band: PRIO_USER_ALLOW, hasBand: true}
		// issue #3191: colliding `.apex` / `www.apex` / bare apex widen, never last-wins demote.
		if existing, found := whiteDB[domain]; found {
			whiteDB[domain] = whiteWidenEntry(existing, newEntry)
		} else {
			whiteDB[domain] = newEntry
		}
	}
	return whiteDB
}
