// Tests of pfb_unbound_abp.go. Ported from tests/test_adr07_parser.py, tests/test_adr07_reconcile.py,
// tests/test_adr06_build_module.py (TestParse, TestNormalise, TestNormaliseVerdictBucket and the normalisation half of
// TestWhitelistNormalisation), tests/test_dnsbl_numeric_host_skip.py, tests/test_issue3056_label_charset.py (the
// normalise rows), tests/test_adr21_abp_per_line.py (its capture-guard rows) and, where they pin a translated
// function, tests/test_adr62_parity_oracle.py, tests/test_ipv4_numeric_host.py,
// tests/test_issue1071_dnsbl_is_ipv4_unicode.py and tests/test_branch_coverage_gaps.py.
//
// testdata/pfb_unbound_abp_oracle.json holds what pfb_unbound.py (CPython 3.11) returned for the inputs below, each
// row recorded by calling the Python function itself:
//   - lines: every string of the abp-*.json and regex-*.json parity fixtures, every line of the adr07 corpus
//     (tests/fixtures/adr07_corpus) and a set of hostile lines (Unicode whitespace, non-ASCII labels, U+0130 and the
//     Kelvin sign, 63/64-character labels, option and marker edge cases), plus each parsing line padded with U+00A0
//     and U+2003: the _dnsbl_* line helpers, parse_abp (with a tally), parse, _normalise_verdict and the one-entry
//     whitelist;
//   - reduce: the inner pattern of every regex line above, the user regex_list of regex-user-sources.json, and
//     variants (upper case, a newline before the "$") for each reducible one;
//   - reconcile: parse_abp over every abp-*/regex-* fixture file (feed and user provenance as its manifest row says),
//     the corpus and a cross-provenance stream, each with and without a TLD exclusion set;
//   - whitelist, ip, decide, corpus_probes, spike: the remaining tables named by the tests that read them.

package decider

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// ---------------------------------------------------------------------------------------------------------------
// helpers

func abpParse(line string) *rule { return parseAbp(line, RULE_PROV_FEED, "", "", "", nil) }

func wantDomainRule(kind, key string, important, badfilter bool) rule {
	opts := ""
	if important {
		opts = "important"
	}
	return rule{kind: kind, target: RULE_TARGET_DOMAIN, keyOrPattern: key, important: important, badfilter: badfilter,
		provenance: RULE_PROV_FEED, signature: ruleSignature{key, opts}, wildcard: true}
}

func wantRegexRule(kind, pattern string, important, badfilter bool) rule {
	opts := ""
	if important {
		opts = "important"
	}
	return rule{kind: kind, target: RULE_TARGET_REGEX, keyOrPattern: pattern, important: important, badfilter: badfilter,
		provenance: RULE_PROV_FEED, signature: ruleSignature{pattern, opts}}
}

func expectRule(t *testing.T, line string, want rule) {
	t.Helper()
	got := abpParse(line)
	if got == nil || *got != want {
		t.Errorf("parseAbp(%s):\n got  %+v\n want %+v", pysem.Repr(line), got, want)
	}
}

func expectSkipped(t *testing.T, line string) {
	t.Helper()
	if got := abpParse(line); got != nil {
		t.Errorf("parseAbp(%s) = %+v, want nil (skipped)", pysem.Repr(line), *got)
	}
}

func abpRules(lines []string, provenance string) []rule {
	var out []rule
	for _, line := range lines {
		if r := parseAbp(line, provenance, "", "", "", nil); r != nil {
			out = append(out, *r)
		}
	}
	return out
}

// tests/test_adr07_reconcile.py _TLDS / _EXCLUSION: the TLD table reconcile takes and never reads.
var (
	abpTlds = map[string]map[string]string{
		"com": {"com": ""}, "net": {"net": ""}, "org": {"org": ""}, "example": {"example": ""}, "io": {"io": ""},
	}
	abpNoExclusion = map[string]struct{}{}
)

func abpReconcile(lines []string, provenance string, tally rejectTally) reconcileResult {
	return reconcile(abpRules(lines, provenance), abpTlds, abpNoExclusion, tally)
}

func onlyBlock(t *testing.T, res reconcileResult) blockDomainRule {
	t.Helper()
	if len(res.blockDomains) != 1 {
		t.Fatalf("want exactly one block domain, got %+v", res.blockDomains)
	}
	return res.blockDomains[0]
}

// abpResolve is test_adr07_reconcile.py _resolve: the spec's {block, resolve, pass} label from the same 6-band rule
// decide() uses. The irreducible patterns are matched with RE2 (?i), as Python matches them with re.IGNORECASE.
func abpResolve(t *testing.T, result reconcileResult, query string) string {
	t.Helper()
	q := strings.ToLower(strings.Trim(query, "."))
	bp, ap := 0, 0
	matched := false
	domMatch := func(domain string, wildcard bool) bool {
		return q == domain || wildcard && strings.HasSuffix(q, "."+domain)
	}
	for _, b := range result.blockDomains {
		if domMatch(b.key, b.cls == DNSBL_CLASS_ZONE) {
			matched = true
			bp = max(bp, b.band)
		}
	}
	for _, a := range result.allowDomains {
		if domMatch(a.domain, a.wildcard) {
			matched = true
			ap = max(ap, a.band)
		}
	}
	search := func(rules []regexRule) (best int) {
		for _, rr := range rules {
			re, err := regexp.Compile("(?i)" + rr.pattern)
			if err != nil {
				t.Fatalf("pattern %q does not compile as RE2: %v", rr.pattern, err)
			}
			if re.MatchString(q) {
				matched = true
				best = max(best, rr.band)
			}
		}
		return best
	}
	bp = max(bp, search(result.blockRegexIrreducible))
	ap = max(ap, search(result.allowRegexIrreducible))
	if !matched {
		return "pass"
	}
	if bp > ap {
		return "block"
	}
	return "resolve"
}

func adr07CorpusDir() string {
	return filepath.Join(paritycorpus.Fixtures(), "..", "..", "..", "fixtures", "adr07_corpus")
}

// readCorpusLines is Python's fh.read().splitlines() over the corpus file (no corpus line holds another separator).
func readCorpusLines(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(adr07CorpusDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// patternLines is the _reducible_lines()/_irreducible_lines() filter: stripped, non-empty, not a "!" comment.
func patternLines(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	for _, ln := range readCorpusLines(t, name) {
		if ln = strings.TrimFunc(ln, pysem.IsSpace); ln != "" && !strings.HasPrefix(ln, "!") {
			out = append(out, ln)
		}
	}
	return out
}

func corpusLines(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, name := range []string{"abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"} {
		out = append(out, readCorpusLines(t, name)...)
	}
	return out
}

func derefOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_adr07_parser.py

func TestParseAbpBlockDomain(t *testing.T) {
	// TestBlockDomain: test_pipe_anchor .. test_plain_leading_dot_stripped
	for _, c := range []struct{ line, key string }{
		{"||ads.example.com^", "ads.example.com"},
		{"||no-sep.example", "no-sep.example"},
		{"||ADS.Example.COM^", "ads.example.com"},
		{"0.0.0.0 tracker.host.example", "tracker.host.example"},
		{"127.0.0.1 metrics.host.example", "metrics.host.example"},
		{"0.0.0.0\ttab.host.example", "tab.host.example"},
		{"plain.bad.example", "plain.bad.example"},
		{".wildcardish.org", "wildcardish.org"},
	} {
		expectRule(t, c.line, wantDomainRule(DNSBL_KIND_BLOCK, c.key, false, false))
	}
	expectSkipped(t, "0.0.0.0\t203.0.113.9") // "<ip>\t<ip>" still routes to the firewall path
}

func TestParseAbpAllowDomain(t *testing.T) {
	expectRule(t, "@@||cdn.example.com^", wantDomainRule(DNSBL_KIND_ALLOW, "cdn.example.com", false, false))
	expectRule(t, "@@||cdn.example.com^$important", wantDomainRule(DNSBL_KIND_ALLOW, "cdn.example.com", true, false))
}

func TestParseAbpRegex(t *testing.T) {
	for _, c := range []struct {
		line string
		want rule
	}{
		{`/ad[0-9]\.example\.com$/`, wantRegexRule(DNSBL_KIND_BLOCK, `ad[0-9]\.example\.com$`, false, false)},
		{`@@/whitelist-[a-z]+\.example$/`, wantRegexRule(DNSBL_KIND_ALLOW, `whitelist-[a-z]+\.example$`, false, false)},
		// a reducible regex stays a regex target at Stage A, and a broken one is accepted raw
		{`/^(.+\.)?doubleclick\.net$/`, wantRegexRule(DNSBL_KIND_BLOCK, `^(.+\.)?doubleclick\.net$`, false, false)},
		{`/ad(unbalanced/`, wantRegexRule(DNSBL_KIND_BLOCK, `ad(unbalanced`, false, false)},
		{`/ad[0-9]\.example\.com$/$important`, wantRegexRule(DNSBL_KIND_BLOCK, `ad[0-9]\.example\.com$`, true, false)},
		{`/ad[0-9]\.example\.com$/$badfilter`, wantRegexRule(DNSBL_KIND_BLOCK, `ad[0-9]\.example\.com$`, false, true)},
		{`@@/whitelist-[a-z]+\.example$/$important`, wantRegexRule(DNSBL_KIND_ALLOW, `whitelist-[a-z]+\.example$`, true, false)},
		{`/ad[0-9]\.example$/$important,badfilter`, wantRegexRule(DNSBL_KIND_BLOCK, `ad[0-9]\.example$`, true, true)},
	} {
		expectRule(t, c.line, c.want)
	}
	for _, line := range []string{
		`/track[0-9]\.example$/$third-party`,
		`/track[0-9]\.example$/$dnsrewrite=0.0.0.0`,
		`@@/safe[0-9]\.example$/$domain=foo.com`,
		`/track[0-9]\.example$/$some-future-option`,
		`/track[0-9]\.example$/$important,third-party`,
	} {
		expectSkipped(t, line)
	}
	for _, name := range []string{"regex_reducible.txt", "regex_irreducible.txt"} {
		for _, line := range patternLines(t, name) {
			if r := abpParse(line); r == nil || r.target != RULE_TARGET_REGEX {
				t.Errorf("%s: parseAbp(%q) = %+v, want a regex target", name, line, r)
			}
		}
	}
}

func TestParseAbpOptions(t *testing.T) {
	expectRule(t, "||promo.example.com^$important", wantDomainRule(DNSBL_KIND_BLOCK, "promo.example.com", true, false))
	// $badfilter never joins the signature
	expectRule(t, "||gone.example^$badfilter", wantDomainRule(DNSBL_KIND_BLOCK, "gone.example", false, true))
	expectRule(t, "||x.example^$important,badfilter", wantDomainRule(DNSBL_KIND_BLOCK, "x.example", true, true))
	for _, line := range []string{
		"||widget.example^$third-party",
		"||script.example^$script",
		"||img.example^$image,third-party",
		"||frame.example^$subdocument",
		"||csp.example^$csp=script-src",
		"||domspecific.example^$domain=foo.com",
		"||rewrite.example^$dnsrewrite=0.0.0.0",
		"||rew.example^$dnstype=AAAA",
		"||cl.example^$client=10.0.0.0/8",
		"||unknown.example^$some-future-option",
		"||mixed.example^$important,third-party",
	} {
		expectSkipped(t, line)
	}
}

func TestParseAbpSkip(t *testing.T) {
	for _, line := range []string{
		// TestSkip.test_skip_lines
		"", "   ", "! Title: comment", "[Adblock Plus 2.0]", "# plain comment", "example.com##.ad-banner", "##.global-ad",
		"example.net#@#.whitelisted-ad", "example.org#?#div:has(> .ad)", "example.com#%#//scriptlet('x')",
		"example.com#$#body { color: red; }", "||example.com/ads/*", "||cdn.example.net/track.js", "/banners/*.gif",
		"||shop.example^/affiliate?id=", "||wild.*^", "not a domain at all",
		// test_skip_ip_valued_anchors
		"||203.0.113.7^", "||198.51.100.42^", "0.0.0.0 203.0.113.99", "127.0.0.1 10.0.0.1", "||[2001:db8::1]^",
		// test_skip_invalid_domain
		"||-bad.example^", "||bad-.example^", "||no_dot^", "0.0.0.0 -invalid.example",
	} {
		expectSkipped(t, line)
	}
}

func TestParseAbpProvenancePlumbing(t *testing.T) {
	if r := abpParse("||a.example^"); r == nil || r.provenance != RULE_PROV_FEED || r.feed != "" || r.group != "" || r.log != "" {
		t.Errorf("default plumbing: %+v", r)
	}
	if r := parseAbp("||a.example^", RULE_PROV_USER, "", "", "", nil); r == nil || r.provenance != RULE_PROV_USER {
		t.Errorf("user provenance: %+v", r)
	}
	for _, line := range []string{"@@||b.example^$important", `/irr[0-9]+\.example$/`} {
		r := parseAbp(line, RULE_PROV_USER, "MyFeed", "MyGroup", "2", nil)
		if r == nil || r.provenance != RULE_PROV_USER || r.feed != "MyFeed" || r.group != "MyGroup" || r.log != "2" {
			t.Errorf("parseAbp(%q) metadata: %+v", line, r)
		}
	}
}

func TestParseAbpCoreFields(t *testing.T) {
	// test_core_fields_match_oracle
	for _, c := range []struct {
		line, kind           string
		important, badfilter bool
	}{
		{"||a.example^", DNSBL_KIND_BLOCK, false, false},
		{"@@||a.example^", DNSBL_KIND_ALLOW, false, false},
		{"||a.example^$important", DNSBL_KIND_BLOCK, true, false},
		{"@@||a.example^$important", DNSBL_KIND_ALLOW, true, false},
		{"||a.example^$badfilter", DNSBL_KIND_BLOCK, false, true},
		{"0.0.0.0 a.example", DNSBL_KIND_BLOCK, false, false},
		{"a.example", DNSBL_KIND_BLOCK, false, false},
	} {
		expectRule(t, c.line, wantDomainRule(c.kind, "a.example", c.important, c.badfilter))
	}
}

func TestParseAbpScopeMatchesSpike(t *testing.T) {
	// test_scope_agrees_with_spike: the spike's categoriser, recorded per corpus line.
	inScope := []string{"block", "block_important", "block_dns_opts", "allow", "hosts", "plain", "regex_block", "regex_allow"}
	outOfScope := []string{"comment", "element_hiding", "path_url", "page_context_opts", "non_dns_modifier", "ip_anchored", "other"}
	for _, row := range abpOracle(t).Spike {
		r := abpParse(row.In)
		switch {
		case row.Category == "badfilter":
			if r == nil || !r.badfilter {
				t.Errorf("badfilter: parseAbp(%q) = %+v", row.In, r)
			}
		case slices.Contains(inScope, row.Category):
			if r == nil {
				t.Errorf("%s: %q should be in DNS scope", row.Category, row.In)
			}
		case slices.Contains(outOfScope, row.Category):
			if r != nil {
				t.Errorf("%s: %q should be skipped, got %+v", row.Category, row.In, *r)
			}
		default:
			t.Errorf("unhandled spike category %q for %q", row.Category, row.In)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_adr07_reconcile.py

func TestReconcileBadfilterPrune(t *testing.T) {
	res := abpReconcile([]string{"||y.example.com^", "||y.example.com^$badfilter"}, RULE_PROV_FEED, nil)
	if got := abpResolve(t, res, "y.example.com"); got != "pass" || res.pruned != 1 || res.skippedBadfilter != 1 || len(res.blockDomains) != 0 {
		t.Errorf("feed badfilter: resolve=%s pruned=%d skipped=%d blocks=%v", got, res.pruned, res.skippedBadfilter, res.blockDomains)
	}

	// a user rule with the same signature survives a feed $badfilter (fact 7)
	rules := append(abpRules([]string{"||y.example.com^"}, RULE_PROV_USER), abpRules([]string{"||y.example.com^$badfilter"}, RULE_PROV_FEED)...)
	res = reconcile(rules, abpTlds, abpNoExclusion, nil)
	if got := abpResolve(t, res, "y.example.com"); got != "block" || res.pruned != 0 || !slices.ContainsFunc(res.blockDomains, func(b blockDomainRule) bool { return b.band == PRIO_USER_BLOCK }) {
		t.Errorf("user survives: resolve=%s pruned=%d blocks=%+v", got, res.pruned, res.blockDomains)
	}

	// a different signature is not pruned
	res = abpReconcile([]string{"||x.example.com^$important", "||x.example.com^$badfilter"}, RULE_PROV_FEED, nil)
	if got := abpResolve(t, res, "x.example.com"); got != "block" || res.pruned != 0 {
		t.Errorf("different signature: resolve=%s pruned=%d", got, res.pruned)
	}

	res = abpReconcile([]string{"||a.example.com^", "||b.example.com^", "||a.example.com^$badfilter"}, RULE_PROV_FEED, nil)
	if a, b := abpResolve(t, res, "a.example.com"), abpResolve(t, res, "b.example.com"); a != "pass" || b != "block" {
		t.Errorf("only its signature: a=%s b=%s", a, b)
	}

	// cross-feed: the prune is scoped by provenance, not by feed identity
	blockB := parseAbp("||y.example.com^", RULE_PROV_FEED, "FeedB", "", "", nil)
	badA := parseAbp("||y.example.com^$badfilter", RULE_PROV_FEED, "FeedA", "", "", nil)
	if blockB == nil || badA == nil || blockB.feed != "FeedB" || badA.feed != "FeedA" {
		t.Fatalf("setup: %v %v", blockB, badA)
	}
	before := reconcile([]rule{*blockB}, abpTlds, abpNoExclusion, nil)
	if got := abpResolve(t, before, "y.example.com"); got != "block" || before.pruned != 0 {
		t.Errorf("cross-feed before: resolve=%s pruned=%d", got, before.pruned)
	}
	after := reconcile([]rule{*blockB, *badA}, abpTlds, abpNoExclusion, nil)
	if got := abpResolve(t, after, "y.example.com"); got != "pass" || after.pruned != 1 || after.skippedBadfilter != 1 {
		t.Errorf("cross-feed after: resolve=%s pruned=%d skipped=%d", got, after.pruned, after.skippedBadfilter)
	}

	// and a user block in another feed is not pruned by it
	userB := parseAbp("||y.example.com^", RULE_PROV_USER, "FeedB", "", "", nil)
	if userB == nil {
		t.Fatal("setup: user block did not parse")
	}
	res = reconcile([]rule{*userB, *badA}, abpTlds, abpNoExclusion, nil)
	if got := abpResolve(t, res, "y.example.com"); got != "block" || res.pruned != 0 || !slices.ContainsFunc(res.blockDomains, func(b blockDomainRule) bool { return b.band == PRIO_USER_BLOCK }) {
		t.Errorf("cross-feed user: resolve=%s pruned=%d blocks=%+v", got, res.pruned, res.blockDomains)
	}
}

func TestReconcileRegexReduction(t *testing.T) {
	res := abpReconcile([]string{`/^(.+\.)?doubleclick\.net$/`}, RULE_PROV_FEED, nil)
	if len(res.blockRegexIrreducible) != 0 || res.reduced != 1 {
		t.Errorf("reducible block: irreducible=%v reduced=%d", res.blockRegexIrreducible, res.reduced)
	}
	for q, want := range map[string]string{"doubleclick.net": "block", "ad.doubleclick.net": "block", "other.net": "pass"} {
		if got := abpResolve(t, res, q); got != want {
			t.Errorf("zone fold %s = %s, want %s", q, got, want)
		}
	}

	res = abpReconcile([]string{`/^pixel\.example\.com$/`}, RULE_PROV_FEED, nil)
	if res.reduced != 1 || abpResolve(t, res, "pixel.example.com") != "block" || abpResolve(t, res, "sub.pixel.example.com") != "pass" ||
		!slices.ContainsFunc(res.blockDomains, func(b blockDomainRule) bool { return b.cls == DNSBL_CLASS_DATA }) {
		t.Errorf("exact fold: %+v", res)
	}

	res = abpReconcile([]string{"||example.com^", `@@/^(.+\.)?cdn\.example\.com$/`}, RULE_PROV_FEED, nil)
	for q, want := range map[string]string{"cdn.example.com": "resolve", "deep.cdn.example.com": "resolve", "example.com": "block"} {
		if got := abpResolve(t, res, q); got != want {
			t.Errorf("allow fold %s = %s, want %s", q, got, want)
		}
	}
	if !slices.ContainsFunc(res.allowDomains, func(a allowDomainRule) bool { return a.wildcard }) {
		t.Errorf("allow fold: no wildcard whiteDB entry in %+v", res.allowDomains)
	}

	res = abpReconcile([]string{`/ad[0-9]\.example\.com$/`}, RULE_PROV_FEED, nil)
	if res.reduced != 0 || len(res.blockRegexIrreducible) != 1 || res.blockRegexIrreducible[0].pattern != `ad[0-9]\.example\.com$` ||
		abpResolve(t, res, "ad7.example.com") != "block" {
		t.Errorf("irreducible block: %+v", res)
	}

	res = abpReconcile([]string{`@@/ad[0-9]\.example\.com$/`}, RULE_PROV_FEED, nil)
	if len(res.allowRegexIrreducible) != 1 || len(res.blockRegexIrreducible) != 0 {
		t.Errorf("irreducible allow: %+v", res)
	}
}

func TestReconcileUnqueryableFoldedKeyIsDropped(t *testing.T) {
	// #753: the wire caps apply to a folded key as to its ||host^ twin; the drop tallies 'wire_cap' on the rule's own
	// (feed, group), here ("", "").
	for _, c := range []struct {
		lines []string
		drops int
	}{
		{[]string{"/^(.+\\.)?" + strings.Repeat("a", 64) + "\\.com$/", "@@/^" + strings.Repeat("a", 64) + "\\.net$/"}, 2},
		{[]string{"/^(.+\\.)?" + strings.Repeat("A", 64) + "\\.com$/"}, 1}, // mixed case: the cap checks the lower-cased key
	} {
		tally := rejectTally{}
		res := abpReconcile(c.lines, RULE_PROV_FEED, tally)
		if len(res.blockDomains)+len(res.allowDomains)+len(res.blockRegexIrreducible)+len(res.allowRegexIrreducible) != 0 || res.reduced != 0 {
			t.Errorf("%q: dropped rule survived: %+v", c.lines, res)
		}
		if want := (rejectTally{{"", ""}: {"shape": 0, "wire_cap": c.drops}}); !reflect.DeepEqual(tally, want) {
			t.Errorf("%q: tally = %v, want %v", c.lines, tally, want)
		}
	}
}

func TestDnsblReduceRegex(t *testing.T) {
	// test_reduction_matches_oracle_and_spike, test_regex_reduction_case_folds_literal_to_lowercase and
	// test_branch_coverage_gaps TestReduceRegexIrreducible
	type result struct {
		wildcard bool
		domain   string
		ok       bool
	}
	for _, c := range []struct {
		inner string
		want  result
	}{
		{`^(.+\.)?doubleclick\.net$`, result{true, "doubleclick.net", true}},
		{`^pixel\.example\.com$`, result{false, "pixel.example.com", true}},
		{`(^|\.)tracker\.net$`, result{true, "tracker.net", true}},
		{`^(www\.)?simple\.example\.com$`, result{false, "simple.example.com", true}},
		{`ad[0-9]\.example\.com$`, result{}},
		{`(a+)+$`, result{}},
		{`^Example\.com$`, result{false, "example.com", true}},
		{`^(.+\.)?AdServer\.Example$`, result{true, "adserver.example", true}},
		{`(^|\.)Tracker\.NET$`, result{true, "tracker.net", true}},
		{`^(www\.)?Simple\.Example\.com$`, result{false, "simple.example.com", true}},
		{`^(WWW\.)?Example\.com$`, result{false, "example.com", true}}, // #2199: the www-opt token itself is mixed case
		{`(^|\.)ad[0-9]\.x$`, result{}},
		{`(^|\.)ads\.example\.com$`, result{true, "ads.example.com", true}},
		// Python's "$" also matches before a trailing newline, and the folded key keeps that newline.
		{"^a\\.b\n$", result{false, "a.b\n", true}},
		{"^(.+\\.)?a\\.b\n$", result{true, "a.b\n", true}},
		{"^a\\.b\n\n$", result{}},
	} {
		wildcard, domain, ok := dnsblReduceRegex(c.inner)
		if got := (result{wildcard, domain, ok}); got != c.want {
			t.Errorf("dnsblReduceRegex(%s) = %+v, want %+v", pysem.Repr(c.inner), got, c.want)
		}
	}
}

func TestReconcileClassify(t *testing.T) {
	res := abpReconcile([]string{"||example.com^"}, RULE_PROV_FEED, nil)
	if b := onlyBlock(t, res); b.cls != DNSBL_CLASS_ZONE || b.key != "example.com" {
		t.Errorf("registrable parent: %+v", b)
	}

	// #718: a deep anchor is a ZONE at its own key, and a deep wildcard fold shares that
	for _, line := range []string{"||ads.example.com^", `/^(.+\.)?ads\.example\.com$/`} {
		res = abpReconcile([]string{line}, RULE_PROV_FEED, nil)
		if b := onlyBlock(t, res); b.cls != DNSBL_CLASS_ZONE || b.key != "ads.example.com" || abpResolve(t, res, "deep.ads.example.com") != "block" {
			t.Errorf("%q: %+v", line, b)
		}
	}

	// a whole-domain TLD exclusion forces exact DATA
	res = reconcile(abpRules([]string{"||ads.example.com^"}, RULE_PROV_FEED), abpTlds, map[string]struct{}{"ads.example.com": {}}, nil)
	if b := onlyBlock(t, res); b.cls != DNSBL_CLASS_DATA || b.key != "ads.example.com" || abpResolve(t, res, "deep.ads.example.com") != "pass" {
		t.Errorf("exclusion: %+v", b)
	}

	res = abpReconcile([]string{`/^pixel\.example\.com$/`}, RULE_PROV_FEED, nil)
	if b := onlyBlock(t, res); b.cls != DNSBL_CLASS_DATA || b.key != "pixel.example.com" {
		t.Errorf("exact fold: %+v", b)
	}
}

func TestReconcileBands(t *testing.T) {
	for _, c := range []struct {
		line, prov string
		want       int
	}{
		{"||a.example.com^", RULE_PROV_FEED, PRIO_FEED_BLOCK},
		{"@@||a.example.com^", RULE_PROV_FEED, PRIO_FEED_ALLOW},
		{"||a.example.com^$important", RULE_PROV_FEED, PRIO_FEED_BLOCK_IMPORTANT},
		{"@@||a.example.com^$important", RULE_PROV_FEED, PRIO_FEED_ALLOW_IMPORTANT},
		{"||a.example.com^", RULE_PROV_USER, PRIO_USER_BLOCK},
		{"@@||a.example.com^", RULE_PROV_USER, PRIO_USER_ALLOW},
	} {
		res := abpReconcile([]string{c.line}, c.prov, nil)
		got := 0
		if len(res.blockDomains) == 1 {
			got = res.blockDomains[0].band
		} else if len(res.allowDomains) == 1 {
			got = res.allowDomains[0].band
		}
		if got != c.want {
			t.Errorf("%s %s: band %d, want %d", c.prov, c.line, got, c.want)
		}
		// test_band_matches_oracle_priority: dnsblRuleBand is the oracle's priority() (1..6)
		r := parseAbp(c.line, c.prov, "", "", "", nil)
		if r == nil {
			t.Fatalf("%s %s did not parse", c.prov, c.line)
		}
		if got := dnsblRuleBand(*r); got != c.want {
			t.Errorf("dnsblRuleBand(%s %s) = %d, want %d", c.prov, c.line, got, c.want)
		}
	}
}

func TestReconcilePrecedence(t *testing.T) {
	res := abpReconcile([]string{"||example.com^", "@@||cdn.example.com^"}, RULE_PROV_FEED, nil)
	if a, b := abpResolve(t, res, "cdn.example.com"), abpResolve(t, res, "example.com"); a != "resolve" || b != "block" {
		t.Errorf("feed allow beats feed block: %s %s", a, b)
	}
	res = abpReconcile([]string{"||x.example.com^$important", "@@||x.example.com^"}, RULE_PROV_FEED, nil)
	if got := abpResolve(t, res, "x.example.com"); got != "block" {
		t.Errorf("important block beats feed allow: %s", got)
	}
	res = abpReconcile([]string{"@@||y.example.com^$important", "||y.example.com^"}, RULE_PROV_FEED, nil)
	if got := abpResolve(t, res, "y.example.com"); got != "resolve" {
		t.Errorf("important allow beats feed block: %s", got)
	}
	rules := append(abpRules([]string{"||z.example.com^$important"}, RULE_PROV_FEED), abpRules([]string{"@@||z.example.com^"}, RULE_PROV_USER)...)
	if got := abpResolve(t, reconcile(rules, abpTlds, abpNoExclusion, nil), "z.example.com"); got != "resolve" {
		t.Errorf("user allow (6) beats feed important block (3): %s", got)
	}
	rules = append(abpRules([]string{"@@||w.example.com^$important"}, RULE_PROV_FEED), abpRules([]string{"||w.example.com^"}, RULE_PROV_USER)...)
	if got := abpResolve(t, reconcile(rules, abpTlds, abpNoExclusion, nil), "w.example.com"); got != "block" {
		t.Errorf("user block (5) beats feed important allow (4): %s", got)
	}
	// test_matches_oracle_decide: outcomes of the Python oracle decide()
	for _, row := range abpOracle(t).Decide {
		if got := abpResolve(t, abpReconcile(row.Lines, RULE_PROV_FEED, nil), row.Query); got != row.Outcome {
			t.Errorf("%q query %s: %s, oracle decide() says %s", row.Lines, row.Query, got, row.Outcome)
		}
	}
}

func TestReconcileImportantRulesFlag(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
		prov  string
		want  bool
	}{
		{"plain feed blocks keep the fast path", []string{"||a.example.com^", "||b.example.com^", "0.0.0.0 c.example.com"}, RULE_PROV_FEED, false},
		{"feed important", []string{"||a.example.com^$important"}, RULE_PROV_FEED, true},
		{"feed allow", []string{"@@||a.example.com^"}, RULE_PROV_FEED, true},
		{"feed irreducible regex", []string{`/ad[0-9]\.example\.com$/`}, RULE_PROV_FEED, true},
		{"user rules alone", []string{"||a.example.com^", "@@||b.example.com^"}, RULE_PROV_USER, false},
		// test_branch_coverage_gaps: a user irreducible regex does not force the numeric path, a feed one does
		{"user irreducible regex", []string{"/(a|b)+x/"}, RULE_PROV_USER, false},
	} {
		if got := abpReconcile(c.lines, c.prov, nil).importantRules; got != c.want {
			t.Errorf("%s: importantRules = %v, want %v", c.name, got, c.want)
		}
	}
	feed := abpReconcile([]string{"/(a|b)+x/"}, RULE_PROV_FEED, nil)
	user := abpReconcile([]string{"/(a|b)+x/"}, RULE_PROV_USER, nil)
	if !feed.importantRules || len(feed.blockRegexIrreducible) != 1 || user.importantRules || len(user.blockRegexIrreducible) != 1 ||
		user.blockRegexIrreducible[0].provenance != RULE_PROV_USER {
		t.Errorf("feed=%+v user=%+v", feed, user)
	}
}

func TestReconcilePurityReentrancy(t *testing.T) {
	rules := abpRules(corpusLines(t), RULE_PROV_FEED)
	r1 := reconcile(rules, abpTlds, abpNoExclusion, nil)
	r2 := reconcile(rules, abpTlds, abpNoExclusion, nil)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("two reconcile calls on equal inputs differ")
	}

	rules = abpRules([]string{"||a.example.com^", "||a.example.com^$badfilter"}, RULE_PROV_FEED)
	before := slices.Clone(rules)
	tlds := map[string]map[string]string{}
	for k, v := range abpTlds {
		tlds[k] = maps.Clone(v)
	}
	exclusion := map[string]struct{}{}
	reconcile(rules, abpTlds, exclusion, nil)
	if !slices.Equal(rules, before) || !reflect.DeepEqual(abpTlds, tlds) || len(exclusion) != 0 {
		t.Error("reconcile mutated an argument")
	}

	// an irreducible pattern that is not a valid regex survives as a raw pattern: Stage B never compiles
	res := abpReconcile([]string{`/ad[0-9\.broken$/`}, RULE_PROV_FEED, nil)
	if len(res.blockRegexIrreducible) != 1 || res.blockRegexIrreducible[0].pattern != `ad[0-9\.broken$` {
		t.Errorf("broken pattern: %+v", res.blockRegexIrreducible)
	}
}

func TestReconcileCorpusEquivalence(t *testing.T) {
	// TestCorpusEquivalence: the oracle decide() outcome for a spread of probes derived from the reduced sets.
	res := abpReconcile(corpusLines(t), RULE_PROV_FEED, nil)
	probes := map[string]struct{}{}
	for _, b := range res.blockDomains {
		probes[b.key] = struct{}{}
		probes["sub."+b.key] = struct{}{}
	}
	for _, a := range res.allowDomains {
		probes[a.domain] = struct{}{}
		probes["sub."+a.domain] = struct{}{}
	}
	for _, q := range []string{"doubleclick.net", "ad.doubleclick.net", "unrelated.example", "example.com"} {
		probes[q] = struct{}{}
	}
	want := abpOracle(t).CorpusProbes
	got := slices.Sorted(maps.Keys(probes))
	if wantQueries := func() (qs []string) {
		for _, p := range want {
			qs = append(qs, p.Query)
		}
		return
	}(); !slices.Equal(got, wantQueries) {
		t.Fatalf("probe set differs from Python's:\n got  %q\n want %q", got, wantQueries)
	}
	for _, p := range want {
		if got := abpResolve(t, res, p.Query); got != p.Outcome {
			t.Errorf("%s: %s, oracle decide() says %s", p.Query, got, p.Outcome)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the _dnsbl_* line helpers

func TestDnsblIsAbpRuleLine(t *testing.T) {
	for _, line := range []string{
		// tests/test_adr62_parity_oracle.py test_cosmetic_prefix_guard_matches_php_row_for_row: not capturable
		"0.0.0.0 example.com ## comment", "example.com ## seen 2024", "12345,http://evil.example/path##frag,phish,online",
		"http://example.com/##banner", "# note ## x", "# The Spamhaus Project Ltd ## marketing ## banner", "# c#@#d",
		"\thost.example##.ad", "//cdn.example.com/ads/", "//", "@stray.example", ",a,b,c,d##x", ",example.com,example.org##.ad",
		",a,,1,RealFeed,x##y", ",||x^", ",", ",,##x", "## Section header", "##\tSection", "#@# note", "##", "##\rSection",
		"##\x0bsection", "##\x0csection", "##\u00a0Section", "#?# note", "#%# note", "#$# note",
		// test_adr62_parity_oracle.py: bare domains and the other negatives, tests/test_adr21_abp_per_line.py (e)/(f)
		"sub.deep.example.com", "\ufeff||bomabp.example^", strings.Repeat("a", 254), "domain.com", "plain.com", "allow.com", "example.com", "subdomain.example.com",
	} {
		if dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%s) = true, must NOT capture", pysem.Repr(line))
		}
	}
	for _, line := range []string{
		"####################", "##.ad", "example.com##.ad", "a.com,b.com##.ad", "example.com,example.org##.ad", "~ex.com##.ad",
		"EXAMPLE.com##.ad", "/re/", "/re/$important", "#@#selector", "#?#selector", "#%#selector", "#$#selector",
		// bare anchors, hostile regex shapes
		"@@", "||", `/^re1\.example$/`, `@@/^re2\.example$/`, `/^re3\.example$/$important`,
		// test_adr21_abp_per_line.py (a)-(d), (g), (h): every ||/@@|| line is routed to parse_abp
		"||block-me.com^", "@@||allow.com^", "||domain.com^$important", "||cancel-me.com^$badfilter", "||block.com^",
		"||domain.com/path^", "||*.com^", "||domain.com^$third-party",
	} {
		if !dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%s) = false, must capture", pysem.Repr(line))
		}
	}
	// the regex-shaped half of the PHP predicate: a lone slash and a missing closing slash are not rules
	for line, want := range map[string]bool{"/": false, "/no-closing-slash": false, "/no-closing-slash/": true} {
		if got := dnsblIsAbpRuleLine(line); got != want {
			t.Errorf("dnsblIsAbpRuleLine(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestDnsblClassifyOptions(t *testing.T) {
	// test_branch_coverage_gaps: a trailing comma is an empty token, skipped
	opts, important, badfilter, ok := dnsblClassifyOptions("important,")
	if !slices.Equal(opts, []string{"important"}) || !important || badfilter || !ok {
		t.Errorf("important, = %v %v %v %v", opts, important, badfilter, ok)
	}
	if _, _, _, ok := dnsblClassifyOptions("important,third-party"); ok {
		t.Error("one page-context option must poison the rule")
	}
	// a repeated $important keeps both names: Python's sorted() list, not a set
	if opts, _, _, ok := dnsblClassifyOptions("important,badfilter,important"); !ok || !slices.Equal(opts, []string{"important", "important"}) {
		t.Errorf("repeated important: %v %v", opts, ok)
	}
	if name := dnsblOptName(" \u00a0dnsrewrite=0.0.0.0"); name != "dnsrewrite" {
		t.Errorf("dnsblOptName = %q", name)
	}
}

func TestDnsblParseAbpRegex(t *testing.T) {
	// test_branch_coverage_gaps: an empty inner pattern is not a regex rule
	for _, line := range []string{"//", "@@//", "/", "@@/", "/$", "/a", "plain"} {
		if _, _, _, ok := dnsblParseAbpRegex(line); ok {
			t.Errorf("dnsblParseAbpRegex(%q) accepted", line)
		}
	}
	for _, c := range []struct{ line, kind, inner, opts string }{
		{`/ad[0-9]\.example$/`, DNSBL_KIND_BLOCK, `ad[0-9]\.example$`, ""},
		{`@@/ad/$important`, DNSBL_KIND_ALLOW, "ad", "important"},
		{"/a/b/", DNSBL_KIND_BLOCK, "a/b", ""},
		{"/a/$b/", DNSBL_KIND_BLOCK, "a/$b", ""},
	} {
		kind, inner, opts, ok := dnsblParseAbpRegex(c.line)
		if !ok || kind != c.kind || inner != c.inner || opts != c.opts {
			t.Errorf("dnsblParseAbpRegex(%q) = %q %q %q %v", c.line, kind, inner, opts, ok)
		}
	}
}

func TestDnsblStripHostsPrefix(t *testing.T) {
	// test_branch_coverage_gaps TestStripHostsPrefix
	for in, want := range map[string]string{
		"notanip domain.com": "notanip", "0.0.0.0 domain.com": "domain.com", "0.0.0.0  \u2003 domain.com \u00a0": "domain.com", "domain.com": "domain.com",
	} {
		if got := dnsblStripHostsPrefix(in); got != want {
			t.Errorf("dnsblStripHostsPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEntry(t *testing.T) {
	// tests/test_adr06_build_module.py TestParse, TestParseSkipBranches (Python parse(); parseEntry here, as the test
	// helper parse() of pfb_dns_proxy_test.go already holds the name)
	for _, c := range []struct{ line, value string }{
		{"0.0.0.0 tracker.org", "tracker.org"}, {"127.0.0.1 tracker.org", "tracker.org"}, {"malware.com", "malware.com"},
		{".wildcardish.org", "wildcardish.org"},
	} {
		e := parseEntry(c.line)
		if e == nil || e.value != c.value || e.kind != DNSBL_KIND_BLOCK {
			t.Errorf("parseEntry(%q) = %+v, want a block of %q", c.line, e, c.value)
		}
	}
	for _, line := range []string{"# a comment", "0.0.0.0 198.51.100.23", "203.0.113.45", "   ", "", "."} {
		if e := parseEntry(line); e != nil {
			t.Errorf("parseEntry(%q) = %+v, want nil", line, *e)
		}
	}
}

func TestDnsblIsIpv4(t *testing.T) {
	// tests/test_issue1071_dnsbl_is_ipv4_unicode.py
	for _, token := range []string{
		"1.1.1.\u00b2", "\u00b2.\u00b2.\u00b2.\u00b2", "1.1.1.\u2461", "\u0661.\u0661.\u0661.\u0661", "1\u00b2.1.1.1", "\uff11.\uff11.\uff11.\uff11",
		"1.1.1." + strings.Repeat("9", 4301), strings.Repeat("9", 4301) + ".1.1.1", "1.1.1." + strings.Repeat("0", 4301),
	} {
		if dnsblIsIpv4(token) {
			t.Errorf("dnsblIsIpv4(%.30q) = true", token)
		}
	}
	for token, want := range map[string]bool{
		"1.1.1.1": true, "255.255.255.255": true, "0.0.0.0": true, "192.168.0.1": true, "1.1.1.256": false, "01.1.1.1": false,
		"1.1.1": false, "1.1.1.1.1": false, "1.1.1.": false, "a.b.c.d": false, "+1.1.1.1": false, "1.1.1.-1": false, "1.1.1.1000": false,
	} {
		if got := dnsblIsIpv4(token); got != want {
			t.Errorf("dnsblIsIpv4(%q) = %v, want %v", token, got, want)
		}
	}
}

func TestDnsblIsNumericHost(t *testing.T) {
	// tests/test_ipv4_numeric_host.py: the table shared with the PHP pfb_ipv4_numeric_host()
	data, err := os.ReadFile(filepath.Join(paritycorpus.Fixtures(), "..", "..", "..", "fixtures", "ipv4_numeric_host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct{ Cases [][2]any }
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) < 10 {
		t.Fatalf("shared table has %d cases", len(table.Cases))
	}
	for _, c := range table.Cases {
		host, want := c[0].(string), c[1] != nil
		if got := dnsblIsNumericHost(host); got != want {
			t.Errorf("dnsblIsNumericHost(%q) = %v, want %v (PHP result %v)", host, got, want, c[1])
		}
	}
	for _, host := range []string{"1.2.3.\u00b2", "1.2.3.\u0663", "\uff11.\uff12.\uff13.\uff14"} {
		if dnsblIsNumericHost(host) {
			t.Errorf("dnsblIsNumericHost(%q) = true: non-ASCII digits are not numeric-shaped", host)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// normalise

func TestNormalise(t *testing.T) {
	// tests/test_adr06_build_module.py TestNormalise, tests/test_dnsbl_numeric_host_skip.py,
	// tests/test_issue3056_label_charset.py
	name253 := strings.Repeat(strings.Repeat("b", 61)+".", 4) + strings.Repeat("b", 5)
	name254 := strings.Repeat(strings.Repeat("b", 61)+".", 4) + strings.Repeat("b", 6)
	if len(name253) != 253 || len(name254) != 254 {
		t.Fatalf("setup: %d %d", len(name253), len(name254))
	}
	for in, want := range map[string]string{
		" Tracker.ORG. ": "tracker.org", "198.51.100.23": "198.51.100.23", "deep.host.cleandata.com": "deep.host.cleandata.com",
		"under_score.com": "under_score.com", "_dmarc.example.com": "_dmarc.example.com", "trailing_.example.com": "trailing_.example.com",
		strings.Repeat("a", 63) + ".com": strings.Repeat("a", 63) + ".com", name253: name253, name253 + ".": name253,
		"1.2.example.com": "1.2.example.com", "example.com": "example.com", "0xg.com": "0xg.com",
	} {
		if got, ok := normalise(in); !ok || got != want {
			t.Errorf("normalise(%.40q) = %.40q %v, want %.40q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"localhost", "-bad.com", "bad-.com", "emp..ty", "sp ace.com", strings.Repeat("a", 64) + ".com", name254, "", ".", "a..com",
		// numeric last label: a client parses these as an IPv4 literal
		"0xc0.0xa8.0x1.0x64", "0300.0250.01.0144", "192.168.356", "192.168.01.100", "a.0x1",
	} {
		if got, ok := normalise(in); ok {
			t.Errorf("normalise(%.40q) = %q, want a reject", in, got)
		}
	}
	// the numeric-host skip leaves canonical quads to parseEntry(): normalise accepts one, parseEntry() drops it
	if parseEntry("198.51.100.23") != nil {
		t.Error("parseEntry must drop a bare IP")
	}

	// test_ascii_alphabets_remain_distinct: every ASCII character in the middle of a label
	for _, row := range abpOracle(t).Charset {
		got, ok := normalise(row.In)
		if (row.Out != nil) != ok || ok && got != *row.Out {
			t.Errorf("normalise(%s) = %q %v, Python says %v", pysem.Repr(row.In), got, ok, derefOr(row.Out, "None"))
		}
	}
}

func TestNormaliseVerdict(t *testing.T) {
	// tests/test_adr06_build_module.py TestNormaliseVerdictBucket and test_issue3056 (empty names)
	name254 := strings.Repeat(strings.Repeat("b", 61)+".", 4) + strings.Repeat("b", 6)
	if d, b := normaliseVerdict(" Tracker.ORG. ", false); d != "tracker.org" || b != "" {
		t.Errorf("accept = %q %q", d, b)
	}
	for in, bucket := range map[string]string{
		"localhost": "shape", "-bad.com": "shape", "bad-.com": "shape", "emp..ty": "shape", "sp ace.com": "shape", "": "shape", ".": "shape", "a..com": "shape",
		"0xc0.0xa8.0x1.0x64": "shape", "192.168.356": "shape",
		strings.Repeat("a", 64) + ".com": "wire_cap", name254: "wire_cap",
		// the caps count characters, not bytes: 63 two-byte letters is a legal label that fails the charset instead
		strings.Repeat("\u00e9", 63) + ".example": "shape", strings.Repeat("\u00e9", 64) + ".example": "wire_cap",
		// and they count the lower-cased name: U+0130 lowers to two characters
		strings.Repeat("i", 62) + "\u0130.example": "wire_cap",
	} {
		if d, b := normaliseVerdict(in, false); d != "" || b != bucket {
			t.Errorf("normaliseVerdict(%.40q) = %q %q, want a %s reject", in, d, b, bucket)
		}
	}
	// single_label_ok lifts only the has-a-dot rule (#3378)
	if d, b := normaliseVerdict(".lan", true); d != "lan" || b != "" {
		t.Errorf("single label ok: %q %q", d, b)
	}
	if d, b := normaliseVerdict("-lan", true); d != "" || b != "shape" {
		t.Errorf("single label still validated: %q %q", d, b)
	}
	if d, b := normaliseVerdict("\u212a.example", false); d != "k.example" || b != "" {
		t.Errorf("Kelvin sign lowers to k: %q %q", d, b)
	}
}

func TestDnsblWithinWireCaps(t *testing.T) {
	if !dnsblWithinWireCaps(strings.Repeat("\u00e9", 63)+".example") || dnsblWithinWireCaps(strings.Repeat("\u00e9", 64)+".example") {
		t.Error("the label cap counts characters")
	}
	if !dnsblWithinWireCaps(strings.Repeat("a", 63)+".b") || dnsblWithinWireCaps(strings.Repeat("a", 64)+".b") {
		t.Error("label cap 63")
	}
}

// ---------------------------------------------------------------------------------------------------------------
// _dnsbl_normalise_whitelist (tests/test_adr06_build_module.py TestWhitelistNormalisation, the normalisation half;
// the lookup half belongs to whitelist_lookup_domain)

func userAllow(wildcard bool) whiteEntry {
	return whiteEntry{wildcard: wildcard, important: true, band: PRIO_USER_ALLOW, hasBand: true}
}

func TestDnsblNormaliseWhitelist(t *testing.T) {
	apex := "collapex.com"
	for _, c := range []struct {
		name    string
		entries []string
		want    map[string]whiteEntry
	}{
		{"www strip and exact", []string{"www.adblock.com"}, map[string]whiteEntry{"adblock.com": userAllow(false)}},
		{"leading dot wildcard", []string{".wildwhite.org"}, map[string]whiteEntry{"wildwhite.org": userAllow(true)}},
		{"mixed case", []string{"Example.COM"}, map[string]whiteEntry{"example.com": userAllow(false)}},
		{"mixed case wildcard", []string{".Example.COM"}, map[string]whiteEntry{"example.com": userAllow(true)}},
		{"mixed case www prefix", []string{"WWW.Example.COM"}, map[string]whiteEntry{"example.com": userAllow(false)}},
		{"rejected entry dropped", []string{"bad domain!", "ok.com"}, map[string]whiteEntry{"ok.com": userAllow(false)}},
		{"trailing dot", []string{"example.com."}, map[string]whiteEntry{"example.com": userAllow(false)}},
		{"single label wildcard kept (#3378)", []string{".lan", ".Internal"}, map[string]whiteEntry{"lan": userAllow(true), "internal": userAllow(true)}},
		{"single label without wildcard dot dropped", []string{"lan", "com.", "www.", "www.."}, map[string]whiteEntry{}},
		{"single label wildcard validates the label", []string{".-bad", ".bad-", "." + strings.Repeat("a", 64), ". example.com", ". lan", ".bad!", ".123", ".", ".."}, map[string]whiteEntry{}},
		{"single label wildcard at the cap", []string{"." + strings.Repeat("a", 63)}, map[string]whiteEntry{strings.Repeat("a", 63): userAllow(true)}},
		{"wildcard follows the www-stripped body", []string{"www..example.com"}, map[string]whiteEntry{"example.com": userAllow(true)}},
		{"single label behind the strip is a wildcard", []string{"www..lan"}, map[string]whiteEntry{"lan": userAllow(true)}},
		{"www single label remainder keeps matching", []string{"www.com", "WWW.Org", "www.example"},
			map[string]whiteEntry{"www.com": userAllow(false), "www.org": userAllow(false), "www.example": userAllow(false)}},
		{"invalid names behind www", []string{"www.-bad.com", "www.bad domain"}, map[string]whiteEntry{}},
		{"blank lines skipped", []string{"", "   ", "keep.com"}, map[string]whiteEntry{"keep.com": userAllow(false)}},
		// issue #3191: collisions widen, never last-wins
		{"dot then www", []string{"." + apex, "www." + apex}, map[string]whiteEntry{apex: userAllow(true)}},
		{"dot then bare", []string{"." + apex, apex}, map[string]whiteEntry{apex: userAllow(true)}},
		{"www then dot", []string{"www." + apex, "." + apex}, map[string]whiteEntry{apex: userAllow(true)}},
		{"www then bare stays exact", []string{"www." + apex, apex}, map[string]whiteEntry{apex: userAllow(false)}},
		{"dot plus mail keeps two keys", []string{"." + apex, "mail." + apex}, map[string]whiteEntry{apex: userAllow(true), "mail." + apex: userAllow(false)}},
	} {
		if got := dnsblNormaliseWhitelist(c.entries, nil, "user-whitelist"); !maps.Equal(got, c.want) {
			t.Errorf("%s: dnsblNormaliseWhitelist(%q) = %+v, want %+v", c.name, c.entries, got, c.want)
		}
	}

	// a rejected entry is tallied under (source, "DNSBL") with its bucket; a nil tally counts nothing
	tally := rejectTally{}
	dnsblNormaliseWhitelist([]string{"bad domain!", "ok.com", "." + strings.Repeat("a", 64)}, tally, "user-whitelist")
	if want := (rejectTally{{"user-whitelist", "DNSBL"}: {"shape": 1, "wire_cap": 1}}); !reflect.DeepEqual(tally, want) {
		t.Errorf("tally = %v, want %v", tally, want)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the Python oracle table

type abpOracleRule struct {
	Kind, Target, Key              string
	Important, Badfilter, Wildcard bool
	Opts                           []string
}

type abpOracleLine struct {
	In               string         `json:"in"`
	AbpLine          bool           `json:"abp_line"`
	RegexHit         []string       `json:"regex_hit"`
	Classify         []any          `json:"classify"`
	Rule             *abpOracleRule `json:"rule"`
	Tally            [][]any        `json:"tally"`
	Verdict          [2]*string     `json:"verdict"`
	VerdictSingle    [2]*string     `json:"verdict_single"`
	Parse            *string        `json:"parse"`
	StripHostsPrefix *string        `json:"strip_hosts_prefix"`
	Ipv4             bool           `json:"ipv4"`
	NumericHost      bool           `json:"numeric_host"`
	WireCaps         bool           `json:"wire_caps"`
	Whitelist        [][]any        `json:"whitelist"`
}

type abpOracleResult struct {
	BlockDomains          []string `json:"block_domains"`
	AllowDomains          []string `json:"allow_domains"`
	BlockRegexIrreducible []string `json:"block_regex_irreducible"`
	AllowRegexIrreducible []string `json:"allow_regex_irreducible"`
	Counters              [4]int   `json:"counters"`
	Tally                 []string `json:"tally"`
}

type abpOracleFile struct {
	Lines  []abpOracleLine `json:"lines"`
	Spike  []struct{ In, Category string }
	Reduce []struct {
		In  string
		Out []any
	}
	Reconcile []struct {
		Name      string
		Segments  [][]any
		Exclusion []string
		Result    abpOracleResult
	}
	Decide []struct {
		Lines          []string
		Query, Outcome string
	}
	CorpusProbes []struct{ Query, Outcome string } `json:"corpus_probes"`
	Whitelist    []struct {
		Entries []string
		Out     [][]any
		Tally   [][]any
		Source  string
	}
	IP []struct {
		In          string
		Ipv4        bool
		NumericHost bool `json:"numeric_host"`
	}
	Charset []struct {
		In  string
		Out *string
	}
}

var (
	abpOracleOnce sync.Once
	abpOracleData abpOracleFile
	abpOracleErr  error
)

func abpOracle(t *testing.T) *abpOracleFile {
	t.Helper()
	abpOracleOnce.Do(func() {
		var data []byte
		if data, abpOracleErr = os.ReadFile(filepath.Join("testdata", "pfb_unbound_abp_oracle.json")); abpOracleErr == nil {
			abpOracleErr = json.Unmarshal(data, &abpOracleData)
		}
	})
	if abpOracleErr != nil {
		t.Fatal(abpOracleErr)
	}
	return &abpOracleData
}

// oracleTallyRows renders [feed, group, {bucket: n}] rows as "feed\tgroup\t{json}", the form reconcile rows use.
func oracleTallyRows(rows [][]any) []string {
	out := []string{}
	for _, r := range rows {
		counts, _ := json.Marshal(r[2])
		out = append(out, fmt.Sprintf("%s\t%s\t%s", r[0], r[1], counts))
	}
	return out
}

func tallyRows(tally rejectTally) []string {
	out := []string{}
	for _, key := range slices.SortedFunc(maps.Keys(tally), func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) }) {
		counts, _ := json.Marshal(tally[key])
		out = append(out, fmt.Sprintf("%s\t%s\t%s", key[0], key[1], counts))
	}
	return out
}

func b2i(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func whitelistFromRows(rows [][]any) map[string]whiteEntry {
	out := map[string]whiteEntry{}
	for _, r := range rows {
		e := r[1].(map[string]any)
		out[r[0].(string)] = whiteEntry{wildcard: e["wildcard"].(bool), important: e["important"].(bool), band: int(e["band"].(float64)), hasBand: true}
	}
	return out
}

func TestAbpOracleLines(t *testing.T) {
	rows := abpOracle(t).Lines
	if len(rows) < 500 {
		t.Fatalf("oracle table has %d line rows", len(rows))
	}
	for _, row := range rows {
		in := row.In
		bad := func(fn string, got, want any) {
			t.Errorf("%s(%s) = %#v, Python says %#v", fn, pysem.Repr(in), got, want)
		}

		if got := dnsblIsAbpRuleLine(in); got != row.AbpLine {
			bad("dnsblIsAbpRuleLine", got, row.AbpLine)
		}
		kind, inner, opts, ok := dnsblParseAbpRegex(in)
		if got, want := []string{kind, inner, opts}, row.RegexHit; ok != (want != nil) || ok && !slices.Equal(got, want) {
			bad("dnsblParseAbpRegex", []any{ok, got}, want)
		}
		gotOpts, important, badfilter, ok := dnsblClassifyOptions(in)
		if ok != (row.Classify != nil) {
			bad("dnsblClassifyOptions ok", ok, row.Classify != nil)
		} else if ok {
			var wantOpts []string
			for _, o := range row.Classify[0].([]any) {
				wantOpts = append(wantOpts, o.(string))
			}
			if !slices.Equal(gotOpts, wantOpts) || important != row.Classify[1].(bool) || badfilter != row.Classify[2].(bool) {
				bad("dnsblClassifyOptions", []any{gotOpts, important, badfilter}, row.Classify)
			}
		}

		tally := rejectTally{}
		got := parseAbp(in, RULE_PROV_FEED, "F", "G", "1", tally)
		switch {
		case (got != nil) != (row.Rule != nil):
			bad("parseAbp", got, row.Rule)
		case got != nil:
			want := rule{kind: row.Rule.Kind, target: row.Rule.Target, keyOrPattern: row.Rule.Key, important: row.Rule.Important, badfilter: row.Rule.Badfilter,
				provenance: RULE_PROV_FEED, feed: "F", group: "G", log: "1", signature: ruleSignature{row.Rule.Key, strings.Join(row.Rule.Opts, ",")}, wildcard: row.Rule.Wildcard}
			if *got != want {
				bad("parseAbp", *got, want)
			}
		}
		if got, want := tallyRows(tally), oracleTallyRows(row.Tally); !slices.Equal(got, want) {
			bad("parseAbp tally", got, want)
		}

		for i, single := range []bool{false, true} {
			domain, bucket := normaliseVerdict(in, single)
			want := row.Verdict
			if single {
				want = row.VerdictSingle
			}
			if domain != derefOr(want[0], "") || bucket != derefOr(want[1], "") || (want[0] == nil) != (domain == "") {
				bad(fmt.Sprintf("normaliseVerdict[single=%v]", i == 1), []string{domain, bucket}, []string{derefOr(want[0], "None"), derefOr(want[1], "None")})
			}
		}
		if e := parseEntry(in); (e != nil) != (row.Parse != nil) || e != nil && e.value != *row.Parse {
			bad("parseEntry", e, row.Parse)
		}
		if got, want := dnsblStripHostsPrefix(in), derefOr(row.StripHostsPrefix, in); got != want {
			bad("dnsblStripHostsPrefix", got, want)
		}
		if got := dnsblIsIpv4(in); got != row.Ipv4 {
			bad("dnsblIsIpv4", got, row.Ipv4)
		}
		if got := dnsblIsNumericHost(in); got != row.NumericHost {
			bad("dnsblIsNumericHost", got, row.NumericHost)
		}
		if got := dnsblWithinWireCaps(in); got != row.WireCaps {
			bad("dnsblWithinWireCaps", got, row.WireCaps)
		}
		if got, want := dnsblNormaliseWhitelist([]string{in}, nil, "user-whitelist"), whitelistFromRows(row.Whitelist); !maps.Equal(got, want) {
			bad("dnsblNormaliseWhitelist", got, want)
		}
	}
}

func TestAbpOracleReduce(t *testing.T) {
	rows := abpOracle(t).Reduce
	if len(rows) < 200 {
		t.Fatalf("oracle table has %d reduce rows", len(rows))
	}
	for _, row := range rows {
		wildcard, domain, ok := dnsblReduceRegex(row.In)
		if ok != (row.Out != nil) || ok && (wildcard != row.Out[0].(bool) || domain != row.Out[1].(string)) {
			t.Errorf("dnsblReduceRegex(%s) = %v %s %v, Python says %v", pysem.Repr(row.In), wildcard, pysem.Repr(domain), ok, row.Out)
		}
	}
}

func TestAbpOracleIP(t *testing.T) {
	for _, row := range abpOracle(t).IP {
		if got := dnsblIsIpv4(row.In); got != row.Ipv4 {
			t.Errorf("dnsblIsIpv4(%s) = %v, Python says %v", pysem.Repr(row.In), got, row.Ipv4)
		}
		if got := dnsblIsNumericHost(row.In); got != row.NumericHost {
			t.Errorf("dnsblIsNumericHost(%s) = %v, Python says %v", pysem.Repr(row.In), got, row.NumericHost)
		}
	}
}

func TestAbpOracleWhitelist(t *testing.T) {
	rows := abpOracle(t).Whitelist
	if len(rows) < 30 {
		t.Fatalf("oracle table has %d whitelist rows", len(rows))
	}
	for _, row := range rows {
		tally := rejectTally{}
		got := dnsblNormaliseWhitelist(row.Entries, tally, row.Source)
		if want := whitelistFromRows(row.Out); !maps.Equal(got, want) {
			t.Errorf("dnsblNormaliseWhitelist(%q):\n got  %+v\n want %+v", row.Entries, got, want)
		}
		if got, want := tallyRows(tally), oracleTallyRows(row.Tally); !slices.Equal(got, want) {
			t.Errorf("dnsblNormaliseWhitelist(%q) tally:\n got  %q\n want %q", row.Entries, got, want)
		}
	}
}

func TestAbpOracleReconcile(t *testing.T) {
	rows := abpOracle(t).Reconcile
	if len(rows) < 15 {
		t.Fatalf("oracle table has %d reconcile scenarios", len(rows))
	}
	for _, row := range rows {
		tally := rejectTally{}
		var rules []rule
		for _, seg := range row.Segments {
			prov, feed, group, log := seg[0].(string), seg[1].(string), seg[2].(string), seg[3].(string)
			for _, line := range seg[4].([]any) {
				if r := parseAbp(line.(string), prov, feed, group, log, tally); r != nil {
					rules = append(rules, *r)
				}
			}
		}
		exclusion := map[string]struct{}{}
		for _, d := range row.Exclusion {
			exclusion[d] = struct{}{}
		}
		res := reconcile(rules, abpTlds, exclusion, tally)

		var got abpOracleResult
		for _, b := range res.blockDomains {
			got.BlockDomains = append(got.BlockDomains, strings.Join([]string{b.cls, b.key, fmt.Sprint(b.band), b2i(b.important), b.provenance, b.feed, b.group, b.log}, "\t"))
		}
		for _, a := range res.allowDomains {
			got.AllowDomains = append(got.AllowDomains, strings.Join([]string{a.domain, b2i(a.wildcard), fmt.Sprint(a.band), b2i(a.important), a.provenance}, "\t"))
		}
		regexRows := func(rs []regexRule) (out []string) {
			for _, r := range rs {
				out = append(out, strings.Join([]string{r.pattern, r.kind, fmt.Sprint(r.band), b2i(r.important), r.provenance, r.feed, r.group, r.log}, "\t"))
			}
			return out
		}
		got.BlockRegexIrreducible, got.AllowRegexIrreducible = regexRows(res.blockRegexIrreducible), regexRows(res.allowRegexIrreducible)
		important := 0
		if res.importantRules {
			important = 1
		}
		got.Counters = [4]int{important, res.pruned, res.reduced, res.skippedBadfilter}
		got.Tally = tallyRows(tally)

		want := row.Result
		if !slices.Equal(got.BlockDomains, want.BlockDomains) || !slices.Equal(got.AllowDomains, want.AllowDomains) ||
			!slices.Equal(got.BlockRegexIrreducible, want.BlockRegexIrreducible) || !slices.Equal(got.AllowRegexIrreducible, want.AllowRegexIrreducible) ||
			got.Counters != want.Counters || !slices.Equal(got.Tally, want.Tally) {
			t.Errorf("%s:\n got  %+v\n want %+v", row.Name, got, want)
		}
	}
}
