// Tests of pfb_unbound_psl.go. Ported from tests/test_psl_resolver.py, tests/test_psl_runtime_integration.py (the
// classifier and authority-loader rows), tests/test_issue2371_feed_suffix_policy.py (TestSuffixFeedPolicyPredicate)
// and tests/test_issue3056_label_charset.py (the _psl_normalize_name rows). Rows the Python tests do not have were
// produced by running pfb_unbound.py under CPython 3.11 (unicodedata 14.0.0) and are marked "oracle"; the rows in
// pslIdnaDivergences are the ones where the Go answer (golang.org/x/net/idna, UTS #46) deliberately differs from
// Python's IDNA2003 codec.
//
// Not ported, because they pin CPython internals with no Go counterpart: test_resolver_throughput_is_indexed_not_linear_scan's
// rule-set hash count (the lru_cache regression of issue #3046) and test_ascii_psl_validation_avoids_per_label_any_scans
// and test_ascii_validation_python_work_does_not_scale_with_label_length (cProfile call counts). The index-built-once half
// of the throughput test is TestPslRulesIndexIsBuiltOnceAndRaceFree and TestResolvePublicSuffixDoesNotRebuildTheIndex.
package decider

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

const pslResolverAuthority = `# Public Suffix List authority
// ===BEGIN ICANN DOMAINS===
com
co.uk
act.edu.au
chtr.k12.ma.us
*.ck
!www.ck
io
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
*.nom.br
one.two.three.four.five.example
*.two.three.four.five.six.example
// ===END PRIVATE DOMAINS===
`

const pslRuntimeAuthority = `// ===BEGIN ICANN DOMAINS===
com
io
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
`

const pslPolicyAuthority = `// ===BEGIN ICANN DOMAINS===
com
io
co.uk
xn--p1ai
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
`

const pslShippedAuthority = "../../../src/usr/local/pkg/pfblockerng/dnsbl_psl"

func pslMustParse(t *testing.T, text string) pslRules {
	t.Helper()
	rules, err := parsePslRules(text)
	if err != nil {
		t.Fatalf("parsePslRules: %v", err)
	}
	return rules
}

// pslResult renders (value, error) as "ok:<value>" or "err:<message>"; the messages are Python's ValueError texts.
func pslResult(value string, err error) string {
	if err != nil {
		if !errors.As(err, new(*valueError)) {
			return "not a ValueError: " + err.Error()
		}
		return "err:" + err.Error()
	}
	return "ok:" + value
}

func pslNormalizeNameResult(name string) string {
	got, err := pslNormalizeName(name)
	return pslResult(got, err)
}

func pslNormalizeQueryResult(name string) string {
	labels, err := pslNormalizeQuery(name)
	return pslResult(strings.Join(labels, "|"), err)
}

func pslResolutionRow(r pslResolution) [4]any {
	return [4]any{r.icannSuffix, r.publicSuffix, r.registrableDomain, r.privateActive}
}

func TestParsePslRulesPreservesSectionsRulesAndMarkers(t *testing.T) { // test_parser_preserves_sections_rules_and_markers
	rules := pslMustParse(t, pslResolverAuthority)
	for _, c := range []struct {
		field     string
		got, want []string
	}{
		{"icannExact", rules.icannExact, []string{"com", "co.uk", "act.edu.au", "chtr.k12.ma.us", "io"}},
		{"icannWildcard", rules.icannWildcard, []string{"ck"}},
		{"icannException", rules.icannException, []string{"www.ck"}},
		{"privateExact", rules.privateExact, []string{"github.io", "one.two.three.four.five.example"}},
		{"privateWildcard", rules.privateWildcard, []string{"nom.br", "two.three.four.five.six.example"}},
		{"privateException", rules.privateException, nil},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

func TestResolvePublicSuffixPrecedenceAndPrivateBoundary(t *testing.T) { // test_resolver_precedence_and_private_boundary
	rules := pslMustParse(t, pslResolverAuthority)
	for _, c := range []struct {
		name, icann, public, registrable string
		private                          bool
	}{
		{"example.com", "com", "com", "example.com", false},
		{"example.co.uk", "co.uk", "co.uk", "example.co.uk", false},
		{"example.act.edu.au", "act.edu.au", "act.edu.au", "example.act.edu.au", false},
		{"example.chtr.k12.ma.us", "chtr.k12.ma.us", "chtr.k12.ma.us", "example.chtr.k12.ma.us", false},
		{"a.ck", "a.ck", "a.ck", "", false},
		{"www.ck", "ck", "ck", "www.ck", false},
		{"x.www.ck", "ck", "ck", "www.ck", false},
		{"evil.github.io", "io", "github.io", "evil.github.io", true},
		{"github.io", "io", "github.io", "", true},
		{"evil.nom.br", "br", "evil.nom.br", "", true},
		{"foo.unknown", "unknown", "unknown", "foo.unknown", false},
	} {
		got, err := resolvePublicSuffix(c.name, rules)
		want := pslResolution{c.icann, c.public, c.registrable, c.private}
		if err != nil || got != want {
			t.Errorf("resolvePublicSuffix(%q) = %+v, %v; want %+v", c.name, got, err, want)
		}
	}
}

func TestResolvePublicSuffixExceptionsBeatWildcardsAtAnyDepth(t *testing.T) { // oracle: _psl_prevailing exception carve-out
	rules := pslMustParse(t, `// ===BEGIN ICANN DOMAINS===
jp
*.kawasaki.jp
!city.kawasaki.jp
*.deep.test
!a.deep.test
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
*.priv.example
!ok.priv.example
// ===END PRIVATE DOMAINS===
`)
	for _, c := range []struct {
		name, icann, public, registrable string
		private                          bool
	}{
		{"city.kawasaki.jp", "kawasaki.jp", "kawasaki.jp", "city.kawasaki.jp", false},
		{"a.city.kawasaki.jp", "kawasaki.jp", "kawasaki.jp", "city.kawasaki.jp", false},
		{"kawasaki.jp", "jp", "jp", "kawasaki.jp", false},
		{"foo.kawasaki.jp", "foo.kawasaki.jp", "foo.kawasaki.jp", "", false},
		{"x.foo.kawasaki.jp", "foo.kawasaki.jp", "foo.kawasaki.jp", "x.foo.kawasaki.jp", false},
		{"jp", "jp", "jp", "", false},
		{"a.deep.test", "deep.test", "deep.test", "a.deep.test", false},
		{"b.a.deep.test", "deep.test", "deep.test", "a.deep.test", false},
		{"c.deep.test", "c.deep.test", "c.deep.test", "", false},
		// A PRIVATE exception carves only the combined view: the ICANN-only suffix stays the bare TLD.
		{"ok.priv.example", "example", "priv.example", "ok.priv.example", true},
		{"a.ok.priv.example", "example", "priv.example", "ok.priv.example", true},
		{"b.priv.example", "example", "b.priv.example", "", true},
		{"x.b.priv.example", "example", "b.priv.example", "x.b.priv.example", true},
		{"priv.example", "example", "example", "priv.example", false},
		{"example", "example", "example", "", false},
		{"a.example", "example", "example", "a.example", false},
	} {
		got, err := resolvePublicSuffix(c.name, rules)
		want := pslResolution{c.icann, c.public, c.registrable, c.private}
		if err != nil || got != want {
			t.Errorf("resolvePublicSuffix(%q) = %+v, %v; want %+v", c.name, got, err, want)
		}
	}
}

func TestIdnaRawAndPunycodeNamesAreEquivalent(t *testing.T) { // test_idna_raw_and_punycode_names_are_equivalent
	rules := pslMustParse(t, strings.ReplaceAll(pslResolverAuthority, "com\n", "com\nxn--p1ai\n"))
	raw, rawErr := resolvePublicSuffix("пример.рф", rules)
	ace, aceErr := resolvePublicSuffix("xn--e1afmkfd.xn--p1ai", rules)
	if rawErr != nil || aceErr != nil || raw != ace {
		t.Errorf("raw = %+v, %v; punycode = %+v, %v; want equal and no error", raw, rawErr, ace, aceErr)
	}
	if want := (pslResolution{"xn--p1ai", "xn--p1ai", "xn--e1afmkfd.xn--p1ai", false}); raw != want {
		t.Errorf("resolution = %+v, want %+v", raw, want)
	}
}

func TestResolvePublicSuffixRejectsMalformedNames(t *testing.T) { // test_resolver_rejects_malformed_names
	rules := pslMustParse(t, pslResolverAuthority)
	for _, name := range []string{"", ".example.com", "example.com.", "a..example.com", "*", "bad name.example", "a\x00.example",
		"a." + strings.Repeat("x", 64) + ".com", "a." + strings.Repeat("x", 250) + ".com"} {
		if got, err := resolvePublicSuffix(name, rules); err == nil || !errors.As(err, new(*valueError)) {
			t.Errorf("resolvePublicSuffix(%q) = %+v, %v; want a ValueError", name, got, err)
		}
	}
}

func TestParsePslRulesRefusesBadMarkersOrOrphanExceptions(t *testing.T) { // test_parser_refuses_bad_markers_or_orphan_exceptions
	markers := "PSL authority markers missing or duplicated"
	orphan := "PSL exception has no wildcard family"
	for _, c := range []struct{ authority, want string }{
		{strings.ReplaceAll(pslResolverAuthority, "// ===BEGIN ICANN DOMAINS===", "// ===BEGIN ICANN DOMAINS===\n// ===BEGIN ICANN DOMAINS==="), markers},
		{strings.ReplaceAll(pslResolverAuthority, "// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===\n// ===END ICANN DOMAINS==="), markers},
		{strings.ReplaceAll(pslResolverAuthority, "// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS===\n// ===BEGIN PRIVATE DOMAINS==="), markers},
		{strings.ReplaceAll(pslResolverAuthority, "!www.ck\n", "!orphan.example\n"), orphan},
		{strings.ReplaceAll(pslResolverAuthority, "*.ck\n", ""), orphan},
	} {
		if _, err := parsePslRules(c.authority); err == nil || err.Error() != c.want {
			t.Errorf("parsePslRules error = %v, want %q", err, c.want)
		}
	}
}

func TestParsePslRulesRefusesMarkersOutOfOrder(t *testing.T) { // oracle: parse_psl_rules reports order only after the counts pass
	swapped := strings.NewReplacer(
		"// ===BEGIN ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===", "// ===END ICANN DOMAINS===", "// ===END PRIVATE DOMAINS===",
		"// ===BEGIN PRIVATE DOMAINS===", "// ===BEGIN ICANN DOMAINS===", "// ===END PRIVATE DOMAINS===", "// ===END ICANN DOMAINS===",
	).Replace(pslResolverAuthority)
	if _, err := parsePslRules(swapped); err == nil || err.Error() != "PSL authority markers out of order" {
		t.Errorf("parsePslRules(private section first) error = %v, want %q", err, "PSL authority markers out of order")
	}
}

func TestParsePslRulesRejectsShellAndRegexMetacharacters(t *testing.T) { // test_parser_rejects_shell_and_regex_metacharacters
	for _, rule := range []string{"a$[b].com", "a|b.com", "a;$(id).com"} {
		_, err := parsePslRules(strings.Replace(pslResolverAuthority, "com\n", "com\n"+rule+"\n", 1))
		if err == nil || err.Error() != "invalid DNS label" {
			t.Errorf("parsePslRules(rule %q) error = %v, want %q", rule, err, "invalid DNS label")
		}
	}
}

func TestParserAndResolverRejectInvalidAceLabels(t *testing.T) { // test_parser_and_resolver_reject_invalid_ace_labels
	for _, label := range []string{"xn--bad", "xn--abc"} {
		_, err := parsePslRules(strings.Replace(pslResolverAuthority, "com\n", "com\n"+label+"\n", 1))
		if err == nil || err.Error() != "invalid IDNA label" {
			t.Errorf("parsePslRules(rule %q) error = %v, want %q", label, err, "invalid IDNA label")
		}
		got, err := resolvePublicSuffix(label+".com", pslMustParse(t, pslResolverAuthority))
		if err == nil || err.Error() != "invalid IDNA label" {
			t.Errorf("resolvePublicSuffix(%q) = %+v, %v; want %q", label+".com", got, err, "invalid IDNA label")
		}
	}
}

func TestParsePslRulesAcceptsDuplicateOverlappingRules(t *testing.T) { // test_parser_accepts_duplicate_overlapping_rules_without_changing_precedence
	text := strings.ReplaceAll(strings.ReplaceAll(pslResolverAuthority, "com\n", "com\ncom\n"), "*.ck\n", "*.ck\n*.ck\n")
	rules := pslMustParse(t, text)
	if want := []string{"com", "com", "co.uk", "act.edu.au", "chtr.k12.ma.us", "io"}; !slices.Equal(rules.icannExact, want) {
		t.Errorf("icannExact = %q, want %q (duplicates kept, in source order)", rules.icannExact, want)
	}
	for name, want := range map[string]string{"example.com": "com", "a.ck": "a.ck"} {
		if got, err := resolvePublicSuffix(name, rules); err != nil || got.publicSuffix != want {
			t.Errorf("resolvePublicSuffix(%q).publicSuffix = %q, %v; want %q", name, got.publicSuffix, err, want)
		}
	}
}

func TestParsePslRulesLineAndRuleShapes(t *testing.T) { // oracle: _psl_rule_token / _psl_section
	// A rule line is its first whitespace-separated token: a trailing comment after the rule is dropped. # and //
	// lines and blank lines are skipped, and every str.splitlines() break ends a line.
	text := "// ===BEGIN ICANN DOMAINS===\r\n  com  // the one\n\n# note\n// note\nco.uk\tx\u0085!www.ck\u2028*.ck\x0cEXAMPLE.Org\n// ===END ICANN DOMAINS===\x0b// ===BEGIN PRIVATE DOMAINS===\r// ===END PRIVATE DOMAINS===\u2029"
	rules := pslMustParse(t, text)
	if want := []string{"com", "co.uk", "example.org"}; !slices.Equal(rules.icannExact, want) {
		t.Errorf("icannExact = %q, want %q", rules.icannExact, want)
	}
	if !slices.Equal(rules.icannWildcard, []string{"ck"}) || !slices.Equal(rules.icannException, []string{"www.ck"}) {
		t.Errorf("wildcard = %q, exception = %q; want [ck], [www.ck]", rules.icannWildcard, rules.icannException)
	}
	for _, c := range []struct{ line, want string }{
		{"*.com", "ok:wildcard|com"}, {"!a.com", "ok:exception|a.com"}, {"Com", "ok:exact|com"}, {"  com  x", "ok:exact|com"},
		{"a.*.com", "err:invalid PSL rule"}, {"a*", "err:invalid PSL rule"}, {"a!b", "err:invalid PSL rule"},
		{"*.", "err:invalid PSL rule"}, {"!", "err:invalid PSL rule"}, {".com", "err:invalid PSL rule"}, {"com.", "err:invalid PSL rule"},
		{"a..com", "err:invalid PSL rule"}, {"", "err:not a rule"}, {"   ", "err:not a rule"}, {"#com", "err:not a rule"},
		{"//com", "err:not a rule"}, {"*.*.com", "err:invalid DNS label"}, {"!*.com", "err:invalid DNS label"},
	} {
		kind, name, err := pslRuleToken(c.line)
		if got := pslResult(kind+"|"+name, err); got != c.want {
			t.Errorf("pslRuleToken(%q) = %s, want %s", c.line, got, c.want)
		}
	}
}

func TestPslSplitlinesMatchesPython(t *testing.T) { // oracle: str.splitlines
	for _, c := range []struct {
		text string
		want []string
	}{
		{"a\nb\r\nc\rd\x0be\x0cf\x1cg\x1dh\x1ei\u0085j\u2028k\u2029l", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"}},
		{"a\n", []string{"a"}},
		{"a\n\n", []string{"a", ""}},
		{"", nil},
		{"\n", []string{""}},
		{"a\r\n\r\nb", []string{"a", "", "b"}},
		{"a\r", []string{"a"}},
		{"\r\r\n", []string{"", ""}},
	} {
		if got := pslSplitlines(c.text); !slices.Equal(got, c.want) {
			t.Errorf("pslSplitlines(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

func TestPslRulesIndexIsBuiltOnceAndRaceFree(t *testing.T) { // test_resolver_throughput_is_indexed_not_linear_scan, the index-rebuild half
	rules := pslMustParse(t, pslResolverAuthority)
	if rules.cachedIndex.Load() != nil {
		t.Fatal("parsePslRules built the index eagerly; Python builds it on first use")
	}
	icann, combined := rules.index()
	first := rules.cachedIndex.Load()
	if first == nil {
		t.Fatal("index() left nothing cached on the rules")
	}
	icann2, combined2 := rules.index()
	for _, c := range []struct {
		what       string
		first, now map[string]struct{}
	}{
		{"icann exact", icann.exact, icann2.exact}, {"icann wildcard", icann.wildcard, icann2.wildcard},
		{"combined exact", combined.exact, combined2.exact}, {"combined exception", combined.exception, combined2.exception},
	} {
		if reflect.ValueOf(c.first).Pointer() != reflect.ValueOf(c.now).Pointer() {
			t.Errorf("%s set was rebuilt by the second index() call", c.what)
		}
	}
	if _, ok := combined.exact["github.io"]; !ok {
		t.Error("the combined view lacks the PRIVATE rule github.io")
	}
	if _, ok := icann.exact["github.io"]; ok {
		t.Error("the ICANN-only view holds the PRIVATE rule github.io")
	}
	if _, ok := combined.exception["www.ck"]; !ok {
		t.Error("the combined view lacks the ICANN exception www.ck")
	}
	copied := rules
	if copied.cachedIndex.Load() != first {
		t.Error("a copy of the rules does not share the index")
	}

	// Racing first uses on a fresh rule set: -race fails if the lazy build is a plain store.
	fresh := pslMustParse(t, pslResolverAuthority)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if got, err := resolvePublicSuffix("evil.github.io", fresh); err != nil || got.publicSuffix != "github.io" {
					t.Errorf("resolvePublicSuffix under contention = %+v, %v", got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestResolvePublicSuffixDoesNotRebuildTheIndex(t *testing.T) { // test_resolver_throughput_is_indexed_not_linear_scan
	rules, err := loadPslAuthority(pslShippedAuthority, true)
	if err != nil {
		t.Fatal(err)
	}
	rules.index()
	// A resolve allocates its label slices (about a kilobyte); rebuilding the ~10k-rule sets allocates hundreds of
	// kilobytes, so 600 resolves under 4 MiB cannot be rebuilding them.
	names := []string{"example.com", "foo.bar.co.uk", "tenant.github.io", "deep.a.b.c.example.org", "evil.foo.ck", "host.one.two.three.example.nom.br"}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 100 {
		for _, name := range names {
			if _, err := resolvePublicSuffix(name, rules); err != nil {
				t.Fatal(err)
			}
		}
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4<<20 {
		t.Errorf("600 resolves allocated %d bytes; the index is being rebuilt per lookup", grew)
	}
}

func TestShippedPslAuthorityLoadsAsPythonDoes(t *testing.T) { // oracle: the shipped dnsbl_psl under Python 3.11
	rules, err := loadPslAuthority(pslShippedAuthority, true)
	if err != nil {
		t.Fatalf("the shipped PSL authority no longer loads (a UTS #46 table change refusing one of its ~460 xn-- rules fails the whole authority): %v", err)
	}
	for _, c := range []struct {
		field string
		got   []string
		want  int
	}{
		{"icannExact", rules.icannExact, 6927}, {"icannWildcard", rules.icannWildcard, 16}, {"icannException", rules.icannException, 8},
		{"privateExact", rules.privateExact, 3162}, {"privateWildcard", rules.privateWildcard, 298}, {"privateException", rules.privateException, 0},
	} {
		if len(c.got) != c.want {
			t.Errorf("len(%s) = %d, want %d", c.field, len(c.got), c.want)
		}
	}
	if rules.icannExact[0] != "ac" || rules.icannWildcard[0] != "nom.br" || rules.privateExact[0] != "co.krd" || rules.privateWildcard[0] != "dev.adobeaemcloud.com" {
		t.Errorf("source order lost: %q %q %q %q", rules.icannExact[0], rules.icannWildcard[0], rules.privateExact[0], rules.privateWildcard[0])
	}
	for _, c := range []struct {
		name string
		want pslResolution
	}{
		{"example.com", pslResolution{"com", "com", "example.com", false}},
		{"foo.bar.co.uk", pslResolution{"co.uk", "co.uk", "bar.co.uk", false}},
		{"tenant.github.io", pslResolution{"io", "github.io", "tenant.github.io", true}},
		{"deep.a.b.c.example.org", pslResolution{"org", "org", "example.org", false}},
		{"evil.foo.ck", pslResolution{"foo.ck", "foo.ck", "evil.foo.ck", false}},
		{"host.one.two.three.example.nom.br", pslResolution{"example.nom.br", "example.nom.br", "three.example.nom.br", false}},
		{"no-rule.zz-unknown", pslResolution{"zz-unknown", "zz-unknown", "no-rule.zz-unknown", false}},
		{"x.act.edu.au", pslResolution{"act.edu.au", "act.edu.au", "x.act.edu.au", false}},
		{"www.ck", pslResolution{"ck", "ck", "www.ck", false}},
		{"пример.рф", pslResolution{"xn--p1ai", "xn--p1ai", "xn--e1afmkfd.xn--p1ai", false}},
		{"xn--e1afmkfd.xn--p1ai", pslResolution{"xn--p1ai", "xn--p1ai", "xn--e1afmkfd.xn--p1ai", false}},
		{"münchen.de", pslResolution{"de", "de", "xn--mnchen-3ya.de", false}},
		{"a.b.xn--mnchen-3ya.com", pslResolution{"com", "com", "xn--mnchen-3ya.com", false}},
	} {
		if got, err := resolvePublicSuffix(c.name, rules); err != nil || got != c.want {
			t.Errorf("resolvePublicSuffix(%q) = %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
}

func TestZeroPslRulesIsPythonsEmptyPslRules(t *testing.T) { // oracle: PslRules()
	got, err := resolvePublicSuffix("example.com", pslRules{})
	if want := (pslResolution{"com", "com", "example.com", false}); err != nil || got != want {
		t.Errorf("resolvePublicSuffix on the zero pslRules = %+v, %v; want %+v", got, err, want)
	}
	if class, key := tldWildcardClassify("example.com", pslRules{}, nil, true, nil); class != DNSBL_CLASS_DATA || key != "example.com" {
		t.Errorf("tldWildcardClassify on the zero pslRules = %q, %q; want data, example.com (no rules: wildcard classification off)", class, key)
	}
	hand := pslRules{icannExact: []string{"com"}, privateExact: []string{"github.io"}} // no cached index: rebuilt per use, still correct
	if got, err := resolvePublicSuffix("a.github.io", hand); err != nil || got.publicSuffix != "github.io" || !got.privateActive {
		t.Errorf("resolvePublicSuffix on hand-built rules = %+v, %v; want github.io, private", got, err)
	}
}

func TestLoadPslAuthority(t *testing.T) { // test_psl_authority_loader_rejects_invalid_files, test_psl_authority_loader_off_is_exact_only_without_open, oracle
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	prefix := func(path string) string { return "PSL authority '" + path + "': " }

	if rules, err := loadPslAuthority(filepath.Join(dir, "missing"), false); err != nil || len(rules.icannExact) != 0 || rules.cachedIndex != nil {
		t.Errorf("disabled load of a missing file = %+v, %v; want the empty PslRules() without opening it", rules, err)
	}
	for i, bad := range []string{"", "not-a-psl", "xn--bad", "a..com", "a$[b].com"} {
		path := write("bad"+string(rune('0'+i)), []byte(bad))
		if _, err := loadPslAuthority(path, true); err == nil || err.Error() != prefix(path)+"PSL authority markers missing or duplicated" {
			t.Errorf("loadPslAuthority(file %q) error = %v, want markers refusal", bad, err)
		}
	}
	framedBad := strings.Replace(pslResolverAuthority, "com\n", "com\nxn--bad\n", 1)
	path := write("framed", []byte(framedBad))
	if _, err := loadPslAuthority(path, true); err == nil || err.Error() != prefix(path)+"invalid IDNA label" {
		t.Errorf("loadPslAuthority(framed bad rule) error = %v, want invalid IDNA label", err)
	}
	path = write("nul", []byte(strings.Replace(pslResolverAuthority, "com\n", "com\n\x00\n", 1)))
	if _, err := loadPslAuthority(path, true); err == nil || err.Error() != prefix(path)+"authority contains NUL" {
		t.Errorf("loadPslAuthority(NUL) error = %v, want authority contains NUL", err)
	}
	path = write("latin1", []byte(strings.Replace(pslResolverAuthority, "com\n", "com\n\xff\n", 1)))
	if _, err := loadPslAuthority(path, true); err == nil || !errors.As(err, new(*valueError)) || !strings.HasPrefix(err.Error(), prefix(path)) {
		t.Errorf("loadPslAuthority(invalid UTF-8) error = %v, want a ValueError carrying the path", err)
	}
	if _, err := loadPslAuthority(dir, true); err == nil || err.Error() != prefix(dir)+"authority is not a readable regular file" {
		t.Errorf("loadPslAuthority(directory) error = %v, want not a readable regular file", err)
	}
	missing := filepath.Join(dir, "missing")
	if _, err := loadPslAuthority(missing, true); err == nil || !errors.As(err, new(*valueError)) || !strings.HasPrefix(err.Error(), prefix(missing)) {
		t.Errorf("loadPslAuthority(missing file) error = %v, want a ValueError carrying the path", err)
	}
	path = write("good", []byte(pslResolverAuthority))
	rules, err := loadPslAuthority(path, true)
	if err != nil || !slices.Equal(rules.icannExact, pslMustParse(t, pslResolverAuthority).icannExact) || !slices.Equal(rules.privateWildcard, []string{"nom.br", "two.three.four.five.six.example"}) {
		t.Errorf("loadPslAuthority(good file) = %+v, %v", rules, err)
	}
}

func TestPslNormalizeNameEmptyNamesAndLabelsAreRejected(t *testing.T) { // test_empty_names_and_labels_are_rejected
	for _, name := range []string{"", ".", "a..com"} {
		if got := pslNormalizeNameResult(name); got != "err:invalid DNS name" {
			t.Errorf("pslNormalizeName(%q) = %s, want err:invalid DNS name", name, got)
		}
	}
}

func TestPslNormalizeNameAsciiAlphabetsRemainDistinct(t *testing.T) { // test_ascii_alphabets_remain_distinct
	for codepoint := range 128 {
		char := string(rune(codepoint))
		name := "a" + char + "b.com"
		allowed := strings.Contains("abcdefghijklmnopqrstuvwxyz0123456789-", strings.ToLower(char)) || char == "."
		want := "err:invalid DNS label"
		if allowed {
			want = "ok:" + strings.ToLower(name)
		}
		if got := pslNormalizeNameResult(name); got != want {
			t.Errorf("pslNormalizeName(%q) = %s, want %s", name, got, want)
		}
	}
}

// pslNameRows are inputs on which Go and Python agree: name, pslNormalizeName, pslNormalizeQuery (labels joined by "|").
// test_idna_normalization_is_preserved and test_hostile_labels_are_rejected rows are among them; the rest are oracle.
var pslNameRows = []struct{ name, strict, query string }{
	{"BÜCHER.de", "ok:xn--bcher-kva.de", "ok:xn--bcher-kva|de"},
	{"xn--bcher-kva.de", "ok:xn--bcher-kva.de", "ok:xn--bcher-kva|de"},
	{"XN--BCHER-KVA.de", "ok:xn--bcher-kva.de", "ok:xn--bcher-kva|de"},
	{"münchen.de", "ok:xn--mnchen-3ya.de", "ok:xn--mnchen-3ya|de"},
	{"MÜNCHEN.DE", "ok:xn--mnchen-3ya.de", "ok:xn--mnchen-3ya|de"},
	{"MAÑANA.com", "ok:xn--maana-pta.com", "ok:xn--maana-pta|com"},
	{"a\u0301.com", "ok:xn--1ca.com", "ok:xn--1ca|com"},
	{"пример.рф", "ok:xn--e1afmkfd.xn--p1ai", "ok:xn--e1afmkfd|xn--p1ai"},
	{"xn--e1afmkfd.xn--p1ai", "ok:xn--e1afmkfd.xn--p1ai", "ok:xn--e1afmkfd|xn--p1ai"},
	{"XN--E1AFMKFD.com", "ok:xn--e1afmkfd.com", "ok:xn--e1afmkfd|com"},
	{"ΣΑΣ.gr", "ok:xn--mxa9ab.gr", "ok:xn--mxa9ab|gr"},
	{"Σ.gr", "ok:xn--4xa.gr", "ok:xn--4xa|gr"},
	{"ǅ.com", "ok:xn--d-toa.com", "ok:xn--d-toa|com"},
	{"İ.com", "ok:xn--i-9bb.com", "ok:xn--i-9bb|com"},
	{"ı.com", "ok:xn--cfa.com", "ok:xn--cfa|com"},
	{"\u1c90.ge", "ok:xn--lod.ge", "ok:xn--lod|ge"},
	{"\u05d0\u05d1.com", "ok:xn--4dbc.com", "ok:xn--4dbc|com"},
	{"\u0f0b.com", "ok:xn--nbd.com", "ok:xn--nbd|com"},
	{"\ud7a0.kr", "ok:xn--r78b.kr", "ok:xn--r78b|kr"},
	{"\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com", "ok:example.com", "ok:example|com"},
	{"\u2460.com", "ok:1.com", "ok:1|com"},
	{"a\u2160b.com", "ok:aib.com", "ok:aib|com"},
	{"\ufb01.com", "ok:fi.com", "ok:fi|com"},
	{"a\U0001f600b.com", "ok:xn--ab-no82a.com", "ok:xn--ab-no82a|com"},
	{"\U0001f600.com", "ok:xn--e28h.com", "ok:xn--e28h|com"},
	{"ab--ü.com", "ok:xn--ab---3ra.com", "ok:xn--ab---3ra|com"},
	{"-ü.com", "ok:xn----eha.com", "ok:xn----eha|com"},
	{"ü-.com", "ok:xn----dha.com", "ok:xn----dha|com"},
	{"_ü.com", "err:invalid DNS label", "ok:xn--_-eha|com"},
	{"a\u200bb.com", "err:invalid DNS label", "ok:ab|com"},
	{"a\x00b.com", "err:invalid DNS label", "ok:a\x00b|com"},
	{"a\x01b.com", "err:invalid DNS label", "ok:a\x01b|com"},
	{"a\x7fb.com", "err:invalid DNS label", "ok:a\x7fb|com"},
	{"a\x1cb.com", "err:invalid DNS label", "ok:a\x1cb|com"},
	{"a\t b.com", "err:invalid DNS label", "ok:a\t b|com"},
	{"a b.com", "err:invalid DNS label", "ok:a b|com"},
	{"a\u00a0b.com", "err:invalid DNS label", "ok:a b|com"},
	{"a\u2028b.com", "err:invalid DNS label", "ok:a\u2028b|com"},
	{"a\u00adb.com", "err:invalid DNS label", "ok:ab|com"},
	{"a\u3002b.com", "err:invalid DNS label", "ok:a.b|com"},
	{"\u3002a.com", "err:invalid IDNA label", "ok:\u3002a|com"},
	{"\u05d0a.com", "err:invalid IDNA label", "ok:\u05d0a|com"},
	{"a1\u05d0.com", "err:invalid IDNA label", "ok:a1\u05d0|com"},
	{"xn--bad.com", "err:invalid IDNA label", "ok:xn--bad|com"},
	{"xn--abc.com", "err:invalid IDNA label", "ok:xn--abc|com"},
	{"xn--a-.com", "err:invalid IDNA label", "ok:xn--a-|com"},
	{"xn--.com", "err:invalid IDNA label", "ok:xn--|com"},
	{"xn--ab.com", "err:invalid IDNA label", "ok:xn--ab|com"},
	{"xn--fi-.com", "err:invalid IDNA label", "ok:xn--fi-|com"},
	{"xn--0xai.gr", "ok:xn--0xai.gr", "ok:xn--0xai|gr"},
	{"xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "err:invalid IDNA label", "ok:xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"xn--p1ai", "ok:xn--p1ai", "ok:xn--p1ai"},
	{"-bad.com", "err:invalid DNS label", "ok:-bad|com"},
	{"bad-.com", "err:invalid DNS label", "ok:bad-|com"},
	{"a_b.com", "err:invalid DNS label", "ok:a_b|com"},
	{"A-B.COM", "ok:a-b.com", "ok:a-b|com"},
	{"a--b.com", "ok:a--b.com", "ok:a--b|com"},
	{"a*b.com", "err:invalid DNS label", "ok:a*b|com"},
	{"a!b.com", "err:invalid DNS label", "ok:a!b|com"},
	{"1.com", "ok:1.com", "ok:1|com"},
	{"WWW.Example.COM", "ok:www.example.com", "ok:www|example|com"},
	{"_dmarc.example.com", "err:invalid DNS label", "ok:_dmarc|example|com"},
	{"_sip._tcp.example.com", "err:invalid DNS label", "ok:_sip|_tcp|example|com"},
	{"üüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüü.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"üüüüüüüüüüüüüüüüüüüüüüüüüüüüüüü.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"üüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüü.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "ok:xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "err:invalid DNS label", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "err:invalid DNS name", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|com"},
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "err:invalid DNS name", "ok:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"éééééééééééééééééééééééééééééé.éééééééééééééééééééééééééééééé.éééééééééééééééééééééééééééééé.éééééééééééééééééééééééééééééé.éééééééééééééééééééééééééééééé", "err:invalid DNS name", "ok:xn--9caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|xn--9caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|xn--9caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|xn--9caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|xn--9caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"", "err:invalid DNS name", "err:invalid DNS name"},
	{".", "err:invalid DNS name", "err:invalid DNS name"},
	{"a..b", "err:invalid DNS name", "err:invalid DNS name"},
	{".example.com", "err:invalid DNS name", "err:invalid DNS name"},
	{"example.com.", "err:invalid DNS name", "err:invalid DNS name"},
	{"x.", "err:invalid DNS name", "err:invalid DNS name"},
	{"x..y", "err:invalid DNS name", "err:invalid DNS name"},
	{".x", "err:invalid DNS name", "err:invalid DNS name"},
	{"example.com", "ok:example.com", "ok:example|com"},
	{"*", "err:invalid DNS label", "ok:*"},
	{"bad name.example", "err:invalid DNS label", "ok:bad name|example"},
	{"a\x00.example", "err:invalid DNS label", "ok:a\x00|example"},
	{"a.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com", "err:invalid DNS label", "ok:a|xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|com"},
	{"a.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com", "err:invalid DNS name", "ok:a|xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|com"},
	{"a\x01b", "err:invalid DNS label", "ok:a\x01b"},
}

func TestPslNormalizeNameAndQueryMatchPython(t *testing.T) {
	for _, c := range pslNameRows {
		if got := pslNormalizeNameResult(c.name); got != c.strict {
			t.Errorf("pslNormalizeName(%q) = %s, want %s", c.name, got, c.strict)
		}
		if got := pslNormalizeQueryResult(c.name); got != c.query {
			t.Errorf("pslNormalizeQuery(%q) = %s, want %s", c.name, got, c.query)
		}
	}
}

// pslIdnaDivergences are the inputs where the Go answer (golang.org/x/net/idna, UTS #46 non-transitional, Unicode of
// the Go toolchain) differs from the Python codec's (IDNA2003 / RFC 3490 nameprep, Unicode 14). The Go result is
// asserted; the Python result is named in the failure message. Owner decision on #3779: Go's answer stands. Only
// rows with the same Go answer under Go 1.26 (x/net tables for Unicode 15.0) and Go 1.27 (Unicode 17.0) are pinned.
var pslIdnaDivergences = []struct{ name, goStrict, pyStrict, goQuery, pyQuery, why string }{
	{"straße.de", "ok:xn--strae-oqa.de", "ok:strasse.de", "ok:xn--strae-oqa|de", "ok:strasse|de", "ß is a deviation character: IDNA2003 nameprep folds it to ss, UTS #46 non-transitional keeps it"},
	{"xn--strae-oqa.de", "ok:xn--strae-oqa.de", "err:invalid IDNA label", "ok:xn--strae-oqa|de", "ok:xn--strae-oqa|de", "the ACE form of ß: IDNA2003 refuses it as non-canonical (it re-encodes to strasse), UTS #46 accepts it"},
	{"ος.gr", "ok:xn--0xag.gr", "ok:xn--0xai.gr", "ok:xn--0xag|gr", "ok:xn--0xai|gr", "final sigma ς is a deviation character: IDNA2003 folds it to σ, UTS #46 non-transitional keeps it"},
	{"xn--zva.com", "err:invalid IDNA label", "ok:xn--zva.com", "ok:xn--zva|com", "ok:xn--zva|com", "the ACE form of unassigned U+0378: CPython's nameprep has no unassigned-code-point check, UTS #46 disallows it"},
	{"a\U0001f6dcb.com", "ok:xn--ab-i782a.com", "err:invalid DNS label", "ok:xn--ab-i782a|com", "ok:xn--ab-i782a|com", "U+1F6DC was assigned in Unicode 15: unassigned (Cn) to Python 3.11's Unicode 14, valid to the Go tables"},
	{"\u0301a.com", "err:invalid IDNA label", "ok:xn--a-wbb.com", "ok:\u0301a|com", "ok:xn--a-wbb|com", "a label opening with a combining mark: no check in IDNA2003, disallowed by UTS #46 validity"},
	{"a\u0378b.com", "err:invalid DNS label", "err:invalid DNS label", "ok:a\u0378b|com", "ok:xn--ab-g4b|com", "unassigned U+0378 inside a raw label: the strict path refuses it in both; the lenient path encodes it in Python, keeps the raw label in Go"},
	{"a\u0660b.com", "err:invalid IDNA label", "ok:xn--ab-7xd.com", "ok:a\u0660b|com", "ok:xn--ab-7xd|com", "an Arabic-Indic digit in an LTR label: nameprep's bidi check does not see it (AN), RFC 5893 / UTS #46 CheckBidi refuses it"},
}

func TestPslIdnaDivergesFromPythonAsDocumented(t *testing.T) {
	for _, c := range pslIdnaDivergences {
		if got := pslNormalizeNameResult(c.name); got != c.goStrict {
			t.Errorf("pslNormalizeName(%q) = %s; the Go (UTS #46) answer is %s, Python's IDNA2003 answer is %s (%s)", c.name, got, c.goStrict, c.pyStrict, c.why)
		}
		if got := pslNormalizeQueryResult(c.name); got != c.goQuery {
			t.Errorf("pslNormalizeQuery(%q) = %s; the Go (UTS #46) answer is %s, Python's IDNA2003 answer is %s (%s)", c.name, got, c.goQuery, c.pyQuery, c.why)
		}
		if c.goStrict == c.pyStrict && c.goQuery == c.pyQuery {
			t.Errorf("row %q no longer diverges from Python: move it to pslNameRows", c.name)
		}
	}
}

func TestPslRefusedCategoryMatchesPythonUnicodedata(t *testing.T) { // oracle: unicodedata.category(char) in {"Cc", "Cf", "Cn"}
	for _, c := range []struct {
		char rune
		want bool
	}{
		{0x0, true}, {0x1f, true}, {0x20, false}, {'a', false}, {0x7f, true}, {0x85, true}, {0xad, true}, {0x200b, true}, {0x2028, false},
		{0x378, true}, {0xe000, false}, {0xfffe, true}, {0xfdd0, true}, {0x10ffff, true}, {0x301, false}, {0x1f600, false}, {0x600, true},
		{0x1c90, false}, {0x20e0, false}, {0xfeff, true}, {0xd666f, true},
	} {
		if got := pslRefusedCategory(c.char); got != c.want {
			t.Errorf("pslRefusedCategory(U+%04X) = %v, want %v", c.char, got, c.want)
		}
	}
	// U+1F6DC was assigned in Unicode 15: Cn to Python 3.11 (Unicode 14), assigned to every Go toolchain that can build
	// this module (Unicode 15.0.0 or newer).
	if pslRefusedCategory(0x1f6dc) {
		t.Error("pslRefusedCategory(U+1F6DC) = true; Python 3.11 says true (Cn in Unicode 14), the Go tables know the Unicode 15 emoji")
	}
}

func TestTldWildcardClassifyUsesArbitraryDepthAndPrivatePolicy(t *testing.T) { // test_psl_classifier_uses_arbitrary_depth_and_private_policy
	rules := pslMustParse(t, pslRuntimeAuthority)
	for _, c := range []struct {
		domain         string
		includePrivate bool
		class          string
	}{
		{"com", true, DNSBL_CLASS_DATA},
		{"example.com", true, DNSBL_CLASS_ZONE},
		{"a.b.example.com", true, DNSBL_CLASS_DATA},
		{"example.github.io", true, DNSBL_CLASS_ZONE},
		{"example.github.io", false, DNSBL_CLASS_DATA},
		{"a.b.example.github.io", true, DNSBL_CLASS_DATA},
		{"foo.ck", true, DNSBL_CLASS_DATA},
		{"www.ck", true, DNSBL_CLASS_ZONE},
	} {
		class, key := tldWildcardClassify(c.domain, rules, map[string]struct{}{}, c.includePrivate, nil)
		if class != c.class || key != c.domain {
			t.Errorf("tldWildcardClassify(%q, includePrivate=%v) = %q, %q; want %q, %q", c.domain, c.includePrivate, class, key, c.class, c.domain)
		}
	}
}

func TestTldWildcardClassifyBlacklistExclusionAndShapes(t *testing.T) { // oracle: tld_wildcard_classify branches
	rules := pslMustParse(t, pslRuntimeAuthority)
	set := func(values ...string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, v := range values {
			out[v] = struct{}{}
		}
		return out
	}
	for _, c := range []struct {
		domain               string
		exclusion, blacklist map[string]struct{}
		includePrivate       bool
		class                string
	}{
		{"example.com", nil, set("com"), true, DNSBL_CLASS_DATA},             // root blacklisted
		{"example.github.io", nil, set("github.io"), true, DNSBL_CLASS_DATA}, // suffix blacklisted
		{"example.github.io", nil, set("io"), true, DNSBL_CLASS_DATA},        // root of a PRIVATE suffix blacklisted
		{"example.github.io", nil, set("github.io"), false, DNSBL_CLASS_DATA},
		{"example.com", set("com"), nil, true, DNSBL_CLASS_DATA},             // root excluded
		{"example.com", set("example.com"), nil, true, DNSBL_CLASS_DATA},     // the domain itself excluded
		{"example.github.io", set("github.io"), nil, true, DNSBL_CLASS_DATA}, // suffix excluded
		{"example.github.io", set("io"), nil, true, DNSBL_CLASS_DATA},
		{"example.github.io", set("example.github.io"), nil, true, DNSBL_CLASS_DATA},
		{"example.com", set("net"), set("org"), true, DNSBL_CLASS_ZONE}, // unrelated entries change nothing
		{"github.io", nil, nil, true, DNSBL_CLASS_DATA},                 // a name that is its own suffix
		{"github.io", nil, nil, false, DNSBL_CLASS_ZONE},                // ICANN-only view: github.io is registrable under io
		{"EXAMPLE.com", nil, nil, true, DNSBL_CLASS_ZONE},               // not lowercased here: the caller normalise()s first
		{"foo.ck", nil, nil, true, DNSBL_CLASS_DATA},
		{"a.foo.ck", nil, nil, true, DNSBL_CLASS_ZONE},
		{"x.www.ck", nil, nil, true, DNSBL_CLASS_DATA},
		{"münchen.de", nil, nil, true, DNSBL_CLASS_ZONE}, // returned as given, never as the punycode form
		{"example.unknown", nil, nil, true, DNSBL_CLASS_ZONE},
		{"a.b.unknown", nil, nil, true, DNSBL_CLASS_DATA},
		{"foo_bar.com", nil, nil, true, DNSBL_CLASS_DATA}, // not a valid PSL name: exact DATA
		{"a..com", nil, nil, true, DNSBL_CLASS_DATA},
	} {
		class, key := tldWildcardClassify(c.domain, rules, c.exclusion, c.includePrivate, c.blacklist)
		if class != c.class || key != c.domain {
			t.Errorf("tldWildcardClassify(%q, exclusion=%v, includePrivate=%v, blacklist=%v) = %q, %q; want %q, %q",
				c.domain, c.exclusion, c.includePrivate, c.blacklist, class, key, c.class, c.domain)
		}
	}
}

func TestSuffixFeedPolicyPredicate(t *testing.T) { // tests/test_issue2371_feed_suffix_policy.py::TestSuffixFeedPolicyPredicate, plus oracle rows
	rules := pslMustParse(t, pslPolicyAuthority)
	for _, c := range []struct {
		test, name, private, icann string
		want                       string // "" is Python's None
	}{
		{"test_private_apex_returns_private_policy", "github.io", "ignore", "apex", "ignore"},
		{"test_icann_apex_returns_icann_policy", "co.uk", "ignore", "apex", "apex"},
		{"test_wildcard_derived_boundary_is_at_boundary", "foo.ck", "x", "ignore", "ignore"},
		{"test_exception_carved_name_is_not_at_boundary", "www.ck", "ignore", "ignore", ""},
		{"test_bare_tld_in_exception_bearing_family_resolves_icann_section", "ck", "x", "ignore", "ignore"},
		{"test_punycode_apex_is_at_boundary", "xn--p1ai", "x", "apex", "apex"},
		{"test_invalid_name_is_not_at_boundary", "foo_bar.com", "ignore", "ignore", ""},
		{"test_non_suffix_registrable_is_not_at_boundary", "example.com", "ignore", "ignore", ""},
		{"test_deep_subdomain_is_not_at_boundary", "a.b.example.github.io", "ignore", "ignore", ""},
		{"oracle: a bare ICANN TLD", "io", "P", "I", "I"},
		{"oracle: a bare TLD with no rule", "com", "P", "I", "I"},
		{"oracle: a wildcard-derived name", "a.ck", "P", "I", "I"},
	} {
		got := dnsblSuffixFeedPolicy(c.name, rules, c.private, c.icann)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: dnsblSuffixFeedPolicy(%q) = %q, want nil", c.test, c.name, *got)
		case c.want != "" && (got == nil || *got != c.want):
			t.Errorf("%s: dnsblSuffixFeedPolicy(%q) = %v, want %q", c.test, c.name, got, c.want)
		}
	}
}

func TestSelectedTldRoots(t *testing.T) { // oracle: _selected_tld_roots
	for _, c := range []struct {
		values, want []string
	}{
		{[]string{"COM", " .Net. ", "com", "", "  ", "..", "Io", "\u0130x", "a.b"}, []string{"com", "net", "io", "i\u0307x", "a.b"}},
		{nil, nil},
		{[]string{"  ", "."}, nil},
		{[]string{"io", "IO", ".io."}, []string{"io"}},
	} {
		if got := selectedTldRoots(c.values); !slices.Equal(got, c.want) {
			t.Errorf("selectedTldRoots(%q) = %q, want %q", c.values, got, c.want)
		}
	}
}
