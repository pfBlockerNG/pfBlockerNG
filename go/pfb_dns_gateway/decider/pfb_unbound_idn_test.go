// Tests for the Go translation of pfb_unbound.py's IDN gate (is_idn_domain, idn_mode_decision) and the ADR-08
// TR39 homoglyph analyzer (decode_idn_label .. idn_confusable_action, _idn_dual_form). They mirror
// tests/test_adr08_analyzer.py, tests/test_adr08_confusable_matcher.py (TestConfusableActionMatchesOracle) and
// tests/test_adr28_cfg_adapters.py (TestIdnModeDecisionEnum) over the same fixtures
// (tests/fixtures/adr08_spec/decision_table.json, tests/fixtures/adr08_corpus/corpus.json). Expected values are
// the Python source's, taken by running pfb_unbound.py (Python 3.11, Unicode 14.0.0); where Go's Unicode 17.0.0
// tables give a different answer the row is a divergence row: it asserts Go's result and its message names Python's.
package decider

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func idnFixture(t *testing.T, name string, into any) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type idnDecisionTable struct {
	Meta struct {
		UcdVersion string `json:"ucd_version"`
	} `json:"_meta"`
	SingleLabel []struct {
		ID              string   `json:"id"`
		ALabel          string   `json:"a_label"`
		Decoded         string   `json:"decoded"`
		ResolvedScripts []string `json:"resolved_scripts"`
		Severity        string   `json:"severity"`
	} `json:"single_label"`
	MultiLabel []struct {
		ID               string     `json:"id"`
		AName            string     `json:"a_name"`
		PerLabelScripts  [][]string `json:"per_label_scripts"`
		PerLabelSeverity []string   `json:"per_label_severity"`
		Severity         string     `json:"severity"`
	} `json:"multi_label"`
	EdgeDecode []struct {
		ID       string `json:"id"`
		ALabel   string `json:"a_label"`
		DecodeOk bool   `json:"decode_ok"`
		Severity string `json:"severity"`
	} `json:"edge_decode"`
}

type idnCorpusEntry struct {
	ALabel           string   `json:"a_label"`
	Decoded          string   `json:"decoded"`
	AName            string   `json:"a_name"`
	ExpectedSeverity string   `json:"expected_severity"`
	PerLabelSeverity []string `json:"per_label_severity"`
}

type idnCorpus struct {
	LegitSingleLabel      []idnCorpusEntry `json:"legit_single_label"`
	LegitMultiLabel       []idnCorpusEntry `json:"legit_multi_label"`
	HomographSingleLabel  []idnCorpusEntry `json:"homograph_single_label"`
	HomographMultiLabel   []idnCorpusEntry `json:"homograph_multi_label"`
	SuspiciousSingleLabel []idnCorpusEntry `json:"suspicious_single_label"`
	LimitationWholeScript []idnCorpusEntry `json:"limitation_whole_script"`
	EdgeDecode            []idnCorpusEntry `json:"edge_decode"`
}

func idnLoadTable(t *testing.T) idnDecisionTable {
	t.Helper()
	var table idnDecisionTable
	idnFixture(t, "adr08_spec/decision_table.json", &table)
	return table
}

func idnLoadCorpus(t *testing.T) idnCorpus {
	t.Helper()
	var corpus idnCorpus
	idnFixture(t, "adr08_corpus/corpus.json", &corpus)
	return corpus
}

func idnSet(names ...string) scriptSet {
	s := scriptSet{}
	for _, name := range names {
		s[name] = struct{}{}
	}
	return s
}

func idnList(s scriptSet) []string { return slices.Sorted(maps.Keys(s)) }

func idnWantScripts(t *testing.T, what string, got scriptSet, want ...string) {
	t.Helper()
	want = slices.Sorted(slices.Values(want))
	if g := idnList(got); !slices.Equal(g, want) {
		t.Errorf("%s: scripts = %q, want %q", what, g, want)
	}
}

func idnMustDecode(t *testing.T, label string) string {
	t.Helper()
	decoded, err := decodeIdnLabel(label)
	if err != nil {
		t.Fatalf("decodeIdnLabel(%q): %v", label, err)
	}
	return decoded
}

func idnErrClass(err error) string {
	var codecErr *pyCodecError
	if !errors.As(err, &codecErr) {
		return "<not a pyCodecError>"
	}
	return codecErr.class
}

// ---- tests/test_adr28_cfg_adapters.py: TestIdnModeDecisionEnum ----

var (
	idnQueries    = []string{"xn--evil.com", "sub.xn--80akhbyknj4f.example", "xn--pple-43d.com"}
	idnNonQueries = []string{"example.com", "plain.sub.example.org"}
)

func TestIdnModeDecisionEnum(t *testing.T) {
	for _, q := range idnQueries {
		if !isIdnDomain(q) {
			t.Errorf("isIdnDomain(%q) = false, want true", q)
		}
		if !idnModeDecision(q, IdnModeAll) {
			t.Errorf("idnModeDecision(%q, All) = false, want true", q)
		}
		if idnModeDecision(q, IdnModeOff) {
			t.Errorf("idnModeDecision(%q, Off) = true, want false: Off never blocks", q)
		}
		// All WOULD block (above), so it is the mode, not the input, that makes Confusable false: the Confusable tier is
		// decided by idnConfusableAction.
		if idnModeDecision(q, IdnModeConfusable) {
			t.Errorf("idnModeDecision(%q, Confusable) = true, want false", q)
		}
	}
	for _, q := range idnNonQueries {
		if isIdnDomain(q) {
			t.Errorf("isIdnDomain(%q) = true, want false", q)
		}
		for _, mode := range []IdnMode{IdnModeAll, IdnModeOff, IdnModeConfusable} {
			if idnModeDecision(q, mode) {
				t.Errorf("idnModeDecision(%q, %q) = true, want false", q, mode)
			}
		}
	}
}

// is_idn_domain is a plain prefix / ".xn--" test: case-sensitive, and an xn-- that is not at a label start is no IDN.
func TestIsIdnDomainShapes(t *testing.T) {
	for _, tc := range []struct {
		q    string
		want bool
	}{
		{"xn--", true}, {"xn--.", true}, {".xn--a", true}, {"a.xn--", true}, {"a.xn--b.c", true},
		{"XN--x", false}, {"a.XN--b.com", false}, {"axn--b.com", false}, {"exampleXn--a.com", false}, {"", false},
		{"\uff41.xn--a", true},
	} {
		if got := isIdnDomain(tc.q); got != tc.want {
			t.Errorf("isIdnDomain(%q) = %v, want %v", tc.q, got, tc.want)
		}
	}
}

// ---- tests/test_adr08_analyzer.py: TestDecodeIdnLabel ----

func TestDecodeIdnLabel(t *testing.T) {
	for _, tc := range []struct{ label, want string }{
		{"xn--pple-43d", "\u0430pple"},
		{"example", "example"}, {"com", "com"},
		{"XN--a", "XN--a"},                // the xn-- prefix is case-sensitive: this is no A-label and passes through
		{"xn--a", "\u0080"}, {"xn--", ""}, // the raw codec decodes the edge labels the idna codec rejects
		{"xn---", ""}, {"xn--a-", "a"}, {"xn--abc-", "abc"},
		{"xn--bcher-kva", "b\u00fccher"}, {"xn--maana-pta", "ma\u00f1ana"}, {"xn--p1ai", "\u0440\u0444"},
		{"xn--PPLE-43D", "\u0430PPLE"}, // the extended part is upper-cased before decoding
		{"xn--ls8h", "\U0001F4A9"}, {"xn--9A", "\u00a3"}, {"xn--80ak6aa92e", "\u0430\u0440\u0440\u04cf\u0435"},
		{"xn--9A9A9A9A9A9A9A9A9A9A9A9A9A9A9A9A9A", "\u00ca\u00f6\u00d7\u00f1\u00e8\u00f8\u00dc\u00fa\u00d1\u00ee\u00eb\u00c1\u00b5\u00f3\u00e4\u00e0\u00a3"},
	} {
		got, err := decodeIdnLabel(tc.label)
		if err != nil || got != tc.want {
			t.Errorf("decodeIdnLabel(%q) = (%q, %v), want (%q, nil)", tc.label, got, err, tc.want)
		}
	}
}

// Python's raw codec raises UnicodeError for a truncated string, a bad digit and a code point above U+10FFFF, and
// UnicodeEncodeError for a non-ASCII A-label (label[4:].encode("ascii")): classify_label logs type(exc).__name__.
func TestDecodeIdnLabelErrors(t *testing.T) {
	for _, tc := range []struct{ label, class, message string }{
		{"xn--zz", "UnicodeError", "incomplete punicode string"},
		{"xn--0", "UnicodeError", "incomplete punicode string"},
		{"xn--Z9", "UnicodeError", "incomplete punicode string"},
		{"xn--ab-cd", "UnicodeError", "incomplete punicode string"},
		{"xn--A-9", "UnicodeError", "incomplete punicode string"},
		{"xn--k", "UnicodeError", "incomplete punicode string"},
		{"xn--" + strings.Repeat("9", 40), "UnicodeError", "incomplete punicode string"},
		{"xn--a!", "UnicodeError", "Invalid extended code point '!'"},
		{"xn--pple-43d_", "UnicodeError", "Invalid extended code point '_'"},
		{"xn--\x00", "UnicodeError", "Invalid extended code point"},
		{"xn--99999A", "UnicodeError", "Invalid character U+"},
		{"xn--999999A", "UnicodeError", "Invalid character U+"},
		// Python's integers do not overflow: a delta past int64 still ends in the range error, not in a wrapped value.
		{"xn--" + strings.Repeat("9", 20) + "A", "UnicodeError", "Invalid character U+"},
		{"xn--" + strings.Repeat("9", 200) + "A", "UnicodeError", "Invalid character U+"},
		{"xn--\u00e9", "UnicodeEncodeError", "'ascii' codec can't encode character"},
		{"xn--\u00e4-abc", "UnicodeEncodeError", "'ascii' codec can't encode character"},
	} {
		got, err := decodeIdnLabel(tc.label)
		if err == nil {
			t.Errorf("decodeIdnLabel(%q) = %q, want a %s", tc.label, got, tc.class)
			continue
		}
		if class := idnErrClass(err); class != tc.class || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("decodeIdnLabel(%q) error = (%s) %v, want (%s) containing %q", tc.label, class, err, tc.class, tc.message)
		}
	}
}

// Divergence: Python keeps a lone surrogate (chr(0xDC4B)) in the decoded str; a Go string cannot, so it holds U+FFFD.
// Both read as no letter (Python category Cs, Go U+FFFD So), so the scripts and the severity agree; only the decoded
// text shown in the dual form differs (and Python's log write of a surrogate raises UnicodeEncodeError).
func TestDecodeIdnLabelLoneSurrogateDivergence(t *testing.T) {
	got := idnMustDecode(t, "xn--T0py30xC6XA")
	if want := "\ufffd\ub625\u4be8"; got != want {
		t.Errorf("decodeIdnLabel(xn--T0py30xC6XA) = %+q, want %+q (Python: U+DC4B in place of U+FFFD)", got, want)
	}
	v := classifyLabel("xn--T0py30xC6XA")
	idnWantScripts(t, "xn--T0py30xC6XA", v.scripts, "Han", "Hangul")
	if v.severity != SEV_LEGIT {
		t.Errorf("severity = %q, want %q (Python: the surrogate is transparent too)", v.severity, SEV_LEGIT)
	}
}

// ---- tests/test_adr08_analyzer.py: TestScriptOf ----

func TestScriptOf(t *testing.T) {
	for _, tc := range []struct {
		cp   rune
		want string
	}{
		// TestScriptOf.test_letter_resolves_to_its_script
		{'a', "Latin"}, {'\u00fc', "Latin"}, {0x0430, "Cyrillic"}, {0x03b1, "Greek"}, {'\u4e2d', "Han"}, {'\u30c6', "Katakana"},
		{0x306e, "Hiragana"}, {0x304d, "Hiragana"}, {'\ud55c', "Hangul"}, {'\u0627', "Arabic"},
		// the first word of the character name, not the Script property: these are what pfb_unbound.py answers
		{0xff21, "Fullwidth"}, {0xff41, "Fullwidth"}, {0xff76, "Halfwidth"}, {0x1d400, "Mathematical"},
		{0x00aa, "Feminine"}, {0x00ba, "Masculine"}, {0x212a, "Kelvin"}, {0x212b, "Angstrom"}, {0x2126, "Ohm"},
		{0x2102, "Double-struck"}, {0x210e, "Planck"}, {0x2113, "Script"},
		{0x3400, "Han"}, {0x4e2d, "Han"}, {0xf900, "Han"}, {0xac00, "Hangul"}, {0x1b170, "Nushu"}, {0x18b00, "Khitan"},
		{0x18800, "Tangut"}, // a named TANGUT COMPONENT, unlike the unnamed ideographs below
		{0x0131, "Latin"}, {0x1e9e, "Latin"}, {0x0370, "Greek"}, {0x0561, "Armenian"}, {0x13a0, "Cherokee"},
		{0x2c80, "Coptic"}, {0x0e01, "Thai"}, {0x05d0, "Hebrew"}, {0x1d2b, "Cyrillic"},
		// divergence rows: Python 3.11 (Unicode 14.0.0) has no letter there (Cn, transparent: it answers ()); Go (Unicode 17.0.0) does
		{0x1df25, "Latin"}, // Python (): assigned in Unicode 15.0
		{0x11f04, "Kawi"},  // Python (): Unicode 15.0
		{0x31350, "Han"},   // Python (): CJK Ext H, Unicode 15.0
		{0x2ebf0, "Han"},   // Python (): CJK Ext I, Unicode 15.1
		{0xa7ce, "Latin"},  // Python (): Unicode 16.0
		{0x10d4a, "Garay"}, // Python (): Unicode 16.0
	} {
		got, ok := scriptOf(tc.cp)
		if !ok || got != tc.want {
			t.Errorf("scriptOf(U+%04X) = (%q, %v), want (%q, true)", tc.cp, got, ok, tc.want)
		}
	}
}

// TestScriptOf.test_transparent_or_scriptless_codepoint_is_empty and test_common_script_letter_marks_are_transparent.
func TestScriptOfTransparent(t *testing.T) {
	for _, tc := range []struct {
		cp   rune
		desc string
	}{
		{0x2d, "hyphen (Common)"}, {0x31, "digit (Common)"}, {0x20, "space (Common)"}, {0x80, "control char"}, {0x1f4a9, "emoji"},
		{0x30fc, "KATAKANA-HIRAGANA PROLONGED SOUND MARK (Lm, Common)"}, {0x3005, "IDEOGRAPHIC ITERATION MARK (Lm, Common)"},
		{0x3006, "IDEOGRAPHIC CLOSING MARK (Lo, Common)"}, {0x303c, "MASU MARK (Lo, Common)"}, {0x0640, "ARABIC TATWEEL (Lm, Common)"},
		{0x1400, "CANADIAN SYLLABICS HYPHEN (Pd)"}, {0x3007, "IDEOGRAPHIC NUMBER ZERO (Nl)"}, {0x30a0, "KATAKANA-HIRAGANA DOUBLE HYPHEN (Pd)"},
		{0xa015, "YI SYLLABLE WU (Lm)"}, {0x02b0, "MODIFIER LETTER SMALL H (Lm)"}, {0x1d7ce, "MATHEMATICAL BOLD DIGIT ZERO (Nd)"},
		{0xd800, "lone surrogate (Cs)"}, {0x0, "NUL"}, {0x10ffff, "noncharacter"},
		// Python's unicodedata names no code point of the Tangut ideograph range (it expands only the CJK ideograph and Hangul syllable ranges)
		{0x17000, "TANGUT IDEOGRAPH-17000 (Python: unnamed)"}, {0x187f7, "TANGUT IDEOGRAPH-187F7 (Python: unnamed)"},
	} {
		if got, ok := scriptOf(tc.cp); ok {
			t.Errorf("scriptOf(U+%04X %s) = %q, want no script", tc.cp, tc.desc, got)
		}
	}
}

func TestLegitJapaneseWithProlongedMarkStaysSingleScript(t *testing.T) {
	idnWantScripts(t, "コーヒー", resolvedScriptSet("\u30b3\u30fc\u30d2\u30fc"), "Katakana")
	if got := severityOf("\u30b3\u30fc\u30d2\u30fc"); got != SEV_LEGIT {
		t.Errorf("severityOf(コーヒー) = %q, want %q", got, SEV_LEGIT)
	}
}

// ---- TestResolvedScriptSet ----

func TestResolvedScriptSet(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"m\u00fcnchen", []string{"Latin"}}, {"\u0440\u043e\u0441\u0441\u0438\u044f", []string{"Cyrillic"}},
		{"\u3072\u3089\u304c\u306a", []string{"Hiragana"}},
		{"a1-b2", []string{"Latin"}}, // digits and hyphen are transparent
		{"\u30c9\u30e1\u30a4\u30f3\u540d", []string{"Han", "Katakana"}},
		{"\u0430pple", []string{"Cyrillic", "Latin"}},
		{"\u30e1\u30e2\u66f8\u304d", []string{"Han", "Hiragana", "Katakana"}},
		{"", nil}, {"\u0080", nil}, {"\U0001F4A9", nil}, // empty, control char, emoji: the empty set (the FLAGGED trigger)
	} {
		idnWantScripts(t, tc.text, resolvedScriptSet(tc.text), tc.want...)
	}
}

// ---- TestRestrictionLevel ----

func TestRestrictionLevel(t *testing.T) {
	for _, tc := range []struct {
		scripts   scriptSet
		asciiOnly bool
		want      string
	}{
		{idnSet("Latin"), true, LEVEL_ASCII},
		{idnSet("Cyrillic"), false, LEVEL_SINGLE},
		{idnSet("Han", "Katakana"), false, LEVEL_HIGHLY_RESTRICTIVE},
		{idnSet("Han", "Hangul"), false, LEVEL_HIGHLY_RESTRICTIVE},
		{idnSet("Han", "Hiragana", "Katakana"), false, LEVEL_HIGHLY_RESTRICTIVE},
		{idnSet("Latin", "Han"), false, LEVEL_HIGHLY_RESTRICTIVE},
		{idnSet("Han", "Bopomofo"), false, LEVEL_HIGHLY_RESTRICTIVE},
		{idnSet("Cyrillic", "Latin"), false, LEVEL_NON_RESTRICTIVE},
		{idnSet("Armenian", "Latin"), false, LEVEL_NON_RESTRICTIVE},
		{idnSet("Han", "Cyrillic"), false, LEVEL_NON_RESTRICTIVE},
		{idnSet(), false, LEVEL_NON_RESTRICTIVE}, // no script: not SINGLE, and the highly-restrictive branch needs a non-empty set
	} {
		if got := restrictionLevel(tc.scripts, tc.asciiOnly); got != tc.want {
			t.Errorf("restrictionLevel(%q, ascii_only=%v) = %q, want %q", idnList(tc.scripts), tc.asciiOnly, got, tc.want)
		}
	}
}

// ---- TestCjkLegitIsZeroFalsePositive / TestMaliciousConfusablePairs / TestSuspiciousTierBorderlineCalls /
// TestSingleScriptIsLegitEvenForTrioScripts / TestWholeScriptConfusableNotCaught ----

func TestCjkLegitIsZeroFalsePositive(t *testing.T) {
	for _, tc := range []struct {
		label string
		want  []string
	}{
		{"xn--eckwd4c7c777u", []string{"Han", "Katakana"}},
		{"xn--eqr704t9deq8o", []string{"Han", "Hangul"}},
		{"xn--w8jxqd8946c", []string{"Han", "Hiragana", "Katakana"}},
	} {
		decoded := idnMustDecode(t, tc.label)
		scripts := resolvedScriptSet(decoded)
		idnWantScripts(t, tc.label, scripts, tc.want...)
		// A naive any-mix rule would block it: it IS multi-script; the restriction level is what rescues it.
		if len(scripts) < 2 {
			t.Errorf("%s: %d scripts, want a multi-script label", tc.label, len(scripts))
		}
		if got := restrictionLevel(scripts, false); got != LEVEL_HIGHLY_RESTRICTIVE {
			t.Errorf("%s: restrictionLevel = %q, want %q", tc.label, got, LEVEL_HIGHLY_RESTRICTIVE)
		}
		if got := severityOf(decoded); got != SEV_LEGIT {
			t.Errorf("%s: severityOf = %q, want %q", tc.label, got, SEV_LEGIT)
		}
		if v := classifyIdn(tc.label); v.severity != SEV_LEGIT {
			t.Errorf("%s: classifyIdn severity = %q, want %q", tc.label, v.severity, SEV_LEGIT)
		}
	}
}

func TestMaliciousConfusablePairs(t *testing.T) {
	for _, tc := range []struct {
		label     string
		offending []string
		noLatin   bool
	}{
		{"xn--pple-43d", []string{"Latin", "Cyrillic"}, false},
		{"xn--ggle-0nda", []string{"Latin", "Greek"}, false},
		{"xn--mxa00ab", []string{"Cyrillic", "Greek"}, true}, // the rule is >=2 of the trio, not Latin-anchored
	} {
		if tc.noLatin {
			if _, has := resolvedScriptSet(idnMustDecode(t, tc.label))["Latin"]; has {
				t.Errorf("%s: precondition: this mix has no Latin", tc.label)
			}
		}
		v := classifyIdn(tc.label)
		if v.severity != SEV_MALICIOUS {
			t.Errorf("%s: severity = %q, want %q", tc.label, v.severity, SEV_MALICIOUS)
		}
		idnWantScripts(t, tc.label+" offending", v.offending, tc.offending...)
	}
}

func TestSuspiciousTierBorderlineCalls(t *testing.T) {
	for _, tc := range []struct{ label, other string }{
		{"xn--bnk-1ce", "Armenian"}, {"xn--bnk-u8p", "Cherokee"}, {"xn--bnk-q10b", "Coptic"},
	} {
		decoded := idnMustDecode(t, tc.label)
		idnWantScripts(t, tc.label, resolvedScriptSet(decoded), "Latin", tc.other)
		sev := severityOf(decoded)
		if sev == SEV_MALICIOUS || sev != SEV_SUSPICIOUS {
			t.Errorf("%s: severityOf = %q, want %q (not a default block)", tc.label, sev, SEV_SUSPICIOUS)
		}
		idnWantScripts(t, tc.label+" offending", classifyIdn(tc.label).offending, "Latin", tc.other)
	}
}

func TestSingleScriptIsLegitEvenForTrioScripts(t *testing.T) {
	for _, tc := range []struct{ label, script string }{
		{"xn--h1alffa9f", "Cyrillic"}, {"xn--hxakic4aa", "Greek"}, {"xn--mnchen-3ya", "Latin"},
		{"xn--80ak6aa92e", "Cyrillic"}, // the whole-script look-alike (аррӏе) is a documented miss, pinned as legit
	} {
		decoded := idnMustDecode(t, tc.label)
		idnWantScripts(t, tc.label, resolvedScriptSet(decoded), tc.script)
		if got := severityOf(decoded); got != SEV_LEGIT {
			t.Errorf("%s: severityOf = %q, want %q", tc.label, got, SEV_LEGIT)
		}
	}
}

// ---- TestPerLabelNeverUnionsAcrossTheDot ----

func TestPerLabelNeverUnionsAcrossTheDot(t *testing.T) {
	for _, name := range []string{"example.xn--p1ai", "site.xn--fiqs8s"} {
		v := classifyIdn(name)
		if got := idnSeverities(v); !slices.Equal(got, []string{SEV_LEGIT, SEV_LEGIT}) || v.severity != SEV_LEGIT {
			t.Errorf("classifyIdn(%q) = labels %v, name %q, want [legit legit], legit", name, got, v.severity)
		}
	}
	// The wrong whole-name union of example.рф is {Cyrillic, Latin}, which the malicious rule WOULD flag.
	union := scriptSet{}
	for _, label := range strings.Split("example.xn--p1ai", ".") {
		maps.Copy(union, resolvedScriptSet(idnMustDecode(t, label)))
	}
	if n := len(idnIntersect(union, CONFUSABLE_SET)); n < 2 {
		t.Errorf("the wrong union has %d confusable scripts, want >= 2 (it genuinely looks malicious)", n)
	}
	v := classifyIdn("xn--ypal-43d9g.example.com")
	if got := idnSeverities(v); !slices.Equal(got, []string{SEV_MALICIOUS, SEV_LEGIT, SEV_LEGIT}) || v.severity != SEV_MALICIOUS {
		t.Errorf("classifyIdn(paypal homograph) = labels %v, name %q, want [malicious legit legit], malicious", got, v.severity)
	}
	idnWantScripts(t, "offending", v.offending, "Latin", "Cyrillic")
}

func idnSeverities(v nameVerdict) []string {
	var out []string
	for _, label := range v.labels {
		out = append(out, label.severity)
	}
	return out
}

func idnIntersect(a, b scriptSet) scriptSet {
	out := scriptSet{}
	for k := range a {
		if _, ok := b[k]; ok {
			out[k] = struct{}{}
		}
	}
	return out
}

// ---- TestMalformedLabelsAreFlaggedNotRaised ----

func TestMalformedLabelsAreFlaggedNotRaised(t *testing.T) {
	for _, row := range idnLoadTable(t).EdgeDecode {
		verdict := classifyLabel(row.ALabel)
		if verdict.severity != row.Severity {
			t.Errorf("%s: severity = %q, want %q", row.ID, verdict.severity, row.Severity)
		}
		if verdict.severity == SEV_MALICIOUS {
			t.Errorf("%s: an edge label is never malicious", row.ID)
		}
		_, err := decodeIdnLabel(row.ALabel)
		if !row.DecodeOk {
			// Python 3.11 raises the base UnicodeError for these; 3.13+ raises UnicodeDecodeError, which this port does not follow.
			if verdict.decodeError != "UnicodeError" || verdict.decoded != nil || verdict.severity != SEV_FLAGGED {
				t.Errorf("%s: decodeError = %q decoded = %v severity = %q, want UnicodeError, nil, flagged", row.ID, verdict.decodeError, verdict.decoded, verdict.severity)
			}
			if err == nil {
				t.Errorf("%s: decodeIdnLabel did not fail: the catch in classifyLabel would be dead code", row.ID)
			}
		} else {
			if verdict.decodeError != "" || verdict.decoded == nil || err != nil {
				t.Errorf("%s: decodeError = %q decoded = %v err = %v, want a decoded label and no error", row.ID, verdict.decodeError, verdict.decoded, err)
			}
		}
	}
}

func TestClassifyIdnOnUndecodableNameIsFlaggedNotRaised(t *testing.T) {
	v := classifyIdn("xn--zz.example.com")
	if v.labels[0].severity != SEV_FLAGGED || v.labels[0].decodeError != "UnicodeError" || v.severity != SEV_FLAGGED {
		t.Errorf("classifyIdn(xn--zz.example.com) = first label (%q, %q), name %q, want (flagged, UnicodeError), flagged",
			v.labels[0].severity, v.labels[0].decodeError, v.severity)
	}
	if v.labels[0].decoded != nil {
		t.Errorf("decoded = %q, want nil (Python None)", *v.labels[0].decoded)
	}
}

// Rows of classify_idn the Python tests reach only through evaluate_domain: the empty label of a trailing or doubled dot
// is flagged (no letter-script, not digits/hyphen), the most severe label wins, and the first of two equal ones is kept.
func TestClassifyIdnShapes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		severity   string
		labelSevs  []string
		firstLabel string
	}{
		{"", SEV_FLAGGED, []string{SEV_FLAGGED}, ""},
		{"a..b", SEV_FLAGGED, []string{SEV_LEGIT, SEV_FLAGGED, SEV_LEGIT}, "a"},
		{"xn--pple-43d.", SEV_MALICIOUS, []string{SEV_MALICIOUS, SEV_FLAGGED}, "xn--pple-43d"},
		{"xn--ls8h.xn--zz", SEV_FLAGGED, []string{SEV_FLAGGED, SEV_FLAGGED}, "xn--ls8h"},
		{"1-2.3", SEV_LEGIT, []string{SEV_LEGIT, SEV_LEGIT}, "1-2"}, // digits and hyphen only: the Common-only carve-out
		{"-", SEV_LEGIT, []string{SEV_LEGIT}, "-"},
	} {
		v := classifyIdn(tc.name)
		if v.aName != tc.name || v.severity != tc.severity || !slices.Equal(idnSeverities(v), tc.labelSevs) || v.labels[0].aLabel != tc.firstLabel {
			t.Errorf("classifyIdn(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.name, v.aName, v.severity, idnSeverities(v), tc.name, tc.severity, tc.labelSevs)
		}
	}
}

// ---- TestAnalyzerMatchesPhase2OracleAndCorpus (the golden rows the Phase-2 oracle authored) ----

func TestAnalyzerMatchesGoldenSingleLabel(t *testing.T) {
	for _, row := range idnLoadTable(t).SingleLabel {
		decoded := idnMustDecode(t, row.ALabel)
		if decoded != row.Decoded {
			t.Errorf("%s: decode = %q, want %q", row.ID, decoded, row.Decoded)
		}
		idnWantScripts(t, row.ID, resolvedScriptSet(decoded), row.ResolvedScripts...)
		if got := severityOf(decoded); got != row.Severity {
			t.Errorf("%s: severity = %q, want %q", row.ID, got, row.Severity)
		}
	}
}

func TestAnalyzerMatchesGoldenMultiLabel(t *testing.T) {
	for _, row := range idnLoadTable(t).MultiLabel {
		verdict := classifyIdn(row.AName)
		if len(verdict.labels) != len(row.PerLabelScripts) {
			t.Errorf("%s: %d labels, want %d", row.ID, len(verdict.labels), len(row.PerLabelScripts))
			continue
		}
		for i, label := range verdict.labels {
			idnWantScripts(t, row.ID+" label "+label.aLabel, label.scripts, row.PerLabelScripts[i]...)
		}
		if got := idnSeverities(verdict); !slices.Equal(got, row.PerLabelSeverity) {
			t.Errorf("%s: per-label severity = %v, want %v", row.ID, got, row.PerLabelSeverity)
		}
		if verdict.severity != row.Severity {
			t.Errorf("%s: name severity = %q, want %q", row.ID, verdict.severity, row.Severity)
		}
	}
}

func TestAnalyzerMatchesCorpus(t *testing.T) {
	corpus := idnLoadCorpus(t)
	for section, entries := range map[string][]idnCorpusEntry{
		"legit_single_label": corpus.LegitSingleLabel, "homograph_single_label": corpus.HomographSingleLabel,
		"suspicious_single_label": corpus.SuspiciousSingleLabel, "limitation_whole_script": corpus.LimitationWholeScript,
	} {
		for _, entry := range entries {
			if got := severityOf(entry.Decoded); got != entry.ExpectedSeverity {
				t.Errorf("%s/%s: severityOf(%q) = %q, want %q", section, entry.ALabel, entry.Decoded, got, entry.ExpectedSeverity)
			}
		}
	}
	for section, entries := range map[string][]idnCorpusEntry{"legit_multi_label": corpus.LegitMultiLabel, "homograph_multi_label": corpus.HomographMultiLabel} {
		for _, entry := range entries {
			verdict := classifyIdn(entry.AName)
			if verdict.severity != entry.ExpectedSeverity || !slices.Equal(idnSeverities(verdict), entry.PerLabelSeverity) {
				t.Errorf("%s/%s: severity = %q labels %v, want %q %v", section, entry.AName, verdict.severity, idnSeverities(verdict), entry.ExpectedSeverity, entry.PerLabelSeverity)
			}
		}
	}
}

func TestZeroFalsePositiveOnEveryLegitEntry(t *testing.T) {
	corpus := idnLoadCorpus(t)
	for _, entry := range append(slices.Clone(corpus.LegitSingleLabel), corpus.LegitMultiLabel...) {
		sev := ""
		if entry.AName != "" {
			sev = classifyIdn(entry.AName).severity
		} else {
			sev = severityOf(entry.Decoded)
		}
		if sev == SEV_MALICIOUS {
			t.Errorf("false positive on legit %s%s", entry.ALabel, entry.AName)
		}
	}
}

// test_analyzer_ucd_independent_of_pinned_table: the golden is recorded against UCD 15.1.0 whatever the runtime's.
func TestAnalyzerUcdIndependentOfPinnedTable(t *testing.T) {
	if got := idnLoadTable(t).Meta.UcdVersion; got != "15.1.0" {
		t.Errorf("decision_table.json ucd_version = %q, want 15.1.0", got)
	}
}

// ---- tests/test_adr08_confusable_matcher.py: TestConfusableActionMatchesOracle ----

// idnOracleAction is test_adr08_decision_spec.action: the Phase-2 oracle's severity -> action policy.
func idnOracleAction(severity string, blockMalicious, escalateSuspicious bool) string {
	switch severity {
	case SEV_LEGIT:
		return "none"
	case SEV_MALICIOUS:
		if blockMalicious {
			return "block"
		}
		return "alert"
	case SEV_SUSPICIOUS, SEV_FLAGGED:
		if escalateSuspicious {
			return "block"
		}
		return "alert"
	}
	panic("unknown severity " + severity)
}

func TestConfusableActionMatchesOracle(t *testing.T) {
	corpus := idnLoadCorpus(t)
	if IDN_ACT_NONE != "none" || IDN_ACT_ALERT != "alert" || IDN_ACT_BLOCK != "block" {
		t.Fatalf("IDN_ACT_* = (%q, %q, %q), want (none, alert, block)", IDN_ACT_NONE, IDN_ACT_ALERT, IDN_ACT_BLOCK)
	}
	for _, tc := range []struct{ name, severity string }{
		{corpus.HomographSingleLabel[0].ALabel + ".com", SEV_MALICIOUS},   // xn--pple-43d
		{corpus.HomographSingleLabel[4].ALabel + ".com", SEV_MALICIOUS},   // xn--mxa00ab
		{corpus.SuspiciousSingleLabel[0].ALabel + ".com", SEV_SUSPICIOUS}, // xn--bnk-1ce
		{corpus.EdgeDecode[4].ALabel + ".com", SEV_FLAGGED},               // xn--ls8h: no letter-script
		{corpus.EdgeDecode[2].ALabel + ".com", SEV_FLAGGED},               // xn--zz: the decode error
		{corpus.LegitSingleLabel[5].ALabel + ".com", SEV_LEGIT},           // xn--wgv71a119e
		{corpus.LegitSingleLabel[0].ALabel + ".com", SEV_LEGIT},           // xn--mnchen-3ya
		{corpus.LegitMultiLabel[0].AName, SEV_LEGIT},                      // example.xn--p1ai
	} {
		for _, blockMalicious := range []bool{true, false} {
			for _, escalateSuspicious := range []bool{true, false} {
				act, verdict := idnConfusableAction(tc.name, blockMalicious, escalateSuspicious)
				if verdict == nil || verdict.severity != tc.severity {
					t.Errorf("idnConfusableAction(%q) verdict = %v, want severity %q", tc.name, verdict, tc.severity)
					continue
				}
				if want := idnOracleAction(tc.severity, blockMalicious, escalateSuspicious); act != want {
					t.Errorf("idnConfusableAction(%q, block_malicious=%v, escalate_suspicious=%v) = %q, want %q", tc.name, blockMalicious, escalateSuspicious, act, want)
				}
			}
		}
	}
}

func TestConfusableActionNonIdnPaysNothing(t *testing.T) {
	act, verdict := idnConfusableAction("plain-ascii.example.com", true, false)
	if act != IDN_ACT_NONE || verdict != nil {
		t.Errorf("idnConfusableAction(plain name) = (%q, %v), want (none, nil): no analysis for a name without an xn-- label", act, verdict)
	}
}

func TestConfusableActionMalformedLabelNeverRaises(t *testing.T) {
	act, verdict := idnConfusableAction("xn--zz.com", true, false)
	if verdict == nil || verdict.severity != SEV_FLAGGED || act != IDN_ACT_ALERT {
		t.Errorf("idnConfusableAction(xn--zz.com) = (%q, %v), want (alert, a flagged verdict)", act, verdict)
	}
}

func TestIdnFeedConstants(t *testing.T) {
	for name, pair := range map[string][2]string{
		"IDN_FEED_MALICIOUS": {IDN_FEED_MALICIOUS, "Homoglyph"}, "IDN_GROUP_MALICIOUS": {IDN_GROUP_MALICIOUS, "DNSBL_Homoglyph"},
		"IDN_FEED_SUSPECT": {IDN_FEED_SUSPECT, "Homoglyph_Suspect"}, "IDN_GROUP_SUSPECT": {IDN_GROUP_SUSPECT, "DNSBL_Homoglyph_Suspect"},
		"SEV_LEGIT": {SEV_LEGIT, "legit"}, "SEV_SUSPICIOUS": {SEV_SUSPICIOUS, "suspicious"}, "SEV_MALICIOUS": {SEV_MALICIOUS, "malicious"},
		"SEV_FLAGGED": {SEV_FLAGGED, "flagged"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

// ---- _idn_dual_form: the b_eval text of an IDN block / alert; every want is what pfb_unbound.py returns ----

func TestIdnDualForm(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"xn--pple-43d.com", "xn--pple-43d [\u0430pple] Cyrillic Latin"},
		{"xn--bnk-1ce.com", "xn--bnk-1ce [b\u0561nk] Armenian Latin"},
		{"xn--bnk-q10b", "xn--bnk-q10b [b\u2c81nk] Coptic Latin"},
		{"xn--zz.com", "xn--zz [decode-error:UnicodeError]"},
		{"xn--\u00e9.com", "xn--\u00e9 [decode-error:UnicodeEncodeError]"},
		{"xn--ls8h.com", "xn--ls8h [\U0001F4A9]"},
		{"xn--a.xn--zz", "xn--a [\u0080]"}, // the first label of the winning severity
		{"xn--mnchen-3ya.com", "xn--mnchen-3ya [m\u00fcnchen]"},
		{"example.xn--p1ai", "example [example]"}, // a legit name: the first legit label, no scripts
		{"xn--ypal-43d9g.example.com", "xn--ypal-43d9g [\u0440\u0430ypal] Cyrillic Latin"},
		{"xn--ggle-0nda.xn--pple-43d", "xn--ggle-0nda [g\u03bf\u03bfgle] Greek Latin"},
		{"xn--mxa00ab.xn--p1ai", "xn--mxa00ab [\u0441\u03b1\u0440] Cyrillic Greek"},
	} {
		v := classifyIdn(tc.name)
		if got := idnDualForm(&v); got != tc.want {
			t.Errorf("idnDualForm(classifyIdn(%q)) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestIdnDualFormHandBuiltVerdicts(t *testing.T) {
	latin := "x"
	decoded := "b"
	for _, tc := range []struct {
		what    string
		verdict nameVerdict
		want    string
	}{
		{"no label has the name severity: the whole name", nameVerdict{aName: "x.com", severity: SEV_MALICIOUS, offending: idnSet(),
			labels: []labelVerdict{{aLabel: "x", decoded: &latin, scripts: idnSet("Latin"), severity: SEV_LEGIT, offending: idnSet()}}}, "x.com"},
		{"a missing decoded form with no recorded error", nameVerdict{aName: "a.com", severity: SEV_FLAGGED, offending: idnSet(),
			labels: []labelVerdict{{aLabel: "a", scripts: idnSet(), severity: SEV_FLAGGED, offending: idnSet()}}}, "a [decode-error:unknown]"},
		{"the offending scripts are sorted", nameVerdict{aName: "a.com", severity: SEV_MALICIOUS, offending: idnSet("Latin", "Greek"),
			labels: []labelVerdict{{aLabel: "a", decoded: &decoded, scripts: idnSet("Latin", "Greek"), severity: SEV_MALICIOUS, offending: idnSet("Greek", "Latin")}}}, "a [b] Greek Latin"},
	} {
		if got := idnDualForm(&tc.verdict); got != tc.want {
			t.Errorf("%s: idnDualForm = %q, want %q", tc.what, got, tc.want)
		}
	}
}
