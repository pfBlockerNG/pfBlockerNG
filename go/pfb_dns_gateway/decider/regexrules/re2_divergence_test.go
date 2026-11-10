// Where Go's regexp (RE2) reads an admitted compile text differently from Python's re.compile(text, re.IGNORECASE),
// pinned as rows: `python` is what Python's re gave (Python 3.11, run when the rows were written), `goRE2` is what
// regexp gives today. A row whose two columns differ is a KNOWN DIVERGENCE, not parity; the first three are corpus
// cases of tests/dns_proxy/fixtures/parity/regex-cname-target-octets.json that a decider matching with plain regexp
// would decide differently from the frozen expectation. The rows with equal columns are controls: the same pattern on
// an ASCII name, where the engines agree, so a divergence row cannot pass because the pattern is broken.
//
// Nothing here fixes a divergence: the rows record what plain regexp does with the text Python compiles. A caller that
// rewrites the text before compiling it owns its own rows against the Python results in the `python` column.

package regexrules

import "testing"

var RE2_DIVERGENCES = []struct {
	text, name    string
	python, goRE2 bool
	why           string
}{
	// corpus cases (a CNAME target is decoded from Latin-1 octets, so a name can carry 0x80-0xFF)
	{`^caf\w\.example$`, "caf\u00e9.example", true, false, `corpus latin1-letter-does-not-match-backslash-w: Python \w is Unicode, RE2 \w is [0-9A-Za-z_]`},
	{`^cak\s\.example$`, "cak\u00a0.example", true, false, `corpus latin1-no-break-space-does-not-match-backslash-s: Python \s takes U+00A0, RE2 \s is [\t\n\f\r ]`},
	{`^cai\W\.example$`, "cai\u00e9.example", false, true, `corpus latin1-letter-matches-backslash-capital-w: é is a word character to Python, not to RE2`},
	// controls: the same patterns, ASCII names
	{`^caf\w\.example$`, "cafe.example", true, true, "control"},
	{`^cak\s\.example$`, "cak .example", true, true, "control"},
	{`^cai\W\.example$`, "cai-.example", true, true, "control"},
	// not in the corpus
	{`^cak\s\.example$`, "cak\x85.example", true, false, `Python \s takes U+0085`},
	{`^r3s\s\.example$`, "r3s\x0b.example", true, false, `Python \s takes \v (0x0B); RE2 \s does not`},
	{`^r3s\s\.example$`, "r3s\x1c.example", true, false, `Python \s takes 0x1C-0x1F; RE2 \s does not`},
	{`\br5e\.example$`, "\u00b2r5e.example", false, true, `² is a word character to Python (isalnum), so \b finds no boundary before r; RE2 finds one`},
	{`\br5e\.example$`, "-r5e.example", true, true, "control"},
	{`^ads\w*\.example$`, "ads\u00e9.example", true, false, `Unicode \w on a Latin-1 CNAME target (test_the_probe_keeps_unicode_word_matching_for_latin_1_cname_targets)`},
	{`^ads\.example$`, "ads.example\n", true, false, "Python $ also matches before a final newline; RE2 $ only at the end of the text"},
	{`^ads\.example$`, "ads.example", true, true, "control"},
	// beyond Latin-1: no wire octet decodes to these, so they cannot reach a decision
	{`^caf\w\.example$`, "caf\u0661.example", true, false, `ARABIC-INDIC DIGIT ONE is \w and \d to Python`},
	{`^i$`, "\u0131", true, false, "Python's IGNORECASE also equates i with dotless U+0131; Go's simple case folding does not"},
	{`^k$`, "\u212a", true, true, "control: KELVIN SIGN folds to k in both"},
	{`^s$`, "\u017f", true, true, "control: LATIN SMALL LETTER LONG S folds to s in both"},
}

func TestRE2ReadsTheAdmittedTextAsPinnedAgainstPythonRe(t *testing.T) {
	diverging := 0
	for _, row := range RE2_DIVERGENCES {
		re, err := goCompile(row.text)
		if err != nil {
			t.Fatalf("Go cannot compile %q: %v", row.text, err)
		}
		if got := re.MatchString(row.name); got != row.goRE2 {
			t.Errorf("%q on %q: Go matched %v, the row pins %v (Python: %v; %s)", row.text, row.name, got, row.goRE2, row.python, row.why)
		}
		if row.python != row.goRE2 {
			diverging++
		}
	}
	if diverging < 10 {
		t.Errorf("only %d divergence rows: the table lost its point", diverging)
	}
}
