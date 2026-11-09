// Port of tests/test_pfb_dnsbl_regex_rules.py (admission grammar, compile text, excerpt) plus the admission rows of
// tests/test_adr07_regex_safety.py and the split rows of tests/test_issue1867_regex_hash_escape.py. The probe CLI
// (main, _report) is not translated, so the Python rows that drive it through a subprocess are covered here through
// the function they call. Where the Python rows hand the compile text to `re`, these hand it to Go's regexp (RE2):
// every admitted text must compile there.

package regexrules

import (
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The bounds are repeated here as literals on purpose: a changed constant must fail a test.
const (
	MAX_LEN         = 256
	COST_MAX        = 1 << 18
	CLASS_WIDTH_MAX = 256
)

func rep(s string, n int) string { return strings.Repeat(s, n) }

func brief(pattern string) string {
	runes := []rune(pattern)
	if len(runes) <= 40 {
		return strconv.QuoteToASCII(pattern)
	}
	return strconv.QuoteToASCII(string(runes[:40])) + " ... (" + strconv.Itoa(len(runes)) + " chars)"
}

// goCompile is how a Go caller compiles an admitted text: Python's re.compile(text, re.IGNORECASE).
func goCompile(text string) (*regexp.Regexp, error) { return regexp.Compile("(?i)" + text) }

type costRow struct {
	pattern string
	cost    uint64
}

// Every row the grammar must refuse, whatever the reason (the reason has its own rows).
var REFUSED = []string{
	"",
	rep("a", MAX_LEN+1),
	rep("a", 1_000_000),
	"é",
	"a b",
	"a\tb",
	"a\x00",
	"(",
	")",
	"[",
	"[]",
	"[^]",
	"[z-a]",
	"[[a]]",
	"[a--b]",
	`[\b]`,
	"(?=a)",
	"(?!a)",
	"(?<=a)",
	"(?<!a)",
	"(?P<n>a)",
	"(?P=n)",
	"(?i)a",
	"(?#c)",
	"(?(1)a|b)",
	"(?>a)",
	`\1`,
	`\g<1>`,
	`\x41`,
	`\u0041`,
	`\U00000041`,
	`\N{DIGIT ONE}`,
	`\0`,
	`\t`,
	`\A`,
	`\Z`,
	`a\`,
	`[\x00-\U0010ffff]`,
	"a{256}",
	"a{4294967296}",
	"a{5,3}",
	"a{,3}",
	"a{",
	"a{x}",
	"a**",
	"a*+",
	"a{2}{3}",
	"+a",
	"^*",
	`\b+`,
	"(|a)+",
	rep("(", 9) + "a" + rep(")", 9),
	`[\d-a]`,
	`[a-\d]`,
	"[+--]",
	"a}",
	"a]",
	"(a+)+",
	"(a|b)+",
	"(a?){5}",
	"((a))+",
	"(.*a){20}",
	"a{1,256}",
	"[a-z]+[a-z]+x",
	"^a?a?a?a?a?.*.*x",
	"^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x",
	"()+",
	"(?:)*",
	"(){2}",
	"(^a)+",
	`(\ba)+`,
	"(a$){3}",
	"(a(b+))+",
	"(a(b))+",
	`\B+`,
	`(\Ba)+`,
	"[a&&b]",
	"[a~~b]",
	"[a||b]",
	"^a?a?a?a?.*.*x",
	"^[a-z]+[a-z]+[a-z]+x",
	"^" + rep("(a|a)", 20) + "x",
	"^" + rep("a?", 16) + rep("a", 216) + "b",
	"^" + rep("a?", 20) + rep("a", 208) + "b",
	"^" + rep(".?", 20) + rep(".", 208) + "b",
	"^" + rep("a?", 12) + rep("a", 224) + "b",
	"^" + rep("[!-~]", 6) + "x",
}

// Rows the grammar must admit, with the exact cost bound it computes for each.
var ADMITTED_COSTS = []costRow{
	{`^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$`, 143921},
	{`^[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}$`, 776},
	{`\d+\.\d+`, 131840},
	{`[a-z]+[0-9]+\.example\.com`, 134656},
	{`^[^.]+\.[^.]+\.[^.]+\.example$`, 783},
	{`^[a-z]+\.[a-z]+\.[a-z]+$`, 775},
	{`metrics?-[0-9a-f]{6,}\.example$`, 71680},
	{"cdn[0-9]+", 66560},
	{"analytics", 2304},
	{`^cdn[a-z]{1,3}\.ads\.example$`, 21},
	{"^[a-z]+[a-z]+x", 131586},
	{"^" + rep("(a|a)", 16) + "x", 196607},
	{rep("a{255}", 4), COST_MAX}, // exactly at the bound
	{"(ab)+", 131584},
	{"^(ab)+c", 771},  // a repeated plain run multiplies what follows it
	{`^\w+_`, 514},    // `_` is a word character: the run and the next atom overlap
	{"^a+A", 514},     // letters fold: `a` also matches `A`
	{"^[a-c]+c", 514}, // the upper end of a class range is a member
	{`^(\.[a-z]){2}x`, 8},
	{`^xn--[a-z0-9-]+\.example$`, 271},
	{"a|", 512}, // an empty branch is still a step
	{"|", 512},
	{"()", 256},
	{"a||b", 768},
	{"(|a)b", 1024},
	{"^a|^b", 4},
	{"a|^b", 768}, // one branch is not anchored: the whole pattern is searched from every position
	{"a^", 512},   // a `^` that does not lead its branch does not anchor it
	{`\B`, 256},
	{`\/ads\/`, 1280},
	{"ad#1", 1024},
	{"[-a]", 256},
	{"[a-]", 256},
	{"[^.]", 256},
	{"[!-~]", 256},
	{"a*?", 65536},
	{"a{0,1}", 512},
	{rep("(", 8) + "a" + rep(")", 8), 256},
	{rep("a", MAX_LEN), 65536},
	{"a{255}", 65536},
	{"^a{1,255}", 257},
	{"[a-z-9]", 256},
	{"[a-a]", 256},
	{`[\d-]`, 256},
	{`^(a\))x`, 4}, // an escaped `)` inside a group is a literal, not the group's end
	// A branch that starts with `.*` or `.+` is anchored (see LEADING_DOT_PAIRS): `.*ads.*` costs what `^.*ads.*` does.
	{".*ads.*", 66561},
	{".*", 257},
	// The anchored forms of the patterns the unanchored search refuses (ANCHOR_REMEDY_REFUSALS).
	{`^\S+\.EXAMPLE\.COM`, 3330},
	{`^\D+\.EXAMPLE\.COM`, 3330},
	{`^\W+\.EXAMPLE\.COM`, 3330},
	{`^ad.*\.example\.com`, 3331},
	{"^a+b{1,255}a?a*a", COST_MAX}, // the caret costs one node: exactly at the bound
}

// Refused only because the bound on its backtracking work is exceeded, with that bound.
var COST_REFUSALS = []struct {
	pattern string
	bound   string
}{
	{rep("a?", 128), "18446744073709551616"},              // the bound saturates at 1<<64, so the reason stays short
	{"^" + rep("a?", 12) + rep("a", 224) + "b", "929791"}, // a long mandatory tail behind a dozen optional atoms
	{"^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}x", "439322"},
	{"^" + rep("(a|a)", 17) + "x", "393215"},
	{"^a?a?a?a?.*.*x", "2101279"},
	{"^a?a?a?a?a?.*.*x", "4202559"},
	{"^[a-z]+[a-z]+[a-z]+x", "33686018"},
	{"^[a-z]+a[a-z]+a[a-z]+1$", "17105666"},
	{"^" + rep("(a|a)", 20) + "x", "3145727"},
	{"^" + rep("a?", 16) + rep("a", 216) + "b", "14352383"},
	{"^" + rep("a?", 20) + rep("a", 208) + "b", "221249535"},
	{"^" + rep(".?", 20) + rep(".", 208) + "b", "221249535"},
	{"^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x", "33293312"},
}

// Unanchored and over the bound even with a `^` in front of every branch, so the reason offers no remedy that would
// not work.
var UNANCHORED_PLAIN_REFUSALS = []costRow{
	{"[a-z]+[a-z]+[a-z]+x", 8623620352},
	{"a*a+b{1,255}a?", 67108864},    // 262144 nodes: the caret itself costs one more
	{"a*b{1,255}a?a*a|x", 67108608}, // two branches need two carets
}

// Over the bound only because an unanchored search starts a match at every position of the name (x256): with a `^`
// in front of every branch the pattern fits.
var ANCHOR_REMEDY_REFUSALS = []costRow{
	{rep("a{255}", 4) + "a", 262400}, // one node over the bound
	{"[a-z]+[a-z]+x", 33685760},
	{`\S+\.EXAMPLE\.COM`, 852224},
	{`\D+\.EXAMPLE\.COM`, 852224},
	{`\W+\.EXAMPLE\.COM`, 852224},
	{`ad.*\.example\.com`, 852480},
	{"a+b{1,255}a?a*a", 67108608}, // with the caret it is exactly at the bound
}

// The bound on the ASCII members that the bracket classes of one pattern list, summed. A class lists its members
// before any `^` negation; letters fold, so `[a-z]` lists 52; `\d \w \s \D \W \S` inside a bracket list their ASCII
// members; `.` and the bare escapes list none.
var WIDTH_REFUSALS = []costRow{
	{"^" + rep("[!-~]", 3) + "x", 282}, // printable ASCII listed three times
	{"^" + rep("[!-~]", 6) + "x", 564},
	{"^" + rep("[!-~]", 49) + "x0001", 4606}, // cheap to match, milliseconds to compile
	{"^" + rep("[a-z]", 5) + "x", 260},       // folded: 52 each, not 26
	{"^" + rep("[^!-~]", 3) + "x", 282},      // counted before the negation, not after
	{"^" + rep(`[\w]`, 5) + "x", 315},        // 63 ASCII members, no non-ASCII stand-in
	{"^" + rep(`[\W]`, 4) + "x", 260},
	{"^" + rep(`[\D]`, 3) + "x", 354},
	{"^" + rep(`[\S]`, 3) + "x", 354},
	{"^" + rep(`[\d]`, 26) + "x", 260},
	{"^" + rep(`[\s]`, 26) + "x", 260},
	{"^(?:" + strings.Join([]string{"[!-~]", "[!-~]", "[!-~]"}, "|") + ")x", 282}, // summed across the branches of a group
	{"^" + rep(`[\w.-]`, 9) + "x", 585},
	{"^[!-~][!-~][abcdefghijklmnopqrstuvwxyz0123456789!#%&][!][#][%]x", 257}, // a 40-item class counts in full
}

// Admitted rows: the exact cost bound, and in the comment the class width that stays under the bound.
var WIDTH_ADMITTED = []costRow{
	{`^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.example$`, 1041}, // 252
	{"^" + rep("[!-~]", 2) + "x", 4},                                    // 188
	{"^" + rep("[a-z]", 4) + "x", 6},                                    // 208, folded
	{"^" + rep("[^a]", 60) + "x", 62},                                   // 120 listed, although each class matches 126 ASCII characters
	{"^" + rep(`[\w]`, 4) + rep("[!]", 4) + "x", 10},                    // 256: [\w] lists 63
	{"^" + rep("[!-@]", 8) + rep(".", 50) + "x", 60},                    // `.` lists nothing: still exactly at the bound
	{"^" + rep(`[\d]`, 25) + "x", 27},                                   // 250
	{"^" + rep(`[\s]`, 25) + "x", 27},                                   // 250
	{"^" + rep(`[\D]`, 2) + "x", 4},                                     // 236
	{"^" + rep(`[\W]`, 3) + "x", 5},                                     // 195
	{"^(?:[!-~]|[!-~])x", 5},                                            // 188
	{"^" + rep(`\w`, 60) + "x", 62},                                     // bare escapes list nothing
	{"^" + rep(`\D\W\S\d\w\s`, 20) + ".x", 123},
}

// A pattern whose every branch starts with `^`, `.*` or `.+` (greedy or lazy) is anchored: a leading dot run can
// stand for everything before the match, so it matches from position 0 exactly when it matches from some start
// position, and the leading run costs what the same run behind a written `^` costs.
var LEADING_DOT_PAIRS = []struct {
	pattern  string
	anchored string
	cost     int
}{
	{`.*\.microsoft\.com$`, `^.*\.microsoft\.com$`, 4097},
	{`.+\.x\.com$`, `^.+\.x\.com$`, 2050},
	{".*ads.*", "^.*ads.*", 66561},
	{".+ads.+", "^.+ads.+", 66818},
	{".*?a", "^.*?a", 513},
	{".+?a", "^.+?a", 514},
	{".*a|.+b", "^.*a|^.+b", 1027},
	{".*a|^b", "^.*a|^b", 515},
	{".*", "^.*", 257},
	{".+", "^.+", 258},
}

// A leading `.*` or `.+` anchors only as the very first item of a top-level branch: another quantifier (`.?` is
// optional, not a run), a group around it or a class standing in for the dot keep the unanchored search (every start
// position).
var UNANCHORED_DOT_ROWS = []costRow{
	{"(.*)x", 131072},
	{"[^.]*x", 131072},
	{".{2,}x", 131584},
	{"a|.*b", 131584}, // one branch is not anchored, so the whole pattern is searched from every position
	{".*a|b", 131584},
	{"(?:.*a)|b", 131328},
	{".?x", 1024},
	{".??x", 1024},
}

// The compile text (third item of the admission result): the text a pattern is compiled from. A pattern that is
// anchored only through a leading `.*` / `.+` is compiled behind a written `^` so the engine itself skips every other
// start position, and each such leading run is spelled so that it crosses a newline exactly as an unanchored search
// does: `.*` as `(?s:.*)`, `.+` as `(?s:.*)[^\n]` (lazy forms likewise). Every other pattern is compiled as written.
var COMPILE_TEXT = []struct{ pattern, text string }{
	{".*a|.+b", `^(?:(?s:.*)a|(?s:.*)[^\n]b)`},
	{`.*\.microsoft\.com$`, `^(?:(?s:.*)\.microsoft\.com$)`},
	{".+?a", `^(?:(?s:.*?)[^\n]a)`},
	{".*?a", `^(?:(?s:.*?)a)`},
	{".+a", `^(?:(?s:.*)[^\n]a)`},
	{"^a|.*b", `^(?:^a|(?s:.*)b)`},
	{".*a|^b", `^(?:(?s:.*)a|^b)`},
	{".*ads.*", `^(?:(?s:.*)ads.*)`}, // only the leading run is rewritten
	{".*", `^(?:(?s:.*))`},
	{".+", `^(?:(?s:.*)[^\n])`},
	// compiled as written: not anchored, anchored by `^` alone, or refused
	{"a|.*b", "a|.*b"},
	{"(.*)x", "(.*)x"},
	{"[^.]*x", "[^.]*x"},
	{".{2,}x", ".{2,}x"},
	{".?x", ".?x"},
	{".??x", ".??x"},
	{"^.*x", "^.*x"},
	{"^.+x", "^.+x"},
	{"^.*?x", "^.*?x"},
	{"^a|^b", "^a|^b"},
	{"abc", "abc"},
	{"(.*a)+", "(.*a)+"},
}

// Cost of patterns built from quantified single atoms. Two atoms are disjoint when no ASCII character (letters folded
// to both cases) and no non-ASCII character can match both; the non-ASCII side is one shared pseudo-member of `.`,
// `\w \W \D \S \s` and every negated class. A quantified atom multiplies the work after it, unless a disjoint mandatory
// atom follows it directly (it cannot hand characters over) or nothing but `$` follows it in a top-level branch.
var DISJOINTNESS_COSTS = []costRow{
	// disjoint: the run cannot give characters to the atom after it
	{`^\w+-`, 259},
	{`^\w+\.`, 259},
	{`^[^.]+\.`, 259},
	{"^[a-z]+1", 259},
	{`^\d+\.`, 259}, // a digit class and a literal that is not a digit
	{`^\d+x`, 259},
	// overlap: the run and the next atom can share a character
	{`^.+\.`, 514},
	{`^\W+\.`, 514},
	{"^[a-z]+A", 514}, // letters fold: [a-z] also matches A
	{"^[a-z]+[A-Z]", 514},
	{`^\S+\w`, 514},
	{`^\w+\W`, 514}, // no ASCII overlap: only the non-ASCII pseudo-member is shared
	// the next item must be a MANDATORY single atom
	{`^[a-z]*\.`, 258},
	{`^[a-z]+\.?`, 770},
	{`^[a-z]+(\.)`, 514},
	{`^[a-z]+\b\.`, 770},
	{`^[a-z]+a?\.`, 1026},
	// a run that ends a top-level branch, or is followed only by `$`, multiplies nothing
	{"^[a-z]+", 258},
	{"^[a-z]+$", 259},
	{"^[a-z]+$$", 260},
	{`^[a-z]+\b`, 514},
	{"[a-z]+$", 66048},
	// inside a group the run still multiplies what follows the group
	{`^(x|[a-z]+)\.`, 516},
	// the non-ASCII pseudo-member: shared by `\d \s \S \D` and every negated class (`\d` matches every Unicode decimal
	// digit, so it stands for non-ASCII characters too), not by an ASCII literal
	{`^\s+\S`, 514},
	{`^\S+\s`, 514},
	{`^\D+[^\D]`, 514},
	{`^[^\W]+\W`, 514},
	{`^\D+\d`, 514},
	{`^\d+\D`, 514},
	{`^\d+\W`, 514},
	{`^\d+\s`, 514},
	{`^[^0-9]+\d`, 514},
}

// Names that separate every wrapped row from its wrongly anchored cousin: each row matches some of them and fails
// others, and the matches sit at the start, in the middle and at the end of a name.
var EQUIVALENCE_NAMES = []string{
	"",
	"a",
	"b",
	"xa",
	"xb",
	"ba",
	"ab",
	"a.example",
	"ads.example",
	"foo.ads.example",
	"sub.x.com",
	"x.com",
	"microsoft.com",
	"foo.microsoft.com",
	"foo.microsoft.com.evil.example",
	"www.example.com",
}

// Names that carry a newline (a CNAME target is decoded from Latin-1 bytes and may hold one): the compile text must
// match exactly the names the pattern as written matches, newline or not.
var NEWLINE_NAMES = []string{
	"x\n.ads.example",
	"b\nads",
	"\n",
	"a\nb\nc.x.com",
	"x\n.microsoft.com",
	"a\n",
	"\na",
	"foo\n.ads.example\n",
}

func TestExportedBoundsAreTheFixedAdmissionBounds(t *testing.T) {
	got := [...]int{REGEX_STATIC_LEN_CAP, REGEX_PATTERN_MAX_LEN, REGEX_REPEAT_MAX, REGEX_GROUP_DEPTH_MAX, REGEX_COST_MAX, REGEX_CLASS_WIDTH_MAX, REGEX_COST_UNBOUNDED}
	want := [...]int{200, MAX_LEN, 255, 8, COST_MAX, CLASS_WIDTH_MAX, 256}
	if got != want {
		t.Errorf("REGEX_STATIC_LEN_CAP, REGEX_PATTERN_MAX_LEN, REGEX_REPEAT_MAX, REGEX_GROUP_DEPTH_MAX, REGEX_COST_MAX, REGEX_CLASS_WIDTH_MAX, REGEX_COST_UNBOUNDED = %v, want %v", got, want)
	}
}

// test_gate_never_compiles_or_matches_feed_pattern_text + test_gate_module_keeps_no_compiled_patterns_of_its_own:
// the verdict is reached by reading the text once; the package holds no regexp, so none can be applied to hostile text.
func TestGateNeverCompilesOrMatchesFeedPatternText(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if path := strings.Trim(spec.Path.Value, `"`); path == "regexp" || strings.HasPrefix(path, "regexp/") {
				t.Errorf("%s imports %s: the gate must reach for no regex engine while judging feed-supplied pattern text", name, path)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no production file found to check")
	}
}

// Every row the Python test lists answers with a verdict and never panics.
func TestGateAnswersEveryRowWithAVerdict(t *testing.T) {
	var rows []string
	for _, row := range ADMITTED_COSTS {
		rows = append(rows, row.pattern)
	}
	for _, rowset := range [][]costRow{WIDTH_ADMITTED, UNANCHORED_DOT_ROWS, WIDTH_REFUSALS} {
		for _, row := range rowset {
			rows = append(rows, row.pattern)
		}
	}
	for _, row := range LEADING_DOT_PAIRS {
		rows = append(rows, row.pattern)
	}
	for _, row := range COMPILE_TEXT {
		rows = append(rows, row.pattern)
	}
	rows = append(rows, REFUSED...)
	rows = append(rows, "[a-z]+[a-z]+[a-z]+[a-z]+", `^([a-z]+)\1$`, "(a+)(a+)+")
	for _, pattern := range rows {
		cost, compiled, reason := Admission(pattern)
		if (compiled != nil) != (reason == "") || (compiled != nil) != (cost > 0) {
			t.Errorf("Admission(%s) = (%d, %v, %q): admitted needs a cost, a compile text and no reason; refused needs none of the first two", brief(pattern), cost, compiled, reason)
		}
	}
}

func TestOversizedPatternIsRefusedFromItsLengthAlone(t *testing.T) {
	cost, compiled, reason := Admission(rep("a", 1_000_000))
	if cost != 0 || compiled != nil || reason != "over 256 characters" {
		t.Errorf("Admission(1,000,000 characters) = (%d, %v, %q), want (0, nil, %q)", cost, compiled, reason, "over 256 characters")
	}
}

// The length is counted in characters, as Python's len() counts them, not in UTF-8 bytes.
func TestLengthIsCountedInCharactersNotBytes(t *testing.T) {
	for _, row := range []struct {
		pattern, reason string
	}{
		{rep("é", 129), "non-ASCII, space or control character"}, // 258 bytes, 129 characters
		{rep("é", MAX_LEN), "non-ASCII, space or control character"},
		{rep("é", MAX_LEN+1), "over 256 characters"},
	} {
		if cost, compiled, reason := Admission(row.pattern); cost != 0 || compiled != nil || reason != row.reason {
			t.Errorf("Admission(%s) = (%d, %v, %q), want (0, nil, %q)", brief(row.pattern), cost, compiled, reason, row.reason)
		}
	}
}

func TestGateSettlesHostilePatternsOfAnySizeWithoutStalling(t *testing.T) {
	big := map[string]func(size int) string{
		"unclosed-group-plus-run": func(size int) string { return "(a" + rep("+", size-2) },
		"open-groups":             func(size int) string { return rep("(", size) },
		"nested-alternation":      func(size int) string { return rep("(?:a|", size/7) + "b" + rep(")", size/7) },
		"class-plus-run":          func(size int) string { return rep("[a-z]+", size/6) },
	}
	rows := 0
	for family, build := range big {
		for _, size := range []int{2_000, 32_000, 1_000_000} {
			pattern := build(size)
			cost, compiled, reason := Admission(pattern)
			if cost != 0 || compiled != nil || reason != "over 256 characters" {
				t.Errorf("%s of %d characters: (%d, %v, %q), want a refusal on length", family, len(pattern), cost, compiled, reason)
			}
			rows++
		}
	}
	if rows != 12 {
		t.Errorf("hostile big rows = %d, want 12", rows)
	}

	small := map[string]string{
		"groups-to-the-depth-limit":             rep("(", 8) + "a" + rep(")", 8),
		"groups-past-the-depth-limit":           rep("(", 9) + "a" + rep(")", 9),
		"open-groups-to-the-length-limit":       rep("(", 256),
		"unclosed-group-plus-run":               "(a" + rep("+", 250),
		"alternation-nested-to-the-depth-limit": rep("(?:a|", 8) + "b" + rep(")", 8),
		"alternation-chain":                     strings.Join(slices.Repeat([]string{"ab"}, 60), "|"),
		"optional-chain":                        rep("a?", 128),
		"class-plus-run":                        rep("[a-z]+", 42),
		"class-of-many-items":                   "[" + rep("a", 254) + "]",
		"wide-classes":                          "^" + rep("[!-~]", 49) + "x0001",
	}
	admitted := map[string]int{}
	refused := map[string]string{}
	for name, pattern := range small {
		if len(pattern) > MAX_LEN {
			t.Errorf("%s: %d characters, the row must fit the length ceiling", name, len(pattern))
		}
		cost, compiled, reason := Admission(pattern)
		if compiled != nil {
			admitted[name] = cost
		} else {
			refused[name] = reason
		}
	}
	wantAdmitted := map[string]int{
		"groups-to-the-depth-limit":             256,
		"alternation-nested-to-the-depth-limit": 2304,
		"alternation-chain":                     30720,
		"class-of-many-items":                   256,
	}
	if len(admitted) != len(wantAdmitted) {
		t.Errorf("admitted = %v, want %v", admitted, wantAdmitted)
	}
	for name, cost := range wantAdmitted {
		if admitted[name] != cost {
			t.Errorf("admitted = %v, want %v", admitted, wantAdmitted)
			break
		}
	}
	for name, fragment := range map[string]string{
		"groups-past-the-depth-limit":     "nested",
		"open-groups-to-the-length-limit": "nested",
		"unclosed-group-plus-run":         "quantifier",
		"optional-chain":                  "too costly to match",
		"class-plus-run":                  "too costly to match",
		"wide-classes":                    "character classes too wide",
	} {
		if !strings.Contains(refused[name], fragment) {
			t.Errorf("%s refused as %q, want a reason containing %q", name, refused[name], fragment)
		}
	}
	if len(refused) != 6 {
		t.Errorf("refused = %v, want exactly the 6 named rows", refused)
	}
}

// The Python test seeds random.Random(0x5EED); Go's generator differs, so this is the same shape of corpus, not the
// same patterns. Every admitted text compiles in Go and is searched against 253-character names built to force
// backtracking (RE2 runs in linear time, so completing is the pin).
func TestEveryAdmittedGeneratedPatternCompilesAndSearchesHostileNamesToCompletion(t *testing.T) {
	atoms := []string{"a", "b", "1", "-", `\.`, ".", "[a-z]", "[a-z0-9-]", `\w`, `\d`, "[^.]", "a", "[ab]"}
	quants := []string{"", "", "", "?", "*", "+", "{1,3}", "{2,}", "{1,60}", "{1,255}", "{2}", "+", "*"}
	groups := []string{"(ab)", "(?:a|b)", `(\.[a-z])`, "(a?b)", "(?:a|)", "(.*a)", "(a+)", `([a-z]+\.)`}
	tails := []string{"", "#", "x", "$", "#", "x"} // '#' and 'x' never occur in the names: forces full backtracking
	names := []string{rep("a", 253), rep("a.", 127)[:253], rep("ab-1.", 60)[:253]}
	rng := rand.New(rand.NewPCG(0x5EED, 0x5EED))
	pick := func(items []string) string { return items[rng.IntN(len(items))] }
	admitted, refused := 0, 0
	for range 400 {
		var parts []string
		if rng.Float64() < 0.5 {
			parts = append(parts, "^")
		}
		for range 2 + rng.IntN(6) {
			unit := pick(atoms)
			if rng.Float64() < 0.2 {
				unit = pick(groups)
			}
			parts = append(parts, unit+pick(quants))
		}
		parts = append(parts, pick(tails))
		pattern := strings.Join(parts, "")
		_, compiled, _ := Admission(pattern)
		if compiled == nil {
			refused++
			continue
		}
		admitted++
		re, err := goCompile(*compiled)
		if err != nil {
			t.Errorf("admitted %s but Go cannot compile %q: %v", brief(pattern), *compiled, err)
			continue
		}
		for _, name := range names {
			re.MatchString(name)
		}
	}
	if admitted < 50 || refused < 50 {
		t.Errorf("the corpus must exercise both verdicts in volume: admitted %d, refused %d", admitted, refused)
	}
}

// test_probe_and_resolver_agree_on_every_admission_verdict builds this corpus for the probe; the admission half is
// the verdict itself: whatever the four-way combinations admit compiles in Go, and both verdicts occur.
func TestEveryAdmittedFourWayCombinationCompilesInGo(t *testing.T) {
	blocks := []string{"(", ")", "(?:", "[a-z]", "a", ".", "+", "*", "{2}", "|", `\`, "$"}
	admitted, refused := 0, 0
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		if depth == 0 {
			cost, compiled, reason := Admission(prefix)
			if (compiled != nil) != (reason == "") || (compiled != nil) != (cost > 0) {
				t.Errorf("Admission(%s) = (%d, %v, %q): not one consistent verdict", brief(prefix), cost, compiled, reason)
			}
			if compiled == nil {
				refused++
				return
			}
			admitted++
			if _, err := goCompile(*compiled); err != nil {
				t.Errorf("admitted %s but Go cannot compile %q: %v", brief(prefix), *compiled, err)
			}
			return
		}
		for _, block := range blocks {
			walk(prefix+block, depth-1)
		}
	}
	walk("", 4)
	if admitted == 0 || refused == 0 {
		t.Errorf("corpus never exercised both verdicts: admitted %d, refused %d", admitted, refused)
	}
}

func TestPatternOutsideTheGrammarIsRefused(t *testing.T) {
	for _, pattern := range REFUSED {
		t.Run(brief(pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(pattern)
			if cost != 0 || compiled != nil || reason == "" {
				t.Errorf("expected a refusal of %s, got cost=%d compiled=%v reason=%q", brief(pattern), cost, compiled, reason)
			}
		})
	}
}

func TestAdmittedPatternReportsItsBacktrackingBound(t *testing.T) {
	for _, row := range ADMITTED_COSTS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			if uint64(cost) != row.cost || compiled == nil || reason != "" {
				t.Errorf("%s: expected cost %d admitted, got (%d, %v, %q)", brief(row.pattern), row.cost, cost, compiled, reason)
			}
		})
	}
}

func TestPatternOverTheCostBoundIsRefusedAndNamesTheBound(t *testing.T) {
	for _, row := range COST_REFUSALS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			want := "too costly to match (bound " + row.bound + " > " + strconv.Itoa(COST_MAX) + ")"
			if cost != 0 || compiled != nil || reason != want {
				t.Errorf("%s: got (%d, %v, %q), want a refusal %q", brief(row.pattern), cost, compiled, reason, want)
			}
		})
	}
}

// anchorEveryBranch is the remedy the reason names: "|".join("^" + branch for branch in pattern.split("|")).
func anchorEveryBranch(pattern string) string {
	branches := strings.Split(pattern, "|")
	for index, branch := range branches {
		branches[index] = "^" + branch
	}
	return strings.Join(branches, "|")
}

func TestAPatternRefusedOnlyForItsUnanchoredSearchSaysSoAndNamesTheRemedy(t *testing.T) {
	for _, row := range ANCHOR_REMEDY_REFUSALS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			want := "too costly to match unanchored (bound " + strconv.FormatUint(row.cost, 10) + " > " + strconv.Itoa(COST_MAX) + "); anchor it with ^"
			if cost != 0 || compiled != nil || reason != want {
				t.Errorf("%s: got (%d, %v, %q), want a refusal %q", brief(row.pattern), cost, compiled, reason, want)
			}
			// The remedy it names works: a `^` in front of every branch admits the pattern.
			if _, anchored, why := Admission(anchorEveryBranch(row.pattern)); anchored == nil {
				t.Errorf("anchored %s is still refused: %q", brief(anchorEveryBranch(row.pattern)), why)
			}
		})
	}
}

func TestAPatternACaretWouldNotSaveKeepsThePlainReason(t *testing.T) {
	for _, row := range UNANCHORED_PLAIN_REFUSALS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			want := "too costly to match (bound " + strconv.FormatUint(row.cost, 10) + " > " + strconv.Itoa(COST_MAX) + ")"
			if cost != 0 || compiled != nil || reason != want {
				t.Errorf("%s: got (%d, %v, %q), want a refusal %q", brief(row.pattern), cost, compiled, reason, want)
			}
			// Anchoring it would still be over the bound.
			if _, anchored, _ := Admission(anchorEveryBranch(row.pattern)); anchored != nil {
				t.Errorf("anchored %s is admitted", brief(anchorEveryBranch(row.pattern)))
			}
		})
	}
}

func TestPatternOverTheClassWidthBoundIsRefusedAndNamesTheWidth(t *testing.T) {
	for _, row := range WIDTH_REFUSALS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			want := "character classes too wide (width " + strconv.FormatUint(row.cost, 10) + " > " + strconv.Itoa(CLASS_WIDTH_MAX) + ")"
			if cost != 0 || compiled != nil || reason != want {
				t.Errorf("%s: got (%d, %v, %q), want a refusal %q", brief(row.pattern), cost, compiled, reason, want)
			}
		})
	}
}

func TestPatternWithinTheClassWidthBoundIsAdmitted(t *testing.T) {
	for _, row := range WIDTH_ADMITTED {
		t.Run(brief(row.pattern), func(t *testing.T) {
			cost, compiled, reason := Admission(row.pattern)
			if uint64(cost) != row.cost || compiled == nil || reason != "" {
				t.Errorf("%s: expected cost %d admitted, got (%d, %v, %q)", brief(row.pattern), row.cost, cost, compiled, reason)
			}
		})
	}
}

// classesOfWidth is an anchored pattern whose bracket classes list exactly width ASCII members, none a letter.
func classesOfWidth(width int) string {
	blocks, rest := width/32, width%32
	return "^" + rep("[!-@]", blocks) + rep("[!]", rest) + "x"
}

func TestTheClassWidthBoundAdmitsEveryWidthUpToItsLimit(t *testing.T) {
	for _, width := range []int{CLASS_WIDTH_MAX - 31, CLASS_WIDTH_MAX - 1, CLASS_WIDTH_MAX} {
		cost, compiled, reason := Admission(classesOfWidth(width))
		if compiled == nil || reason != "" || cost <= 0 {
			t.Errorf("width %d: got (%d, %v, %q), want an admission", width, cost, compiled, reason)
		}
	}
}

func TestTheClassWidthBoundRefusesEveryWidthPastItsLimit(t *testing.T) {
	for _, width := range []int{CLASS_WIDTH_MAX + 1, CLASS_WIDTH_MAX + 32} {
		cost, compiled, reason := Admission(classesOfWidth(width))
		want := "character classes too wide (width " + strconv.Itoa(width) + " > " + strconv.Itoa(CLASS_WIDTH_MAX) + ")"
		if cost != 0 || compiled != nil || reason != want {
			t.Errorf("width %d: got (%d, %v, %q), want a refusal %q", width, cost, compiled, reason, want)
		}
	}
}

func TestAQuantifiedAtomMultipliesTheWorkAfterItOnlyWhenTheyCanShareCharacters(t *testing.T) {
	for _, row := range DISJOINTNESS_COSTS {
		t.Run(row.pattern, func(t *testing.T) {
			if cost, compiled, reason := Admission(row.pattern); uint64(cost) != row.cost || compiled == nil || reason != "" {
				t.Errorf("%s: expected cost %d admitted, got (%d, %v, %q)", row.pattern, row.cost, cost, compiled, reason)
			}
		})
	}
}

func TestALeadingDotRunCostsWhatTheSameRunBehindAWrittenCaretCosts(t *testing.T) {
	for _, row := range LEADING_DOT_PAIRS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			for _, pattern := range []string{row.anchored, row.pattern} {
				if cost, compiled, reason := Admission(pattern); cost != row.cost || compiled == nil || reason != "" {
					t.Errorf("%s: expected cost %d admitted, got (%d, %v, %q)", brief(pattern), row.cost, cost, compiled, reason)
				}
			}
		})
	}
}

func TestADotRunThatIsNotTheFirstItemOfEveryBranchKeepsTheUnanchoredSearch(t *testing.T) {
	for _, row := range UNANCHORED_DOT_ROWS {
		t.Run(brief(row.pattern), func(t *testing.T) {
			if cost, compiled, reason := Admission(row.pattern); uint64(cost) != row.cost || compiled == nil || reason != "" {
				t.Errorf("%s: expected cost %d admitted, got (%d, %v, %q)", brief(row.pattern), row.cost, cost, compiled, reason)
			}
		})
	}
}

// The Python table lists "(.*a)+" among the rows compiled as written: a refused pattern is returned as its own compile
// text there. Go has no compile text for a refusal (nil), so that row must be a refusal whose Python text is the pattern.
func TestTheCompileTextIsWrappedBehindACaretOnlyWhenALeadingDotRunAnchorsThePattern(t *testing.T) {
	refusedRows := map[string]string{"(.*a)+": "quantified group"}
	for _, row := range COMPILE_TEXT {
		t.Run(brief(row.pattern), func(t *testing.T) {
			_, compiled, reason := Admission(row.pattern)
			if want, refused := refusedRows[row.pattern]; refused {
				if compiled != nil || reason != want || row.text != row.pattern {
					t.Errorf("%s: got compile text %v and reason %q, want a refusal %q", brief(row.pattern), compiled, reason, want)
				}
				return
			}
			if compiled == nil || *compiled != row.text {
				t.Errorf("%s: compile text %v (reason %q), want %q", brief(row.pattern), compiled, reason, row.text)
			}
		})
	}
}

// ADMISSION_RESULTS: the result is one parse of the text. The Python refusal carries its own text as the compile text
// (nothing compiles it); here a refusal has no compile text at all (nil), as the contract says.
func TestAdmissionReturnsTheCostTheReasonAndTheCompileTextTogether(t *testing.T) {
	text := func(s string) *string { return &s }
	for _, row := range []struct {
		pattern string
		cost    int // 0 with a text: any positive cost
		compile *string
		reason  string
	}{
		{".*a|.+b", 1027, text(`^(?:(?s:.*)a|(?s:.*)[^\n]b)`), ""},
		{`^keep\.example$`, 0, text(`^keep\.example$`), ""},
		{"a|.*b", 131584, text("a|.*b"), ""},
		{"(a+)+", 0, nil, "quantified group"},
		{rep("a", MAX_LEN+1), 0, nil, "over 256 characters"},
	} {
		cost, compiled, reason := Admission(row.pattern)
		if reason != row.reason || (compiled == nil) != (row.compile == nil) || (compiled != nil && *compiled != *row.compile) {
			t.Errorf("%s: got (%d, %v, %q), want compile text %v and reason %q", brief(row.pattern), cost, compiled, reason, row.compile, row.reason)
		}
		if row.compile == nil && cost != 0 || row.compile != nil && row.cost == 0 && cost <= 0 || row.cost != 0 && cost != row.cost {
			t.Errorf("%s: cost %d, want %d (0 = any positive cost for an admission, 0 for a refusal)", brief(row.pattern), cost, row.cost)
		}
	}
}

// Every pattern that a leading dot run anchors, as written (the unanchored forms).
func leadingDotRows() []string {
	set := map[string]bool{}
	for _, row := range COMPILE_TEXT {
		if row.text != row.pattern {
			set[row.pattern] = true
		}
	}
	for _, row := range LEADING_DOT_PAIRS {
		set[row.pattern] = true
	}
	rows := make([]string, 0, len(set))
	for pattern := range set {
		rows = append(rows, pattern)
	}
	slices.Sort(rows)
	return rows
}

// The compile text and the pattern as written agree on every name, newline or not, in Go's engine as in Python's.
func TestTheCompileTextAndThePatternAsWrittenAgreeOnEveryNameNewlineOrNot(t *testing.T) {
	matchesEveryName := map[string]bool{".*": true}
	for _, pattern := range leadingDotRows() {
		t.Run(brief(pattern), func(t *testing.T) {
			original, err := goCompile(pattern)
			if err != nil {
				t.Fatalf("Go cannot compile %s: %v", brief(pattern), err)
			}
			_, compiledText, reason := Admission(pattern)
			if compiledText == nil {
				t.Fatalf("%s is refused: %s", brief(pattern), reason)
			}
			compiled, err := goCompile(*compiledText)
			if err != nil {
				t.Fatalf("Go cannot compile %q: %v", *compiledText, err)
			}
			seen := map[bool]bool{}
			for _, name := range append(slices.Clone(EQUIVALENCE_NAMES), NEWLINE_NAMES...) {
				before, after := original.MatchString(name), compiled.MatchString(name)
				if before != after {
					t.Errorf("%s on %q: as written %v, compile text %q %v", brief(pattern), name, before, *compiledText, after)
				}
				seen[before] = true
			}
			if !matchesEveryName[pattern] && !(seen[true] && seen[false]) {
				t.Errorf("%s does not tell the names apart in both directions (%v)", brief(pattern), seen)
			}
		})
	}
}

func TestACaretWrittenBeforeAPlainDotRunWouldNotMatchWhatTheUnanchoredPatternDoes(t *testing.T) {
	name := "x\n.microsoft.com"
	if re, _ := goCompile(`.*\.microsoft\.com$`); !re.MatchString(name) {
		t.Errorf(`the unanchored .*\.microsoft\.com$ must match %q`, name)
	}
	if re, _ := goCompile(`^.*\.microsoft\.com$`); re.MatchString(name) {
		t.Errorf(`^.*\.microsoft\.com$ must not match %q: a plain dot does not cross the newline`, name)
	}
	_, compiled, _ := Admission(`.*\.microsoft\.com$`)
	if re, err := goCompile(*compiled); err != nil || !re.MatchString(name) {
		t.Errorf("compile text %q must match %q (err %v)", *compiled, name, err)
	}
}

func TestRefusalNamesItsReason(t *testing.T) {
	for _, row := range []struct{ pattern, fragment string }{
		{"", "empty pattern"},
		{rep("a", MAX_LEN+1), "over 256 characters"},
		{"a b", "non-ASCII, space or control character"},
		{"é", "non-ASCII, space or control character"},
		{`\1`, "unsupported escape"},
		{`\x41`, "unsupported escape"},
		{"(?=a)", "unsupported group"},
		{"(?P<n>a)", "unsupported group"},
		{"(a+)+", "quantified group"},
		{"(|a)+", "quantified group"},
		{rep("(", 9) + "a" + rep(")", 9), "nested"},
		{"(", "unbalanced"},
		{")", "unbalanced"},
		{"[a", "unclosed"},
		{"[]", "empty"},
		{"[z-a]", "range"},
		{"a{256}", "repeat"},
		{"a**", "quantifier"},
		{`\b+`, "quantifier"},
		{"()+", "quantified group"},
		{"(?:)*", "quantified group"},
		{"(){2}", "quantified group"},
		{"(^a)+", "quantified group"},
		{`(\ba)+`, "quantified group"},
		{"(a$){3}", "quantified group"},
		{"(a(b+))+", "quantified group"},
		{"(a(b))+", "quantified group"},
		{"[a&&b]", "set operation"},
		{"[a~~b]", "set operation"},
		{"[a||b]", "set operation"},
		{"[a--b]", "set operation"},
		{"^" + rep("a?", 20) + rep("a", 208) + "b", "too costly to match"},
	} {
		cost, compiled, reason := Admission(row.pattern)
		if cost != 0 || compiled != nil || !strings.Contains(reason, row.fragment) {
			t.Errorf("%s: got (%d, %v, %q), want a refusal containing %q", brief(row.pattern), cost, compiled, reason, row.fragment)
		}
	}
}

// Reasons end up in logs and admin-facing errors; they stay short and fixed.
func TestRefusalReasonNeverEmbedsThePatternText(t *testing.T) {
	for _, pattern := range []string{"(?P<TAILMARKER>a)", "[TAILMARKER-A]", `TAILMARKER\x41`, "TAILMARKER{999}"} {
		_, compiled, reason := Admission(pattern)
		if compiled != nil || reason == "" {
			t.Errorf("%s must be refused", brief(pattern))
		}
		if strings.Contains(reason, "TAILMARKER") || len(reason) >= 100 {
			t.Errorf("reason %q embeds the pattern text or is long", reason)
		}
	}
}

func TestExcerptIsAShortEscapedPrefixWithTheFullLength(t *testing.T) {
	for _, row := range []struct{ pattern, want string }{
		{"abc", "'abc'"},
		{rep("a", 32), "'" + rep("a", 32) + "'"},
		{rep("a", 33), "'" + rep("a", 32) + "' ... (33 chars)"},
		{rep("a", 300), "'" + rep("a", 32) + "' ... (300 chars)"},
		{"a\nb\x00c\x1b", `'a\nb\x00c\x1b'`},
		{rep("é", 40), "'" + rep(`\xe9`, 32) + "' ... (40 chars)"},
		{"\u2028\U0001f600", `'\u2028\U0001f600'`},
		{"a'b", `"a'b"`},
	} {
		if got := Excerpt(row.pattern); got != row.want {
			t.Errorf("Excerpt(%s) = %s, want %s", brief(row.pattern), got, row.want)
		}
	}
}

// The diagnostics the probe composes (`line N: <excerpt>: <reason>`) from the gate's pieces, for the rows of the
// test_probe_* tests that are about admission.
func TestProbeDiagnosticPiecesNameExcerptAndReason(t *testing.T) {
	long := "^" + rep("a", 290) + "TAILMARKER$"
	for _, row := range []struct{ pattern, excerpt, reason string }{
		{"[a-z]+[a-z]+x", "'[a-z]+[a-z]+x'", "too costly to match unanchored (bound 33685760 > 262144); anchor it with ^"},
		{"^" + rep("[!-~]", 5) + "x", "'^[!-~][!-~][!-~][!-~][!-~]x'", "character classes too wide (width 470 > 256)"},
		{long, "'" + long[:32] + "' ... (" + strconv.Itoa(len(long)) + " chars)", "over 256 characters"},
		{"[[a]+[c]+x", "'[[a]+[c]+x'", "nested class at 1"},
		{"(a+)+", "'(a+)+'", "quantified group"},
		{"^ads\x01$", `'^ads\x01$'`, "non-ASCII, space or control character"},
		{"(?=a)b", "'(?=a)b'", "unsupported group at 0"},
		{`^[a-z]+[a-z]+[a-z]+[a-z]+@example\.com$`, `'^[a-z]+[a-z]+[a-z]+[a-z]+@exampl' ... (39 chars)`, "too costly to match (bound 4546757122 > 262144)"},
		{`^[a-z]+[a-z]+a[a-z]+[a-z]+@x\.com$`, `'^[a-z]+[a-z]+a[a-z]+[a-z]+@x\\.co' ... (34 chars)`, "too costly to match (bound 4446159362 > 262144)"},
	} {
		_, compiled, reason := Admission(row.pattern)
		if compiled != nil || reason != row.reason {
			t.Errorf("Admission(%s) reason = %q (compiled %v), want %q", brief(row.pattern), reason, compiled, row.reason)
		}
		if got := Excerpt(row.pattern); got != row.excerpt {
			t.Errorf("Excerpt(%s) = %s, want %s", brief(row.pattern), got, row.excerpt)
		}
		if strings.Contains(Excerpt(row.pattern), "TAILMARKER") {
			t.Errorf("the excerpt of a long pattern quotes its tail: %s", Excerpt(row.pattern))
		}
	}
}

// Fragments `re` itself would reject (an unterminated class, a dangling backslash, a half-written repeat) come back
// with a verdict, never a panic, and a verdict is a reason XOR a cost.
func TestAdmissionGateStaysTotalOnMalformedPatternFragments(t *testing.T) {
	for _, fragment := range []string{
		"", "[a-z", "[^", "[]", `\`, `\x`, `\u00`, `\N{`, "a{", "a{2,", "**", "((((", ")+", "(?", "(?(", "(?(1", "(?(1)",
		"(?(1)a", "(?(1)a|b", "(?(1))", "(?i", "(?i:", "(?>", "(?>a", "(?aiLmsux-imsx:x)", "(?-:x)", "(?P=", "(?P=g",
		"(?P=g)", "(a|b", "(a|(b", "(a|(b))", "(?>a)", `\1`, `([a-z])\1`, rep("[a-z]+", 500), rep("a", 5000) + "+",
	} {
		cost, compiled, reason := Admission(fragment)
		if (compiled == nil) != (cost == 0) || (compiled == nil) != (reason != "") {
			t.Errorf("Admission(%s) = (%d, %v, %q): not one consistent verdict", brief(fragment), cost, compiled, reason)
		}
	}
	// A construct the grammar has no place for is refused whatever follows it: the gate does not go blind from the
	// first `(?#` onwards.
	for _, fragment := range []string{`(?#x\w+\w+\w+`, `(?=a\w+\w+\w+`, `(?i:\w+\w+\w+`} {
		if _, compiled, _ := Admission(fragment); compiled != nil {
			t.Errorf("Admission(%s) admitted a construct the grammar has no place for", brief(fragment))
		}
	}
}

// issue #2364's separator spellings: the conditional and atomic spellings are refused as unsupported groups and the
// plain runs by their cost bound; the anchored host patterns whose runs are separated by dots stay admitted.
func TestIssue2364AdmissionRows(t *testing.T) {
	for _, row := range []struct {
		pattern string
		refused bool
	}{
		{`^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$`, true},
		{`^(a)?(?(1)b|[a-z]+[a-z]+[a-z]+[a-z]+)@x\.com$`, true},
		{`^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$`, true},
		{`^[a-z]+[a-z]+(foo|foobar)[a-z]+[a-z]+@x\.com$`, true},
		{`^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$`, true},
		{`^(a)?(?(1)[a-z]+[a-z]+|[a-z]+[a-z]+)$`, true},
		{`^[a-z]+[a-z]+(?>12)[a-z]+[a-z]+$`, true},
		{`^[a-z]+[a-z]+(\+|\*)[a-z]+[a-z]+$`, true},
		{`^xn--bcher-kva\.[a-z]+$`, false},
		{`^[a-z]+\.[a-z]+\.[a-z]+$`, false},
	} {
		if _, compiled, reason := Admission(row.pattern); (compiled == nil) != row.refused {
			t.Errorf("Admission(%s): refused=%v (%q), want %v", row.pattern, compiled == nil, reason, row.refused)
		}
	}
}

// issue #2035 (adjacent quantified atoms) and #2082 (an overlapping mandatory atom between two runs): the gate half of
// the two probe-and-resolver rows.
func TestAdjacentAndOverlappingQuantifierRunsAreRefusedWithTheirBound(t *testing.T) {
	for _, row := range []struct{ pattern, reason string }{
		{`^[a-z]+[a-z]+[a-z]+[a-z]+@example\.com$`, "too costly to match (bound 4546757122 > 262144)"},
		{`^[a-z]+[a-z]+a[a-z]+[a-z]+@x\.com$`, "too costly to match (bound 4446159362 > 262144)"},
	} {
		cost, compiled, reason := Admission(row.pattern)
		if cost != 0 || compiled != nil || reason != row.reason {
			t.Errorf("Admission(%s) = (%d, %v, %q), want a refusal %q", row.pattern, cost, compiled, reason, row.reason)
		}
	}
}

func TestAnchoringIsNotOfferedWhenTheCharacterClassWidthWouldStillRefuseThePattern(t *testing.T) {
	pattern := rep("[!-~]", 3) + rep("a?", 10) + "x"
	cost, compiled, reason := Admission(pattern)
	if cost != 0 || compiled != nil || reason == "" || strings.Contains(reason, "anchor it") {
		t.Errorf("Admission(%s) = (%d, %v, %q), want a refusal that does not offer the caret", brief(pattern), cost, compiled, reason)
	}
	if _, anchored, _ := Admission("^" + pattern); anchored != nil {
		t.Errorf("the caret form of %s is admitted", brief(pattern))
	}
}

func TestAnchoringIsNotOfferedWhenTheCaretWouldExceedThePatternLengthLimit(t *testing.T) {
	pattern := rep("a?", 8) + rep("a", 240)
	if len(pattern) != MAX_LEN {
		t.Fatalf("the row must be exactly %d characters, is %d", MAX_LEN, len(pattern))
	}
	cost, compiled, reason := Admission(pattern)
	if cost != 0 || compiled != nil || reason == "" || strings.Contains(reason, "anchor it") {
		t.Errorf("Admission(%s) = (%d, %v, %q), want a refusal that does not offer the caret", brief(pattern), cost, compiled, reason)
	}
	if _, anchored, why := Admission("^" + pattern); anchored != nil || why != "over 256 characters" {
		t.Errorf("the caret form: compiled %v, reason %q, want a refusal %q", anchored, why, "over 256 characters")
	}
}

// tests/test_adr07_regex_safety.py TestAdmissionGateAtLoad and the cost rows of the build-time loader.
func TestAdmissionRowsOfTheLoaderTests(t *testing.T) {
	for _, pattern := range []string{
		`ads\.`,
		`ad[0-9]\.example\.com$`,
		`^x[0-9]+\.example\.com$`,
		`\.doubleclick\.net$`,
		`^(.+\.)?doubleclick\.net$`,
		`^(www\.)?ad-?serv(er|ice)\.example$`,
		`^(foo|bar)\.example$`,
		`^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$`,
		`^[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}$`,
		`^[^.]+\.[^.]+\.[^.]+\.example$`,
		`\d+\.\d+`,
		`[a-z]+[0-9]+\.example\.com`,
	} {
		if _, compiled, reason := Admission(pattern); compiled == nil {
			t.Errorf("benign pattern %s refused: %q", pattern, reason)
		}
	}
	// The length ceiling over REGEX_STATIC_LEN_CAP is the separate opt-in cap: a long safe pattern is admitted.
	long := `^(sub)?` + rep("verylongsubdomainlabel", 10) + `\.example\.com$`
	if len(long) <= REGEX_STATIC_LEN_CAP {
		t.Fatalf("the long row is %d characters, want over %d", len(long), REGEX_STATIC_LEN_CAP)
	}
	if _, compiled, reason := Admission(long); compiled == nil {
		t.Errorf("long benign pattern refused: %q", reason)
	}
	// An anchored pattern of exactly the cap length and one over it: the gate admits both (the cap is not its business).
	for _, length := range []int{REGEX_STATIC_LEN_CAP, REGEX_STATIC_LEN_CAP + 1, REGEX_STATIC_LEN_CAP + 50} {
		pattern := "^" + rep("a", length-2) + "$"
		if _, compiled, reason := Admission(pattern); compiled == nil {
			t.Errorf("anchored pattern of %d characters refused: %q", length, reason)
		}
	}
	if cost, compiled, _ := Admission(`000x{252}`); cost != 65536 || compiled == nil {
		t.Errorf("Admission(000x{252}) cost = %d, want 65536 (three digit atoms and x{252}, searched from every position)", cost)
	}
	if cost, compiled, _ := Admission("host00000"); cost != 2304 || compiled == nil {
		t.Errorf("Admission(host00000) cost = %d, want 2304", cost)
	}
}

func TestEveryAdmittedTextOfTheRowsCompilesInGo(t *testing.T) {
	var rows []string
	for _, set := range [][]costRow{ADMITTED_COSTS, WIDTH_ADMITTED, UNANCHORED_DOT_ROWS, DISJOINTNESS_COSTS} {
		for _, row := range set {
			rows = append(rows, row.pattern)
		}
	}
	for _, row := range LEADING_DOT_PAIRS {
		rows = append(rows, row.pattern, row.anchored)
	}
	for _, row := range COMPILE_TEXT {
		rows = append(rows, row.pattern)
	}
	for _, row := range ANCHOR_REMEDY_REFUSALS {
		rows = append(rows, anchorEveryBranch(row.pattern))
	}
	admitted := 0
	for _, pattern := range rows {
		_, compiled, _ := Admission(pattern)
		if compiled == nil {
			continue
		}
		admitted++
		if _, err := goCompile(*compiled); err != nil {
			t.Errorf("admitted %s but Go cannot compile %q: %v", brief(pattern), *compiled, err)
		}
	}
	if admitted < 100 {
		t.Errorf("only %d admitted rows compiled: the table walk is vacuous", admitted)
	}
}

func TestSplitRegexLine(t *testing.T) {
	label := func(s string) *string { return &s }
	for _, row := range []struct {
		name, line, pattern string
		label               *string
	}{
		{"no marker", `^ads\.example\.com$`, `^ads\.example\.com$`, nil},
		{"description follows the marker", `^ads\.example\.com$#plain`, `^ads\.example\.com$`, label("plain")},
		{"escaped hash stays in the pattern, the bare one is the marker", `^track\.example\.com/\#/ads$#adshash`, `^track\.example\.com/\#/ads$`, label("adshash")},
		{"escaped hash and no description", `^ads\#tag\.example\.com$`, `^ads\#tag\.example\.com$`, nil},
		{"an escaped backslash does not escape the hash after it", `^ads\\#evenrun`, `^ads\\`, label("evenrun")},
		{"three backslashes escape it", `a\\\#b#d`, `a\\\#b`, label("d")},
		{"four backslashes do not", `a\\\\#d`, `a\\\\`, label("d")},
		{"a leading escaped hash is a pattern", `\#foo`, `\#foo`, nil},
		{"a leading bare hash is an empty pattern with a description", `# note`, ``, label(" note")},
		{"an empty description is not no description", `pattern#`, `pattern`, label("")},
		{"only the first marker splits", `a#b#c`, `a`, label("b#c")},
		{"another character resets the backslash run", `a\b#c`, `a\b`, label("c")},
		{"a backslash run reset by a non-ASCII character", `\é#c`, `\é`, label("c")},
		{"empty line", ``, ``, nil},
	} {
		pattern, got := SplitRegexLine(row.line)
		if pattern != row.pattern || (got == nil) != (row.label == nil) || (got != nil && *got != *row.label) {
			t.Errorf("%s: SplitRegexLine(%q) = (%q, %v), want (%q, %v)", row.name, row.line, pattern, got, row.pattern, row.label)
		}
	}
}
