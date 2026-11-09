// Tests for the configparser.ConfigParser subset init_standard depends on. Every expectation was produced by
// running Python 3.11/3.13 configparser (default ConfigParser(): '='/':' delimiters, '#'/';' full-line comments,
// strict, empty lines kept in values, BasicInterpolation, DEFAULT section) on the same input.
package decider

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cfgParse(t *testing.T, text string) *configParser {
	t.Helper()
	c := newConfigParser()
	if err := c.readString(text, "t.ini"); err != nil {
		t.Fatalf("readString(%q) = %v, want nil", text, err)
	}
	return c
}

func cfgGet(t *testing.T, c *configParser, section, option, want string) {
	t.Helper()
	got, err := c.get(section, option)
	if err != nil || got != want {
		t.Errorf("get(%q, %q) = (%q, %v), want (%q, nil)", section, option, got, err, want)
	}
}

func cfgErrContains(t *testing.T, what string, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: error = nil, want one containing %q", what, parts)
		return
	}
	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("%s: error = %q, want it to contain %q", what, err.Error(), part)
		}
	}
}

func TestConfigParserSectionHeaders(t *testing.T) {
	// SECTCRE is greedy to the last ']' and ignores whatever follows it.
	c := cfgParse(t, "[a]b]\nk=v\n[x]yz\nq=1\n[M] # trailing\nm=1\n[J]\n  [I]\n  i = 2\n")
	for _, want := range []string{"a]b", "x", "M", "J", "I"} {
		if !c.hasSection(want) {
			t.Errorf("hasSection(%q) = false, want true", want)
		}
	}
	if c.hasSection("a") {
		t.Errorf("hasSection(%q) = true: the header runs to the LAST ']', so the section is %q", "a", "a]b")
	}
	cfgGet(t, c, "a]b", "k", "v")
	cfgGet(t, c, "x", "q", "1")
	cfgGet(t, c, "M", "m", "1")
	cfgGet(t, c, "I", "i", "2")

	// DEFAULT is not a section.
	if cfgParse(t, "[DEFAULT]\nd = 1\n").hasSection("DEFAULT") {
		t.Errorf("hasSection(DEFAULT) = true, want false")
	}

	// "[]" has no header text, so the line is no header; before any section it is a MissingSectionHeaderError.
	err := newConfigParser().readString("[]\nk=v\n", "t.ini")
	cfgErrContains(t, "[] before any section", err, "no section headers", "line: 1")
}

func TestConfigParserDelimitersNamesAndValues(t *testing.T) {
	c := cfgParse(t, "[M]\nA B = x: y\nc: d = e\nKey = V\nspaced   =   padded value   \nnbsp\u00a0=\u00a0v\u00a0\nempty =\ncolon:first=second\n")
	cfgGet(t, c, "M", "a b", "x: y")            // the first delimiter wins; the name is stripped and lower-cased
	cfgGet(t, c, "M", "c", "d = e")             // ':' came first
	cfgGet(t, c, "M", "KEY", "V")               // lookups lower-case the option too
	cfgGet(t, c, "M", "spaced", "padded value") // value stripped
	cfgGet(t, c, "M", "nbsp", "v")              // Python str.strip() strips U+00A0
	cfgGet(t, c, "M", "empty", "")              // present, empty
	cfgGet(t, c, "M", "colon", "first=second")  // first delimiter again, '=' inside the value
	if !c.hasOption("M", "kEy") {
		t.Errorf("hasOption(M, kEy) = false, want true: option names are case-insensitive")
	}
	if c.hasOption("m", "key") {
		t.Errorf("hasOption(m, key) = true, want false: section names are case-sensitive")
	}
	if c.hasOption("M", "nope") || c.hasOption("Nope", "key") {
		t.Errorf("hasOption of an absent option or section = true, want false")
	}
}

func TestConfigParserCommentsAndBlankLines(t *testing.T) {
	c := cfgParse(t, "# top\n[M]\n; semi\n  # indented comment\n   ; indented semi\n\nk = v\n\n# after\nj = w\nx = keep # not an inline comment\n")
	cfgGet(t, c, "M", "k", "v")
	cfgGet(t, c, "M", "j", "w")
	cfgGet(t, c, "M", "x", "keep # not an inline comment") // inline_comment_prefixes is None
	for _, option := range []string{"#", "; semi"} {
		if c.hasOption("M", option) {
			t.Errorf("hasOption(M, %q) = true, want false: a full-line comment is no option", option)
		}
	}
	// A comment line neither ends a value nor becomes part of it.
	c = cfgParse(t, "[M]\nk = x\n# c\n  y\nj = x\n  # c\ni = 1\n")
	cfgGet(t, c, "M", "k", "x\ny")
	cfgGet(t, c, "M", "j", "x")
	cfgGet(t, c, "M", "i", "1")
}

func TestConfigParserContinuationLines(t *testing.T) {
	c := cfgParse(t, "[M]\na = 1\n  2\n\n  3\nb = x\n# c\n  y\nc=\n    z\nd = 1\n\n\ne = 2\nf = 1\n\n   cont\n")
	cfgGet(t, c, "M", "a", "1\n2\n\n3") // a blank line inside a value is kept
	cfgGet(t, c, "M", "b", "x\ny")
	cfgGet(t, c, "M", "c", "\nz") // empty first line, continuation keeps its newline
	cfgGet(t, c, "M", "d", "1")   // trailing blank lines are dropped
	cfgGet(t, c, "M", "e", "2")
	cfgGet(t, c, "M", "f", "1\n\ncont")

	// Only a line indented deeper than the option's own line continues it.
	c = cfgParse(t, "[M]\n  a = 1\n b = 2\n")
	cfgGet(t, c, "M", "a", "1")
	cfgGet(t, c, "M", "b", "2")
	c = cfgParse(t, "[M]\na = 1\n b = 2\n")
	cfgGet(t, c, "M", "a", "1\nb = 2")
	if c.hasOption("M", "b") {
		t.Errorf("hasOption(M, b) = true, want false: ' b = 2' is a continuation of a")
	}
	// An indented header after an option is a continuation line, not a section.
	c = cfgParse(t, "[M]\nk = v\n  [Z]\n")
	cfgGet(t, c, "M", "k", "v\n[Z]")
	if c.hasSection("Z") {
		t.Errorf("hasSection(Z) = true, want false")
	}
}

func TestConfigParserDefaultSectionInheritance(t *testing.T) {
	c := cfgParse(t, "[DEFAULT]\nd = 1\no = base\nflag = yes\n[M]\ne = 2\no = mine\n[DEFAULT]\nlater = 3\n")
	cfgGet(t, c, "M", "d", "1")
	cfgGet(t, c, "M", "o", "mine") // the section overrides DEFAULT
	cfgGet(t, c, "M", "later", "3")
	cfgGet(t, c, "DEFAULT", "d", "1")
	if !c.hasOption("M", "d") || !c.hasOption("DEFAULT", "d") || !c.hasOption("", "d") {
		t.Errorf("hasOption(M|DEFAULT|\"\", d) = (%v, %v, %v), want all true", c.hasOption("M", "d"), c.hasOption("DEFAULT", "d"), c.hasOption("", "d"))
	}
	if c.hasOption("Absent", "d") {
		t.Errorf("hasOption(Absent, d) = true, want false: an absent section has no options, DEFAULT or not")
	}
	if got, err := c.getboolean("M", "flag"); err != nil || !got {
		t.Errorf("getboolean(M, flag) = (%v, %v), want (true, nil): inherited from DEFAULT", got, err)
	}
}

func TestConfigParserStrictDuplicatesKeepWhatWasRead(t *testing.T) {
	for _, tc := range []struct {
		name, text, wantErr, wantKept string
	}{
		{"section", "[MAIN]\na = 1\n[MAIN]\nb = 2\n", "section", "1"},
		{"option", "[MAIN]\na = 1\na = 2\n", "option", "1"},
		{"option differing in case", "[MAIN]\nA = 1\na = 2\n", "option", "1"},
		{"option in DEFAULT", "[DEFAULT]\na = 1\n[DEFAULT]\na = 2\n[MAIN]\n", "option", ""},
	} {
		c := newConfigParser()
		err := c.readString(tc.text, "t.ini")
		cfgErrContains(t, tc.name, err, tc.wantErr, "already exists", "t.ini")
		if tc.wantKept != "" {
			cfgGet(t, c, "MAIN", "a", tc.wantKept) // the first value survives and the read stopped there
		}
		if tc.name == "section" && c.hasOption("MAIN", "b") {
			t.Errorf("%s: hasOption(MAIN, b) = true, want false: reading stops at the duplicate", tc.name)
		}
	}
	// A repeated [DEFAULT] header is no duplicate section; the same option name in two sections is fine.
	c := cfgParse(t, "[DEFAULT]\na = 1\n[DEFAULT]\nb = 2\n[S1]\nk = 1\n[S2]\nk = 2\n")
	cfgGet(t, c, "S1", "a", "1")
	cfgGet(t, c, "S1", "b", "2")
	cfgGet(t, c, "S1", "k", "1")
	cfgGet(t, c, "S2", "k", "2")
}

func TestConfigParserMissingSectionHeader(t *testing.T) {
	c := newConfigParser()
	err := c.readString("a = 1\n[MAIN]\nb = 2\n", "t.ini")
	cfgErrContains(t, "an option before any section", err, "no section headers", "t.ini", "line: 1")
	if c.hasSection("MAIN") {
		t.Errorf("hasSection(MAIN) = true, want false: the read aborts at the first line")
	}
	// A UTF-8 BOM is not stripped (Python opens with encoding="utf-8"), so the first header is not one.
	c = newConfigParser()
	err = c.readString("\ufeff[MAIN]\nk = v\n", "t.ini")
	cfgErrContains(t, "a BOM before the first header", err, "no section headers", "line: 1")
	if c.hasSection("MAIN") {
		t.Errorf("hasSection(MAIN) = true, want false")
	}
}

func TestConfigParserLineWithoutDelimiterIsAParsingErrorAfterTheFullRead(t *testing.T) {
	c := newConfigParser()
	err := c.readString("[MAIN]\na = 1\ngarbage\nb = 2\n= 3\nc = 4\n", "t.ini")
	cfgErrContains(t, "garbage line and empty name", err, "parsing errors", "t.ini", "[line  3]", "garbage", "[line  5]")
	cfgGet(t, c, "MAIN", "a", "1")
	cfgGet(t, c, "MAIN", "b", "2") // the read went on past the bad lines
	cfgGet(t, c, "MAIN", "c", "4")
}

func TestConfigParserBasicInterpolation(t *testing.T) {
	c := cfgParse(t, "[DEFAULT]\ndflt = from-default\n[M]\nesc = 100%%\nref = %(esc)s!\nviaDefault = %(dflt)s\nnested = a%%b %(esc)s\n"+
		"missing = %(zz)s\nbare = 5%\nother = %x\nunterminated = %(esc\nbadconv = %(esc)x\nempty = %()s\nself = %(self)s\nping = %(pong)s\npong = %(ping)s\n")
	cfgGet(t, c, "M", "esc", "100%")
	cfgGet(t, c, "M", "ref", "100%!") // %(name)s whose value itself holds %% is interpolated again
	cfgGet(t, c, "M", "viaDefault", "from-default")
	cfgGet(t, c, "M", "nested", "a%b 100%")
	for _, tc := range []struct {
		option string
		want   string
	}{
		{"missing", "Bad value substitution"},
		{"bare", "'%' must be followed by '%' or '('"},
		{"other", "'%' must be followed by '%' or '('"},
		{"unterminated", "bad interpolation variable reference"},
		{"badconv", "bad interpolation variable reference"}, // %(name) needs the trailing 's'
		{"empty", "bad interpolation variable reference"},   // _KEYCRE %\(([^)]+)\)s needs a non-empty name
		{"self", "Recursion limit exceeded"},
		{"ping", "Recursion limit exceeded"},
	} {
		got, err := c.get("M", tc.option)
		if err == nil {
			t.Errorf("get(M, %s) = %q, want an error containing %q", tc.option, got, tc.want)
			continue
		}
		cfgErrContains(t, "get(M, "+tc.option+")", err, tc.want)
		if errors.As(err, new(*valueError)) {
			t.Errorf("get(M, %s) error is a valueError; interpolation errors are not ValueError, so parseIniInt must not swallow them", tc.option)
		}
	}
	for option, want := range map[string]string{"esc": "100%%", "bare": "5%"} {
		if got, err := c.getRaw("M", option); err != nil || got != want {
			t.Errorf("getRaw(M, %s) = (%q, %v), want (%q, nil)", option, got, err, want)
		}
	}
	cfgErrContains(t, "get of an absent section", func() error { _, err := c.get("Nope", "k"); return err }(), "No section")
	cfgErrContains(t, "get of an absent option", func() error { _, err := c.get("M", "absent"); return err }(), "No option")
}

func TestConfigParserGetboolean(t *testing.T) {
	for _, value := range []string{"1", "yes", "true", "on", "YES", "True", "ON"} {
		if got, err := cfgParse(t, "[M]\nk = "+value+"\n").getboolean("M", "k"); err != nil || !got {
			t.Errorf("getboolean(%q) = (%v, %v), want (true, nil)", value, got, err)
		}
	}
	for _, value := range []string{"0", "no", "false", "off", "Off", "FALSE", "No"} {
		if got, err := cfgParse(t, "[M]\nk = "+value+"\n").getboolean("M", "k"); err != nil || got {
			t.Errorf("getboolean(%q) = (%v, %v), want (false, nil)", value, got, err)
		}
	}
	for _, value := range []string{"maybe", "", "2", "y", "enabled", "tru"} {
		_, err := cfgParse(t, "[M]\nk = "+value+"\n").getboolean("M", "k")
		var ve *valueError
		if !errors.As(err, &ve) || err.Error() != "Not a boolean: "+value {
			t.Errorf("getboolean(%q) error = %v, want a valueError %q", value, err, "Not a boolean: "+value)
		}
	}
}

func TestConfigParserGetint(t *testing.T) {
	for value, want := range map[string]int{"12": 12, "-7": -7, "+3": 3, "1_000": 1000, "007": 7, "0": 0} {
		if got, err := cfgParse(t, "[M]\nk = "+value+"\n").getint("M", "k"); err != nil || got != want {
			t.Errorf("getint(%q) = (%d, %v), want (%d, nil)", value, got, err, want)
		}
	}
	for _, value := range []string{"1.5", "0x10", "1e3", "1__0", "_1", "1_", "", "abc", "+", "- 5", "5 5"} {
		_, err := cfgParse(t, "[M]\nk = "+value+"\n").getint("M", "k")
		var ve *valueError
		if !errors.As(err, &ve) {
			t.Errorf("getint(%q) error = %v, want a valueError (Python ValueError: invalid literal for int())", value, err)
			continue
		}
		cfgErrContains(t, "getint("+value+")", err, "invalid literal for int() with base 10")
	}
	// Python ints are unbounded; this port keeps an int that does not fit 64 bits at the nearest bound.
	if got, err := cfgParse(t, "[M]\nbig = 99999999999999999999\nsmall = -99999999999999999999\n").getint("M", "big"); err != nil || got != math.MaxInt {
		t.Errorf("getint(99999999999999999999) = (%d, %v), want (%d, nil)", got, err, math.MaxInt)
	}
	if got, err := cfgParse(t, "[M]\nsmall = -99999999999999999999\n").getint("M", "small"); err != nil || got != math.MinInt {
		t.Errorf("getint(-99999999999999999999) = (%d, %v), want (%d, nil)", got, err, math.MinInt)
	}
}

func TestConfigParserGetfloat(t *testing.T) {
	for value, want := range map[string]float64{
		"1.5": 1.5, "12": 12, "1e3": 1000, ".5": 0.5, "5.": 5, "1_0.5": 10.5, "-2.5": -2.5, "+1E2": 100,
		"inf": math.Inf(1), "-inf": math.Inf(-1), "Infinity": math.Inf(1), "1e999": math.Inf(1),
	} {
		if got, err := cfgParse(t, "[M]\nk = "+value+"\n").getfloat("M", "k"); err != nil || got != want {
			t.Errorf("getfloat(%q) = (%v, %v), want (%v, nil)", value, got, err, want)
		}
	}
	if got, err := cfgParse(t, "[M]\nk = nan\n").getfloat("M", "k"); err != nil || !math.IsNaN(got) {
		t.Errorf("getfloat(nan) = (%v, %v), want (NaN, nil)", got, err)
	}
	for _, value := range []string{"0x10", "0x1p-2", "1__0", "_1", "1_", "1_.5", "abc", "", "1e", "1.5.2", "1 5"} {
		_, err := cfgParse(t, "[M]\nk = "+value+"\n").getfloat("M", "k")
		var ve *valueError
		if !errors.As(err, &ve) {
			t.Errorf("getfloat(%q) error = %v, want a valueError (Python ValueError: could not convert string to float)", value, err)
			continue
		}
		cfgErrContains(t, "getfloat("+value+")", err, "could not convert string to float")
	}
}

func TestConfigParserReadFromAFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// ConfigParser.read() skips a file it cannot open: an absent path and a directory both read as empty, no error.
	for name, path := range map[string]string{"absent": filepath.Join(dir, "nope.ini"), "directory": dir} {
		c := newConfigParser()
		if err := c.read(path); err != nil {
			t.Errorf("read(%s) = %v, want nil", name, err)
		}
		if c.hasSection("MAIN") {
			t.Errorf("read(%s): hasSection(MAIN) = true, want false", name)
		}
	}

	// A file is read with universal newlines; read_string (StringIO) is not.
	text := "[M]\r\nk=v\r\nz=w\rq=1\r\n"
	c := newConfigParser()
	if err := c.read(write("crlf.ini", []byte(text))); err != nil {
		t.Fatalf("read(crlf) = %v, want nil", err)
	}
	cfgGet(t, c, "M", "k", "v")
	cfgGet(t, c, "M", "z", "w")
	cfgGet(t, c, "M", "q", "1")
	cfgGet(t, cfgParse(t, text), "M", "z", "w\rq=1")

	// encoding="utf-8": undecodable bytes are a read error (a small file is rejected before any line is parsed).
	c = newConfigParser()
	err := c.read(write("bad.ini", []byte("[M]\nk=\xff\n")))
	cfgErrContains(t, "invalid UTF-8", err, "utf-8")
	if c.hasSection("M") {
		t.Errorf("hasSection(M) = true after an undecodable file, want false")
	}

	// A well-formed UTF-8 value is kept as is.
	c = newConfigParser()
	if err := c.read(write("utf8.ini", []byte("[M]\nk = caf\u00e9\n"))); err != nil {
		t.Fatalf("read(utf8) = %v, want nil", err)
	}
	cfgGet(t, c, "M", "k", "caf\u00e9")
}

func TestConfigParserKeepsTheLinesOfAnEightyThousandLineValue(t *testing.T) {
	const n = 80000
	for _, c := range []struct {
		name, text, want string
	}{
		{"blank lines then a continuation", "[M]\nk = 1\n" + strings.Repeat("\n", n) + "  2\n", "1" + strings.Repeat("\n", n+1) + "2"},
		{"continuation lines", "[M]\nk = 1\n" + strings.Repeat("  x\n", n), "1" + strings.Repeat("\nx", n)},
	} {
		if got, err := cfgParse(t, c.text).get("M", "k"); err != nil || got != c.want {
			t.Errorf("%s: got %d bytes, err %v; want %d bytes equal to the joined lines", c.name, len(got), err, len(c.want))
		}
	}
}

func TestConfigParserTreatsTheAsciiSeparators0x1cTo0x1fAsWhitespace(t *testing.T) {
	// str.strip() and the regex \S count them as whitespace, so they are stripped, make a blank line and indent.
	c := cfgParse(t, "[M]\nk = \x1cv\x1f\nj\x1c = 1\n")
	cfgGet(t, c, "M", "k", "v")
	cfgGet(t, c, "M", "j", "1")
	cfgGet(t, cfgParse(t, "[M]\nk = 1\n\x1c\n  2\n"), "M", "k", "1\n\n2")
	c = cfgParse(t, "[M]\nk = 1\n\x1c2\nj = 3\n")
	cfgGet(t, c, "M", "k", "1\n2")
	cfgGet(t, c, "M", "j", "3")
	if !cfgParse(t, "\x1c[M]\x1d\nk = v\n").hasSection("M") {
		t.Errorf("hasSection(M) = false, want true for a header wrapped in separators")
	}
}

func TestConfigParserReadsAMultiLineValueOfACRLFFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crlf.ini")
	if err := os.WriteFile(path, []byte("[M]\r\nk = 1\r\n  2\r\nj = 3\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newConfigParser()
	if err := c.read(path); err != nil {
		t.Fatalf("read(crlf) = %v, want nil", err)
	}
	cfgGet(t, c, "M", "k", "1\n2") // a CRLF is one line break, not a blank line after the value line
	cfgGet(t, c, "M", "j", "3")
}

func TestConfigParserInterpolationRecursionLimitIsTenSubstitutions(t *testing.T) {
	// a1 -> a2 -> ... -> an, each value holding a '%' so it is interpolated again: n-1 nested substitutions
	chain := func(n int) *configParser {
		var text strings.Builder
		text.WriteString("[M]\n")
		for i := 1; i < n; i++ {
			fmt.Fprintf(&text, "a%d = %%(a%d)s\n", i, i+1)
		}
		fmt.Fprintf(&text, "a%d = x\n", n)
		return cfgParse(t, text.String())
	}
	cfgGet(t, chain(11), "M", "a1", "x") // 10 substitutions
	_, err := chain(12).get("M", "a1")   // 11
	cfgErrContains(t, "11 nested substitutions", err, "Recursion limit exceeded in value substitution", "in 10 steps")
}
