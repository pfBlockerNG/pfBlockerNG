// Tests of the Python standard-library behaviour the decider packages share (repr, int, str.isspace, str.split);
// their expectations were produced by running Python 3.13.

package pysem

import (
	"math"
	"slices"
	"testing"
)

var reprCases = []struct{ in, want string }{
	{"abc", "'abc'"},
	{"", "''"},
	{"a'b", "\"a'b\""},
	{"a\"b", "'a\"b'"},
	{"a'\"b", "'a\\'\"b'"},
	{"a\\b", "'a\\\\b'"},
	{"tab\u0009", "'tab\\t'"},
	{"nl\u000a\u000d", "'nl\\n\\r'"},
	{"\u0000\u0001", "'\\x00\\x01'"},
	{"\u007f\u00ad\u0085\u00e9", "'\\x7f\\xad\\x85\u00e9'"},
	{"\U0001f600", "'\U0001f600'"},
	{"\ue000", "'\\ue000'"},
	{"\U000e0001", "'\\U000e0001'"},
	{"\u00a0", "'\\xa0'"},
	{"\u2028", "'\\u2028'"},
	{"\u0007\u000b\u000c\u001b", "'\\x07\\x0b\\x0c\\x1b'"},
	{"\u00ff\u00ff\u0100", "'\u00ff\u00ff\u0100'"},
}

func TestReprMatchesPython(t *testing.T) {
	for _, c := range reprCases {
		if got := Repr(c.in); got != c.want {
			t.Errorf("Repr(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

var splitCases = []struct {
	in   string
	want []string
}{
	{"a b c d e", []string{"a", "b", "c", "d", "e"}},
	{"a b c d e  f  ", []string{"a", "b", "c", "d", "e  f  "}},
	{"  a  b  ", []string{"a", "b"}},
	{"a b c d   ", []string{"a", "b", "c", "d"}},
	{"a b c d  e f g ", []string{"a", "b", "c", "d", "e f g "}},
	{"a\u001cb c d e f", []string{"a", "b", "c", "d", "e f"}},
	{"a\u00a0b c d e f", []string{"a", "b", "c", "d", "e f"}},
	{"", []string{}},
	{"   ", []string{}},
	{"a", []string{"a"}},
	{"a b c d e\u0009f\u000a", []string{"a", "b", "c", "d", "e\u0009f\u000a"}},
}

func TestSplitWhitespaceMatchesPython(t *testing.T) {
	for _, c := range splitCases {
		if got := SplitWhitespace(c.in, 4); !slices.Equal(got, c.want) {
			t.Errorf("SplitWhitespace(%q, 4) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsSpaceMatchesPython(t *testing.T) {
	for _, r := range []rune{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000} {
		if !IsSpace(r) {
			t.Errorf("IsSpace(%#x) = false, want true", r)
		}
	}
	for _, r := range []rune{'a', '!', 0x1b, 0x7f, 0x180e, 0x200b, 0x3001} {
		if IsSpace(r) {
			t.Errorf("IsSpace(%#x) = true, want false", r)
		}
	}
}

func TestLowerMatchesPythonStrLower(t *testing.T) {
	for in, want := range map[string]string{"ABC": "abc", "\u0130": "i\u0307", "S\u0130": "si\u0307", "\u00c9T\u00c9": "\u00e9t\u00e9", "": ""} {
		if got := Lower(in); got != want {
			t.Errorf("Lower(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIntMatchesPython(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
	}{
		{"5", 5}, {" 5 ", 5}, {"\u00a05\u2003", 5}, {"\u00855\u2028", 5}, {"\t5\n", 5}, {"+7", 7}, {"-7", -7}, {"1_000", 1000},
		{"007", 7}, {"-0", 0}, {"+0_0", 0}, {"1_000_000", 1000000},
		// Python's ints are unbounded; this port keeps an int beyond 64 bits at the nearest bound.
		{"99999999999999999999", math.MaxInt64}, {"-99999999999999999999", math.MinInt64},
	} {
		if got, err := Int(c.in); err != nil || got != c.want {
			t.Errorf("Int(%q) = %d, %v; want %d, nil", c.in, got, err, c.want)
		}
	}
	// 0x1c-0x1f are str.isspace() and str.strip() whitespace, but int() does not strip them.
	for _, c := range []struct{ in, repr string }{
		{"", `''`}, {"  ", `'  '`}, {"+", `'+'`}, {"-", `'-'`}, {"_1", `'_1'`}, {"1_", `'1_'`}, {"1__0", `'1__0'`}, {"+_1", `'+_1'`},
		{"0x10", `'0x10'`}, {"1.5", `'1.5'`}, {"5x", `'5x'`}, {" 5x ", `' 5x '`}, {"- 5", `'- 5'`}, {"5 5", `'5 5'`},
		{"\x1c5\x1f", `'\x1c5\x1f'`}, {"\x1f5", `'\x1f5'`}, {"5\x1c", `'5\x1c'`},
	} {
		want := "invalid literal for int() with base 10: " + c.repr
		if got, err := Int(c.in); err == nil || err.Error() != want {
			t.Errorf("Int(%q) = %d, %v; want error %q", c.in, got, err, want)
		}
	}
}
