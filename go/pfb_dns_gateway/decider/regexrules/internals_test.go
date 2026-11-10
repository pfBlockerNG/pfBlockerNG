// What the translation had to build for itself where Python has an unbounded int: the saturating counter and the
// 129-bit set. The reason rows were produced by running the Python gate (pfb_regex_admission, Python 3.11) on each
// pattern: the exact text, index and bound of every refusal, which the Python suite pins only by fragment.

package regexrules

import (
	"math"
	"testing"
)

func TestCounterSaturatesAtTwoToThe64LikePythonsMin(t *testing.T) {
	sat := counter{sat: true}
	for _, row := range []struct {
		name string
		got  counter
		want counter
	}{
		{"max uint64 plus zero stays exact", counter{v: math.MaxUint64}.add(count(0)), counter{v: math.MaxUint64}},
		{"max uint64 plus one is 1<<64", counter{v: math.MaxUint64}.add(count(1)), sat},
		{"two halves of 1<<63 are 1<<64", counter{v: 1 << 63}.add(counter{v: 1 << 63}), sat},
		{"two sub-limit values add exactly", counter{v: 1 << 62}.add(counter{v: 1 << 62}), counter{v: 1 << 63}},
		{"a saturated value stays saturated", sat.add(count(0)), sat},
		{"1<<32 times 1<<32 is 1<<64", counter{v: 1 << 32}.mul(counter{v: 1 << 32}), sat},
		{"1<<32 times (1<<32)-1 is exact", counter{v: 1 << 32}.mul(counter{v: 1<<32 - 1}), counter{v: (1 << 32) * (1<<32 - 1)}},
		{"zero times a saturated value is zero", count(0).mul(sat), counter{}},
		{"a saturated value times zero is zero", sat.mul(count(0)), counter{}},
		{"a saturated value times one is saturated", sat.mul(count(1)), sat},
		{"saturated times saturated is saturated", sat.mul(sat), sat},
	} {
		if row.got != row.want {
			t.Errorf("%s: got %+v, want %+v", row.name, row.got, row.want)
		}
	}
	if got := sat.String(); got != "18446744073709551616" {
		t.Errorf("1<<64 renders as %q", got)
	}
	if got := (counter{v: math.MaxUint64}).String(); got != "18446744073709551615" {
		t.Errorf("max uint64 renders as %q", got)
	}
	if sat.atMost(math.MaxUint64) || !(counter{v: 5}).atMost(5) || (counter{v: 6}).atMost(5) {
		t.Error("atMost must be false for 1<<64 and compare exactly otherwise")
	}
}

func TestBitSetOperationsCrossWordBoundaries(t *testing.T) {
	if got := lowBits(128).bitCount(); got != 128 {
		t.Errorf("lowBits(128) holds %d bits, want 128", got)
	}
	if got := lowBits(129).bitCount(); got != 129 {
		t.Errorf("lowBits(129) holds %d bits, want 129", got)
	}
	if lowBits(0) != (bitSet{}) || lowBits(64) != (bitSet{math.MaxUint64, 0, 0}) || lowBits(65) != (bitSet{math.MaxUint64, 1, 0}) {
		t.Errorf("lowBits at the word edges: %v %v %v", lowBits(0), lowBits(64), lowBits(65))
	}
	if got := bit('A').shl(32); got != bit('a') {
		t.Errorf("'A' << 32 = %v, want 'a' %v", got, bit('a'))
	}
	if got := bit(128).shr(1); got != bit(127) {
		t.Errorf("bit 128 >> 1 = %v, want bit 127 %v", got, bit(127))
	}
	if got := bit(1).shl(127); got != bit(128) {
		t.Errorf("bit 1 << 127 = %v, want bit 128 %v", got, bit(128))
	}
	if got := bit(65).shl(63); got != bit(128) {
		t.Errorf("bit 65 << 63 = %v, want bit 128 %v", got, bit(128))
	}
	// _UPPER and _LOWER are the 26 letters each; folding a set of letters adds the other case and nothing else.
	if _UPPER.bitCount() != 26 || _LOWER.bitCount() != 26 || _UPPER.and(_LOWER) != (bitSet{}) {
		t.Errorf("_UPPER %v _LOWER %v", _UPPER, _LOWER)
	}
	if got, want := fold(bit('k').or(bit('0'))), bit('k').or(bit('K')).or(bit('0')); got != want {
		t.Errorf("fold('k', '0') = %v, want %v", got, want)
	}
	// \w lists the 63 ASCII word characters, \s the 10 ASCII whitespace characters (\t-\r, 0x1C-0x1F, space).
	if got := _CLASS_ESCAPES['w'].and(_ASCII).bitCount(); got != 63 {
		t.Errorf(`\w lists %d ASCII characters, want 63`, got)
	}
	if got := _CLASS_ESCAPES['s'].and(_ASCII).bitCount(); got != 10 {
		t.Errorf(`\s lists %d ASCII characters, want 10`, got)
	}
	if _CLASS_ESCAPES['D'].and(_NONASCII) == (bitSet{}) || _DOT.and(bit('\n')) != (bitSet{}) || _DOT.and(_NONASCII) == (bitSet{}) {
		t.Error(`\D and . carry the non-ASCII pseudo-member; . excludes the newline`)
	}
}

// Every refusal reason with its text, index and bound, and a few admitted rows, from the Python gate.
func TestAdmissionMatchesTheLiveGateOnRowsPythonsSuitePinsOnlyByFragment(t *testing.T) {
	for _, row := range []struct {
		pattern string
		cost    int
		reason  string // "" = admitted
		text    string // the compile text of an admitted pattern
	}{
		{"a\\", 0, "trailing backslash at 1", ""},
		{"\\1", 0, "unsupported escape at 0", ""},
		{"a\\x", 0, "unsupported escape at 1", ""},
		{"[\\b]", 0, "unsupported escape in class at 1", ""},
		{"[\\1]", 0, "unsupported escape at 1", ""},
		{"[[a]]", 0, "nested class at 1", ""},
		{"[]", 0, "empty class at 1", ""},
		{"[^]", 0, "empty class at 2", ""},
		{"[a--b]", 0, "set operation in class at 2", ""},
		{"[a&&b]", 0, "set operation in class at 2", ""},
		{"[a~~b]", 0, "set operation in class at 2", ""},
		{"[a||b]", 0, "set operation in class at 2", ""},
		{"[\\d-a]", 0, "class escape in range at 5", ""},
		{"[a-\\d]", 0, "class escape in range at 5", ""},
		{"[z-a]", 0, "reversed range at 4", ""},
		{"[a-z", 0, "unclosed class", ""},
		{"[a-", 0, "unclosed class", ""},
		{"a{", 0, "invalid repeat at 1", ""},
		{"a{x}", 0, "invalid repeat at 1", ""},
		{"a{,3}", 0, "invalid repeat at 1", ""},
		{"a{2,x}", 0, "invalid repeat at 1", ""},
		{"a{2,3,4}", 0, "invalid repeat at 1", ""},
		{"a{256}", 0, "repeat out of bounds at 1", ""},
		{"a{256,}", 0, "repeat out of bounds at 1", ""},
		{"a{5,3}", 0, "repeat out of bounds at 1", ""},
		{"a{1,256}", 0, "repeat out of bounds at 1", ""},
		{"a{0,256}", 0, "repeat out of bounds at 1", ""},
		{"a{300,200}", 0, "repeat out of bounds at 1", ""},
		{"a{00255}", 65536, "", "a{00255}"},
		{"a{255,}", 130816, "", "a{255,}"},
		{"a{255,255}", 65536, "", "a{255,255}"},
		{"a{0}", 256, "", "a{0}"},
		{"(?=a)", 0, "unsupported group at 0", ""},
		{"x(?i)", 0, "unsupported group at 1", ""},
		{"(((((((((a)))))))))", 0, "groups nested over 8 at 9", ""},
		{"a)", 0, "unbalanced ) at 1", ""},
		{"(a", 0, "unbalanced (", ""},
		{"+a", 0, "misplaced quantifier at 0", ""},
		{"a|*", 0, "misplaced quantifier at 2", ""},
		{"a]", 0, "unescaped ] at 1", ""},
		{"a}", 0, "unescaped } at 1", ""},
		{"(a+)+", 0, "quantified group", ""},
		{"(?:a)", 256, "", "(?:a)"},
		{"a{2}?", 768, "", "a{2}?"},
		{"a{2,}?", 66048, "", "a{2,}?"},
		{"(a){2}", 768, "", "(a){2}"},
		{"(ab){2}", 1536, "", "(ab){2}"},
		{"[a-z-9]", 256, "", "[a-z-9]"},
		{"[a\\]b]", 256, "", "[a\\]b]"},
		{"[\\]]", 256, "", "[\\]]"},
		{"[^a-c]", 256, "", "[^a-c]"},
		{"[-]", 256, "", "[-]"},
		{"[--a]", 0, "set operation in class at 1", ""},
		{"a|b|", 768, "", "a|b|"},
		{"|", 512, "", "|"},
		{"\\w+\\W", 131328, "", "\\w+\\W"},
		{"\\_", 256, "", "\\_"},
		{"\\/", 256, "", "\\/"},
		{"a$$b", 1024, "", "a$$b"},
		{"^^", 2, "", "^^"},
		{"(?:|)", 512, "", "(?:|)"},
		{"(?:a|)+", 0, "quantified group", ""},
		{".*.*", 65793, "", "^(?:(?s:.*).*)"},
		{".+.", 514, "", "^(?:(?s:.*)[^\\n].)"},
		{"^.*", 257, "", "^.*"},
		{"(.*)", 65536, "", "(.*)"},
		{".*?x", 513, "", "^(?:(?s:.*?)x)"},
		{".+?x", 514, "", "^(?:(?s:.*?)[^\\n]x)"},
	} {
		cost, compiled, reason := Admission(row.pattern)
		admitted := row.reason == ""
		switch {
		case admitted && (compiled == nil || *compiled != row.text || cost != row.cost || reason != ""):
			t.Errorf("Admission(%q) = (%d, %v, %q), want cost %d and compile text %q", row.pattern, cost, compiled, reason, row.cost, row.text)
		case !admitted && (compiled != nil || cost != 0 || reason != row.reason):
			t.Errorf("Admission(%q) = (%d, %v, %q), want the refusal %q", row.pattern, cost, compiled, reason, row.reason)
		}
	}
}
