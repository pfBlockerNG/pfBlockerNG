// Package regexrules is the Go translation of src/usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py (issue #1765 /
// #1711) without its save-time probe (_report, main): the pure static predicates that decide whether a DNSBL regex
// pattern is admitted (an allowlist of constructs plus a static cost bound), the text a pattern is compiled from, the
// log excerpt and the pattern/description line splitter.
//
// The gate reads the pattern text once, left to right, with an explicit stack. It never compiles, matches or
// otherwise executes pattern text (this package imports no regexp), so judging a pattern costs time linear in its
// capped length however hostile it is. The compile text is Python re syntax; a Go caller hands it to regexp with the
// (?i) flag. RE2 reads some admitted texts differently from Python's re (Unicode \w \s \b on Latin-1, `$` before a
// trailing newline): re2_divergence_test.go pins those rows, and the three that flip parity-corpus cases carry a
// go_expect signed off on https://github.com/pfBlockerNG/pfBlockerNG/issues/3511#issuecomment-6757232482.
package regexrules

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// Length ceiling (heuristic): a pattern over this many characters is dropped at load ONLY when the opt-in "Limit regex
// length to 200 characters" setting is enabled. Length alone is a tunable convenience cap, NOT a safety gate.
const REGEX_STATIC_LEN_CAP = 200

// Admission bounds, always on. A pattern is matched against names of at most 253 characters; the bounds below keep the
// matcher's work on one name within a fixed budget of backtracking steps.
const (
	REGEX_PATTERN_MAX_LEN = 256     // refused on length alone, before any scan
	REGEX_REPEAT_MAX      = 255     // largest m and n in {m}, {m,n}, {m,}
	REGEX_GROUP_DEPTH_MAX = 8       // deepest nesting of ( ... )
	REGEX_COST_MAX        = 1 << 18 // largest admitted bound on backtracking steps (search-tree nodes)
	// Largest sum, over the bracket classes of one pattern, of the ASCII characters each class lists, counted before any
	// `^` negation and after case folding (`[a-z]` lists 52). It bounds compile time for wide classes.
	REGEX_CLASS_WIDTH_MAX = 256
	// Attempts of one unbounded quantifier (*, +, {m,}), and of an unanchored search (it starts a match at every
	// position of the name).
	REGEX_COST_UNBOUNDED = 256
)

const (
	_EXCERPT_CHARS       = 32
	_QUANTIFIER_START    = "?*+{"
	_SET_OPERATION_CHARS = "-&~|"
)

// counter is a non-negative int that saturates at 1<<64 (Python's _COST_SATURATION, so a refusal reason stays short).
// A uint64 cannot hold 1<<64, so sat stands for exactly that value; every operation is Python's exact arithmetic
// followed by min(result, 1<<64).
type counter struct {
	v   uint64
	sat bool
}

func count(n int) counter { return counter{v: uint64(n)} }

func (a counter) add(b counter) counter {
	if a.sat || b.sat {
		return counter{sat: true}
	}
	sum, carry := bits.Add64(a.v, b.v, 0)
	return counter{v: sum, sat: carry != 0}
}

func (a counter) mul(b counter) counter {
	if !a.sat && a.v == 0 || !b.sat && b.v == 0 {
		return counter{}
	}
	if a.sat || b.sat {
		return counter{sat: true}
	}
	high, low := bits.Mul64(a.v, b.v)
	return counter{v: low, sat: high != 0}
}

func (a counter) atMost(limit uint64) bool { return !a.sat && a.v <= limit }

func (a counter) String() string {
	if a.sat {
		return "18446744073709551616"
	}
	return strconv.FormatUint(a.v, 10)
}

// bitSet is the 129-bit set a Python int serves as: bits 0-127 are the ASCII characters and bit 128 is one
// pseudo-member standing for every non-ASCII character.
type bitSet [3]uint64

func bit(n int) bitSet {
	var set bitSet
	set[n/64] = 1 << (n % 64)
	return set
}

// lowBits is (1 << n) - 1.
func lowBits(n int) bitSet {
	var set bitSet
	for index := range set {
		switch {
		case n >= 64:
			set[index] = ^uint64(0)
			n -= 64
		case n > 0:
			set[index] = 1<<n - 1
			n = 0
		}
	}
	return set
}

func (s bitSet) or(o bitSet) bitSet {
	return bitSet{s[0] | o[0], s[1] | o[1], s[2] | o[2]}
}

func (s bitSet) and(o bitSet) bitSet {
	return bitSet{s[0] & o[0], s[1] & o[1], s[2] & o[2]}
}

func (s bitSet) xor(o bitSet) bitSet {
	return bitSet{s[0] ^ o[0], s[1] ^ o[1], s[2] ^ o[2]}
}

func (s bitSet) andNot(o bitSet) bitSet {
	return bitSet{s[0] &^ o[0], s[1] &^ o[1], s[2] &^ o[2]}
}

// shl is s << n, bits past 191 dropped (nothing here shifts a bit that far).
func (s bitSet) shl(n uint) bitSet {
	var out bitSet
	word, shift := int(n/64), n%64
	for index := len(s) - 1; index >= word; index-- {
		out[index] = s[index-word] << shift
		if index-word > 0 {
			out[index] |= s[index-word-1] >> (64 - shift)
		}
	}
	return out
}

// shr is s >> n.
func (s bitSet) shr(n uint) bitSet {
	var out bitSet
	word, shift := int(n/64), n%64
	for index := 0; index+word < len(s); index++ {
		out[index] = s[index+word] >> shift
		if index+word+1 < len(s) {
			out[index] |= s[index+word+1] << (64 - shift)
		}
	}
	return out
}

// bitCount is int.bit_count().
func (s bitSet) bitCount() int {
	return bits.OnesCount64(s[0]) + bits.OnesCount64(s[1]) + bits.OnesCount64(s[2])
}

// Character sets of single-character atoms, as bit sets: bits 0-127 are the ASCII characters and bit 128 is one
// pseudo-member standing for every non-ASCII character (`re` reads `\d` and `\w` as Unicode, so they carry it like `.`
// and the negated escapes). Two atoms are disjoint when their sets share no bit. Sets are case-folded (a letter in a
// set adds its other case) because every pattern is compiled with IGNORECASE.
var (
	_ASCII    = lowBits(128)
	_NONASCII = bit(128)
	_UPPER    = lowBits(26).shl(65)
	_LOWER    = lowBits(26).shl(97)
	_DIGITS   = asciiSet(func(code int) bool { return '0' <= code && code <= '9' })
	_WORD     = asciiSet(func(code int) bool {
		return '0' <= code && code <= '9' || 'A' <= code && code <= 'Z' || 'a' <= code && code <= 'z' || code == '_'
	})
	_SPACE = asciiSet(func(code int) bool { return pysem.IsSpace(rune(code)) })
	_DOT   = _ASCII.andNot(bit('\n')).or(_NONASCII)

	_CLASS_ESCAPES = map[byte]bitSet{
		'd': _DIGITS.or(_NONASCII),
		'D': _ASCII.andNot(_DIGITS).or(_NONASCII),
		'w': _WORD.or(_NONASCII),
		'W': _ASCII.andNot(_WORD).or(_NONASCII),
		's': _SPACE.or(_NONASCII),
		'S': _ASCII.andNot(_SPACE).or(_NONASCII),
	}
)

func asciiSet(member func(code int) bool) bitSet {
	var set bitSet
	for code := range 128 {
		if member(code) {
			set = set.or(bit(code))
		}
	}
	return set
}

// Item kinds of a branch.
const (
	_ZERO  = 0
	_ATOM  = 1
	_GROUP = 2
)

// fold is members with the other case of every letter in it added.
func fold(members bitSet) bitSet {
	return members.or(members.and(_UPPER).shl(32)).or(members.and(_LOWER).shr(32))
}

// refusal is a pattern outside the grammar (Python's _Refusal); the message is the short fixed reason.
type refusal string

func (r refusal) Error() string { return string(r) }

func refuse(format string, args ...any) error { return refusal(fmt.Sprintf(format, args...)) }

// quantifierSpec is Python's _Quantifier, (minimum, maximum) repeat count; unbounded is maximum None.
type quantifierSpec struct {
	low, high int
	unbounded bool
}

var _OPTIONAL = quantifierSpec{low: 0, high: 1}

// item is one element of a branch: an atom, a zero-width token or a group.
type item struct {
	kind int
	// atom: the characters it matches
	members        bitSet
	quantified     bool
	quantifierSpec         // repeat count; 1, 1 when unquantified
	dollar         bool    // zero-width: a `$`
	nodes          counter // group: search-tree nodes of its body
	out            counter // group: ways its body can have been walked when it ends
	length         int     // group: atoms in its body (a plain run when the group is repeated)
}

func newItem(kind int) item {
	return item{kind: kind, quantifierSpec: quantifierSpec{low: 1, high: 1}, out: count(1)}
}

// frame is one alternation level: the whole pattern (top) or the body of one open group.
type frame struct {
	top            bool
	items          []item   // the current branch
	nodes          counter  // search-tree nodes of the finished branches, summed
	out            counter  // ways the finished branches can end, summed
	atoms          int      // atoms in the body (all branches)
	simple         bool     // body is only plain atoms: no quantifier, group, `|` or zero-width
	unanchored     int      // finished branches that did not begin with `^` or a leading `.*` / `.+`
	branchAnchored bool     // the current branch began with `^` (or a leading `.*` / `.+`)
	dotRuns        [][2]int // top level: offsets of each leading dot run
}

func newFrame(top bool) frame { return frame{top: top, simple: true} }

func (f *frame) endBranch() {
	nodes, out := branchCost(f.items, f.top)
	f.nodes = f.nodes.add(nodes)
	f.out = f.out.add(out)
	if !f.branchAnchored {
		f.unanchored++
	}
	f.items = nil
	f.branchAnchored = false
}

// escape classifies the escape at index as (class | zero | literal, next index).
func escape(pattern string, index int) (string, int, error) {
	if index+1 >= len(pattern) {
		return "", 0, refuse("trailing backslash at %d", index)
	}
	escaped := pattern[index+1]
	if strings.IndexByte("dDwWsS", escaped) >= 0 {
		return "class", index + 2, nil
	}
	if strings.IndexByte("bB", escaped) >= 0 {
		return "zero", index + 2, nil
	}
	if '0' <= escaped && escaped <= '9' || 'A' <= escaped && escaped <= 'Z' || 'a' <= escaped && escaped <= 'z' {
		// backreferences, octal and every letter escape
		return "", 0, refuse("unsupported escape at %d", index)
	}
	return "literal", index + 2, nil
}

func checkSetOperation(pattern string, index int) error {
	char := pattern[index]
	if strings.IndexByte(_SET_OPERATION_CHARS, char) >= 0 && index+1 < len(pattern) && pattern[index+1] == char {
		return refuse("set operation in class at %d", index)
	}
	return nil
}

// classItem is one class item as (code point, its character set, next index); a class escape has no code point (-1:
// it cannot end a range).
func classItem(pattern string, index int) (int, bitSet, int, error) {
	char := pattern[index]
	if char == '\\' {
		kind, end, err := escape(pattern, index)
		if err != nil {
			return 0, bitSet{}, 0, err
		}
		if kind == "zero" {
			return 0, bitSet{}, 0, refuse("unsupported escape in class at %d", index)
		}
		escaped := pattern[index+1]
		if kind == "class" {
			return -1, _CLASS_ESCAPES[escaped], end, nil
		}
		return int(escaped), bit(int(escaped)), end, nil
	}
	if char == '[' {
		return 0, bitSet{}, 0, refuse("nested class at %d", index)
	}
	return int(char), bit(int(char)), index + 1, nil
}

// classEnd is (index after the class, its character set, the ASCII characters it lists) for the class whose `[`
// precedes index; a negated class lists the characters it excludes.
func classEnd(pattern string, index int) (int, bitSet, int, error) {
	negated := index < len(pattern) && pattern[index] == '^'
	if negated {
		index++
	}
	var members bitSet
	items := 0
	for index < len(pattern) {
		if pattern[index] == ']' {
			if items == 0 {
				return 0, bitSet{}, 0, refuse("empty class at %d", index)
			}
			members = fold(members)
			listed := members.and(_ASCII).bitCount()
			if negated {
				return index + 1, _ASCII.andNot(members).or(_NONASCII), listed, nil
			}
			return index + 1, members, listed, nil
		}
		if err := checkSetOperation(pattern, index); err != nil {
			return 0, bitSet{}, 0, err
		}
		low, found, next, err := classItem(pattern, index)
		if err != nil {
			return 0, bitSet{}, 0, err
		}
		index = next
		members = members.or(found)
		items++
		// A `-` that ends the class is a literal; any other `-` joins two literal ends.
		if index < len(pattern) && pattern[index] == '-' && index+1 < len(pattern) && pattern[index+1] != ']' {
			if err := checkSetOperation(pattern, index); err != nil {
				return 0, bitSet{}, 0, err
			}
			high, _, next, err := classItem(pattern, index+1)
			if err != nil {
				return 0, bitSet{}, 0, err
			}
			index = next
			if low < 0 || high < 0 {
				return 0, bitSet{}, 0, refuse("class escape in range at %d", index)
			}
			if low > high {
				return 0, bitSet{}, 0, refuse("reversed range at %d", index)
			}
			members = members.or(lowBits(high + 1).xor(lowBits(low)))
		}
	}
	return 0, bitSet{}, 0, refuse("unclosed class")
}

// repeatCount is int(digits), held at REGEX_REPEAT_MAX+1 once it passes REGEX_REPEAT_MAX: Python's int is unbounded,
// and every test of it is `> REGEX_REPEAT_MAX` (a refusal whatever its size, and the refusal text does not quote it).
func repeatCount(digits string) int {
	value := 0
	for index := range len(digits) {
		value = min(value*10+int(digits[index]-'0'), REGEX_REPEAT_MAX+1)
	}
	return value
}

// quantifier reads the quantifier starting at index -- `?` `*` `+` `{m}` `{m,}` `{m,n}` with an optional lazy `?` --
// as (next index, its (min, max), true); (index, _, false) when none starts there.
func quantifier(pattern string, index int) (int, quantifierSpec, bool, error) {
	if index >= len(pattern) || strings.IndexByte(_QUANTIFIER_START, pattern[index]) < 0 {
		return index, quantifierSpec{}, false, nil
	}
	char := pattern[index]
	var spec quantifierSpec
	var end int
	if char == '{' {
		offset := strings.IndexByte(pattern[index:], '}')
		if offset < 0 {
			return 0, quantifierSpec{}, false, refuse("invalid repeat at %d", index)
		}
		close := index + offset
		lowText, highText, comma := strings.Cut(pattern[index+1:close], ",")
		if !pysem.IsASCIIDigits(lowText) || highText != "" && !pysem.IsASCIIDigits(highText) {
			return 0, quantifierSpec{}, false, refuse("invalid repeat at %d", index)
		}
		spec.low = repeatCount(lowText)
		switch {
		case !comma:
			spec.high = spec.low
		case highText == "":
			spec.unbounded = true
		default:
			spec.high = repeatCount(highText)
		}
		end = close + 1
	} else {
		switch char {
		case '?':
			spec = quantifierSpec{low: 0, high: 1}
		case '*':
			spec = quantifierSpec{low: 0, unbounded: true}
		case '+':
			spec = quantifierSpec{low: 1, unbounded: true}
		}
		end = index + 1
	}
	if spec.low > REGEX_REPEAT_MAX || !spec.unbounded && (spec.high > REGEX_REPEAT_MAX || spec.low > spec.high) {
		return 0, quantifierSpec{}, false, refuse("repeat out of bounds at %d", index)
	}
	if end < len(pattern) && pattern[end] == '?' { // lazy
		end++
	}
	return end, spec, true, nil
}

// handsNothingOn is whether the quantified atom items[index] leaves the work after it unmultiplied: nothing but `$`
// follows it in a top-level branch (the match ends or fails at once), or a mandatory atom that shares no character with
// it follows directly (the run cannot give a character to that atom, so each attempt of the run has one way on).
func handsNothingOn(items []item, index int, top bool, trailing int) bool {
	if top && index+1 >= trailing {
		return true
	}
	if index+1 >= len(items) {
		return false
	}
	following := items[index+1]
	return following.kind == _ATOM && following.low >= 1 && items[index].members.and(following.members) == bitSet{}
}

// attempts is the ways to end a quantified item's repeat after its low mandatory steps.
func attempts(it item) int {
	if it.unbounded {
		return REGEX_COST_UNBOUNDED
	}
	return it.high - it.low + 1
}

// branchCost is (nodes, out) of one branch of an alternation: the matcher's search-tree nodes below this branch and
// the number of ways the branch can have been walked when it ends (what a following item multiplies by). top marks a
// branch of the whole pattern, not of a group.
func branchCost(items []item, top bool) (counter, counter) {
	nodes := count(1) // an empty branch is still one step
	if len(items) > 0 {
		nodes = count(0)
	}
	paths := count(1)
	trailing := len(items) // index from which only `$` items remain
	for trailing > 0 && items[trailing-1].dollar {
		trailing--
	}
	for index, it := range items {
		switch {
		case it.kind == _ATOM && it.quantified:
			tries := attempts(it)
			nodes = nodes.add(paths.mul(count(it.low + tries)))
			if !handsNothingOn(items, index, top, trailing) {
				paths = paths.mul(count(tries))
			}
		case it.kind == _GROUP && it.quantified && it.quantifierSpec == _OPTIONAL:
			nodes = nodes.add(paths.mul(count(1).add(it.nodes))) // the body, or skipping it
			paths = paths.mul(count(1).add(it.out))
		case it.kind == _GROUP && it.quantified:
			// a plain run of `length` atoms repeated: every repeat walks the whole run
			tries := attempts(it)
			nodes = nodes.add(paths.mul(count(it.length)).mul(count(it.low + tries)))
			paths = paths.mul(count(tries))
		case it.kind == _GROUP:
			nodes = nodes.add(paths.mul(it.nodes))
			paths = paths.mul(it.out)
		default: // an unquantified atom or a zero-width token
			nodes = nodes.add(paths)
		}
	}
	return nodes, paths
}

// A leading dot run as written and as compiled: `(?s:.*)` crosses a newline (a CNAME target decoded from Latin-1 bytes
// may hold one), `[^\n]` is the character a `+` run needs besides.
var _DOT_RUNS = map[string]string{
	".*":  "(?s:.*)",
	".*?": "(?s:.*?)",
	".+":  `(?s:.*)[^\n]`,
	".+?": `(?s:.*?)[^\n]`,
}

// compileText is pattern behind a written `^`, each leading dot run (as the (start, end) offsets) spelled so that it
// crosses a newline.
func compileText(pattern string, dotRuns [][2]int) string {
	var parts strings.Builder
	parts.WriteString("^(?:")
	last := 0
	for _, run := range dotRuns {
		start, end := run[0], run[1]
		parts.WriteString(pattern[last:start])
		parts.WriteString(_DOT_RUNS[pattern[start:end]])
		last = end
	}
	parts.WriteString(pattern[last:])
	parts.WriteString(")")
	return parts.String()
}

// admit is (cost, compile text) of an admitted pattern: the compile text wraps a pattern that is anchored only through
// leading `.*` / `.+` runs behind a `^`, so the compile text carries the anchor.
func admit(pattern string) (counter, string, error) {
	if len(pattern) == 0 {
		return counter{}, "", refuse("empty pattern")
	}
	// Python's len() counts characters; every character past this check is ASCII, where a byte is one.
	if utf8.RuneCountInString(pattern) > REGEX_PATTERN_MAX_LEN {
		return counter{}, "", refuse("over %d characters", REGEX_PATTERN_MAX_LEN)
	}
	for index := range len(pattern) {
		if char := pattern[index]; char < '!' || char > '~' {
			return counter{}, "", refuse("non-ASCII, space or control character")
		}
	}
	stack := []frame{newFrame(true)}
	index := 0
	width := 0
	for index < len(pattern) {
		char := pattern[index]
		current := &stack[len(stack)-1]
		switch {
		case char == '(':
			if strings.HasPrefix(pattern[index:], "(?") {
				if !strings.HasPrefix(pattern[index:], "(?:") {
					return counter{}, "", refuse("unsupported group at %d", index)
				}
				index += 3
			} else {
				index++
			}
			if len(stack) > REGEX_GROUP_DEPTH_MAX {
				return counter{}, "", refuse("groups nested over %d at %d", REGEX_GROUP_DEPTH_MAX, index)
			}
			current.simple = false
			stack = append(stack, newFrame(false))
		case char == ')':
			if len(stack) == 1 {
				return counter{}, "", refuse("unbalanced ) at %d", index)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			body.endBranch()
			next, spec, quantified, err := quantifier(pattern, index+1)
			if err != nil {
				return counter{}, "", err
			}
			index = next
			// A group repeated more than optionally must be a plain run of atoms, so its repeat count stays one factor
			// of the cost instead of nesting.
			if quantified && spec != _OPTIONAL && !(body.simple && body.atoms != 0) {
				return counter{}, "", refuse("quantified group")
			}
			group := newItem(_GROUP)
			group.nodes, group.out, group.length = body.nodes, body.out, body.atoms
			if quantified {
				group.quantified = true
				group.quantifierSpec = spec
			}
			parent := &stack[len(stack)-1]
			parent.items = append(parent.items, group)
		case char == '|':
			current.simple = false
			current.endBranch()
			index++
		case char == '^' || char == '$' || strings.HasPrefix(pattern[index:], `\b`) || strings.HasPrefix(pattern[index:], `\B`):
			if char == '^' && len(current.items) == 0 {
				current.branchAnchored = true
			}
			current.simple = false
			zero := newItem(_ZERO)
			zero.dollar = char == '$'
			current.items = append(current.items, zero)
			if char == '^' || char == '$' {
				index++
			} else {
				index += 2
			}
		case strings.IndexByte(_QUANTIFIER_START, char) >= 0:
			return counter{}, "", refuse("misplaced quantifier at %d", index)
		default:
			var members bitSet
			switch {
			case char == '[':
				end, set, listed, err := classEnd(pattern, index+1)
				if err != nil {
					return counter{}, "", err
				}
				index, members = end, set
				width += listed
			case char == '\\':
				kind, end, err := escape(pattern, index) // refuses an unsupported or trailing escape
				if err != nil {
					return counter{}, "", err
				}
				escaped := pattern[index+1]
				if kind == "class" {
					members = _CLASS_ESCAPES[escaped]
				} else {
					members = fold(bit(int(escaped)))
				}
				index = end
			case char == ']' || char == '}':
				return counter{}, "", refuse("unescaped %c at %d", char, index)
			default:
				if char == '.' {
					members = _DOT
				} else {
					members = fold(bit(int(char)))
				}
				index++
			}
			// A leading `.*` / `.+` (greedy or lazy) anchors its branch: the run can stand for everything before the
			// match, so a match from any start position can start at 0 instead. It costs what a written `^` costs.
			leadingDotRun := char == '.' && current.top && len(current.items) == 0 &&
				index < len(pattern) && (pattern[index] == '*' || pattern[index] == '+')
			runStart := index - 1 // the `.` just read
			next, spec, quantified, err := quantifier(pattern, index)
			if err != nil {
				return counter{}, "", err
			}
			index = next
			if leadingDotRun {
				current.dotRuns = append(current.dotRuns, [2]int{runStart, index})
				current.items = append(current.items, newItem(_ZERO))
				current.branchAnchored = true
			}
			atom := newItem(_ATOM)
			atom.members = members
			if quantified {
				atom.quantified = true
				atom.quantifierSpec = spec
			}
			current.atoms++
			current.simple = current.simple && !quantified
			current.items = append(current.items, atom)
		}
	}
	if len(stack) != 1 {
		return counter{}, "", refuse("unbalanced (")
	}
	top := &stack[0]
	top.endBranch()
	anchored := top.unanchored == 0
	factor := REGEX_COST_UNBOUNDED
	if anchored {
		factor = 1
	}
	cost := top.nodes.mul(count(factor))
	if !cost.atMost(REGEX_COST_MAX) {
		// Each unanchored branch needs one caret (one node and one character).
		// Suggest it only when the anchored text fits every admission bound.
		if top.nodes.add(count(top.unanchored)).atMost(REGEX_COST_MAX) &&
			len(pattern)+top.unanchored <= REGEX_PATTERN_MAX_LEN && width <= REGEX_CLASS_WIDTH_MAX {
			return counter{}, "", refuse("too costly to match unanchored (bound %s > %d); anchor it with ^", cost, REGEX_COST_MAX)
		}
		return counter{}, "", refuse("too costly to match (bound %s > %d)", cost, REGEX_COST_MAX)
	}
	if width > REGEX_CLASS_WIDTH_MAX {
		return counter{}, "", refuse("character classes too wide (width %d > %d)", width, REGEX_CLASS_WIDTH_MAX)
	}
	if anchored && len(top.dotRuns) > 0 {
		return cost, compileText(pattern, top.dotRuns), nil
	}
	return cost, pattern, nil
}

// Admission is pfb_regex_admission: the cost bound and the compile text of pattern when it is admitted (reason ""), a
// nil compiled and the short fixed reason when it is refused (Python returns the pattern as the text then; nothing
// compiles it). A refused pattern is never compiled, and the reason never quotes it.
//
// compiled is the text to hand the regex engine: pattern as written, except that when every top-level branch starts
// with `^`, `.*` or `.+` and at least one relies on its leading dot run it is `^(?:` + the pattern with each such run
// spelled to cross a newline (`.*` as `(?s:.*)`, `.+` as `(?s:.*)[^\n]`) + `)`. A dot run stands for everything before
// the match, so with or without it the pattern matches exactly the same names, newline or not, and the engine skips
// every later start position of a pattern that begins with `^`; the cost counts that pattern as anchored, so it is
// compiled as one.
//
// The gate is applied to FEED and user regex UNCONDITIONALLY at load (independent of the opt-in length cap). It admits
// only the constructs a host-name pattern needs -- printable ASCII without spaces; literals, `.`, `\d\D\w\W\s\S` and
// punctuation escapes, `[...]` classes, `(...)` / `(?:...)` groups, `|`, `^ $ \b \B` and the quantifiers `? * + {m}
// {m,} {m,n}` -- and bounds the work of one failed match: cost counts the nodes of the matcher's backtracking search
// tree, from every start position unless every top-level branch starts with `^`, `.*` or `.+` (a leading dot run costs
// what a written `^` costs). A quantified atom multiplies the work after it, unless a disjoint mandatory atom follows
// it directly or nothing but `$` follows it in a top-level branch; a group repeated more than optionally must be a
// plain run of atoms. The bracket classes of one pattern list at most REGEX_CLASS_WIDTH_MAX ASCII characters in total,
// because compiling a class costs time in proportion to what it lists. Pure static analysis of the text, one
// left-to-right parse. A pattern over the bound only because of the unanchored search is refused with the remedy: a `^`
// in front of every branch.
func Admission(pattern string) (cost int, compiled *string, reason string) {
	bound, text, err := admit(pattern)
	if err != nil {
		return 0, nil, err.Error()
	}
	return int(bound.v), &text, ""
}

// Excerpt is pfb_regex_excerpt, the log form of a pattern: ascii() of its first 32 characters, plus its length when
// longer. Keeps feed-supplied text short and free of raw control characters.
func Excerpt(pattern string) string {
	length := utf8.RuneCountInString(pattern)
	head := pattern
	if length > _EXCERPT_CHARS {
		characters := 0
		for index := range pattern {
			if characters == _EXCERPT_CHARS {
				head = pattern[:index]
				break
			}
			characters++
		}
	}
	excerpt := ascii(head)
	if length <= _EXCERPT_CHARS {
		return excerpt
	}
	return fmt.Sprintf("%s ... (%d chars)", excerpt, length)
}

// ascii is Python's ascii(s): repr(s) with every non-ASCII character escaped as \xNN, \uNNNN or \UNNNNNNNN.
func ascii(s string) string {
	var out strings.Builder
	for _, char := range pysem.Repr(s) {
		switch {
		case char < 0x80:
			out.WriteRune(char)
		case char < 0x100:
			fmt.Fprintf(&out, `\x%02x`, char)
		case char < 0x10000:
			fmt.Fprintf(&out, `\u%04x`, char)
		default:
			fmt.Fprintf(&out, `\U%08x`, char)
		}
	}
	return out.String()
}

// SplitRegexLine is pfb_split_regex_line: split a regex-list line into (pattern, description) at the first UNESCAPED
// '#'.
//
// issue #1867: a '#' preceded by an ODD number of backslashes is escaped and belongs to the pattern; an EVEN run
// (including none) leaves it as the description marker. The escaped form is returned verbatim -- `\#` is a literal '#'
// to the regex engine already, so no unescaping step is needed.
//
// Returns (line, nil) when the line carries no description marker at all; the caller distinguishes that from an empty
// description ("pattern#").
//
// The PHP twin is pfb_split_regex_line() in pfblockerng_extra.inc and the editor twin is the Pattern/Comment token
// pair in tools/webassets/lezer-pfb-regex-list/src/pfb-regex-list.grammar -- all three implement this one rule.
func SplitRegexLine(line string) (pattern string, label *string) {
	backslashes := 0
	// Bytes, not characters: '\\' and '#' are ASCII, and no byte of a multi-byte UTF-8 sequence is one.
	for index := range len(line) {
		switch line[index] {
		case '\\':
			backslashes++
			continue
		case '#':
			if backslashes%2 == 0 {
				description := line[index+1:]
				return line[:index], &description
			}
		}
		backslashes = 0
	}
	return line, nil
}
