// The slice of Python the control channel needs from json.loads and str(): a parser with json.loads' grammar (the NaN,
// Infinity and -Infinity literals included, which encoding/json refuses), ints of any size, and the str() of a parsed
// value, which _control_record_to_command puts in the duration token.
package decider

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// A parsed JSON value is nil (null), bool, *big.Int, float64, string, []any or *jsonObject.

// jsonObject is a JSON object as Python's dict holds it: a repeated key keeps its first position and its last value.
type jsonObject struct {
	keys []string
	vals map[string]any
}

func (o *jsonObject) set(key string, value any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = value
}

// jsonMaxDepth bounds the recursion.
// shortcut: Python raises an uncaught RecursionError near 1000 levels, which ends the watcher thread; Go reads anything
// deeper as no record and the watcher goes on. A hand-written channel file never nests; upgrade if one does.
// On the observer path Python's limit is its stack depth at the call, not a constant: a report that nests an ignored key
// between about 990 and 1000 levels fits a datagram, and is read here where Python may refuse it as a RecursionError.
const jsonMaxDepth = 1000

var jsonNumber = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`)

var jsonEscapes = map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

type jsonParser struct {
	text string
	pos  int
	// surrogates keeps a lone surrogate escape as the str it is in Python (pysem's three-byte encoding of it), where
	// otherwise it reads as U+FFFD.
	surrogates bool
}

// parsePyJSON is json.loads(text): ok is false where Python raises a ValueError.
// shortcut: a lone surrogate escape ("\ud800") becomes U+FFFD, where Python keeps the surrogate. It reaches only the IP
// and duration of a control record, which PHP never writes with one: the command rejects them (an IP is not an address, a
// duration is out of range) in both, and the rejection's message and the log_info line that carries it hold U+FFFD here
// and the surrogate in Python, which the shim's print to stderr writes as \ud800. No row or log file takes it, so no
// UnicodeEncodeError is lost. parsePyJSONSurrogates keeps it for the observer's reports, whose rows do; both are pinned
// by pfb_unbound_control_surrogate_test.go. Upgrade if the control channel's messages must match byte for byte.
func parsePyJSON(text string) (value any, ok bool) { return parsePyJSONText(text, false) }

// parsePyJSONText parses text; surrogates is jsonParser.surrogates.
func parsePyJSONText(text string, surrogates bool) (value any, ok bool) {
	p := &jsonParser{text: text, surrogates: surrogates}
	value, ok = p.value(0)
	if !ok {
		return nil, false
	}
	p.space()
	return value, p.pos == len(p.text)
}

// parsePyJSONSurrogates is parsePyJSON with a lone surrogate escape kept as Python keeps it, for text that reaches a row.
func parsePyJSONSurrogates(text string) (value any, ok bool) { return parsePyJSONText(text, true) }

func (p *jsonParser) space() {
	for p.pos < len(p.text) && strings.IndexByte(" \t\n\r", p.text[p.pos]) >= 0 {
		p.pos++
	}
}

// peek is the next byte after the whitespace, 0 at the end.
func (p *jsonParser) peek() byte {
	p.space()
	if p.pos >= len(p.text) {
		return 0
	}
	return p.text[p.pos]
}

func (p *jsonParser) value(depth int) (any, bool) {
	if depth > jsonMaxDepth {
		return nil, false
	}
	switch p.peek() {
	case '{':
		return p.object(depth + 1)
	case '[':
		return p.array(depth + 1)
	case '"':
		return p.str()
	}
	return p.scalar()
}

func (p *jsonParser) scalar() (any, bool) {
	rest := p.text[p.pos:]
	for _, literal := range []struct {
		text  string
		value any
	}{{"true", true}, {"false", false}, {"null", nil}, {"NaN", math.NaN()}, {"Infinity", math.Inf(1)}, {"-Infinity", math.Inf(-1)}} {
		if strings.HasPrefix(rest, literal.text) {
			p.pos += len(literal.text)
			return literal.value, true
		}
	}
	match := jsonNumber.FindStringSubmatch(rest)
	if match == nil {
		return nil, false
	}
	p.pos += len(match[0])
	if match[1] == "" && match[2] == "" {
		if len(strings.TrimPrefix(match[0], "-")) > pyIntMaxStrDigits {
			return nil, false
		}
		number, _ := new(big.Int).SetString(match[0], 10)
		return number, true
	}
	number, _ := strconv.ParseFloat(match[0], 64) // a range error leaves +-Inf or 0, as float() does
	return number, true
}

// hex4 reads the four hex digits of a \u escape.
func (p *jsonParser) hex4() (rune, bool) {
	if p.pos+4 > len(p.text) {
		return 0, false
	}
	number, err := strconv.ParseUint(p.text[p.pos:p.pos+4], 16, 16) // four hex digits never exceed 0xFFFF
	if err != nil {
		return 0, false
	}
	p.pos += 4
	return rune(number), true
}

func (p *jsonParser) str() (any, bool) {
	p.pos++ // the opening quote
	var out strings.Builder
	for p.pos < len(p.text) {
		c := p.text[p.pos]
		p.pos++
		switch {
		case c == '"':
			return out.String(), true
		case c < 0x20:
			return nil, false // strict: a control character must be escaped
		case c != '\\':
			out.WriteByte(c)
			continue
		case p.pos >= len(p.text):
			return nil, false
		}
		escape := p.text[p.pos]
		p.pos++
		if plain, ok := jsonEscapes[escape]; ok {
			out.WriteByte(plain)
			continue
		}
		if escape != 'u' {
			return nil, false
		}
		r, ok := p.hex4()
		if !ok {
			return nil, false
		}
		if 0xD800 <= r && r < 0xDC00 && strings.HasPrefix(p.text[p.pos:], `\u`) {
			save := p.pos
			p.pos += 2
			if low, ok := p.hex4(); ok && 0xDC00 <= low && low < 0xE000 {
				r = 0x10000 + (r-0xD800)<<10 + (low - 0xDC00)
			} else {
				p.pos = save
			}
		}
		if p.surrogates {
			pysem.WriteRune(&out, r)
		} else {
			out.WriteRune(r) // a lone surrogate is written as U+FFFD
		}
	}
	return nil, false
}

func (p *jsonParser) array(depth int) (any, bool) {
	p.pos++
	items := []any{}
	if p.peek() == ']' {
		p.pos++
		return items, true
	}
	for {
		item, ok := p.value(depth)
		if !ok {
			return nil, false
		}
		items = append(items, item)
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return items, true
		default:
			return nil, false
		}
	}
}

func (p *jsonParser) object(depth int) (any, bool) {
	p.pos++
	obj := &jsonObject{vals: map[string]any{}}
	if p.peek() == '}' {
		p.pos++
		return obj, true
	}
	for {
		if p.peek() != '"' {
			return nil, false
		}
		key, ok := p.str()
		if !ok || p.peek() != ':' {
			return nil, false
		}
		p.pos++
		value, ok := p.value(depth)
		if !ok {
			return nil, false
		}
		obj.set(key.(string), value)
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, true
		default:
			return nil, false
		}
	}
}

// pyStr is str(value) of a parsed JSON value.
func pyStr(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return pyRepr(value)
}

// pyRepr is repr(value) of a parsed JSON value.
func pyRepr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case bool:
		if v {
			return "True"
		}
		return "False"
	case *big.Int:
		return v.String()
	case float64:
		return pyFloatRepr(v)
	case string:
		return pysem.Repr(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = pyRepr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *jsonObject:
		parts := make([]string, len(v.keys))
		for i, key := range v.keys {
			parts[i] = pysem.Repr(key) + ": " + pyRepr(v.vals[key])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	panic("pyRepr: not a parsed JSON value")
}

// pyFloatRepr is repr(float): the shortest digits that round-trip, in positional notation unless the decimal point
// falls more than 16 places right or 4 places left of the digits, then d[.ddd]e+XX.
func pyFloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	text := strconv.FormatFloat(f, 'e', -1, 64) // [-]d[.ddd]e[+-]XX
	sign := ""
	if text[0] == '-' {
		sign, text = "-", text[1:]
	}
	mantissa, exponent, _ := strings.Cut(text, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp10, _ := strconv.Atoi(exponent)
	point := exp10 + 1 // the decimal point's position in digits
	switch {
	case point > 16 || point <= -4:
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		expSign := "+"
		if exp10 < 0 {
			expSign, exp10 = "-", -exp10
		}
		return sign + out + "e" + expSign + strings.Repeat("0", max(0, 2-len(strconv.Itoa(exp10)))) + strconv.Itoa(exp10)
	case point <= 0:
		return sign + "0." + strings.Repeat("0", -point) + digits
	case point >= len(digits):
		return sign + digits + strings.Repeat("0", point-len(digits)) + ".0"
	}
	return sign + digits[:point] + "." + digits[point:]
}
