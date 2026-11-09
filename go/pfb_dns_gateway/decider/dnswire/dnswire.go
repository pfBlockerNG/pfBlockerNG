// Package dnswire is the Go translation of src/usr/local/pkg/pfblockerng/dns_proxy/dnswire.py: a standard-library
// DNS wire codec (RFC 1035 with the RFC 6891 OPT record).
//
// Names are absolute presentation strings ("example.com.", root "."); `\.`, `\\` and `\DDD` escape the bytes a
// label may carry. RR rdata is kept canonical: names inside RFC 1035 rdata types are expanded (never compressed),
// which is also how Unbound stores them. Encode compresses owner names only.
//
// The Python module leans on shlex, ipaddress, int(), repr() and str.split(); the helpers below (shlexSplit,
// ipv4Address, ipv6Address, pyInt, pyRepr, splitWhitespace) reproduce those behaviours, error text included.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	QR          uint16 = 0x8000
	AA          uint16 = 0x0400
	TC          uint16 = 0x0200
	RD          uint16 = 0x0100
	RA          uint16 = 0x0080
	CD          uint16 = 0x0010
	OPCODE_MASK uint16 = 0x7800 // header bits 11-14: the opcode
)

const (
	CLASS_IN  uint16 = 1
	CLASS_ANY uint16 = 255
)

const (
	TYPE_A     uint16 = 1
	TYPE_NS    uint16 = 2
	TYPE_CNAME uint16 = 5
	TYPE_SOA   uint16 = 6
	TYPE_PTR   uint16 = 12
	TYPE_MX    uint16 = 15
	TYPE_TXT   uint16 = 16
	TYPE_AAAA  uint16 = 28
	TYPE_OPT   uint16 = 41
	TYPE_RRSIG uint16 = 46
)

var _TYPE_NAMES = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	24:  "SIG",
	28:  "AAAA",
	33:  "SRV",
	39:  "DNAME",
	41:  "OPT",
	43:  "DS",
	46:  "RRSIG",
	47:  "NSEC",
	48:  "DNSKEY",
	50:  "NSEC3",
	51:  "NSEC3PARAM",
	64:  "SVCB",
	65:  "HTTPS",
	255: "ANY",
}

// _NAME stands for Python's None in a layout: a domain name rather than a run of fixed octets.
const _NAME = -1

// rdata layouts of the RFC 1035 types, the only ones whose names may be compressed on the wire:
// a number is a run of fixed octets, _NAME is a domain name.
var _NAME_LAYOUTS = map[uint16][]int{
	TYPE_NS:    {_NAME},
	3:          {_NAME}, // MD
	4:          {_NAME}, // MF
	TYPE_CNAME: {_NAME},
	TYPE_SOA:   {_NAME, _NAME, 20},
	7:          {_NAME}, // MB
	8:          {_NAME}, // MG
	9:          {_NAME}, // MR
	TYPE_PTR:   {_NAME},
	14:         {_NAME, _NAME}, // MINFO
	TYPE_MX:    {2, _NAME},
}

const (
	_MAX_NAME    = 255
	_MAX_LABEL   = 63
	_MAX_HOPS    = 127 // a name has at most 127 labels, so a longer pointer chain is not a compressed name
	_HEADER_SIZE = 12  // struct.Struct("!HHHHHH").size
)

type WireError struct{ msg string }

func (e *WireError) Error() string { return e.msg }

func TypeStr(rtype uint16) string {
	if name, ok := _TYPE_NAMES[rtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", rtype)
}

type Question struct {
	Name          string
	Qtype, Qclass uint16
}

type RR struct {
	Name          string
	Rtype, Rclass uint16
	TTL           uint32
	Rdata         []byte
}

type Message struct {
	ID, Flags                      uint16
	Questions                      []Question
	Answers, Authority, Additional []RR
}

func (m *Message) Rcode() int { return int(m.Flags & 0xF) }

const EDNS_UDP_SIZE uint16 = 1232 // the UDP size the proxy advertises: Unbound's edns-buffer-size default

func MakeOpt(udpSize uint16, do bool, options []byte) RR {
	var ttl uint32
	if do {
		ttl = 0x8000
	}
	return RR{".", TYPE_OPT, udpSize, ttl, options}
}

func labelText(label []byte) string {
	var out strings.Builder
	for _, octet := range label {
		if octet == 0x2E || octet == 0x5C {
			out.WriteByte('\\')
			out.WriteByte(octet)
		} else if 0x21 <= octet && octet <= 0x7E {
			out.WriteByte(octet)
		} else {
			fmt.Fprintf(&out, "\\%03d", octet)
		}
	}
	return out.String()
}

func LabelsToText(labels [][]byte) string {
	var out strings.Builder
	for _, label := range labels {
		out.WriteString(labelText(label) + ".")
	}
	if out.Len() == 0 {
		return "."
	}
	return out.String()
}

func NameToLabels(name string) ([][]byte, error) {
	if name == "." {
		return [][]byte{}, nil
	}
	if name == "" {
		return nil, errors.New("empty name")
	}
	// Python indexes code points; the runes keep the \DDD lookahead and the "isdigit" test on the same footing.
	chars := []rune(name)
	var labels [][]byte
	var current []byte
	i := 0
	for i < len(chars) {
		char := chars[i]
		if char == '\\' {
			i++
			if i >= len(chars) {
				return nil, fmt.Errorf("dangling escape in %s", pyRepr(name))
			}
			digits := chars[i:min(i+3, len(chars))]
			// shortcut: ASCII-only digit escapes. Python's isdigit() also takes the Nd decimal digits (`\٠٠١`: Python
			// converts it to octet 1, Go answers "bad \DDD escape") and the No digits such as superscripts and circled
			// digits (`\²`, `\①`: Python raises ValueError, Go takes the character literally). Unreachable from names the
			// decider renders, because LabelsToText escapes every non-ASCII octet as \DDD; upgrade when a hand-written
			// non-ASCII escape has to match Python.
			if unicode.IsDigit(chars[i]) {
				if len(digits) != 3 || !isASCIIDigits(string(digits)) {
					return nil, fmt.Errorf("bad \\DDD escape in %s", pyRepr(name))
				}
				value := int(digits[0]-'0')*100 + int(digits[1]-'0')*10 + int(digits[2]-'0')
				if value > 255 {
					return nil, fmt.Errorf("bad \\DDD escape in %s", pyRepr(name))
				}
				current = append(current, byte(value))
				i += 3
			} else {
				current = utf8.AppendRune(current, chars[i])
				i++
			}
			continue
		}
		if char == '.' {
			if len(current) == 0 {
				return nil, fmt.Errorf("empty label in %s", pyRepr(name))
			}
			labels = append(labels, current)
			current = nil
		} else {
			current = utf8.AppendRune(current, char)
		}
		i++
	}
	if len(current) > 0 {
		labels = append(labels, current)
	}
	for _, label := range labels {
		if len(label) > _MAX_LABEL {
			return nil, fmt.Errorf("label longer than %d octets in %s", _MAX_LABEL, pyRepr(name))
		}
	}
	wireLen := 1
	for _, label := range labels {
		wireLen += len(label) + 1
	}
	if wireLen > _MAX_NAME {
		return nil, fmt.Errorf("name longer than %d octets", _MAX_NAME)
	}
	return labels, nil
}

func EncodeName(name string) ([]byte, error) {
	labels, err := NameToLabels(name)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, label := range labels {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func NameFromRdata(rdata []byte) (string, error) {
	labels, _, err := readLabels(rdata, 0)
	if err != nil {
		return "", err
	}
	return LabelsToText(labels), nil
}

func readLabels(data []byte, pos int) ([][]byte, int, error) {
	var labels [][]byte
	wireLen := 1 // root octet
	end := -1    // Python's None: no pointer followed yet
	hops := 0
	cur := pos
	for {
		if cur >= len(data) {
			return nil, 0, &WireError{"truncated name"}
		}
		octet := int(data[cur])
		if octet == 0 {
			if end != -1 {
				return labels, end, nil
			}
			return labels, cur + 1, nil
		}
		if octet&0xC0 == 0xC0 {
			if cur+1 >= len(data) {
				return nil, 0, &WireError{"truncated compression pointer"}
			}
			target := (octet&0x3F)<<8 | int(data[cur+1])
			if end == -1 {
				end = cur + 2
			}
			if target >= cur {
				return nil, 0, &WireError{"compression pointer does not point backwards"}
			}
			hops++
			if hops > _MAX_HOPS {
				return nil, 0, &WireError{fmt.Sprintf("more than %d compression pointers in one name", _MAX_HOPS)}
			}
			cur = target
			continue
		}
		if octet&0xC0 != 0 {
			return nil, 0, &WireError{"reserved label type or label longer than 63 octets"}
		}
		if cur+1+octet > len(data) {
			return nil, 0, &WireError{"truncated label"}
		}
		wireLen += 1 + octet
		if wireLen > _MAX_NAME {
			return nil, 0, &WireError{fmt.Sprintf("name longer than %d octets", _MAX_NAME)}
		}
		labels = append(labels, data[cur+1:cur+1+octet])
		cur += 1 + octet
	}
}

func expandRdata(data []byte, rtype uint16, start, end int) ([]byte, error) {
	layout, ok := _NAME_LAYOUTS[rtype]
	if !ok {
		// a copy: Python's bytes slice is one, and the caller may reuse the packet buffer
		return append([]byte{}, data[start:end]...), nil
	}
	var out []byte
	cur := start
	for _, part := range layout {
		if part == _NAME {
			labels, next, err := readLabels(data, cur)
			if err != nil {
				return nil, err
			}
			cur = next
			if cur > end {
				return nil, &WireError{"name overruns rdata"}
			}
			for _, label := range labels {
				out = append(out, byte(len(label)))
				out = append(out, label...)
			}
			out = append(out, 0)
		} else {
			if cur+part > end {
				return nil, &WireError{"fixed rdata field overruns rdata"}
			}
			out = append(out, data[cur:cur+part]...)
			cur += part
		}
	}
	if cur != end {
		return nil, &WireError{"rdata length mismatch"}
	}
	return out, nil
}

func Parse(data []byte) (*Message, error) {
	if len(data) < _HEADER_SIZE {
		return nil, &WireError{"short header"}
	}
	msgID := binary.BigEndian.Uint16(data[0:])
	flags := binary.BigEndian.Uint16(data[2:])
	qdcount := int(binary.BigEndian.Uint16(data[4:]))
	ancount := int(binary.BigEndian.Uint16(data[6:]))
	nscount := int(binary.BigEndian.Uint16(data[8:]))
	arcount := int(binary.BigEndian.Uint16(data[10:]))
	if qdcount*5+(ancount+nscount+arcount)*11 > len(data)-_HEADER_SIZE {
		return nil, &WireError{"record counts exceed packet size"}
	}
	pos := _HEADER_SIZE
	message := &Message{ID: msgID, Flags: flags}
	for range qdcount {
		labels, next, err := readLabels(data, pos)
		if err != nil {
			return nil, err
		}
		pos = next
		if pos+4 > len(data) {
			return nil, &WireError{"truncated question"}
		}
		qtype := binary.BigEndian.Uint16(data[pos:])
		qclass := binary.BigEndian.Uint16(data[pos+2:])
		pos += 4
		message.Questions = append(message.Questions, Question{LabelsToText(labels), qtype, qclass})
	}
	sections := []struct {
		section *[]RR
		count   int
	}{{&message.Answers, ancount}, {&message.Authority, nscount}, {&message.Additional, arcount}}
	for _, s := range sections {
		for range s.count {
			labels, next, err := readLabels(data, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if pos+10 > len(data) {
				return nil, &WireError{"truncated record"}
			}
			rtype := binary.BigEndian.Uint16(data[pos:])
			rclass := binary.BigEndian.Uint16(data[pos+2:])
			ttl := binary.BigEndian.Uint32(data[pos+4:])
			rdlength := int(binary.BigEndian.Uint16(data[pos+8:]))
			pos += 10
			if pos+rdlength > len(data) {
				return nil, &WireError{"rdata overruns packet"}
			}
			rdata, err := expandRdata(data, rtype, pos, pos+rdlength)
			if err != nil {
				return nil, err
			}
			*s.section = append(*s.section, RR{LabelsToText(labels), rtype, rclass, ttl, rdata})
			pos += rdlength
		}
	}
	return message, nil
}

// errStructH is the struct.error Python raises when a count or length does not fit a 16-bit wire field.
var errStructH = errors.New("'H' format requires 0 <= number <= 65535")

func Encode(m *Message) ([]byte, error) {
	for _, count := range []int{len(m.Questions), len(m.Answers), len(m.Authority), len(m.Additional)} {
		if count > 0xFFFF {
			return nil, errStructH
		}
	}
	out := make([]byte, 0, 512)
	out = binary.BigEndian.AppendUint16(out, m.ID)
	out = binary.BigEndian.AppendUint16(out, m.Flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Questions)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Answers)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Authority)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Additional)))
	seen := map[string]int{} // folded label suffix (each label length-prefixed) -> offset

	putName := func(name string) error {
		labels, err := NameToLabels(name)
		if err != nil {
			return err
		}
		folded := make([][]byte, len(labels))
		for i, label := range labels {
			folded[i] = asciiLower(label)
		}
		for i, label := range labels {
			var suffix []byte
			for _, f := range folded[i:] {
				suffix = append(suffix, byte(len(f)))
				suffix = append(suffix, f...)
			}
			if offset, ok := seen[string(suffix)]; ok {
				out = binary.BigEndian.AppendUint16(out, 0xC000|uint16(offset))
				return nil
			}
			if len(out) < 0x4000 {
				seen[string(suffix)] = len(out)
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
		out = append(out, 0)
		return nil
	}

	for _, question := range m.Questions {
		if err := putName(question.Name); err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint16(out, question.Qtype)
		out = binary.BigEndian.AppendUint16(out, question.Qclass)
	}
	for _, section := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for _, rr := range section {
			if err := putName(rr.Name); err != nil {
				return nil, err
			}
			if len(rr.Rdata) > 0xFFFF {
				return nil, errStructH
			}
			out = binary.BigEndian.AppendUint16(out, rr.Rtype)
			out = binary.BigEndian.AppendUint16(out, rr.Rclass)
			out = binary.BigEndian.AppendUint32(out, rr.TTL)
			out = binary.BigEndian.AppendUint16(out, uint16(len(rr.Rdata)))
			out = append(out, rr.Rdata...)
		}
	}
	return out, nil
}

// asciiLower is bytes.lower(): ASCII only, so a non-ASCII label byte keeps its case.
func asciiLower(label []byte) []byte {
	out := make([]byte, len(label))
	for i, b := range label {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		out[i] = b
	}
	return out
}

func txtRdata(rest string) ([]byte, error) {
	tokens, err := shlexSplit(rest)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, errors.New("TXT needs at least one character-string of at most 255 octets")
	}
	var out []byte
	for _, token := range tokens {
		if len(token) > 255 {
			return nil, errors.New("TXT needs at least one character-string of at most 255 octets")
		}
		out = append(out, byte(len(token)))
		out = append(out, token...)
	}
	return out, nil
}

func soaRdata(rest string) ([]byte, error) {
	fields := strings.FieldsFunc(rest, isSpace)
	if len(fields) != 7 {
		return nil, errors.New("SOA rdata is: mname rname serial refresh retry expire minimum")
	}
	numbers := make([]int64, 5)
	for i, value := range fields[2:] {
		number, err := pyInt(value)
		if err != nil {
			return nil, err
		}
		numbers[i] = number
	}
	for _, number := range numbers {
		if number < 0 || number > 0xFFFFFFFF {
			return nil, errors.New("SOA counter out of range")
		}
	}
	mname, err := EncodeName(fields[0])
	if err != nil {
		return nil, err
	}
	rname, err := EncodeName(fields[1])
	if err != nil {
		return nil, err
	}
	out := append(mname, rname...)
	for _, number := range numbers {
		out = binary.BigEndian.AppendUint32(out, uint32(number))
	}
	return out, nil
}

func cnameRdata(rest string) ([]byte, error) {
	fields := strings.FieldsFunc(rest, isSpace)
	if len(fields) != 1 {
		return nil, errors.New("CNAME rdata is one target name")
	}
	return EncodeName(fields[0])
}

var _TEXT_RDATA = map[string]struct {
	code  uint16
	build func(rest string) ([]byte, error)
}{
	"A": {TYPE_A, func(rest string) ([]byte, error) {
		ip, err := ipv4Address(strings.TrimFunc(rest, isSpace))
		return binary.BigEndian.AppendUint32(nil, ip), err
	}},
	"AAAA":  {TYPE_AAAA, func(rest string) ([]byte, error) { return ipv6Address(strings.TrimFunc(rest, isSpace)) }},
	"CNAME": {TYPE_CNAME, cnameRdata},
	"TXT":   {TYPE_TXT, txtRdata},
	"SOA":   {TYPE_SOA, soaRdata},
}

func RRFromText(line string) (RR, error) {
	parts := splitWhitespace(line, 4)
	if len(parts) < 5 {
		return RR{}, fmt.Errorf("expected 'name ttl IN type rdata': %s", pyRepr(line))
	}
	name, ttl, rclass, rtype, rest := parts[0], parts[1], parts[2], parts[3], parts[4]
	ttlValue, _ := pyInt(ttl) // digits only when the isASCIIDigits test passes, so no error to report
	if !isASCIIDigits(ttl) || ttlValue > 0xFFFFFFFF {
		return RR{}, fmt.Errorf("bad ttl %s", pyRepr(ttl))
	}
	if strings.ToUpper(rclass) != "IN" {
		return RR{}, fmt.Errorf("unsupported class %s", pyRepr(rclass))
	}
	entry, ok := _TEXT_RDATA[strings.ToUpper(rtype)]
	if !ok {
		return RR{}, fmt.Errorf("unsupported RR type %s", pyRepr(rtype))
	}
	if _, err := NameToLabels(name); err != nil { // reject a name that cannot be encoded now, not when the reply is serialised
		return RR{}, err
	}
	rdata, err := entry.build(rest)
	if err != nil {
		return RR{}, err
	}
	return RR{name, entry.code, CLASS_IN, uint32(ttlValue), rdata}, nil
}

// isSpace is str.isspace() for one character: Unicode White_Space plus the ASCII separators 0x1C-0x1F.
func isSpace(r rune) bool { return unicode.IsSpace(r) || 0x1C <= r && r <= 0x1F }

// isASCIIDigits is str.isdigit() restricted to ASCII.
// shortcut: for a ttl or SOA counter Python's int() converts Nd decimal digits ("٦٠" is 60; Go rejects it) and rejects
// No digits such as "²" or "①" (Go rejects them too, with its own message). Unreachable from the module's text RRs,
// whose ttls are literals; upgrade when text RRs can come from outside the module.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// splitWhitespace is s.split(None, maxsplit): the remainder after the last split keeps its trailing whitespace.
func splitWhitespace(s string, maxsplit int) []string {
	var parts []string
	i := 0
	skipSpace := func() {
		for i < len(s) {
			r, width := utf8.DecodeRuneInString(s[i:])
			if !isSpace(r) {
				return
			}
			i += width
		}
	}
	for ; maxsplit > 0; maxsplit-- {
		skipSpace()
		if i == len(s) {
			return parts
		}
		start := i
		for i < len(s) {
			r, width := utf8.DecodeRuneInString(s[i:])
			if isSpace(r) {
				break
			}
			i += width
		}
		parts = append(parts, s[start:i])
	}
	skipSpace()
	if i < len(s) {
		parts = append(parts, s[i:])
	}
	return parts
}

// pyInt is int(s) for base 10: an optional sign, then digits with single underscores between them. A value too big
// for 40 bits saturates, which is enough for the 32-bit range checks of its callers.
// shortcut: no 4300-digit limit (Python 3.11+ raises beyond it); irrelevant to a 32-bit field.
func pyInt(s string) (int64, error) {
	digits := s
	negative := false
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		negative = digits[0] == '-'
		digits = digits[1:]
	}
	var value int64
	afterDigit := false
	for i := range len(digits) {
		c := digits[i]
		switch {
		case '0' <= c && c <= '9':
			if value < 1<<40 {
				value = value*10 + int64(c-'0')
			}
			afterDigit = true
		case c == '_' && afterDigit && i+1 < len(digits) && '0' <= digits[i+1] && digits[i+1] <= '9':
			afterDigit = false
		default:
			return 0, fmt.Errorf("invalid literal for int() with base 10: %s", pyRepr(s))
		}
	}
	if !afterDigit {
		return 0, fmt.Errorf("invalid literal for int() with base 10: %s", pyRepr(s))
	}
	if negative {
		value = -value
	}
	return value, nil
}

// pyRepr is repr(s) of a str.
func pyRepr(s string) string {
	quote := '\''
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for _, r := range s {
		switch {
		case r == quote || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r < ' ' || r == 0x7F:
			fmt.Fprintf(&out, `\x%02x`, r)
		case r < 0x7F || unicode.IsPrint(r):
			out.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&out, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			fmt.Fprintf(&out, `\U%08x`, r)
		}
	}
	out.WriteRune(quote)
	return out.String()
}

// shlexSplit is shlex.split(s): POSIX mode, whitespace_split, no comments.
func shlexSplit(s string) ([]string, error) {
	lex := &shlex{input: []rune(s), state: ' '}
	var tokens []string
	for {
		token, ok, err := lex.readToken()
		if err != nil {
			return nil, err
		}
		if !ok {
			return tokens, nil
		}
		tokens = append(tokens, token)
	}
}

type shlex struct {
	input []rune
	pos   int
	state rune // ' ' between tokens, 'a' inside a word, a quote or '\\' while in one; 0 past the end (Python's None)
}

// readToken is shlex.read_token for the posix + whitespace_split + no-comments configuration; ok is false at the
// end of the input.
func (l *shlex) readToken() (token string, ok bool, err error) {
	const eof = rune(-1)
	quoted := false
	escapedstate := ' '
	var current []rune
loop:
	for {
		nextchar := eof
		if l.pos < len(l.input) {
			nextchar = l.input[l.pos]
			l.pos++
		}
		switch {
		case l.state == 0: // past end of file
			current = nil
			break loop
		case l.state == ' ':
			switch {
			case nextchar == eof:
				l.state = 0
				break loop
			case isShlexSpace(nextchar):
				if len(current) > 0 || quoted {
					break loop
				}
			case nextchar == '\\':
				escapedstate = 'a'
				l.state = nextchar
			case nextchar == '\'' || nextchar == '"':
				l.state = nextchar
			default:
				current = []rune{nextchar}
				l.state = 'a'
			}
		case l.state == '\'' || l.state == '"':
			quoted = true
			switch {
			case nextchar == eof:
				return "", false, errors.New("No closing quotation")
			case nextchar == l.state:
				l.state = 'a'
			case nextchar == '\\' && l.state == '"': // only a double quote honours the escape
				escapedstate = l.state
				l.state = nextchar
			default:
				current = append(current, nextchar)
			}
		case l.state == '\\':
			if nextchar == eof {
				return "", false, errors.New("No escaped character")
			}
			// In posix shells, only the quote itself or the escape character may be escaped within quotes.
			if (escapedstate == '\'' || escapedstate == '"') && nextchar != l.state && nextchar != escapedstate {
				current = append(current, l.state)
			}
			current = append(current, nextchar)
			l.state = escapedstate
		default: // 'a'
			switch {
			case nextchar == eof:
				l.state = 0
				break loop
			case isShlexSpace(nextchar):
				l.state = ' '
				if len(current) > 0 || quoted {
					break loop
				}
			case nextchar == '\'' || nextchar == '"':
				l.state = nextchar
			case nextchar == '\\':
				escapedstate = 'a'
				l.state = nextchar
			default:
				current = append(current, nextchar)
			}
		}
	}
	if !quoted && len(current) == 0 {
		return "", false, nil
	}
	return string(current), true, nil
}

func isShlexSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }

// ipv4Address is the value of ipaddress.IPv4Address(address).
func ipv4Address(address string) (uint32, error) {
	if strings.Contains(address, "/") {
		return 0, fmt.Errorf("Unexpected '/' in %s", pyRepr(address))
	}
	if address == "" {
		return 0, errors.New("Address cannot be empty")
	}
	octets := strings.Split(address, ".")
	if len(octets) != 4 {
		return 0, fmt.Errorf("Expected 4 octets in %s", pyRepr(address))
	}
	var value uint32
	for _, octet := range octets {
		number, err := parseOctet(octet)
		if err != nil {
			return 0, fmt.Errorf("%s in %s", err, pyRepr(address))
		}
		value = value<<8 | uint32(number)
	}
	return value, nil
}

func parseOctet(octet string) (int, error) {
	if octet == "" {
		return 0, errors.New("Empty octet not permitted")
	}
	if !isASCIIDigits(octet) {
		return 0, fmt.Errorf("Only decimal digits permitted in %s", pyRepr(octet))
	}
	if len(octet) > 3 {
		return 0, fmt.Errorf("At most 3 characters permitted in %s", pyRepr(octet))
	}
	if octet != "0" && octet[0] == '0' {
		return 0, fmt.Errorf("Leading zeros are not permitted in %s", pyRepr(octet))
	}
	number := 0
	for i := range len(octet) {
		number = number*10 + int(octet[i]-'0')
	}
	if number > 255 {
		return 0, fmt.Errorf("Octet %d (> 255) not permitted", number)
	}
	return number, nil
}

const _HEXTET_COUNT = 8

// ipv6Address is the packed form of ipaddress.IPv6Address(address); a %scope id is validated and dropped.
func ipv6Address(address string) ([]byte, error) {
	if strings.Contains(address, "/") {
		return nil, fmt.Errorf("Unexpected '/' in %s", pyRepr(address))
	}
	ipStr, scopeID, hasScope := strings.Cut(address, "%")
	if hasScope && (scopeID == "" || strings.Contains(scopeID, "%")) {
		return nil, fmt.Errorf("Invalid IPv6 address: \"%s\"", pyRepr(address))
	}

	if ipStr == "" {
		return nil, errors.New("Address cannot be empty")
	}
	if chars := []rune(ipStr); len(chars) > 45 {
		shorten := ipStr
		if len(chars) > 100 {
			shorten = fmt.Sprintf("%s(%d chars elided)%s", string(chars[:45]), len(chars)-90, string(chars[len(chars)-45:]))
		}
		return nil, fmt.Errorf("At most 45 characters expected in %s", pyRepr(shorten))
	}

	// more parts than the max are split off to keep the right error message for too many parts combined with '::'
	maxParts := _HEXTET_COUNT + 1
	parts := strings.SplitN(ipStr, ":", maxParts+1)

	// An IPv6 address needs at least 2 colons (3 parts).
	const minParts = 3
	if len(parts) < minParts {
		return nil, fmt.Errorf("At least %d parts expected in %s", minParts, pyRepr(ipStr))
	}

	// If the address has an IPv4-style suffix, convert it to hexadecimal.
	if strings.Contains(parts[len(parts)-1], ".") {
		ipv4Int, err := ipv4Address(parts[len(parts)-1])
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, pyRepr(ipStr))
		}
		parts = append(parts[:len(parts)-1], fmt.Sprintf("%x", (ipv4Int>>16)&0xFFFF), fmt.Sprintf("%x", ipv4Int&0xFFFF))
	}

	// An IPv6 address can't have more than 8 colons (9 parts). The extra colon comes from using the "::" notation
	// for a single leading or trailing zero part.
	if len(parts) > maxParts {
		return nil, fmt.Errorf("At most %d colons permitted in %s", maxParts-1, pyRepr(ipStr))
	}

	// Disregarding the endpoints, find '::' with nothing in between: a run of zeroes has been skipped.
	skipIndex := -1
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			if skipIndex != -1 {
				return nil, fmt.Errorf("At most one '::' permitted in %s", pyRepr(ipStr))
			}
			skipIndex = i
		}
	}

	// partsHi parts are copied from before the '::', partsLo from after it.
	var partsHi, partsLo, partsSkipped int
	if skipIndex != -1 {
		partsHi = skipIndex
		partsLo = len(parts) - skipIndex - 1
		if parts[0] == "" {
			partsHi--
			if partsHi != 0 {
				return nil, fmt.Errorf("Leading ':' only permitted as part of '::' in %s", pyRepr(ipStr))
			}
		}
		if parts[len(parts)-1] == "" {
			partsLo--
			if partsLo != 0 {
				return nil, fmt.Errorf("Trailing ':' only permitted as part of '::' in %s", pyRepr(ipStr))
			}
		}
		partsSkipped = _HEXTET_COUNT - (partsHi + partsLo)
		if partsSkipped < 1 {
			return nil, fmt.Errorf("Expected at most %d other parts with '::' in %s", _HEXTET_COUNT-1, pyRepr(ipStr))
		}
	} else {
		// The endpoints could still be empty, but parseHextet will check for that.
		if len(parts) != _HEXTET_COUNT {
			return nil, fmt.Errorf("Exactly %d parts expected without '::' in %s", _HEXTET_COUNT, pyRepr(ipStr))
		}
		if parts[0] == "" {
			return nil, fmt.Errorf("Leading ':' only permitted as part of '::' in %s", pyRepr(ipStr))
		}
		if parts[len(parts)-1] == "" {
			return nil, fmt.Errorf("Trailing ':' only permitted as part of '::' in %s", pyRepr(ipStr))
		}
		partsHi = len(parts)
	}

	packed := make([]byte, 0, 16)
	for _, part := range parts[:partsHi] {
		hextet, err := parseHextet(part)
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, pyRepr(ipStr))
		}
		packed = binary.BigEndian.AppendUint16(packed, hextet)
	}
	packed = append(packed, make([]byte, 2*partsSkipped)...)
	for _, part := range parts[len(parts)-partsLo:] {
		hextet, err := parseHextet(part)
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, pyRepr(ipStr))
		}
		packed = binary.BigEndian.AppendUint16(packed, hextet)
	}
	return packed, nil
}

func parseHextet(hextet string) (uint16, error) {
	var value uint16
	for i := range len(hextet) {
		c := hextet[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return 0, fmt.Errorf("Only hex digits permitted in %s", pyRepr(hextet))
		}
	}
	if len(hextet) > 4 {
		return 0, fmt.Errorf("At most 4 characters permitted in %s", pyRepr(hextet))
	}
	if hextet == "" {
		return 0, errors.New("invalid literal for int() with base 16: ''")
	}
	for i := range len(hextet) {
		c := hextet[i]
		switch {
		case c <= '9':
			c -= '0'
		case c <= 'F':
			c = c - 'A' + 10
		default:
			c = c - 'a' + 10
		}
		value = value<<4 | uint16(c)
	}
	return value, nil
}
