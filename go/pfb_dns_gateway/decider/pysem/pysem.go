// Package pysem holds the Python standard-library behaviour that more than one decider package reproduces: repr() of
// a str, int(), str.isspace(), str.split(None, maxsplit) and (ipaddress.go) the ipaddress module's address parsing.
// Error text is Python's, so a refusal reads as the Python code's.
package pysem

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A Python str can hold a lone surrogate (U+D800 to U+DFFF), which Go's strings cannot: here it is its three-byte
// encoding, as the "surrogatepass" codec writes it (ED A0..BF 80..BF), and these helpers read such a string by
// character. Valid UTF-8 never contains the encoding, so a string without a lone surrogate is an ordinary Go string.

// DecodeRune is the first character of s and its size in bytes: an encoded lone surrogate is one character of 3 bytes.
// Any other invalid byte is utf8.RuneError of size 1, as utf8.DecodeRuneInString reports it.
func DecodeRune(s string) (rune, int) {
	if len(s) >= 3 && s[0] == 0xED && 0xA0 <= s[1] && s[1] <= 0xBF && s[2]&0xC0 == 0x80 {
		return 0xD000 | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F), 3
	}
	return utf8.DecodeRuneInString(s)
}

// Len is len(s) of a str: its code points, a lone surrogate being one.
func Len(s string) int {
	n := 0
	for len(s) > 0 {
		_, size := DecodeRune(s)
		s = s[size:]
		n++
	}
	return n
}

// WriteRune writes r to b: a surrogate as its three-byte encoding, which strings.Builder.WriteRune would turn into U+FFFD.
func WriteRune(b *strings.Builder, r rune) {
	if 0xD800 <= r && r <= 0xDFFF {
		b.WriteByte(0xE0 | byte(r>>12))
		b.WriteByte(0x80 | byte(r>>6)&0x3F)
		b.WriteByte(0x80 | byte(r)&0x3F)
		return
	}
	b.WriteRune(r)
}

// Lower is str.lower(): Go's simple case mapping plus str.lower()'s one multi-character mapping, U+0130 to "i" and
// U+0307.
// shortcut: no Final_Sigma (a word-final capital sigma lowers to σ, not ς) and Go's Unicode 17 case tables where
// Python 3.11 has Unicode 14; neither changes an ASCII result. tld_allow_list is free text PHP writes from the form,
// so it can carry them: port Final_Sigma when its TLD Allow matcher is translated.
func Lower(s string) string { return strings.ToLower(strings.ReplaceAll(s, "\u0130", "i\u0307")) }

// IsSpace is str.isspace() for one character: Unicode White_Space plus the ASCII separators 0x1C-0x1F.
func IsSpace(r rune) bool { return unicode.IsSpace(r) || 0x1C <= r && r <= 0x1F }

// IsASCIIDigits is str.isdigit() restricted to ASCII.
// shortcut: for a ttl or SOA counter Python's int() converts Nd decimal digits ("٦٠" is 60; Go rejects it) and rejects
// No digits such as "²" or "①" (Go rejects them too, with its own message). Unreachable from the module's text RRs,
// whose ttls are literals; upgrade when text RRs can come from outside the module.
func IsASCIIDigits(s string) bool {
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

// SplitWhitespace is s.split(None, maxsplit): the remainder after the last split keeps its trailing whitespace.
func SplitWhitespace(s string, maxsplit int) []string {
	var parts []string
	i := 0
	skipSpace := func() {
		for i < len(s) {
			r, width := utf8.DecodeRuneInString(s[i:])
			if !IsSpace(r) {
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
			if IsSpace(r) {
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

// Int is int(s) for base 10: surrounding whitespace, an optional sign, then digits with single underscores between
// them. int() strips unicode.IsSpace only: 0x1C-0x1F, which str.strip() takes, are not whitespace to it (CPython 3.11).
// shortcut: ASCII digits only (Python also takes other Unicode decimal digits), an int beyond 64 bits stays at the
// nearest bound where Python's is unbounded, and there is no 4300-digit limit (Python 3.11+ raises beyond it); none
// of them can come from a PHP-written ini or a 32-bit wire field.
func Int(s string) (int64, error) {
	digits := strings.TrimFunc(s, unicode.IsSpace)
	negative := false
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		negative = digits[0] == '-'
		digits = digits[1:]
	}
	if digits == "" || digits[0] == '_' || digits[len(digits)-1] == '_' || strings.Contains(digits, "__") {
		return 0, invalidInt(s)
	}
	digits = strings.ReplaceAll(digits, "_", "")
	if !IsASCIIDigits(digits) {
		return 0, invalidInt(s)
	}
	if negative {
		digits = "-" + digits
	}
	value, err := strconv.ParseInt(digits, 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) { // only digits reach here, so a range error is the one failure left
		return 0, invalidInt(s)
	}
	return value, nil
}

func invalidInt(s string) error {
	return fmt.Errorf("invalid literal for int() with base 10: %s", Repr(s))
}

// Repr is repr(s) of a str.
// shortcut: printability follows Go's Unicode 17 tables where Python 3.11 has Unicode 14, so a code point unassigned
// in 14 prints raw here and as an escape in Python; it only shapes error and diagnostic text.
func Repr(s string) string {
	quote := '\''
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var out strings.Builder
	out.WriteRune(quote)
	for len(s) > 0 {
		r, size := DecodeRune(s)
		s = s[size:]
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
