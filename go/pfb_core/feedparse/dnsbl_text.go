package feedparse

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// pfb_dnsbl_strip_bom(): exactly one UTF-8 BOM.
func stripBOM(s string) string { return strings.TrimPrefix(s, "\xEF\xBB\xBF") }

// pfb_dnsbl_scrub_line(): every CR removed, then an ASCII-only trim (so no multi-byte character is sliced).
func scrubLine(s string) string {
	return strings.Trim(strings.ReplaceAll(s, "\r", ""), " \t\n\x00\x0b")
}

// A PCRE2 /u "\s" (UCP on): \p{Z}, \h and \v. U+180E is in \h, U+FEFF is added by the callers' classes.
func pcreSpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0D, r == 0x20, r == 0x85, r == 0xA0, r == 0x1680, r == 0x180E,
		r >= 0x2000 && r <= 0x200A, r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000, r == 0xFEFF:
		return true
	}
	return unicode.Is(unicode.Z, r)
}

// pfb_strip(): trim(), then (unless both ends are ASCII) the Unicode whitespace class off both ends. A
// preg_replace() failure (invalid UTF-8) leaves the ASCII-trimmed value.
func pfbStrip(s string) string {
	s = phpTrim(s)
	if s == "" || (s[0] < 0x80 && s[len(s)-1] < 0x80) || !utf8.ValidString(s) {
		return s
	}
	return strings.TrimFunc(s, pcreSpace)
}

// pfb_is_blank() on a string that trim() did not empty: nothing but whitespace, separators and BOMs.
func pfbIsBlank(s string) bool {
	if phpTrim(s) == "" {
		return true
	}
	if !utf8.ValidString(s) {
		return false
	}
	return strings.TrimFunc(s, pcreSpace) == ""
}

// ctype_print() and ctype_alnum() under the C locale; ctype_alnum("") is false.
func ctypePrint(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func ctypeAlnum(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !isWordByte(s[i]) || s[i] == '_' {
			return false
		}
	}
	return true
}

// strcspn(): the length of the prefix holding none of chars.
func strcspn(s, chars string) int {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return i
	}
	return len(s)
}

// strspn(): the length of the prefix made only of chars.
func strspn(s, chars string) int {
	for i := range len(s) {
		if strings.IndexByte(chars, s[i]) < 0 {
			return i
		}
	}
	return len(s)
}

// strstr($s, $needle, true): the text before the first needle, s itself when there is none.
func strBefore(s, needle string) string {
	if i := strings.Index(s, needle); i >= 0 {
		return s[:i]
	}
	return s
}
