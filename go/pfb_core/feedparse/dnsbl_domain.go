package feedparse

import (
	"strings"
	"unicode/utf8"
)

// pfb_idn_to_ascii_wildcard(): idn_to_ascii() keeping one leading '.'; "" when the conversion fails.
func idnToASCIIWildcard(host string) string {
	wildcard := strings.HasPrefix(host, ".")
	if wildcard {
		host = host[1:]
	}
	if pfbIsBlank(host) {
		return ""
	}
	ascii, ok := idnToASCII(host)
	if !ok || phpEmpty(ascii) {
		return ""
	}
	if wildcard {
		return "." + ascii
	}
	return ascii
}

// pfb_filter($line, PFB_FILTER_DOMAIN): whether the line passes. It always holds ASCII here (the IDN step ran first), so
// the punycode-candidate branch for non-ASCII input is never taken.
func domainOK(s string) bool {
	if phpEmpty(s) {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7F || s[i] >= 0x80 { // \p{Cc}; a non-ASCII byte fails the charset below
			return false
		}
	}
	if !strings.Contains(s, ".") || strings.Contains(s, "..") || len(s) >= 255 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) > 63 {
			return false
		}
	}
	for i := range len(s) {
		if !isWordByte(s[i]) && s[i] != '.' && s[i] != '-' {
			return false
		}
	}
	return true
}

// utf8Trail and utf8Lead: html.c's byte classes.
func utf8Trail(c byte) bool { return c >= 0x80 && c <= 0xBF }
func utf8Lead(c byte) bool  { return c < 0x80 || (c >= 0xC2 && c <= 0xF4) }

// phpNextUTF8Char is php_next_utf8_char(): the length of the character (or of the ill-formed prefix) at pos, and
// whether it is well-formed.
func phpNextUTF8Char(s string, pos int) (int, bool) {
	c := s[pos]
	avail := len(s) - pos
	switch {
	case c < 0x80:
		return 1, true
	case c < 0xC2:
		return 1, false
	case c < 0xE0:
		if avail < 2 {
			return 1, false
		}
		if !utf8Trail(s[pos+1]) {
			if utf8Lead(s[pos+1]) {
				return 1, false
			}
			return 2, false
		}
		if rune(c&0x1f)<<6|rune(s[pos+1]&0x3f) < 0x80 {
			return 2, false
		}
		return 2, true
	case c < 0xF0:
		if avail < 3 || !utf8Trail(s[pos+1]) || !utf8Trail(s[pos+2]) {
			switch {
			case avail < 2 || utf8Lead(s[pos+1]):
				return 1, false
			case avail < 3 || utf8Lead(s[pos+2]):
				return 2, false
			}
			return 3, false
		}
		r := rune(c&0x0f)<<12 | rune(s[pos+1]&0x3f)<<6 | rune(s[pos+2]&0x3f)
		if r < 0x800 || (r >= 0xD800 && r <= 0xDFFF) {
			return 3, false
		}
		return 3, true
	case c < 0xF5:
		if avail < 4 || !utf8Trail(s[pos+1]) || !utf8Trail(s[pos+2]) || !utf8Trail(s[pos+3]) {
			switch {
			case avail < 2 || utf8Lead(s[pos+1]):
				return 1, false
			case avail < 3 || utf8Lead(s[pos+2]):
				return 2, false
			case avail < 4 || utf8Lead(s[pos+3]):
				return 3, false
			}
			return 4, false
		}
		r := rune(c&0x07)<<18 | rune(s[pos+1]&0x3f)<<12 | rune(s[pos+2]&0x3f)<<6 | rune(s[pos+3]&0x3f)
		if r < 0x10000 || r > 0x10FFFF {
			return 4, false
		}
		return 4, true
	}
	return 1, false
}

// rowText is the text a NDJSON row carries: json_encode(..., JSON_INVALID_UTF8_SUBSTITUTE) writes U+FFFD for each
// ill-formed prefix as php_next_utf8_char() cuts them.
func rowText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for pos := 0; pos < len(s); {
		n, ok := phpNextUTF8Char(s, pos)
		if ok {
			b.WriteString(s[pos : pos+n])
		} else {
			b.WriteString("\uFFFD")
		}
		pos += n
	}
	return b.String()
}
