package feedparse

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// RFC 3492 punycode and the default-option UTS46 ToASCII that PHP's idn_to_ascii() runs. Lower-casing, the mappings in
// idnMapped and category-based validity are reproduced; ICU's other compatibility mappings, NFC composition and the
// bidi rules are not.

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punycodeEncode encodes a label per RFC 3492; ok is false on overflow.
func punycodeEncode(label []rune) (string, bool) {
	var out []byte
	for _, r := range label {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(label) {
		m := int(^uint(0) >> 1)
		for _, r := range label {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (int(^uint32(0)>>1)-delta)/(h+1) {
			return "", false
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range label {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := k - bias
					if t < pcTMin {
						t = pcTMin
					} else if t > pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out = append(out, pcDigit(q))
				bias = pcAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), true
}

// punycodeDecode decodes a label per RFC 3492; ok is false on malformed input.
func punycodeDecode(s string) ([]rune, bool) {
	var out []rune
	basic := strings.LastIndexByte(s, '-')
	if basic > 0 {
		for i := 0; i < basic; i++ {
			if s[i] >= 0x80 {
				return nil, false
			}
			out = append(out, rune(s[i]))
		}
		s = s[basic+1:]
	} else if basic == 0 {
		s = s[1:]
	}
	n, i, bias := pcInitialN, 0, pcInitialBias
	for pos := 0; pos < len(s); {
		oldi, w := i, 1
		for k := pcBase; ; k += pcBase {
			if pos >= len(s) {
				return nil, false
			}
			c := s[pos]
			pos++
			var d int
			switch {
			case c >= '0' && c <= '9':
				d = int(c-'0') + 26
			case c >= 'a' && c <= 'z':
				d = int(c - 'a')
			case c >= 'A' && c <= 'Z':
				d = int(c - 'A')
			default:
				return nil, false
			}
			if d > (int(^uint32(0)>>1)-i)/w {
				return nil, false
			}
			i += d * w
			t := k - bias
			if t < pcTMin {
				t = pcTMin
			} else if t > pcTMax {
				t = pcTMax
			}
			if d < t {
				break
			}
			if w > int(^uint32(0)>>1)/(pcBase-t) {
				return nil, false
			}
			w *= pcBase - t
		}
		bias = pcAdapt(i-oldi, len(out)+1, oldi == 0)
		if i/(len(out)+1) > int(^uint32(0)>>1)-n {
			return nil, false
		}
		n += i / (len(out) + 1)
		i %= len(out) + 1
		if n > unicode.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return nil, false
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = rune(n)
		i++
	}
	return out, true
}

// idnRuneValid approximates the UTS46 "valid" status from Unicode categories: letters, marks,
// numbers, symbols and punctuation pass; separators, controls, format, private use and unassigned fail.
func idnRuneValid(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) || unicode.IsSymbol(r) || unicode.IsPunct(r)
}

func idnLabelOK(l []rune) bool {
	if len(l) == 0 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	// ICU counts UTF-16 code units for the "--" at positions 3-4 check.
	if u := utf16.Encode(l); len(u) >= 4 && u[2] == '-' && u[3] == '-' {
		return false
	}
	return !unicode.IsMark(l[0])
}

// idnToASCII is the default-option UTS46 ToASCII (idn_to_ascii) for the Unicode classes this port
// supports; ok is false where ICU reports an error.
func idnToASCII(s string) (string, bool) {
	if !utf8.ValidString(s) {
		return "", false
	}
	mapped := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
		default:
			if m, ok := idnMapped(r); ok {
				mapped = append(mapped, []rune(m)...)
				continue
			}
			if !idnRuneValid(r) {
				return "", false
			}
			r = unicode.ToLower(r)
		}
		mapped = append(mapped, r)
	}
	labels := strings.Split(string(mapped), ".")
	root := len(labels) > 1 && labels[len(labels)-1] == ""
	if root {
		labels = labels[:len(labels)-1]
	}
	out := make([]string, 0, len(labels))
	total := 0
	for _, lab := range labels {
		rs := []rune(lab)
		ascii := true
		for _, r := range rs {
			if r >= 0x80 {
				ascii = false
				break
			}
		}
		var enc string
		switch {
		case len(rs) >= 4 && lab[:4] == "xn--":
			dec, ok := punycodeDecode(lab[4:])
			if !ok {
				return "", false
			}
			hasNonASCII := false
			for _, r := range dec {
				if r >= 0x80 {
					hasNonASCII = true
				}
				if r >= 0x80 && (!idnRuneValid(r) || unicode.ToLower(r) != r) {
					return "", false
				}
			}
			if !hasNonASCII || !idnLabelOK(dec) {
				return "", false
			}
			back, ok := punycodeEncode(dec)
			if !ok || "xn--"+back != lab {
				return "", false
			}
			enc = lab
		case ascii:
			if !idnLabelOK(rs) {
				return "", false
			}
			enc = lab
		default:
			if !idnLabelOK(rs) {
				return "", false
			}
			p, ok := punycodeEncode(rs)
			if !ok {
				return "", false
			}
			enc = "xn--" + p
		}
		if len(enc) > 63 {
			return "", false
		}
		total += len(enc)
		out = append(out, enc)
	}
	total += len(out) - 1
	if total > 253 {
		return "", false
	}
	res := strings.Join(out, ".")
	if root {
		res += "."
	}
	return res, true
}

// idnMapped is the UTS46 mapping this port knows beyond lower-casing: ignored characters (the appliance's ICU is
// transitional, so ZWNJ and ZWJ go too), spaces, ideographic stops and the Latin-1 compatibility mappings.
func idnMapped(r rune) (string, bool) {
	switch {
	case r == 0xAD || r == 0x34F || (r >= 0x180B && r <= 0x180D) || r == 0x180F || r == 0x200B || r == 0x2060 ||
		(r >= 0xFE00 && r <= 0xFE0F) || r == 0xFEFF || (r >= 0xE0100 && r <= 0xE01EF) ||
		r == 0x200C || r == 0x200D: // transitional processing drops the joiners; U+180E stays disallowed
		return "", true
	case r == 0xA0 || (r >= 0x2000 && r <= 0x200A) || r == 0x202F || r == 0x205F || r == 0x3000:
		return " ", true
	case r == 0x3002 || r == 0xFF0E || r == 0xFF61:
		return ".", true
	}
	switch r {
	case 0xA8:
		return " \u0308", true
	case 0xAA:
		return "a", true
	case 0xAF:
		return " \u0304", true
	case 0xB2:
		return "2", true
	case 0xB3:
		return "3", true
	case 0xB4:
		return " \u0301", true
	case 0xB5:
		return "\u03bc", true
	case 0xB8:
		return " \u0327", true
	case 0xB9:
		return "1", true
	case 0xBA:
		return "o", true
	case 0xBC:
		return "1\u20444", true
	case 0xBD:
		return "1\u20442", true
	case 0xBE:
		return "3\u20444", true
	case 0x130:
		return "i\u0307", true
	}
	return "", false
}
