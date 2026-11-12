package feedparse

import (
	"bytes"
	"encoding/binary"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var lf = []byte{'\n'}

// Normalize returns the .norm bytes of a downloaded feed's .orig bytes: pfb_feed_normalize_generate() followed by the
// trailing-newline guarantee. Owner rule (#3906): no charset detection, so every encoding except a BOM-marked UTF-16 is
// used as it is; a UTF-16 BOM never opens valid UTF-8, so the old iconv validity gate reduces to the BOM test.
func Normalize(orig []byte) []byte {
	text := orig
	if len(orig) >= 2 && (orig[0] == 0xFF && orig[1] == 0xFE || orig[0] == 0xFE && orig[1] == 0xFF) {
		text = decodeUTF16(orig)
	}
	out := make([]byte, 0, len(text)+1)
	for len(text) > 0 {
		line, rest, terminated := bytes.Cut(text, lf)
		out = sedLine(out, line)
		if terminated {
			out = append(out, '\n')
		}
		text = rest
	}
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out
}

// decodeUTF16 decodes BOM-marked UTF-16 like Python's utf_16 codec with errors=replace: the BOM is consumed, a lone
// surrogate becomes U+FFFD, and so does a stray last byte (one U+FFFD for a high surrogate cut off by the end of data).
func decodeUTF16(b []byte) []byte {
	var order binary.ByteOrder = binary.LittleEndian
	if b[0] == 0xFE {
		order = binary.BigEndian
	}
	b = b[2:]
	out := make([]byte, 0, len(b)/2*3+3)
	for i := 0; i < len(b); i += 2 {
		if i+2 > len(b) {
			return utf8.AppendRune(out, utf8.RuneError)
		}
		u := rune(order.Uint16(b[i:]))
		if u&0xFC00 == 0xD800 {
			if i+4 > len(b) {
				return utf8.AppendRune(out, utf8.RuneError)
			}
			if r := utf16.DecodeRune(u, rune(order.Uint16(b[i+2:]))); r != utf8.RuneError {
				u = r
				i += 2
			}
		}
		out = utf8.AppendRune(out, u) // a lone surrogate encodes as U+FFFD
	}
	return out
}

// kept is what the sed expression leaves alone: a tab or a [:print:] character. These are the appliance's C.UTF-8 classes,
// not the Unicode tables': private use and U+2028/2029 print, BOM and ZWJ do not, and U+0085 is a control but not [:space:].
func kept(r rune) bool {
	return r == '\t' || unicode.IsGraphic(r) || unicode.Is(unicode.Co, r) || r == 0x2028 || r == 0x2029
}

// sedLine appends to dst what LC_ALL=C.UTF-8 sed -E 's/[^[:print:]\t]+|[[:space:]]+$//g' leaves of one line: a single pass
// that never rescans a removal, and an invalid byte (it decodes as the printable U+FFFD) is matched by neither class.
func sedLine(dst, line []byte) []byte {
	tail := len(line)
	for tail > 0 {
		r, size := utf8.DecodeLastRune(line[:tail])
		if !unicode.IsSpace(r) || r == 0x85 {
			break
		}
		tail -= size
	}
	for i := 0; i < tail; {
		r, size := utf8.DecodeRune(line[i:])
		if kept(r) {
			dst = append(dst, line[i:i+size]...)
			i += size
			continue
		}
		for i += size; i < len(line); i += size {
			if r, size = utf8.DecodeRune(line[i:]); kept(r) {
				break
			}
		}
	}
	return dst
}
