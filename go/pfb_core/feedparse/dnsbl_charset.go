package feedparse

import (
	"strconv"
	"strings"
	"sync"
)

// mb_detect_encoding($s, 'UTF-8, ASCII, ISO-8859-1') and mb_convert_encoding($s, 'UTF-8', <that>), as PHP 8.3-8.5 run
// them (ext/mbstring/mbstring.c mb_guess_encoding(), libmbfl's UTF-8 filter).

const mbBad = -1 // MBFL_BAD_INPUT

// utf8Wchar decodes like libmbfl's UTF-8 filter: every ill-formed prefix is one mbBad and the byte that broke it is
// decoded again; an incomplete sequence at the end is one mbBad.
func utf8Wchar(s string) []int32 {
	out := make([]int32, 0, len(s))
	status, cache := 0, int32(0)
	push := func(w int32) { out = append(out, w) }
	for i := 0; i < len(s); i++ {
		c := int32(s[i])
	retry:
		switch status {
		case 0x00:
			switch {
			case c < 0x80:
				push(c)
			case c >= 0xc2 && c <= 0xdf:
				status, cache = 0x10, c&0x1f
			case c >= 0xe0 && c <= 0xef:
				status, cache = 0x20, c&0xf
			case c >= 0xf0 && c <= 0xf4:
				status, cache = 0x30, c&0x7
			default:
				push(mbBad)
			}
		case 0x10, 0x21, 0x32:
			if c >= 0x80 && c <= 0xbf {
				push(cache<<6 | c&0x3f)
				status, cache = 0, 0
			} else {
				push(mbBad)
				status, cache = 0, 0
				goto retry
			}
		case 0x20:
			c1 := cache & 0xf
			if c >= 0x80 && c <= 0xbf && ((c1 == 0 && c >= 0xa0) || (c1 == 0xd && c < 0xa0) || (c1 > 0 && c1 != 0xd)) {
				cache = cache<<6 | c&0x3f
				status++
			} else {
				push(mbBad)
				status, cache = 0, 0
				goto retry
			}
		case 0x30:
			c1 := cache & 0x7
			if c >= 0x80 && c <= 0xbf && ((c1 == 0 && c >= 0x90) || (c1 == 4 && c < 0x90) || (c1 > 0 && c1 != 4)) {
				cache = cache<<6 | c&0x3f
				status++
			} else {
				push(mbBad)
				status, cache = 0, 0
				goto retry
			}
		case 0x31:
			if c >= 0x80 && c <= 0xbf {
				cache = cache<<6 | c&0x3f
				status++
			} else {
				push(mbBad)
				status, cache = 0, 0
				goto retry
			}
		}
	}
	if status != 0 {
		push(mbBad)
	}
	return out
}

var (
	mbRareOnce sync.Once
	mbRare     []uint32
)

func mbRareBits() []uint32 {
	mbRareOnce.Do(func() {
		mbRare = make([]uint32, len(mbRareBitvecHex)/8)
		for i := range mbRare {
			v, _ := strconv.ParseUint(mbRareBitvecHex[i*8:i*8+8], 16, 32)
			mbRare[i] = uint32(v)
		}
	})
	return mbRare
}

// estimate_demerits(): what one decoded code point costs a candidate encoding.
func mbDemerits(w int32) uint64 {
	switch {
	case w > 0xFFFF:
		return 40
	case w >= 0x21 && w <= 0x2F:
		return 6
	case mbRareBits()[w>>5]>>(w&0x1f)&1 == 1:
		return 30
	}
	return 1
}

func mbValidUTF8(w []int32) bool {
	for _, c := range w {
		if c == mbBad {
			return false
		}
	}
	return true
}

// mbDetect: the candidate with the fewest demerits wins, earlier ones weighted 1.0, 1.1, 1.2 (a float, as in C).
func mbDetect(s string) string {
	names := [3]string{"UTF-8", "ASCII", "ISO-8859-1"}
	var demerits [3]uint64

	u8 := utf8Wchar(s)
	if !mbValidUTF8(u8) {
		demerits[0] += 500
	}
	if strings.HasPrefix(s, "\xEF\xBB\xBF") { // the UTF-8 candidate decodes past a BOM
		u8 = utf8Wchar(s[3:])
	}
	for _, w := range u8 {
		if w == mbBad {
			demerits[0] += 1000
		} else {
			demerits[0] += mbDemerits(w)
		}
	}
	high := false
	for i := range len(s) {
		demerits[2] += mbDemerits(int32(s[i]))
		if s[i] >= 0x80 {
			high = true
			demerits[1] += 1000
		} else {
			demerits[1] += mbDemerits(int32(s[i]))
		}
	}
	if high { // the ASCII candidate's validity check failed
		demerits[1] += 500
	}
	var final [3]uint64
	for i := range final {
		m := float32(1.0 + (0.3*float64(i))/3.0)
		final[i] = uint64(float64(demerits[i]) * float64(m))
	}
	best := 0
	for i := 1; i < 3; i++ {
		if final[i] < final[best] {
			best = i
		}
	}
	return names[best]
}

// mbConvertToUTF8 is mb_convert_encoding($s, 'UTF-8', mb_detect_encoding($s, 'UTF-8, ASCII, ISO-8859-1')): an
// ill-formed UTF-8 or non-ASCII byte becomes '?'.
func mbConvertToUTF8(s string) string {
	var b strings.Builder
	switch mbDetect(s) {
	case "ISO-8859-1":
		for i := range len(s) {
			b.WriteRune(rune(s[i]))
		}
	case "ASCII":
		for i := range len(s) {
			if s[i] >= 0x80 {
				b.WriteByte('?')
			} else {
				b.WriteByte(s[i])
			}
		}
	default:
		for _, w := range utf8Wchar(s) {
			if w == mbBad {
				b.WriteByte('?')
			} else {
				b.WriteRune(rune(w))
			}
		}
	}
	return b.String()
}
