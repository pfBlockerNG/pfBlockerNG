package feedfetch

// ADR-49's opt-in plain-text sanity scan (pfb_text_sanity) and the UTF-16/32 transcode of the published copy
// (pfb_utf16_transcode_file): the content rules of pfb_download() that read text.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"unicode"
	"unicode/utf16"
)

// sanityBytes is how much of a body the scan reads: a cap, not a minimum.
const sanityBytes = 64 << 10

// phpSpace is what PHP's trim() strips.
const phpSpace = " \t\n\r\x00\x0b"

var (
	// ipv4Shaped matches anywhere in a line: real feeds serve their addresses inside HTML markup.
	ipv4Shaped = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	// ipv6Run is the IPv6 shape a whole run of [A-Za-z0-9:] must take: PHP bounds it by look-arounds of that class, so a
	// match is always such a run (a CSS "h1::before" or a "403 :: Forbidden" is none).
	ipv6Run = regexp.MustCompile(`^(?:(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}` +
		`|[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?` +
		`|::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)$`)
	// domainLine is a line that is one domain token (bare, ABP "||", wildcard "*.", FQDN dot, ABP "^").
	domainLine = regexp.MustCompile(`^(?:\|\|)?(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?` +
		`(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\.?\^?$`)
)

// textSanity is pfb_text_sanity(): the reason a body's head is no list ("nul_bytes", then "html_error_page", then
// "below_min_content"), or "" when it may be one. UTF-16/32 behind its mark is read as the text it holds.
func textSanity(sample []byte) string {
	sample = bytes.TrimPrefix(toUTF8(sample), []byte("\xef\xbb\xbf"))
	if bytes.IndexByte(sample, 0) >= 0 {
		return "nul_bytes"
	}
	lines := splitLines(sample)
	if htmlTag(bytes.TrimLeft(sample, phpSpace)) && !slices.ContainsFunc(lines, blocklistShaped) {
		return "html_error_page"
	}
	for _, l := range lines {
		if l = bytes.TrimLeft(l, phpSpace); len(l) > 0 && l[0] != '#' && l[0] != '!' {
			return ""
		}
	}
	return "below_min_content"
}

// splitLines is preg_split('/\r\n|\r|\n/').
func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\r':
			if i+1 < len(b) && b[i+1] == '\n' {
				out = append(out, b[start:i])
				i++
				start = i + 1
				continue
			}
			fallthrough
		case '\n':
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return append(out, b[start:])
}

// blocklistShaped tells a line that carries an address or is one domain: an HTML page holding one is a feed.
func blocklistShaped(line []byte) bool {
	line = bytes.Trim(line, phpSpace)
	if len(line) == 0 {
		return false
	}
	if ipv4Shaped.Match(line) || domainLine.Match(line) {
		return true
	}
	run := func(c byte) bool { return c == ':' || c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'z' }
	for i := 0; i < len(line); {
		j := i
		for j < len(line) && run(line[j]) {
			j++
		}
		if j > i && ipv6Run.Match(line[i:j]) {
			return true
		}
		i = j + 1
	}
	return false
}

// sane is the scan of the head of the file at path: its verdict, or "" when it looks like a list or cannot be read
// (fail-open, as PHP: a read error is no empty feed).
func sane(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, sanityBytes)
	n, err := io.ReadFull(f, b)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}
	return textSanity(b[:n])
}

// encoding is a byte order mark and the code units it announces.
type encoding struct {
	mark  string
	width int // bytes per code unit
	order binary.ByteOrder
}

// boms are the marks of UTF-16 and UTF-32 text in the order pfb_utf16_bom_encoding() tests them: FF FE 00 00 is a
// UTF-32LE mark before it is a UTF-16LE mark and a NUL.
var boms = []encoding{
	{"\xff\xfe\x00\x00", 4, binary.LittleEndian}, {"\x00\x00\xfe\xff", 4, binary.BigEndian},
	{"\xff\xfe", 2, binary.LittleEndian}, {"\xfe\xff", 2, binary.BigEndian},
}

func bomOf(b []byte) (encoding, bool) {
	for _, e := range boms {
		if bytes.HasPrefix(b, []byte(e.mark)) {
			return e, true
		}
	}
	return encoding{}, false
}

// toUTF8 is pfb_utf16_sample_to_utf8(): UTF-16/32 text behind its mark as UTF-8 without it; any other text as it is.
func toUTF8(b []byte) []byte {
	e, ok := bomOf(b)
	if !ok {
		return b
	}
	var buf bytes.Buffer
	decodeUnits(&buf, bytes.NewReader(b[len(e.mark):]), e) // a bytes.Buffer takes every write
	return buf.Bytes()
}

// decodeUnits writes the UTF-16 or UTF-32 text of r to w as UTF-8, the way mb_convert_encoding() does: a code unit
// that is no character (a lone surrogate, a value past U+10FFFF) and a code unit cut short at the end become '?'.
func decodeUnits(w io.Writer, r io.Reader, e encoding) error {
	br, bw := bufio.NewReader(r), bufio.NewWriter(w)
	unit := make([]byte, e.width)
	high := rune(-1) // a high surrogate waiting for its low one
	for {
		_, err := io.ReadFull(br, unit)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return err
		}
		if err == io.ErrUnexpectedEOF {
			if high >= 0 {
				bw.WriteByte('?')
				high = -1
			}
			bw.WriteByte('?')
			break
		}
		var c uint32
		if e.width == 2 {
			c = uint32(e.order.Uint16(unit))
		} else {
			c = e.order.Uint32(unit)
		}
		if e.width == 2 && c >= 0xdc00 && c < 0xe000 && high >= 0 {
			bw.WriteRune(utf16.DecodeRune(high, rune(c)))
			high = -1
			continue
		}
		if high >= 0 {
			bw.WriteByte('?')
			high = -1
		}
		switch {
		case e.width == 2 && c >= 0xd800 && c < 0xdc00:
			high = rune(c)
		case c > unicode.MaxRune || c >= 0xd800 && c < 0xe000:
			bw.WriteByte('?')
		default:
			bw.WriteRune(rune(c))
		}
	}
	if high >= 0 {
		bw.WriteByte('?')
	}
	return bw.Flush()
}

// transcode rewrites the UTF-16 or UTF-32 body at path as UTF-8 without its mark, in place and keeping its mode
// (pfb_utf16_transcode_file); any other body is left as it is, and so is one that fails to be rewritten (fail-open).
func transcode(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	e, ok := bomOf(head[:n])
	info, err := f.Stat()
	if !ok || err != nil {
		return
	}
	if _, err := f.Seek(int64(len(e.mark)), io.SeekStart); err != nil {
		return
	}
	out, err := os.CreateTemp(filepath.Dir(path), ".pfbstage_")
	if err != nil {
		return
	}
	err = decodeUnits(out, f, e)
	if cerr := out.Chmod(info.Mode().Perm()); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(out.Name(), path)
	}
	if err != nil {
		os.Remove(out.Name())
	}
}
