package feedparse

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"os"
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

type normalizeInput struct {
	r         *bufio.Reader
	order     binary.ByteOrder
	utf16     bool
	pending   uint16
	hasPending bool
	done      bool
}

func newNormalizeInput(src io.Reader) *normalizeInput {
	in := &normalizeInput{r: bufio.NewReaderSize(src, 64<<10), order: binary.LittleEndian}
	if bom, _ := in.r.Peek(2); len(bom) == 2 {
		switch {
		case bom[0] == 0xFF && bom[1] == 0xFE:
			in.utf16 = true
		case bom[0] == 0xFE && bom[1] == 0xFF:
			in.utf16, in.order = true, binary.BigEndian
		}
		if in.utf16 {
			_, _ = in.r.Discard(2)
		}
	}
	return in
}

func (in *normalizeInput) next() (rune, [utf8.UTFMax]byte, int, error) {
	var raw [utf8.UTFMax]byte
	if in.utf16 {
		r, err := in.nextUTF16()
		if err != nil {
			return 0, raw, 0, err
		}
		return r, raw, utf8.EncodeRune(raw[:], r), nil
	}
	part, err := in.r.Peek(utf8.UTFMax)
	if len(part) == 0 {
		return 0, raw, 0, err
	}
	r, size := utf8.DecodeRune(part)
	copy(raw[:], part[:size])
	if _, err := in.r.Discard(size); err != nil {
		return 0, raw, 0, err
	}
	return r, raw, size, nil
}

func (in *normalizeInput) nextUTF16() (rune, error) {
	if in.done {
		return 0, io.EOF
	}
	u, odd, err := in.nextUTF16Unit()
	if err != nil {
		return 0, err
	}
	if odd {
		in.done = true
		return utf8.RuneError, nil
	}
	r := rune(u)
	switch {
	case u&0xFC00 == 0xD800:
		low, odd, err := in.nextUTF16Unit()
		if err == io.EOF || odd {
			in.done = true
			return utf8.RuneError, nil
		}
		if err != nil {
			return 0, err
		}
		if decoded := utf16.DecodeRune(r, rune(low)); decoded != utf8.RuneError {
			r = decoded
		} else {
			in.pending, in.hasPending, r = low, true, utf8.RuneError
		}
	case u&0xFC00 == 0xDC00:
		r = utf8.RuneError
	}
	return r, nil
}

func (in *normalizeInput) nextUTF16Unit() (uint16, bool, error) {
	if in.hasPending {
		in.hasPending = false
		return in.pending, false, nil
	}
	hi, err := in.r.ReadByte()
	if err != nil {
		return 0, false, err
	}
	lo, err := in.r.ReadByte()
	if err == io.EOF {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	pair := [2]byte{hi, lo}
	return in.order.Uint16(pair[:]), false, nil
}

// normalizeStream mirrors Normalize without holding either the source or result in memory.
func normalizeStream(src io.Reader, out *os.File) error {
	in := newNormalizeInput(src)
	w := bufio.NewWriterSize(out, 64<<10)
	var output [64 << 10]byte
	outputLen := 0
	written, tail := int64(0), int64(0)
	flushOutput := func() error {
		if outputLen == 0 {
			return nil
		}
		n, err := w.Write(output[:outputLen])
		if err == nil && n != outputLen {
			err = io.ErrShortWrite
		}
		outputLen = 0
		return err
	}
	write := func(p []byte) error {
		for len(p) > 0 {
			if outputLen == len(output) {
				if err := flushOutput(); err != nil {
					return err
				}
			}
			n := copy(output[outputLen:], p)
			outputLen += n
			written += int64(n)
			p = p[n:]
		}
		return nil
	}
	trimTail := func() error {
		if tail == 0 {
			return nil
		}
		if err := flushOutput(); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
		written -= tail
		if err := out.Truncate(written); err != nil {
			return err
		}
		if _, err := out.Seek(0, io.SeekEnd); err != nil {
			return err
		}
		w.Reset(out)
		tail = 0
		return nil
	}
	for {
		r, raw, size, err := in.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if r == '\n' {
			if err := trimTail(); err != nil {
				return err
			}
			if err := write([]byte{'\n'}); err != nil {
				return err
			}
			continue
		}
		if unicode.IsSpace(r) && r != 0x85 {
			if kept(r) {
				if err := write(raw[:size]); err != nil {
					return err
				}
				tail += int64(size)
			}
			continue
		}
		tail = 0
		if kept(r) {
			if err := write(raw[:size]); err != nil {
				return err
			}
		}
	}
	if err := trimTail(); err != nil {
		return err
	}
	if err := flushOutput(); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if written > 0 {
		var last [1]byte
		if _, err := out.ReadAt(last[:], written-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			if err := write([]byte{'\n'}); err != nil {
				return err
			}
			if err := flushOutput(); err != nil {
				return err
			}
		}
	}
	return w.Flush()
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
