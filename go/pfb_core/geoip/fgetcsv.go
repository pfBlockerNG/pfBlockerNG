package geoip

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// fgetcsv reads a CSV as PHP's fgetcsv($handle, null, ",", "\"", "\\") does (php_fgetcsv() in ext/standard/file.c, in
// the C.UTF-8 locale PHP starts in), quirks included: white space before an opening quote is skipped,
// text after a closing quote joins the field, a backslash keeps the next character from closing it, a quoted field
// runs on over line breaks (kept as read), and an unterminated one takes the rest of the file. A blank line is an
// empty record (PHP's [null]).
type fgetcsv struct {
	r   *bufio.Reader
	err error
}

func newCSVReader(r io.Reader) *fgetcsv { return &fgetcsv{r: bufio.NewReader(r)} }

// line is php_stream_get_line(): up to and including the next "\n", or the rest of the file.
func (c *fgetcsv) line() (string, bool) {
	s, err := c.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		c.err = err
		return "", false
	}
	return s, s != ""
}

// lineEnd is php_fgetcsv_lookup_trailing_spaces() in C.UTF-8: walking the characters, a byte that is not valid UTF-8 is
// passed over (mbrlen() answers -1 or -2), and when the last two characters read are "\r\n", or the last is "\n" or
// "\r", that many bytes come off the end, whatever bytes they are.
// The other places php_fgetcsv() asks mbrlen() read the same byte by byte: a quote, a backslash, a comma and a line
// break are never inside a multibyte character.
// UTF-8 is RFC 3629's, as FreeBSD's libc reads it; glibc also takes a sequence past U+10FFFF for a character.
// shortcut: isSpace() is the ASCII set; FreeBSD's C.UTF-8 may also call 0x85 or 0xA0 a space before an opening quote.
// Upgrade if a lab probe shows either differs on the appliance.
func lineEnd(s string) int {
	n := len(s)
	switch { // "\r" and "\n" are never inside a multibyte character, so most lines need no walk
	case strings.HasSuffix(s, "\r\n"):
		return n - 2
	case n >= 2 && s[n-1] == '\n' && s[n-2] < 0x80:
		return n - 1
	}
	var before, last byte
	for i := 0; i < n; {
		r, w := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && w <= 1 {
			i++
			continue
		}
		before, last = last, s[i]
		i += w
	}
	switch {
	case last == '\n' && before == '\r':
		return n - 2
	case last == '\n' || last == '\r':
		return n - 1
	}
	return n
}

// at is a C string's byte: its terminating NUL past the end.
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func appendRange(b []byte, s string, from, to int) []byte {
	for i := from; i < to; i++ {
		b = append(b, at(s, i))
	}
	return b
}

func isSpace(c byte) bool { return c == ' ' || c >= '\t' && c <= '\r' }

// Read is the next record; io.EOF at the end, or where fgetcsv() answers false.
func (c *fgetcsv) Read() ([]string, error) {
	buf, ok := c.line()
	if !ok {
		if c.err != nil {
			return nil, c.err
		}
		return nil, io.EOF
	}
	limit := lineEnd(buf)
	step := func(p int) int {
		if p < limit {
			return 1
		}
		return 0
	}
	rec := []string{}
	bptr := 0
	for first := true; ; first = false {
		inc := step(bptr)
		if inc == 1 {
			tmp := bptr
			for at(buf, tmp) != ',' && isSpace(at(buf, tmp)) {
				tmp++
			}
			if at(buf, tmp) == '"' && tmp < limit {
				bptr = tmp
			}
		}
		if first && bptr == limit {
			return rec, nil
		}
		var field []byte
		if inc != 0 && buf[bptr] == '"' {
			state := 0
			bptr++
			hunk := bptr
			inc = step(bptr)
		enclosed:
			for {
				if inc == 0 {
					switch state {
					case 2:
						field = appendRange(field, buf, hunk, bptr-1)
						hunk = bptr
						break enclosed
					case 1:
						field = appendRange(field, buf, hunk, bptr)
						hunk = bptr
					}
					if hunk != limit {
						field = appendRange(field, buf, hunk, bptr)
						hunk = bptr
					}
					field = append(field, buf[limit:]...) // the line break inside the field
					next, ok := c.line()
					if !ok {
						if c.err != nil {
							return nil, c.err
						}
						break enclosed // unterminated: the field runs to the end of the file
					}
					buf, bptr, hunk, state = next, 0, 0, 0
					limit = lineEnd(buf)
				} else {
					switch state {
					case 1: // escaped
						bptr++
						state = 0
					case 2: // a quote: doubled, or the closing one
						if at(buf, bptr) != '"' {
							field = appendRange(field, buf, hunk, bptr-1)
							hunk = bptr
							break enclosed
						}
						field = appendRange(field, buf, hunk, bptr)
						bptr++
						hunk = bptr
						state = 0
					default:
						switch at(buf, bptr) {
						case '"':
							state = 2
						case '\\':
							state = 1
						}
						bptr++
					}
				}
				inc = step(bptr)
			}
			for inc != 0 && at(buf, bptr) != ',' {
				bptr += inc
				inc = step(bptr)
			}
			field = appendRange(field, buf, hunk, bptr)
			bptr += inc
		} else {
			hunk := bptr
			for inc != 0 && buf[bptr] != ',' {
				bptr += inc
				inc = step(bptr)
			}
			raw := buf[hunk:bptr]
			field = []byte(raw[:lineEnd(raw)])
			if at(buf, bptr) == ',' {
				bptr++
			}
		}
		rec = append(rec, string(field))
		if inc <= 0 {
			return rec, nil
		}
	}
}
