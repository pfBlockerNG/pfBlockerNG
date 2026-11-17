package ipset

import (
	"net/netip"
	"strconv"
	"strings"
)

// eachLine calls f with every line of text: split at "\n", a final unterminated line counted, "\r" kept.
func eachLine(text string, f func(line string)) {
	for len(text) > 0 {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			f(text)
			return
		}
		f(text[:i])
		text = text[i+1:]
	}
}

// textRows is the lines of a file's text.
func textRows(text string) []string {
	rows := make([]string, 0, strings.Count(text, "\n")+1)
	eachLine(text, func(l string) { rows = append(rows, l) })
	return rows
}

func appendV4(b []byte, a netip.Addr) []byte {
	x := a.As4()
	for i, v := range x {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	return b
}

// v4Rows spells prefixes as iprange does: a host without "/32".
func v4Rows(prefixes []netip.Prefix) []string {
	rows := make([]string, len(prefixes))
	var buf []byte
	for i, p := range prefixes {
		buf = appendV4(buf[:0], p.Addr())
		if p.Bits() < 32 {
			buf = append(buf, '/')
			buf = strconv.AppendUint(buf, uint64(p.Bits()), 10)
		}
		rows[i] = string(buf)
	}
	return rows
}

// appendV6 writes inet_ntop(AF_INET6): lower case, the first longest run of two or more zero groups compressed, a dotted IPv4
// tail for the IPv4-mapped and IPv4-compatible ranges.
func appendV6(b []byte, a netip.Addr) []byte {
	x := a.As16()
	var w [8]uint16
	for i := range w {
		w[i] = uint16(x[2*i])<<8 | uint16(x[2*i+1])
	}
	best, cur := [2]int{-1, 0}, [2]int{-1, 0}
	for i := 0; i < 8; i++ {
		if w[i] == 0 {
			if cur[0] == -1 {
				cur = [2]int{i, 1}
			} else {
				cur[1]++
			}
		} else if cur[0] != -1 {
			if best[0] == -1 || cur[1] > best[1] {
				best = cur
			}
			cur[0] = -1
		}
	}
	if cur[0] != -1 && (best[0] == -1 || cur[1] > best[1]) {
		best = cur
	}
	if best[0] != -1 && best[1] < 2 {
		best[0] = -1
	}
	for i := 0; i < 8; i++ {
		if best[0] != -1 && i >= best[0] && i < best[0]+best[1] {
			if i == best[0] {
				b = append(b, ':')
			}
			continue
		}
		if i != 0 {
			b = append(b, ':')
		}
		if i == 6 && best[0] == 0 && (best[1] == 6 || (best[1] == 7 && w[7] != 1) || (best[1] == 5 && w[5] == 0xffff)) {
			return appendV4(b, netip.AddrFrom4([4]byte(x[12:16])))
		}
		b = strconv.AppendUint(b, uint64(w[i]), 16)
	}
	if best[0] != -1 && best[0]+best[1] == 8 {
		b = append(b, ':')
	}
	return b
}
