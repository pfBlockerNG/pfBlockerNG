package ipset

import (
	"net/netip"
	"strings"
)

// atonPart reads one dotted part as inet_aton does: 0x hex, a leading 0 octal, else decimal.
func atonPart(p string) (uint64, bool) {
	base, digits := uint64(10), p
	switch {
	case len(p) > 1 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base, digits = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, digits = 8, p[1:]
	}
	if digits == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		if v = v*base + d; v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return v, true
}

// atonV4 is inet_aton: one to four parts, the last filling the remaining bytes.
func atonV4(s string) (uint32, bool) {
	var parts [4]uint64
	n := 0
	for {
		j := 0
		for j < len(s) && s[j] != '.' {
			j++
		}
		v, ok := atonPart(s[:j])
		if !ok || n == 4 {
			return 0, false
		}
		parts[n] = v
		n++
		if j == len(s) {
			break
		}
		if s = s[j+1:]; s == "" {
			return 0, false
		}
	}
	var ip uint64
	for i := 0; i < n-1; i++ {
		if parts[i] > 255 {
			return 0, false
		}
		ip = ip<<8 | parts[i]
	}
	room := uint(8 * (5 - n))
	if parts[n-1] >= 1<<room {
		return 0, false
	}
	return uint32(ip<<room | parts[n-1]), true
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f' }

func skipSpace(s string, i int) int {
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return i
}

// wordEnd ends the word that starts at i: letters, digits, "." and "_", and "-" when dash is set.
func wordEnd(s string, i int, dash bool) int {
	for ; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || dash && c == '-') {
			break
		}
	}
	return i
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// maskBits reads a netmask as a prefix length; ok is false for a mask that is not leading ones then zeros.
func maskBits(v uint32) (int, bool) {
	if inv := ^v; inv&(inv+1) != 0 {
		return 0, false
	}
	n := 0
	for ; n < 32 && v&(1<<(31-n)) != 0; n++ {
	}
	return n, true
}

// parseRangeLine reads one line the way iprange does: a host, "a-b", "ip/bits" or "ip/netmask", the address read as
// inet_aton (so a leading-zero octet is octal) and any text after it ignored. A word with a letter in it is a name: it counts
// only when inet_aton reads it (as 0x1f.1.1.1), as a host, and a name that does not drops the line.
func parseRangeLine(s string) (lo, hi uint32, ok bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i == len(s) || s[i] == '#' {
		return 0, 0, false
	}
	if e := wordEnd(s, i, true); hasLetter(s[i:e]) {
		ip, ok := atonV4(s[i:e])
		return ip, ip, ok
	}
	j := wordEnd(s, i, false)
	ip, ok := atonV4(s[i:j])
	if !ok {
		return 0, 0, false
	}
	lo, hi = ip, ip
	k := skipSpace(s, j)
	if k >= len(s) {
		return lo, hi, true
	}
	switch s[k] {
	case '-':
		k = skipSpace(s, k+1)
		e := wordEnd(s, k, true)
		if e == k {
			return lo, hi, true
		}
		ip2, ok := atonV4(s[k:e])
		switch {
		case !ok:
			return 0, 0, false
		case hasLetter(s[k:e]):
			return lo, hi, true
		}
		return min(ip, ip2), max(ip, ip2), true
	case '/':
		if k != j {
			return lo, hi, true
		}
		if skipSpace(s, k+1) == len(s) {
			return 0, 0, false
		}
		e := wordEnd(s, k+1, false)
		tok := s[k+1 : e]
		if tok == "" || hasLetter(tok) {
			return lo, hi, true
		}
		// A plain number up to 32 is a prefix length, a larger one or a dotted quad is a netmask.
		var m uint64
		if strings.Contains(tok, ".") {
			v, ok := atonV4(tok)
			if !ok {
				return 0, 0, false
			}
			m = uint64(v)
		} else if m, ok = atonPart10(tok); !ok {
			return 0, 0, false
		}
		bits := int(m)
		if m > 32 || strings.Contains(tok, ".") {
			if bits, ok = maskBits(uint32(m)); !ok {
				return 0, 0, false
			}
		}
		var mask uint32
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		return ip & mask, ip&mask | ^mask, true
	}
	return lo, hi, true
}

// atonPart10 reads a mask given as plain decimal digits.
func atonPart10(s string) (uint64, bool) {
	var v uint64
	for i := 0; i < len(s); i++ {
		if v = v*10 + uint64(s[i]-'0'); v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return v, true
}

func addrOf(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// CIDRAggregate is the cidr_aggregate verb: the exact CIDR union of the rows of members, as iprange writes it (numerically
// sorted, a host without "/32", contained and adjacent rows merged). iprange's reading of the bad tokens the corpus holds is
// reproduced, not rejected; a mask of mixed digits and other characters is not followed.
func CIDRAggregate(members string) []string {
	var s addrSet
	eachLine(members, func(line string) {
		if lo, hi, ok := parseRangeLine(line); ok {
			s.add(addrOf(lo), addrOf(hi))
		}
	})
	return v4Rows(s.prefixes())
}
