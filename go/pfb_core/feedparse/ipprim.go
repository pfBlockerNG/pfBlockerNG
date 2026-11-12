package feedparse

import (
	"math"
	"slices"
	"strconv"
	"strings"
)

// Ports of the PHP IP primitives (pfblockerng.inc and the pfSense helpers vendored in tests/php/pfsense_doubles.php),
// bug for bug: libc inet_pton/inet_ntop, PHP's filter_var(FILTER_VALIDATE_IP) and PHP's loose comparisons.

const phpTrimSet = " \t\n\r\x00\x0b"

func phpTrim(s string) string { return strings.Trim(s, phpTrimSet) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWordByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

// ctype_digit() on a string: non-empty, every byte 0-9.
func ctypeDigit(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// (int) of a digits-only string; saturates like PHP.
func digitsInt(s string) int64 {
	s = strings.TrimLeft(s, "0")
	if len(s) > 18 {
		return math.MaxInt64
	}
	var n int64
	for i := 0; i < len(s); i++ {
		n = n*10 + int64(s[i]-'0')
	}
	return n
}

// PHP's empty() on a string.
func phpEmpty(s string) bool { return s == "" || s == "0" }

// PHP 8 numeric-string grammar (leading and trailing whitespace allowed): the value and whether s is wholly numeric.
func phpNumeric(s string) (float64, bool) {
	i, n := 0, len(s)
	isWS := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' }
	for i < n && isWS(s[i]) {
		i++
	}
	start := i
	if i < n && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := 0
	for i < n && isDigit(s[i]) {
		i++
		digits++
	}
	if i < n && s[i] == '.' {
		i++
		for i < n && isDigit(s[i]) {
			i++
			digits++
		}
	}
	if digits == 0 {
		return 0, false
	}
	if i < n && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < n && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if j < n && isDigit(s[j]) {
			for j < n && isDigit(s[j]) {
				j++
			}
			i = j
		}
	}
	end := i
	for i < n && isWS(s[i]) {
		i++
	}
	if i != n {
		return 0, false
	}
	f, _ := strconv.ParseFloat(strings.TrimSuffix(s[start:end], "."), 64)
	return f, true
}

// $s == $n for an int $n: numeric strings compare by value, any other string against the int's text.
func looseEqInt(s string, n int) bool {
	if f, ok := phpNumeric(s); ok {
		return f == float64(n)
	}
	return s == strconv.Itoa(n)
}

// (int) $s for a string: the numeric prefix; a float prefix truncates, an out-of-range one is 0.
func phpIntval(s string) int64 {
	t := strings.TrimLeft(s, " \t\n\r\v\f")
	i := 0
	if i < len(t) && (t[i] == '+' || t[i] == '-') {
		i++
	}
	d := i
	for d < len(t) && isDigit(t[d]) {
		d++
	}
	if d == i && !(d < len(t) && t[d] == '.' && d+1 < len(t) && isDigit(t[d+1])) {
		return 0
	}
	if d == len(t) || (t[d] != '.' && t[d] != 'e' && t[d] != 'E') {
		n := digitsInt(t[i:d])
		if t[0] == '-' {
			return -n
		}
		return n
	}
	j := d
	if j < len(t) && t[j] == '.' {
		j++
		for j < len(t) && isDigit(t[j]) {
			j++
		}
	}
	if j < len(t) && (t[j] == 'e' || t[j] == 'E') {
		k := j + 1
		if k < len(t) && (t[k] == '+' || t[k] == '-') {
			k++
		}
		if k < len(t) && isDigit(t[k]) {
			for k < len(t) && isDigit(t[k]) {
				k++
			}
			j = k
		}
	}
	f, _ := strconv.ParseFloat(strings.TrimSuffix(t[:j], "."), 64)
	if f >= -9.2233720368547758e18 && f < 9.2233720368547758e18 {
		return int64(f)
	}
	return 0
}

// $a < $b for two strings: numeric strings by value, otherwise bytewise.
func phpStringLess(a, b string) bool {
	fa, oka := phpNumeric(a)
	fb, okb := phpNumeric(b)
	if oka && okb {
		return fa < fb
	}
	return strings.Compare(a, b) < 0
}

// --- libc ---

// glibc/FreeBSD inet_pton4: exactly four decimal octets, no leading zeros.
func inetPton4(s string) (b [4]byte, ok bool) {
	sawDigit, octets, idx := false, 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isDigit(c):
			n := uint(b[idx])*10 + uint(c-'0')
			if sawDigit && b[idx] == 0 {
				return b, false
			}
			if n > 255 {
				return b, false
			}
			b[idx] = byte(n)
			if !sawDigit {
				octets++
				if octets > 4 {
					return b, false
				}
				sawDigit = true
			}
		case c == '.' && sawDigit:
			if octets == 4 {
				return b, false
			}
			idx++
			sawDigit = false
		default:
			return b, false
		}
	}
	return b, octets >= 4
}

func hexValue(c byte) int {
	switch {
	case isDigit(c):
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// glibc inet_pton6.
func inetPton6(s string) (out [16]byte, ok bool) {
	if s == "" {
		return out, false
	}
	var tmp [16]byte
	tp, colonp := 0, -1
	i := 0
	if s[0] == ':' {
		i++
		if i == len(s) || s[i] != ':' {
			return out, false
		}
	}
	curtok := i
	xdigits, val := 0, 0
	for i < len(s) {
		ch := s[i]
		i++
		if d := hexValue(ch); d >= 0 {
			if xdigits == 4 {
				return out, false
			}
			val = val<<4 | d
			xdigits++
			continue
		}
		if ch == ':' {
			curtok = i
			if xdigits == 0 {
				if colonp >= 0 {
					return out, false
				}
				colonp = tp
				continue
			} else if i == len(s) {
				return out, false
			}
			if tp+2 > 16 {
				return out, false
			}
			tmp[tp], tmp[tp+1] = byte(val>>8), byte(val)
			tp += 2
			xdigits, val = 0, 0
			continue
		}
		if ch == '.' && tp+4 <= 16 {
			if v4, ok4 := inetPton4(s[curtok:]); ok4 {
				copy(tmp[tp:], v4[:])
				tp += 4
				xdigits = 0
				i = len(s)
				break
			}
		}
		return out, false
	}
	if xdigits > 0 {
		if tp+2 > 16 {
			return out, false
		}
		tmp[tp], tmp[tp+1] = byte(val>>8), byte(val)
		tp += 2
	}
	if colonp >= 0 {
		if tp == 16 {
			return out, false
		}
		n := tp - colonp
		copy(tmp[16-n:], tmp[colonp:tp])
		for j := colonp; j < 16-n; j++ {
			tmp[j] = 0
		}
		tp = 16
	}
	return tmp, tp == 16
}

// PHP inet_pton(): ':' selects IPv6, else '.' IPv4, else failure; a NUL byte is a ValueError in PHP (never reached
// by the callers, which guard it), failure here.
func phpInetPton(s string) ([]byte, bool) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, false
	}
	if strings.IndexByte(s, ':') >= 0 {
		b, ok := inetPton6(s)
		if !ok {
			return nil, false
		}
		return b[:], true
	}
	if strings.IndexByte(s, '.') < 0 {
		return nil, false
	}
	b, ok := inetPton4(s)
	if !ok {
		return nil, false
	}
	return b[:], true
}

func inetNtop4(b []byte) string {
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}

// PHP inet_ntop() on glibc/FreeBSD: longest zero run (first on ties, at least two words) compressed, `::a.b.c.d` for
// `::/96` and `::ffff:0:0/96` tails.
func phpInetNtop(b []byte) string {
	if len(b) == 4 {
		return inetNtop4(b)
	}
	var words [8]uint
	for i := 0; i < 16; i++ {
		words[i>>1] |= uint(b[i]) << ((1 - (i & 1)) << 3)
	}
	bestBase, bestLen, curBase, curLen := -1, 0, -1, 0
	for i := 0; i < 8; i++ {
		if words[i] == 0 {
			if curBase == -1 {
				curBase, curLen = i, 1
			} else {
				curLen++
			}
		} else if curBase != -1 {
			if bestBase == -1 || curLen > bestLen {
				bestBase, bestLen = curBase, curLen
			}
			curBase = -1
		}
	}
	if curBase != -1 && (bestBase == -1 || curLen > bestLen) {
		bestBase, bestLen = curBase, curLen
	}
	if bestBase != -1 && bestLen < 2 {
		bestBase = -1
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if bestBase != -1 && i >= bestBase && i < bestBase+bestLen {
			if i == bestBase {
				sb.WriteByte(':')
			}
			continue
		}
		if i != 0 {
			sb.WriteByte(':')
		}
		if i == 6 && bestBase == 0 && (bestLen == 6 || (bestLen == 5 && words[5] == 0xffff)) {
			sb.WriteString(inetNtop4(b[12:]))
			break
		}
		sb.WriteString(strconv.FormatUint(uint64(words[i]), 16))
	}
	if bestBase != -1 && bestBase+bestLen == 8 {
		sb.WriteByte(':')
	}
	return sb.String()
}

// ip2long(): inet_pton4; a NUL byte is a ValueError in PHP (no parse path reaches it), failure here.
func ip2long(s string) (uint32, bool) {
	if strings.IndexByte(s, 0) >= 0 {
		return 0, false
	}
	b, ok := inetPton4(s)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), ok
}

// --- filter_var(FILTER_VALIDATE_IP), PHP 8.3-8.5 ---

func phpFilterIPv4(s string) (ip [4]int, ok bool) {
	p, n := 0, 0
	for p < len(s) {
		if !isDigit(s[p]) {
			return ip, false
		}
		leadingZero := s[p] == '0'
		m := 1
		num := int(s[p] - '0')
		p++
		for p < len(s) && isDigit(s[p]) {
			num = num*10 + int(s[p]-'0')
			p++
			m++
			if num > 255 || m > 3 {
				return ip, false
			}
		}
		if leadingZero && (num != 0 || m > 1) {
			return ip, false
		}
		ip[n] = num
		n++
		if n == 4 {
			return ip, p == len(s)
		}
		if p >= len(s) || s[p] != '.' {
			return ip, false
		}
		p++
	}
	return ip, false
}

// Port of _php_filter_validate_ipv6 including its fix-up of the 8-word array (an embedded IPv4 makes it ::ffff:a.b.c.d).
func phpFilterIPv6(str string) (ip [8]int, ok bool) {
	if strings.IndexByte(str, ':') < 0 {
		return ip, false
	}
	strLen := len(str)
	compressedPos, blocks := -1, 0
	var ip4 [4]int
	hasV4 := false
	if dot := strings.IndexByte(str, '.'); dot >= 0 {
		v4 := dot
		for v4 > 0 && str[v4-1] != ':' {
			v4--
		}
		var ok4 bool
		if ip4, ok4 = phpFilterIPv4(str[v4:]); !ok4 {
			return ip, false
		}
		hasV4 = true
		strLen = v4
		if strLen < 2 {
			return ip, false
		}
		if str[v4-2] != ':' {
			strLen--
		}
		blocks = 2
	}
	p, end := 0, strLen
	for p < end {
		if str[p] == ':' {
			p++
			if p >= end {
				return ip, false
			}
			if str[p] == ':' {
				if compressedPos >= 0 {
					return ip, false
				}
				if blocks < 8 {
					ip[blocks] = -1
				}
				compressedPos = blocks
				blocks++
				p++
				if p == end {
					if blocks > 8 {
						return ip, false
					}
					break
				}
			} else if p-1 == 0 {
				return ip, false
			}
		}
		num, n := 0, 0
		for p < end && isHexDigit(str[p]) {
			num = 16*num + hexValue(str[p])
			n++
			p++
		}
		if blocks < 8 {
			ip[blocks] = num
		}
		if n < 1 || n > 4 {
			return ip, false
		}
		blocks++
		if blocks > 8 {
			return ip, false
		}
	}
	if hasV4 {
		for i := 0; i < 5; i++ {
			ip[i] = 0
		}
		ip[5], ip[6], ip[7] = 0xffff, 256*ip4[0]+ip4[1], 256*ip4[2]+ip4[3]
	} else if compressedPos >= 0 && blocks <= 8 {
		offset := 8 - blocks
		for i := 7; i > compressedPos+offset; i-- {
			ip[i] = ip[i-offset]
		}
		for i := compressedPos + offset; i >= compressedPos; i-- {
			ip[i] = 0
		}
	}
	return ip, (compressedPos >= 0 && blocks <= 8) || blocks == 8
}

// filter_var($s, FILTER_VALIDATE_IP, flags): the family comes from the first ':' or '.'; the RFC 6890 tables only mark
// the reserved and private ranges the two flags test.
func phpFilterIP(s string, allow4, allow6, noPriv, noRes bool) bool {
	var reserved, private bool
	switch {
	case strings.IndexByte(s, ':') >= 0:
		if allow4 && !allow6 {
			return false
		}
		ip, ok := phpFilterIPv6(s)
		if !ok {
			return false
		}
		allZero := ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 && ip[6] == 0
		switch {
		case allZero && (ip[7] == 0 || ip[7] == 1):
			reserved = true
		case ip[0] == 0x64 && ip[1] == 0xff9b:
		case ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0xffff:
			reserved = true
		case ip[0] >= 0xfc00 && ip[0] <= 0xfdff:
			private = true
		case ip[0] >= 0xfe80 && ip[0] <= 0xfebf:
			reserved = true
		}
	case strings.IndexByte(s, '.') >= 0:
		if allow6 && !allow4 {
			return false
		}
		ip, ok := phpFilterIPv4(s)
		if !ok {
			return false
		}
		switch {
		case ip[0] == 0 || ip[0] == 127 || (ip[0] == 169 && ip[1] == 254) || ip[0] >= 240:
			reserved = true
		case ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168):
			private = true
		}
	default:
		return false
	}
	return !(noPriv && private) && !(noRes && reserved)
}

// --- pfSense util.inc doubles ---

// is_ipaddrv4(): ip2long() plus the appliance's leading-zero reject.
func isIPAddrV4(s string) bool {
	if phpEmpty(s) {
		return false
	}
	if _, ok := ip2long(s); !ok {
		return false
	}
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '0' && isDigit(s[i+1]) && (i == 0 || s[i-1] == '.') {
			return false
		}
	}
	return true
}

// is_linklocal(): 4 for a 169.254/16 IPv4, 6 for fe80::/10-shaped, else 0.
func isLinkLocal(s string) int {
	if isIPAddrV4(s) {
		if p := strings.Split(s, "."); p[0] == "169" && p[1] == "254" {
			return 4
		}
		return 0
	}
	if len(s) >= 5 && (s[0] == 'f' || s[0] == 'F') && (s[1] == 'e' || s[1] == 'E') &&
		strings.IndexByte("89abAB", s[2]) >= 0 && isHexDigit(s[3]) && s[4] == ':' {
		return 6
	}
	return 0
}

// is_ipaddrv6(): no mask, a link-local %zone stripped, one `::` at most, then filter_var(FILTER_FLAG_IPV6).
func isIPAddrV6(s string) bool {
	if phpEmpty(s) || strings.IndexByte(s, '/') >= 0 {
		return false
	}
	if i := strings.IndexByte(s, '%'); i >= 0 && isLinkLocal(s) != 0 {
		s = s[:i]
	}
	if strings.Count(s, "::") > 1 {
		return false
	}
	return phpFilterIP(s, false, true, false, false)
}

// preg_match('/^\d{1,3}$/', $bits) === 1 && (int) $bits <= max; `$` also matches before a final newline.
func subnetBitsOK(bits string, max int64) bool {
	bits = strings.TrimSuffix(bits, "\n")
	return len(bits) >= 1 && len(bits) <= 3 && ctypeDigit(bits) && digitsInt(bits) <= max
}

func isSubnetV4(s string) bool {
	ip, bits, ok := strings.Cut(s, "/")
	return ok && isIPAddrV4(ip) && subnetBitsOK(bits, 32)
}

func isSubnetV6(s string) bool {
	ip, bits, ok := strings.Cut(s, "/")
	return ok && isIPAddrV6(ip) && strings.IndexByte(ip, '%') < 0 && subnetBitsOK(bits, 128)
}

// validate_ipv4()/validate_ipv6(): NUL rejected, then address or subnet.
func validateIPv4(s string) bool {
	if strings.IndexByte(s, 0) >= 0 {
		return false
	}
	if strings.IndexByte(s, '/') >= 0 {
		return isSubnetV4(s)
	}
	return isIPAddrV4(s)
}

func validateIPv6(s string) bool {
	if strings.IndexByte(s, 0) >= 0 {
		return false
	}
	if strings.IndexByte(s, '/') >= 0 {
		return isSubnetV6(s)
	}
	return isIPAddrV6(s)
}

// ip_range_to_subnet_array(): the minimal CIDR cover of the range, vendored algorithm on bit strings.
func ipRangeToSubnets(ip1, ip2 string) []string {
	var bits int
	var b1, b2 string
	v4 := false
	switch {
	case isIPAddrV4(ip1) && isIPAddrV4(ip2):
		v4, bits = true, 32
		l1, _ := ip2long(ip1)
		l2, _ := ip2long(ip2)
		b1, b2 = strconv.FormatUint(uint64(l1), 2), strconv.FormatUint(uint64(l2), 2)
	case isIPAddrV6(ip1) && isIPAddrV6(ip2):
		bits = 128
		b1, b2 = ip6ToBin(ip1), ip6ToBin(ip2)
	default:
		return nil
	}
	pad := func(s string) string { return strings.Repeat("0", bits-len(s)) + s }
	b1, b2 = pad(b1), pad(b2)
	if b1 == b2 {
		return []string{ip1 + "/" + strconv.Itoa(bits)}
	}
	if b1 > b2 {
		b1, b2 = b2, b1
	}
	zeros := func(n int) string { return strings.Repeat("0", n) }
	rs := map[string]int{}
	netsize := 0
	for {
		if b1[bits-1] == '1' {
			rs[b1[netsize:]+zeros(netsize)] = bits - netsize
			n := max(strings.LastIndexByte(b1, '0'), 0)
			b1 = b1[:n] + "1" + zeros(bits-n-1)
		}
		if b2[bits-1] == '0' {
			rs[b2[netsize:]+zeros(netsize)] = bits - netsize
			n := max(strings.LastIndexByte(b2, '1'), 0)
			b2 = b2[:n] + "0" + strings.Repeat("1", bits-n-1)
		}
		if b2 >= b1 {
			shift := bits - max(strings.LastIndexByte(b1, '0'), strings.LastIndexByte(b2, '1'), 0)
			b1 = zeros(shift) + b1[:bits-shift]
			b2 = zeros(shift) + b2[:bits-shift]
			netsize += shift
			if b1 == b2 {
				rs[b1[netsize:]+zeros(netsize)] = bits - netsize
			}
		}
		if b1 >= b2 {
			break
		}
	}
	keys := make([]string, 0, len(rs))
	for k := range rs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		mask := strconv.Itoa(rs[k])
		if v4 {
			var o [4]string
			for i := range o {
				n, _ := strconv.ParseUint(k[i*8:i*8+8], 2, 8)
				o[i] = strconv.FormatUint(n, 10)
			}
			out = append(out, strings.Join(o[:], ".")+"/"+mask)
			continue
		}
		var raw [16]byte
		for i := range raw {
			n, _ := strconv.ParseUint(k[i*8:i*8+8], 2, 8)
			raw[i] = byte(n)
		}
		out = append(out, phpInetNtop(raw[:])+"/"+mask)
	}
	return out
}

// ip6_to_bin(): 128 bits of the address (any "/mask" dropped); an unparseable one reads as all zeros.
func ip6ToBin(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	b, ok := phpInetPton(s)
	if !ok {
		return ""
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteString(strconv.FormatUint(uint64(c)|0x100, 2)[1:])
	}
	return sb.String()
}

// --- pfblockerng.inc ---

// pfb_sanitize_ipaddr(): ok=false is PHP's NULL address.
func sanitizeIPv4(addr string, custom bool, floor string, supp bool) (address string, ok bool, messages []string) {
	parts := strings.SplitN(addr, "/", 3)
	subnet, mask := parts[0], ""
	if len(parts) == 2 {
		mask = parts[1]
	}
	if mask != "" && (!ctypeDigit(mask) || digitsInt(mask) > 32) {
		return "", false, messages
	}
	if mask != "" && digitsInt(mask) == 0 && !custom {
		messages = append(messages, "\n  Feed /0 CIDR clamped to single host: "+stripCntrl(addr))
		mask = ""
	}
	ip := strings.Split(subnet, ".")
	for key, octet := range ip {
		if looseEqInt(octet, 0) {
			ip[key] = "0"
		} else {
			ip[key] = strings.TrimLeft(octet, "0")
		}
		if key == 3 && digitsInt(mask) == 24 && mask != "" && !looseEqInt(octet, 0) {
			ip[key] = "0"
		}
	}
	if mask != "" && digitsInt(mask) == 32 {
		mask = ""
	}
	ipFinal := strings.Join(ip, ".")
	if looseEqInt(ip[0], 0) || phpEmpty(ip[0]) {
		return "", false, messages
	}
	if supp && !custom {
		if looseEqInt(ip[0], 127) {
			return "", false, messages
		}
		if floor != "Disabled" && !phpEmpty(mask) && phpStringLess(mask, floor) {
			messages = append(messages, "\n  Suppression CIDR Limit: "+ipFinal+"/"+mask)
			mask = "32"
		}
		if !phpFilterIP(ipFinal, true, true, true, true) {
			return "", false, messages
		}
		if long, okl := ip2long(ipFinal); okl && (long&0xffffff00 == 0xc0000200 || long&0xffffff00 == 0xc6336400 ||
			long&0xffffff00 == 0xcb007100 || long&0xf0000000 == 0xe0000000 || long&0xffc00000 == 0x64400000 ||
			long&0xfffe0000 == 0xc6120000 || long&0xffffff00 == 0xc0586300) {
			return "", false, messages
		}
	}
	if mask != "" {
		return ipFinal + "/" + mask, true, messages
	}
	return ipFinal, true, messages
}

// The [[:cntrl:]] bytes, 0x00-0x1f and 0x7f, removed.
func stripCntrl(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x20 && s[i] != 0x7f {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// pfb_sanitize_ipaddr_v6(): the canonical inet_ntop() form; ok=false is PHP's NULL address.
func sanitizeIPv6(addr string, custom bool, floor string, supp bool) (string, bool, []string) {
	var messages []string
	parts := strings.Split(addr, "/")
	sIP, mask := parts[0], ""
	if len(parts) > 1 {
		mask = parts[1]
	}
	if strings.IndexByte(sIP, '%') >= 0 {
		return "", false, messages
	}
	bin, ok := phpInetPton(sIP)
	if !ok {
		return "", false, messages
	}
	clamped := false
	if mask != "" && ctypeDigit(mask) && digitsInt(mask) == 0 && !custom {
		messages = append(messages, "\n  Feed /0 CIDR clamped to single host: "+addr)
		clamped = true
	}
	if len(bin) == 16 && string(bin) == string(make([]byte, 16)) {
		return "", false, messages
	}
	if supp && !custom {
		if floor != "Disabled" && mask != "" && ctypeDigit(mask) && digitsInt(mask) > 0 && int64(digitsInt(mask)) < phpIntval(floor) {
			messages = append(messages, "\n  Suppression CIDR Limit: "+sIP+"/"+mask)
			clamped = true
		}
		if !phpFilterIP(sIP, false, true, true, true) {
			return "", false, messages
		}
		if len(bin) == 16 && ((bin[0] == 0x20 && bin[1] == 0x01 && bin[2] == 0x0d && bin[3] == 0xb8) || bin[0] == 0xff ||
			(bin[0] == 0 && bin[1] == 0x64 && bin[2] == 0xff && bin[3] == 0x9b && string(bin[4:12]) == string(make([]byte, 8)))) {
			return "", false, messages
		}
	}
	if mask != "" && !clamped {
		return phpInetNtop(bin) + "/" + mask, true, messages
	}
	return phpInetNtop(bin), true, messages
}

// pfb_ipv4_numeric_host(): the way a WHATWG URL parser reads an IPv4 host. numeric=false is PHP's NULL (not numeric-
// shaped); valid=false is ['ip' => NULL].
func ipv4NumericHost(host string) (ip string, numeric bool, valid bool) {
	if strings.IndexByte(host, ':') >= 0 {
		return "", false, false
	}
	parts := strings.Split(host, ".")
	trailingDot := len(parts) > 1 && parts[len(parts)-1] == ""
	if trailingDot {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	lastHex := len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') && (len(last) == 2 || allHex(last[2:]))
	if !ctypeDigit(last) && !lastHex {
		return "", false, false
	}
	if len(parts) > 4 || (trailingDot && len(parts) < 4) {
		return "", true, false
	}
	numbers := make([]int64, 0, 4)
	for _, part := range parts {
		v, okn := urlIPv4Number(part)
		if !okn {
			return "", true, false
		}
		numbers = append(numbers, v)
	}
	ipv := numbers[len(numbers)-1]
	numbers = numbers[:len(numbers)-1]
	if ipv >= int64(1)<<(8*(4-len(numbers))) {
		return "", true, false
	}
	for i, v := range numbers {
		if v > 255 {
			return "", true, false
		}
		ipv += v << (8 * (3 - i))
	}
	return strconv.Itoa(int(ipv>>24&255)) + "." + strconv.Itoa(int(ipv>>16&255)) + "." + strconv.Itoa(int(ipv>>8&255)) + "." + strconv.Itoa(int(ipv&255)), true, true
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// The WHATWG "IPv4 number parser"; more digits than 2^32 needs reads as MaxInt64 (range-rejected by the caller).
func urlIPv4Number(part string) (int64, bool) {
	radix, maxDigits := 10, 10
	switch {
	case len(part) >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
		part, radix, maxDigits = part[2:], 16, 8
	case len(part) > 1 && part[0] == '0':
		part, radix, maxDigits = part[1:], 8, 11
	case part == "":
		return 0, false
	}
	if part == "" {
		return 0, true
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		if (radix == 16 && !isHexDigit(c)) || (radix == 8 && (c < '0' || c > '7')) || (radix == 10 && !isDigit(c)) {
			return 0, false
		}
	}
	if len(strings.TrimLeft(part, "0")) > maxDigits {
		return math.MaxInt64, true
	}
	v, _ := strconv.ParseInt(part, radix, 64)
	return v, true
}

// pfb_ipv4_unpad(): a zero-padded all-decimal dotted quad read with the feed rule.
func ipv4Unpad(host string) (string, bool) {
	p := strings.Split(host, ".")
	if len(p) != 4 {
		return "", false
	}
	for _, o := range p {
		if !ctypeDigit(o) {
			return "", false
		}
	}
	addr, ok, _ := sanitizeIPv4(host, true, "Disabled", false)
	if !ok || !isIPAddrV4(addr) {
		return "", false
	}
	return addr, true
}

// pfb_ipv4_from_mapped(): the IPv4 inside an IPv4-mapped IPv6 literal.
func ipv4FromMapped(ip string) (string, bool) {
	if strings.IndexByte(ip, 0) >= 0 {
		return "", false
	}
	bin, ok := phpInetPton(ip)
	if !ok || len(bin) != 16 || string(bin[:12]) != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" {
		return "", false
	}
	return inetNtop4(bin[12:]), true
}
