package feedparse

import (
	"math"
	"slices"
	"strconv"
	"strings"
)

// The pfSense appliance's IPv6 helpers: util.inc is_ipaddrv6(), is_linklocal(), is_subnet(), ip6_to_bin() and
// bin_to_compressed_ip6(), which sit on PEAR Net_IPv6 1.3.0b4 with the zone and PHP 8 patches of pfSense's port
// (net/pear-Net_IPv6, distinfo sha256 ec676dc8...). None of them is ever given a '/'. Where PHP throws (a negative
// str_repeat count, a float to dechex) the Go port reports failure; no corpus row can reach such an input.

// _php_math_basetozval(): digits of base 2..36, anything else skipped (so its blank trimming and 0x/0b prefix skipping
// change no value); the number as an int, or as a float once it outgrows one (a zone's letters can make that happen).
func phpBaseToNum(s string, base int) (num int64, fnum float64, isFloat bool) {
	cutoff, cutlim := int64(math.MaxInt64)/int64(base), int64(math.MaxInt64)%int64(base)
	for i := 0; i < len(s); i++ {
		var d int64
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'A' && c <= 'Z':
			d = int64(c-'A') + 10
		case c >= 'a' && c <= 'z':
			d = int64(c-'a') + 10
		default:
			continue
		}
		if d >= int64(base) {
			continue
		}
		if !isFloat {
			if num < cutoff || (num == cutoff && d <= cutlim) {
				num = num*int64(base) + d
				continue
			}
			fnum, isFloat = float64(num), true
		}
		fnum = fnum*float64(base) + float64(d)
	}
	return num, fnum, isFloat
}

// base_convert($s, 16, 2); ok=false where PHP throws (an infinite value).
func phpHexToBin(s string) (string, bool) {
	num, fnum, isFloat := phpBaseToNum(s, 16)
	if !isFloat {
		return strconv.FormatUint(uint64(num), 2), true
	}
	f := math.Floor(fnum)
	if math.IsInf(f, 0) {
		return "", false
	}
	// The float path writes at most 64 digits, lowest first, and divides without flooring.
	var digits [64]byte
	n := 0
	for {
		digits[63-n] = byte('0' + int(math.Mod(f, 2)))
		n++
		f /= 2
		if n == 64 || math.Abs(f) < 1 {
			break
		}
	}
	return string(digits[64-n:]), true
}

// hexdec() of a string of at most four characters.
func phpHexdecSmall(s string) int64 {
	num, _, _ := phpBaseToNum(s, 16)
	return num
}

func padLeft(s string, width int, c byte) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(string(c), width-len(s)) + s
}

// $s >= 0 for a string: a numeric string by value, any other by byte order against "0".
func phpStringGE0(s string) bool {
	if f, ok := phpNumeric(s); ok {
		return f >= 0
	}
	return s != "" && s[0] >= '0'
}

// $a == $b for two short strings: numeric strings by value, any others byte for byte.
func phpLooseEqualStrings(a, b string) bool {
	fa, oka := phpNumeric(a)
	fb, okb := phpNumeric(b)
	if oka && okb {
		return fa == fb
	}
	return a == b
}

// /^\d{1,3}$/ on a short string; `$` also matches before a final newline.
func isOneToThreeDigits(s string) bool {
	s = strings.TrimSuffix(s, "\n")
	return len(s) >= 1 && len(s) <= 3 && ctypeDigit(s)
}

// Net_IPv6::removeZone() and getZone(): the text before the first '%', and the text after the last one.
func netZoneSplit(ip string) (head, zone string) {
	head = ip
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		head = ip[:i]
		zone = ip[strings.LastIndexByte(ip, '%')+1:]
	}
	return head, zone
}

// Net_IPv6::uncompress(): expands '::' to the zero groups; the zone is kept at the end.
func netUncompress(ip string) (string, bool) {
	ip, zone := netZoneSplit(ip)
	uip := ip
	if strings.Contains(uip, "::") {
		ip1, ip2, _ := strings.Cut(uip, "::")
		c1, c2 := -1, -1
		if ip1 != "" {
			c1 = strings.Count(ip1, ":")
		}
		if ip2 != "" {
			c2 = strings.Count(ip2, ":")
		}
		if strings.Contains(ip2, ".") {
			c2++
		}
		switch {
		case c1 == -1 && c2 == -1:
			uip = "0:0:0:0:0:0:0:0"
		case c1 == -1:
			uip = strings.ReplaceAll(uip, "::", strings.Repeat("0:", max(1, 7-c2)))
		case c2 == -1:
			uip = strings.ReplaceAll(uip, "::", strings.Repeat(":0", max(1, 7-c1)))
		default:
			n := 6 - c2 - c1
			if n < 0 {
				return "", false
			}
			uip = strings.ReplaceAll(uip, "::", strings.Repeat(":0:", n))
			uip = strings.ReplaceAll(uip, "::", ":")
		}
	}
	if zone != "" {
		uip += "%" + zone
	}
	return uip, true
}

// Net_IPv6::SplitV64(): the IPv6 part and the IPv4 tail of an address, the zone dropped.
func netSplitV64(ip string, uncompress bool) ([]string, bool) {
	ip, _ = netZoneSplit(ip)
	if uncompress {
		var ok bool
		if ip, ok = netUncompress(ip); !ok {
			return nil, false
		}
	}
	if !strings.Contains(ip, ".") {
		return []string{ip, ""}, true
	}
	pos := strings.LastIndexByte(ip, ':')
	if pos < 0 {
		return []string{"", ip}, true
	}
	b := []byte(ip)
	b[pos] = '_'
	parts := strings.Split(string(b), "_")
	if b[(pos+len(b)-1)%len(b)] == ':' {
		parts[0] += ":"
	}
	return parts, true
}

// preg_replace("/^[0]{1,3}(.*[0-9a-fA-F])$/", "\\1", $s): up to three leading zeros dropped when a hex digit ends the rest.
func netStripLeadingZeros(s string) string {
	body, tail := s, ""
	if strings.HasSuffix(s, "\n") {
		body, tail = s[:len(s)-1], "\n"
	}
	for n := 3; n >= 1; n-- {
		if len(body) <= n || strings.Trim(body[:n], "0") != "" {
			continue
		}
		if rest := body[n:]; !strings.Contains(rest, "\n") && isHexDigit(rest[len(rest)-1]) {
			return rest + tail
		}
	}
	return s
}

// Net_IPv6::checkIPv6(): true for an address of eight 16-bit groups, or six and a dotted IPv4. Its group test is loose
// (hexdec() skips what is not a digit, == compares numeric strings by value), so a trailing blank passes.
func netCheckIPv6(ip string) bool {
	part, ok := netSplitV64(ip, true)
	if !ok || phpEmpty(part[0]) {
		return false
	}
	groups := strings.Split(part[0], ":")
	if len(groups) > 8 {
		return false
	}
	count := 0
	for _, g := range groups {
		if len(g) > 4 {
			return false
		}
		dec := phpHexdecSmall(g)
		if phpStringGE0(g) && dec <= 65535 &&
			phpLooseEqualStrings(strings.ToUpper(netStripLeadingZeros(g)), strings.ToUpper(strconv.FormatInt(dec, 16))) {
			count++
		}
	}
	tailEmpty := len(part) < 2 || phpEmpty(part[1])
	switch {
	case count == 8 && tailEmpty:
		return true
	case count == 6 && !tailEmpty:
		n := 0
		octets := strings.Split(part[1], ".")
		for _, o := range octets {
			if phpStringGE0(o) && phpIntval(o) <= 255 && isOneToThreeDigits(o) {
				n++
			}
		}
		return n == 4
	}
	return false
}

// Net_IPv6::_ip2Bin(): the 128-bit string of an address (a dotted tail folded into two groups first).
func netIPv6ToBinary(ip string) (string, bool) {
	ip, _ = netZoneSplit(ip)
	part, ok := netSplitV64(ip, false)
	if !ok {
		return "", false
	}
	if tail := part[1]; tail != "" {
		var m [4]int64
		for i, f := range strings.SplitN(tail, ".", 4) {
			m[i] = phpIntval(f)
		}
		hi, ok1 := mulAdd256(m[0], m[1])
		lo, ok2 := mulAdd256(m[2], m[3])
		if !ok1 || !ok2 {
			return "", false
		}
		ip = strings.ReplaceAll(ip, tail, strconv.FormatUint(uint64(hi), 16)+":"+strconv.FormatUint(uint64(lo), 16))
	}
	return netGroupsToBinary(ip)
}

// a*256 + b, failing where PHP would turn the int into a float.
func mulAdd256(a, b int64) (int64, bool) {
	if a > math.MaxInt64/256 || a < math.MinInt64/256 {
		return 0, false
	}
	p := a * 256
	if (b > 0 && p > math.MaxInt64-b) || (b < 0 && p < math.MinInt64-b) {
		return 0, false
	}
	return p + b, true
}

// The uncompressed groups of ip as one string of base_convert($group, 16, 2) padded to 16 bits each.
func netGroupsToBinary(ip string) (string, bool) {
	ip, ok := netUncompress(ip)
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for _, g := range strings.Split(ip, ":") {
		bin, ok := phpHexToBin(g)
		if !ok {
			return "", false
		}
		sb.WriteString(padLeft(bin, 16, '0'))
	}
	return sb.String(), true
}

// util.inc is_linklocal() on a string that is not an IPv4: Net_IPv6::getAddressType() is NET_IPV6_LOCAL_LINK, the
// first ten bits being 1111111010.
func isLinkLocalV6(s string) bool {
	bin, ok := netIPv6ToBinary(s)
	return ok && strings.HasPrefix(bin, "1111111010")
}

// util.inc is_ipaddrv6().
func isIPAddrV6(s string) bool {
	if phpEmpty(s) || strings.IndexByte(s, '/') >= 0 {
		return false
	}
	if i := strings.IndexByte(s, '%'); i >= 0 && isLinkLocalV6(s) {
		s = s[:i]
	}
	if strings.Count(s, "::") > 1 {
		return false
	}
	return netCheckIPv6(s)
}

// util.inc ip6_to_bin(): Net_IPv6::uncompress() and base_convert() per group, not padded to 128 bits.
func ip6ToBin(s string) (string, bool) {
	return netGroupsToBinary(s)
}

// util.inc bin_to_compressed_ip6(): bin_to_ip6() groups the bits by sixteen, Net_IPv6::compress() writes the longest run
// of zero groups as '::' (never an IPv4 tail).
func binToCompressedIP6(bin string) string {
	bin = padLeft(bin, 128, '0')
	var groups []string
	for i := 0; i < len(bin); i += 16 {
		num, _, _ := phpBaseToNum(bin[i:min(i+16, len(bin))], 2)
		groups = append(groups, strconv.FormatInt(num, 16))
	}
	cip := ":" + strings.Join(groups, ":") + ":"
	longest := ""
	for i := 0; i < len(cip); {
		j := i
		for strings.HasPrefix(cip[j:], ":0") {
			j += 2
		}
		if j-i >= 4 {
			if j-i > len(longest) {
				longest = cip[i:j]
			}
			i = j
		} else {
			i++
		}
	}
	if longest != "" {
		cip = strings.Replace(cip, longest, ":", 1)
	}
	if cip != "::" {
		cip = replaceEdgeColons(cip, "")
		cip = replaceEdgeColons(cip, "::")
	}
	return cip
}

// preg_replace('/((^:)|(:$))/', $with, $s): a leading and a trailing ':' (one match, when they are the same character).
func replaceEdgeColons(s, with string) string {
	lead := strings.HasPrefix(s, ":")
	trail := strings.HasSuffix(s, ":") && !(lead && len(s) == 1)
	out := s
	if lead {
		out = with + out[1:]
	}
	if trail {
		out = out[:len(out)-1] + with
	}
	return out
}

// util.inc is_subnet(): 4 or 6 for 'address/bits' in the shape ^(?:([0-9.]{7,15})|([0-9a-f:]{2,39}|[0-9a-f:]{2,30}[0-9.]{7,15}))\/(\d{1,3})$,
// the address valid and the bits within 32 or 128; 0 otherwise.
func pfSenseIsSubnet(s string) int {
	t := strings.TrimSuffix(s, "\n")
	slash := strings.LastIndexByte(t, '/')
	if slash < 0 {
		return 0
	}
	addr, bits := t[:slash], t[slash+1:]
	if len(bits) < 1 || len(bits) > 3 || !ctypeDigit(bits) {
		return 0
	}
	n := digitsInt(bits)
	inClass := func(s string, extra func(byte) bool) bool {
		for i := 0; i < len(s); i++ {
			if !extra(s[i]) {
				return false
			}
		}
		return true
	}
	dotted := func(c byte) bool { return isDigit(c) || c == '.' }
	hexColon := func(c byte) bool { return isHexDigit(c) || c == ':' }
	if len(addr) >= 7 && len(addr) <= 15 && inClass(addr, dotted) {
		if isIPAddrV4(addr) && n <= 32 {
			return 4
		}
		return 0
	}
	v6shape := len(addr) >= 2 && len(addr) <= 39 && inClass(addr, hexColon)
	for k := 2; !v6shape && k <= 30 && k < len(addr); k++ {
		tail := addr[k:]
		v6shape = len(tail) >= 7 && len(tail) <= 15 && inClass(addr[:k], hexColon) && inClass(tail, dotted)
	}
	if v6shape && isIPAddrV6(addr) && n <= 128 {
		return 6
	}
	return 0
}

// PHP's == and < on two strings of binary digits: numeric strings compare by value, except that two integers beyond the
// int range which convert to the same float compare as strings.
func phpDigitStringCompare(a, b string) int {
	parse := func(s string) (isInt bool, n int64, f float64) {
		sig := strings.TrimLeft(s, "0")
		if len(sig) < 19 || (len(sig) == 19 && sig < "9223372036854775808") {
			if sig != "" {
				n, _ = strconv.ParseInt(sig, 10, 64)
			}
			return true, n, float64(n)
		}
		f, _ = strconv.ParseFloat(sig, 64)
		return false, 0, f
	}
	ai, an, af := parse(a)
	bi, bn, bf := parse(b)
	switch {
	case !ai && !bi && af-bf == 0:
		return strings.Compare(a, b)
	case ai && bi:
		return cmpInt(an, bn)
	case ai:
		return -1
	case bi:
		return 1
	}
	if af < bf {
		return -1
	}
	if af > bf {
		return 1
	}
	return 0
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// substr() with a non-negative start.
func phpSubstr(s string, start, length int) string {
	if start > len(s) {
		return ""
	}
	rest := s[start:]
	if length < 0 {
		length += len(rest)
		if length < 0 {
			length = 0
		}
	}
	return rest[:min(length, len(rest))]
}

// util.inc ip_range_to_subnet_array(): the minimal CIDR cover of the range, the vendored algorithm run on strings of
// bits. PHP compares those strings as numbers and the IPv6 bits come from ip6ToBin(), so an address with an IPv4 tail
// can give a string longer or shorter than 128 bits; the loop keeps PHP's arithmetic on them.
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
		var ok1, ok2 bool
		b1, ok1 = ip6ToBin(ip1)
		b2, ok2 = ip6ToBin(ip2)
		if !ok1 || !ok2 {
			return nil
		}
	default:
		return nil
	}
	b1, b2 = padLeft(b1, bits, '0'), padLeft(b2, bits, '0')
	if phpDigitStringCompare(b1, b2) == 0 {
		return []string{ip1 + "/" + strconv.Itoa(bits)}
	}
	if phpDigitStringCompare(b1, b2) > 0 {
		b1, b2 = b2, b1
	}
	lastByte := func(s string) byte {
		if s == "" {
			return 0
		}
		return s[len(s)-1]
	}
	// $x = ($n == 0 ? '' : substr($x, 0, $n)) . $edge . str_repeat($fill, $bits - $n - 1), where strrpos() false reads as 0.
	step := func(x string, find, edge, fill string) (string, bool) {
		n := max(strings.LastIndex(x, find), 0)
		if bits-n-1 < 0 {
			return "", false
		}
		prefix := ""
		if n != 0 {
			prefix = phpSubstr(x, 0, n)
		}
		return prefix + edge + strings.Repeat(fill, bits-n-1), true
	}
	rs := map[string]int{}
	netsize := 0
	for {
		if lastByte(b1) == '1' {
			rs[phpSubstr(b1, netsize, bits-netsize)+strings.Repeat("0", netsize)] = bits - netsize
			var ok bool
			if b1, ok = step(b1, "0", "1", "0"); !ok {
				return nil
			}
		}
		if lastByte(b2) == '0' {
			rs[phpSubstr(b2, netsize, bits-netsize)+strings.Repeat("0", netsize)] = bits - netsize
			var ok bool
			if b2, ok = step(b2, "1", "0", "1"); !ok {
				return nil
			}
		}
		if phpDigitStringCompare(b2, b1) < 0 {
			break
		}
		shift := bits - max(strings.LastIndex(b1, "0"), strings.LastIndex(b2, "1"), 0)
		if shift < 0 {
			return nil
		}
		b1 = strings.Repeat("0", shift) + phpSubstr(b1, 0, bits-shift)
		b2 = strings.Repeat("0", shift) + phpSubstr(b2, 0, bits-shift)
		netsize += shift
		if phpDigitStringCompare(b1, b2) == 0 {
			rs[phpSubstr(b1, netsize, bits-netsize)+strings.Repeat("0", netsize)] = bits - netsize
			break
		}
		if phpDigitStringCompare(b1, b2) >= 0 {
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
		if !v4 {
			out = append(out, binToCompressedIP6(k)+"/"+mask)
			continue
		}
		var o [4]string
		for i := range o {
			n, _ := strconv.ParseUint(k[i*8:i*8+8], 2, 8)
			o[i] = strconv.FormatUint(n, 10)
		}
		out = append(out, strings.Join(o[:], ".")+"/"+mask)
	}
	return out
}
