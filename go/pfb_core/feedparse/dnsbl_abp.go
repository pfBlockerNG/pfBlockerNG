package feedparse

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pfb_dnsbl_abp_extract_ip(): the IP an ABP '||' anchor or a hosts line names, "" when it names none; ok is false
// for a numeric-shaped but invalid anchor.
func abpExtractIP(line string) (string, bool) {
	s := phpTrim(line)
	if s == "" {
		return "", true
	}
	if rest, ok := strings.CutPrefix(s, "||"); ok {
		rest = strBefore(rest, "$")
		return anchorIP(phpTrim(strBefore(rest, "^")))
	}
	// hosts line: "<sink-ip> <target>" with the target an IP; \s is ASCII space, \t \n \v \f \r.
	if strings.ContainsAny(s, " \t\n\v\f\r") {
		parts := splitWhitespace(s)
		if len(parts) >= 2 && (isIPAddrV4(parts[0]) || isIPAddrV6(parts[0])) {
			if target := phpTrim(parts[1]); isIPAddrV4(target) || isIPAddrV6(target) {
				return target, true
			}
		}
	}
	return "", true
}

// preg_split('/\s+/', $s): runs of ASCII whitespace separate; a leading or trailing run leaves an empty part.
func splitWhitespace(s string) []string {
	var parts []string
	start, i := 0, 0
	for i < len(s) {
		if strings.IndexByte(" \t\n\v\f\r", s[i]) < 0 {
			i++
			continue
		}
		parts = append(parts, s[start:i])
		for i < len(s) && strings.IndexByte(" \t\n\v\f\r", s[i]) >= 0 {
			i++
		}
		start = i
	}
	return append(parts, s[start:])
}

// A PCRE2 /u "\A(?:[\x{9}-\x{D}\x{1C}-\x{1F}\x{85}]|\p{Z})" on the first character of a string.
func startsWithPCRESpace(s string) bool {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size <= 1 {
		return false
	}
	return (r >= 0x09 && r <= 0x0D) || (r >= 0x1C && r <= 0x1F) || r == 0x85 || unicode.Is(unicode.Z, r)
}

const abpCosmeticPrefix = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._,~*-"

// pfb_dnsbl_is_abp_rule_line(): the line is an ABP-shaped rule ('||'/'@@' anchor, element hiding, '/regex/').
func isABPRuleLine(line string) bool {
	if strings.HasPrefix(line, ",") {
		return false
	}
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") {
		return true
	}
	if strings.Contains(line, "#") {
		first, markerLen := -1, 0
		for _, m := range []string{"##", "#@#", "#?#", "#%#", "#$#"} {
			if pos := strings.Index(line, m); pos >= 0 && (first < 0 || pos < first) {
				first, markerLen = pos, len(m)
			}
		}
		if first == 0 {
			if after := line[markerLen:]; after != "" && !startsWithPCRESpace(after) {
				return true
			}
		} else if first > 0 && strspn(line, abpCosmeticPrefix) >= first {
			return true
		}
	}
	if strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "//") {
		if strings.HasSuffix(line, "/") && len(line) > 1 {
			return true
		}
		return strings.LastIndex(line, "/$") > 0
	}
	return false
}

var (
	abpSchemeGroupRE = regexp.MustCompile(`^\((?:\.\*|\([A-Za-z]+\??(?:\|[A-Za-z]+\??)*\))://\)\?`)
	abpPathTailRE    = regexp.MustCompile(`\((?:\\?/|\[:/\])\.\*\)\?$`)
	abpFirstOctetRE  = regexp.MustCompile(`^(?:1\d\d|2[0-4]\d|25[0-5])$`)
	abpPartRE        = regexp.MustCompile(`^(?:[\d?*+{},()|-]|\\d|\[(?:\d-\d|\\d|\d)+\])+$`)
	abpBraceRE       = regexp.MustCompile(`\{[^}]*`)
	abpDigitsRE      = regexp.MustCompile(`\d+`)
	abpEmptyBoundRE  = regexp.MustCompile(`\{,(\d+\})`)
)

// pfb_dnsbl_abp_regex_ip4_cidrs(): '/^A\.B\.C\.D$/' with one pattern per octet -> the merged CIDRs it matches (at most
// 256, none wider than /16), else nil. RE2 stands in for PCRE; a part PCRE reads differently (possessive quantifiers,
// a quantifier on a quantifier) is refused.
func abpRegexIP4CIDRs(line string) []string {
	if len(line) > 514 || !strings.HasPrefix(line, "/") || !strings.HasSuffix(line, "$/") {
		return nil
	}
	inner := line[1 : len(line)-2]
	anchored := strings.HasPrefix(inner, "^")
	if anchored {
		inner = inner[1:]
	}
	if m := abpSchemeGroupRE.FindString(inner); m != "" {
		inner = inner[len(m):]
	}
	if loc := abpPathTailRE.FindStringIndex(inner); loc != nil {
		inner = inner[:loc[0]]
	}

	var parts []string
	cur, depth := "", 0
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' {
			token := inner[i:min(i+2, len(inner))]
			i++
			if token == `\.` && depth == 0 {
				parts = append(parts, cur)
				cur = ""
			} else {
				cur += token
			}
			continue
		}
		switch {
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return nil
			}
		case c == '|' && depth == 0:
			return nil
		}
		cur += string(c)
	}
	parts = append(parts, cur)
	if depth != 0 || len(parts) != 4 {
		return nil
	}
	if !anchored && !abpFirstOctetRE.MatchString(parts[0]) {
		return nil
	}
	for _, part := range parts {
		if !abpPartRE.MatchString(part) || strings.Contains(part, "(?") || strings.Contains(part, "{,}") {
			return nil
		}
		for _, brace := range abpBraceRE.FindAllString(part, -1) {
			if nums := abpDigitsRE.FindAllString(brace, -1); len(nums) > 0 {
				mx := 0
				for _, n := range nums {
					if v, _ := strconv.Atoi(n); v > mx {
						mx = v
					}
				}
				if mx > 3 {
					return nil
				}
			}
		}
	}

	var sets [4][]int
	for k, part := range parts {
		re, err := regexp.Compile(`^(?:` + abpEmptyBoundRE.ReplaceAllString(part, `{0,$1`) + `)$`)
		if err != nil {
			return nil
		}
		for n := range 256 {
			if re.MatchString(strconv.Itoa(n)) {
				sets[k] = append(sets[k], n)
			}
		}
		if len(sets[k]) == 0 {
			return nil
		}
	}

	var runs [][2]int
	for _, d := range sets[3] {
		if n := len(runs); n > 0 && runs[n-1][1]+1 == d {
			runs[n-1][1] = d
		} else {
			runs = append(runs, [2]int{d, d})
		}
	}
	if len(sets[0])*len(sets[1])*len(sets[2])*len(runs) > 65536 {
		return nil
	}
	var merged [][2]int
	for _, a := range sets[0] {
		for _, b := range sets[1] {
			for _, c := range sets[2] {
				base := a<<24 | b<<16 | c<<8
				for _, r := range runs {
					if n := len(merged); n > 0 && merged[n-1][1]+1 == base+r[0] {
						merged[n-1][1] = base + r[1]
					} else {
						merged = append(merged, [2]int{base + r[0], base + r[1]})
					}
					if len(merged) > 256 {
						return nil
					}
				}
			}
		}
	}

	var cidrs []string
	long2ip := func(v int) string {
		return strconv.Itoa(v>>24&255) + "." + strconv.Itoa(v>>16&255) + "." + strconv.Itoa(v>>8&255) + "." + strconv.Itoa(v&255)
	}
	for _, m := range merged {
		for _, cidr := range ipRangeToSubnets(long2ip(m[0]), long2ip(m[1])) {
			if len(cidrs) >= 256 || digitsInt(cidr[strings.IndexByte(cidr, '/')+1:]) < 16 {
				return nil
			}
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}
