package feedparse

import (
	"regexp"
	"strconv"
	"strings"
)

// pfb_dnsbl_unbracket_ip6(): '[' ... ']' around a valid IPv6 literal is removed, anything else is returned as is.
func unbracketIP6(line string) string {
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && len(line) >= 2 {
		if inner := line[1 : len(line)-1]; isIPAddrV6(inner) {
			return inner
		}
	}
	return line
}

// pfb_strip_trailing_port(): ":<1-5 digits>" at the end, never from an IPv6 literal.
func stripTrailingPort(line string) string {
	if !isIPAddrV6(line) && strings.Contains(line, ":") {
		if i := strings.LastIndexByte(line, ':'); len(line)-i-1 >= 1 && len(line)-i-1 <= 5 && ctypeDigit(line[i+1:]) {
			return line[:i]
		}
	}
	return line
}

// pfb_dnsbl_scheme_pos(): a "://" counts only when nothing before it is path, query or fragment; -1 for none.
func schemePos(line string) int {
	pos := strings.Index(line, "://")
	if pos >= 0 && strcspn(line, "/?#") > pos {
		return pos
	}
	return -1
}

// stripCaretOptions cuts from the first '^' that ends the text or starts a '$...' options tail (the /D regex
// \^(\$.*)?$ replaced by nothing).
func stripCaretOptions(s string) string {
	for i := range len(s) {
		if s[i] == '^' && (i == len(s)-1 || s[i+1] == '$') {
			return s[:i]
		}
	}
	return s
}

var schemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+\-.]*$`)

// pfb_dnsbl_strip_scheme(): ok is false where PHP returns FALSE.
func stripScheme(line string, strict bool) (string, bool) {
	pos := schemePos(line)
	if pos < 0 {
		return line, true
	}
	remainder := line[pos+3:]
	if pos == 0 {
		cand := stripCaretOptions(remainder)
		ip := unbracketIP6(cand)
		if ip != cand || isIPAddrV4(ip) {
			return ip, true
		}
		if strict {
			return "", false
		}
		return remainder, true
	}
	if strict {
		if !schemeRE.MatchString(line[:pos]) {
			return "", false
		}
		remainder = strings.TrimSuffix(remainder, "/")
		if strings.Contains(remainder, "/") {
			return "", false
		}
	}
	return remainder, true
}

// pfb_dnsbl_cidr(): a scheme-less '<IP>/<digits>' line. kind is cidrNone (not a CIDR), cidrReject, or cidrOK with the
// range (padded network unpadded, mask canonical).
type cidrKind int

const (
	cidrNone cidrKind = iota
	cidrReject
	cidrOK
)

func dnsblCIDR(line string) (string, cidrKind) {
	i := strings.LastIndexByte(line, '/')
	if i < 1 || !ctypeDigit(line[i+1:]) || strings.Contains(line[:i], "\n") {
		return "", cidrNone
	}
	net, mask := line[:i], line[i+1:]
	if u, ok := ipv4Unpad(net); ok {
		net = u
	}
	netIsIP := isIPAddrV4(net) || isIPAddrV6(net)
	if netIsIP && (isSubnetV4(net+"/"+mask) || isSubnetV6(net+"/"+mask)) {
		return net + "/" + strconv.FormatInt(digitsInt(mask), 10), cidrOK
	}
	if _, numeric, _ := ipv4NumericHost(net); netIsIP || (!strings.Contains(net, "/") && numeric) {
		return "", cidrReject
	}
	return "", cidrNone
}

var anchorPrefixRE = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){2}\.$`)

// pfb_dnsbl_anchor_ip(): the address or range of an ABP '||' / empty-scheme '://' anchor host; "" when it is none,
// ok false for a numeric-shaped but invalid host or CIDR.
func anchorIP(host string) (string, bool) {
	host = stripTrailingPort(host)
	if c, kind := dnsblCIDR(host); kind == cidrOK {
		return c, true
	} else if kind == cidrReject {
		return "", false
	}
	host = unbracketIP6(host)
	if u, ok := ipv4Unpad(host); ok {
		host = u
	}
	if isIPAddrV4(host) || isIPAddrV6(host) {
		return host, true
	}
	if !strings.Contains(host, "/") {
		if ip, numeric, valid := ipv4NumericHost(host); numeric {
			return ip, valid
		}
	}
	return "", true
}

// extractHost is pfb_dnsbl_extract_host(): the host-munging pipeline of a non-lite line. ok is false when the line is
// to be skipped; each failure record (and the strict-scheme skip count) goes to p.
func (p *DNSBLParser) extractHost(line string, strict bool, out *DNSBLLine) (string, bool) {
	cidr, kind := dnsblCIDR(line)
	if kind == cidrReject {
		p.fail(out, line)
		return "", false
	}
	if kind == cidrOK {
		return cidr, true
	}

	if pos := schemePos(line); pos >= 0 {
		rest := line[pos+3:]
		alen := strcspn(rest, "/?#")
		if at := strings.LastIndexByte(rest[:min(alen, strcspn(rest, "^"))], '@'); at >= 0 {
			rest = rest[at+1:]
			alen -= at + 1
		}
		if pos == 0 {
			anchor := stripCaretOptions(rest)
			if anchorPrefixRE.MatchString(anchor) {
				anchor += "0/24"
			}
			ip, ok := anchorIP(anchor)
			if !ok {
				p.fail(out, line)
				return "", false
			}
			if ip != "" {
				return ip, true
			}
		}
		if _, numeric, _ := ipv4NumericHost(stripTrailingPort(rest[:alen])); strict && numeric {
			rest = rest[:alen]
		}
		line = line[:pos+3] + rest
	}

	stripped, ok := stripScheme(line, strict)
	if !ok {
		p.fail(out, line)
		out.SchemeSkipped++
		return "", false
	}
	line = strBefore(strBefore(strBefore(strBefore(stripped, "/"), "#"), "?"), ";")
	return unbracketIP6(stripTrailingPort(line)), true
}
