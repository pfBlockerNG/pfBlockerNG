package feedparse

import (
	"strconv"
	"strings"
)

// DNSBLConfig is what the DNSBL feed parse depends on besides the feed: whether IPs in a domain feed are collected
// (dnsbl_ip), permissive scheme handling, a user list and the global Suppression setting.
type DNSBLConfig struct {
	DNSBLIP, Lenient, Custom, Suppression bool
}

// DNSBLRow is a row of the staged feed: a domain, or a verbatim ABP rule for the decider.
type DNSBLRow struct {
	ABP  bool
	Text string
}

// DNSBLLine is what one feed line produced: the rows written, the IPs it added to the feed's IPv4 / IPv6 lists (before
// the feed's de-duplication), the failure records (the logged line text), the strict-scheme skips it counts, and whether
// it ended the feed.
type DNSBLLine struct {
	Rows          []DNSBLRow
	IP4, IP6      []string
	Fail          []string
	SchemeSkipped int
	Stop          bool
}

// DNSBLParser parses one DNSBL feed line by line; it carries the per-feed state (CSV detection, reverse format).
type DNSBLParser struct {
	cfg                DNSBLConfig
	csvType            string
	csvParser, runOnce bool
	revFormat          bool
}

func NewDNSBLParser(cfg DNSBLConfig) *DNSBLParser { return &DNSBLParser{cfg: cfg} }

// Names the failure log skips: hosts-file boilerplate and HTML scraps, not feed content.
var dnsblSkipNames = map[string]bool{
	"broadcasthost": true, "local": true, "localhost": true, "<pre>": true, "Vault": true, "Site": true, "list": true,
	"::1": true, ":": true, "ip6-localhost": true, "ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true,
}

// fail is pfb_parse_fail_log(): the line field of the record, "null" for a falsy line.
func (p *DNSBLParser) fail(out *DNSBLLine, line string) {
	if phpEmpty(line) {
		line = "null"
	}
	out.Fail = append(out.Fail, line)
}

// collectFeedIP is pfb_dnsbl_collect_feed_ip(): add candidate to the IPv4 or IPv6 list, judged by the family of guard.
func (p *DNSBLParser) collectFeedIP(guard, candidate string, out *DNSBLLine) bool {
	isCIDR := strings.Contains(candidate, "/")
	// IPv4-mapped IPv6 is collected as its IPv4 address; a mapped /96../128 is the IPv4 range of the remaining bits.
	if isIPAddrV6(guard) && validateIPv6(candidate) {
		addr, bits := candidate, "128"
		if isCIDR {
			addr, bits, _ = strings.Cut(candidate, "/")
		}
		if mapped, ok := ipv4FromMapped(addr); ok && phpIntval(bits) >= 96 {
			guard, candidate = mapped, mapped
			if isCIDR {
				candidate = mapped + "/" + strconv.FormatInt(phpIntval(bits)-96, 10)
			}
		}
	}
	if isIPAddrV4(guard) {
		parsed, ok, _ := sanitizeIPv4(candidate, p.cfg.Custom, "Disabled", p.cfg.Suppression)
		if ok && validateIPv4(parsed) {
			out.IP4 = append(out.IP4, parsed)
			return true
		}
		return false
	}
	if isIPAddrV6(guard) {
		if !validateIPv6(candidate) {
			return false
		}
		if isCIDR { // a bare v6 stays raw; a CIDR goes through the sanitizer
			parsed, ok, _ := sanitizeIPv6(candidate, p.cfg.Custom, "Disabled", p.cfg.Suppression)
			if !ok {
				return false
			}
			candidate = parsed
		}
		out.IP6 = append(out.IP6, candidate)
		return true
	}
	return false
}

// Line parses one line of the feed as fgets() returns it (its line ending included): pfb_dnsbl_parse_line().
func (p *DNSBLParser) Line(raw string) DNSBLLine {
	var out DNSBLLine
	line := scrubLine(stripBOM(raw))

	// An ABP anchor or hosts-line target that is itself an IP goes to the firewall alias, never to the decider.
	if p.cfg.DNSBLIP {
		ip, ok := abpExtractIP(line)
		if !ok {
			p.fail(&out, line)
			return out
		}
		if ip != "" {
			p.collectFeedIP(strBefore(ip, "/"), ip, &out)
			return out
		}
		for _, cidr := range abpRegexIP4CIDRs(line) {
			p.collectFeedIP(strBefore(cidr, "/"), cidr, &out)
		}
	}

	// Any self-identifying ABP shape is staged verbatim.
	if isABPRuleLine(line) {
		out.Rows = []DNSBLRow{{ABP: true, Text: rowText(line)}}
		return out
	}

	line = strings.ReplaceAll(strings.ReplaceAll(line, "\t", " "), "%20", "")

	if strings.HasPrefix(line, "#") {
		h := hashLineClassify(line)
		if h.stop {
			out.Stop = true
			return out
		}
		if h.revFormat {
			p.revFormat = true
		}
		if h.csvType != "" {
			p.csvType = h.csvType
		}
		if h.csvParser {
			p.csvParser = true
		}
		return out
	}

	if isSkippableControlLine(line) {
		return out
	}
	line = strBefore(line, " #")

	var csvline []string
	if p.csvParser {
		csvline = phpStrGetCSV(line)
	} else if !p.runOnce {
		if strings.Count(line, ",") >= 2 {
			csvline = phpStrGetCSV(line)
			p.csvParser = true
		}
		p.runOnce = true
	}
	if phpEmpty(line) {
		return out
	}

	line, skip := p.csvExtract(line, csvline, &out)
	if skip {
		return out
	}
	line = phpTrim(line)

	// Hosts format: the sink address before the first space goes; whatever follows the next space goes too.
	if !p.revFormat && strings.Contains(line, " ") {
		line = phpTrim(line[strings.Index(line, " "):])
	}
	line = strBefore(line, " ")

	lite := strings.Contains(line, ".") && ctypeAlnum(strings.ReplaceAll(line, ".", ""))
	if !lite {
		host, ok := p.extractHost(line, !p.cfg.Lenient, &out)
		if !ok {
			return out
		}
		line = host
	}
	line = phpTrim(line)

	// Padded decimal octets are decimal; a non-canonical IPv4 spelling is the address a client dials.
	if u, ok := ipv4Unpad(line); ok {
		line = u
	}
	if ip, numeric, valid := ipv4NumericHost(line); numeric && (!valid || ip != line) {
		if !valid {
			p.fail(&out, line)
			return out
		}
		line = ip
	}

	host := strBefore(line, "/")
	if isIPAddrV4(host) || isIPAddrV6(host) {
		if p.cfg.DNSBLIP {
			p.collectFeedIP(host, line, &out)
		}
		return out
	}

	// Unicode domains become punycode, after the encoding is settled.
	if !phpEmpty(line) && !ctypePrint(line) {
		line = idnToASCIIWildcard(mbConvertToUTF8(line))
		if phpEmpty(line) {
			p.fail(&out, "")
			return out
		}
	}

	line = strings.Trim(line, ".")

	if !domainOK(line) {
		if strings.HasPrefix(line, "@") { // yHosts '@' lines are skipped silently
			return out
		}
		if !dnsblSkipNames[line] {
			p.fail(&out, line)
		}
		return out
	}
	out.Rows = []DNSBLRow{{Text: rowText(strings.ToLower(line))}}
	return out
}

// pfb_dnsbl_is_skippable_control_line(): blank, '!', '//' and non-IPv6 '[...]' lines.
func isSkippableControlLine(line string) bool {
	line = pfbStrip(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "//") {
		return true
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return unbracketIP6(line) == line
	}
	return false
}
