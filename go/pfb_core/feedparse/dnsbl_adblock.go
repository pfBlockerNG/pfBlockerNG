package feedparse

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ParseMode is the Feed Line Parsing setting dnsbl/pfb_dnsbl_parse_mode (PfbDnsblParseMode, issue #4272): how a domain is
// taken from a feed line that is not a plain domain. The zero value is Strict.
type ParseMode string

const (
	ParseStrict  ParseMode = "strict"  // (<scheme>://)?<domain>/?, then an optional space-separated '#' comment
	ParsePorts   ParseMode = "ports"   // Strict, plus an optional :<1-65535> port
	ParseLenient ParseMode = "lenient" // the ADR-22 permissive host cut
)

// Valid is whether m is one of the three modes.
func (m ParseMode) Valid() bool { return m == ParseStrict || m == ParsePorts || m == ParseLenient }

// ICANNTLDs is pfb_psl_icann_tlds(): the last label of every rule in the ICANN section of the shipped dnsbl_psl, lower-case
// ASCII. An Adblock feed keeps a hostname only under one of them.
type ICANNTLDs struct {
	set map[string]bool
	sum string
}

// LoadICANNTLDs reads the ICANN TLDs of the PSL file at path (its '// ===BEGIN ICANN' to '// ===END ICANN' lines).
func LoadICANNTLDs(path string) (*ICANNTLDs, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := &ICANNTLDs{set: map[string]bool{}}
	icann := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		entry := strings.TrimSuffix(sc.Text(), "\r")
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "// ===") {
			icann = strings.Contains(entry, "BEGIN ICANN")
			continue
		}
		if icann && !strings.HasPrefix(entry, "//") {
			tld := entry[strings.LastIndexByte(entry, '.')+1:]
			if a, ok := IDNToASCII(tld); ok && !phpEmpty(a) {
				tld = a
			}
			t.set[asciiLower(tld)] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(t.set))
	for k := range t.set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	t.sum = strconv.Itoa(len(keys)) + " ICANN TLDs " + hex.EncodeToString(h[:8])
	return t, nil
}

// Len is the number of TLDs: 0 when the PSL has none, so that an Adblock feed keeps no hostname.
func (t *ICANNTLDs) Len() int {
	if t == nil {
		return 0
	}
	return len(t.set)
}

// String names the set by its size and digest: a parse setting (feedstage's reuse record) without the whole list.
func (t *ICANNTLDs) String() string {
	if t == nil {
		return "no ICANN TLDs"
	}
	return t.sum
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

var (
	// pfb_dnsbl_feed_has_abp_header()'s pattern, matched on the ASCII-lowered line ('\s' without /u is ASCII; /i folds
	// ASCII only, so the Kelvin sign is no 'k').
	abpHeaderRE = regexp.MustCompile(`^\[[ \t\n\v\f\r]*(?:adblock|ublock|adguard)[^\]]*\]$`)
	// An AdGuard HTML filter or its exception ('site$$script[...]', 'site$@$...').
	abpHTMLFilterRE = regexp.MustCompile(`^[A-Za-z0-9._,~*-]+\$@?\$`)
)

// DNSBLFeedIsABP is pfb_dnsbl_feed_is_abp() over the feed r (custom: pfb_dnsbl_feed_has_abp_header(), as a custom list is
// an Adblock feed only by its header): its first non-blank line is an Adblock-family header, or any line not led by '#'
// is an Adblock rule or an AdGuard HTML filter. Hosts and IP feeds open with '#' banners such as '#####' or '##Title:'.
// A line over 1 MiB counts for neither, as the parse skips it (ParseDNSBLFeed); the old path reads it whole.
func DNSBLFeedIsABP(r io.Reader, custom bool) (bool, error) {
	first, abp := true, false
	err := eachLine(r, func(line string, overlong, _ bool) error {
		if first {
			if !overlong && strings.TrimRight(line, "\r\n") == "" {
				return nil
			}
			first = false
			if !overlong && abpHeaderRE.MatchString(asciiLower(scrubLine(stripBOM(line)))) {
				abp = true
				return errFeedEnd
			}
			if custom {
				return errFeedEnd
			}
		}
		if overlong {
			return nil
		}
		l := scrubLine(stripBOM(line))
		if !strings.HasPrefix(l, "#") && (isABPRuleLine(l) || abpHTMLFilterRE.MatchString(l)) {
			abp = true
			return errFeedEnd
		}
		return nil
	})
	if err != nil && err != errFeedEnd {
		return false, err
	}
	return abp, nil
}

var abpFeedHostRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$`)

// host is pfb_dnsbl_abp_feed_host(): token as a real hostname, lower-case ASCII (every label letters, digits and inner
// hyphens, an ICANN TLD), or false.
func (t *ICANNTLDs) host(token string) (string, bool) {
	token = strings.TrimRight(token, ".")
	host := token
	if a, ok := IDNToASCII(token); ok && !phpEmpty(a) {
		host = a
	}
	host = asciiLower(host)
	if len(host) > 253 {
		return "", false
	}
	m := abpFeedHostRE.FindStringSubmatch(host)
	if m == nil || t == nil || !t.set[m[1]] {
		return "", false
	}
	return host, true
}

var (
	abpCommentRE  = regexp.MustCompile(`(?s)[ \t\n\v\f\r]#.*$`)
	abpHostPortRE = regexp.MustCompile(`^([^:/]+)(?::([0-9]{1,5}))?/?$`)
	abpMaskRE     = regexp.MustCompile(`^(\||://)?([^|^$*/]+)[|^](\$important)?$`)
)

// abpFeedLine is pfb_dnsbl_abp_feed_line(): in an Adblock feed, a line that is not an Adblock rule is kept only as a
// hostname (with ':<port>' and/or '/'), a hosts line (its first host, all of them real hostnames) or an AdGuard DNS
// hostname mask. '|host^', '|host|' and '://host^' are the host alone; 'host^' and 'host|' become '||host^', keeping
// '$important'; '.host^', '*' masks and every other modifier are dropped. ok is false for a dropped line.
func (t *ICANNTLDs) abpFeedLine(line string) (DNSBLRow, bool) {
	if strings.Contains(line, "\x00") {
		return DNSBLRow{}, false
	}
	line = phpTrim(abpCommentRE.ReplaceAllString(line, ""))
	var fields []string
	for _, f := range splitWhitespace(line) {
		if f != "" {
			fields = append(fields, f)
		}
	}
	if len(fields) >= 2 && (isIPAddrV4(fields[0]) || isIPAddrV6(fields[0])) {
		first, ok := t.host(fields[1])
		for _, alias := range fields[2:] {
			if !ok {
				break
			}
			_, ok = t.host(alias)
		}
		if !ok {
			return DNSBLRow{}, false
		}
		return DNSBLRow{Text: first}, true
	}
	if len(fields) != 1 {
		return DNSBLRow{}, false
	}
	if m := abpHostPortRE.FindStringSubmatch(line); m != nil && (m[2] == "" || validPort(m[2])) {
		if h, ok := t.host(m[1]); ok {
			return DNSBLRow{Text: h}, true
		}
	}
	m := abpMaskRE.FindStringSubmatch(line)
	if m == nil {
		return DNSBLRow{}, false
	}
	h, ok := t.host(m[2])
	if !ok {
		return DNSBLRow{}, false
	}
	if m[1] != "" {
		return DNSBLRow{Text: h}, true
	}
	return DNSBLRow{ABP: true, Text: "||" + h + "^" + m[3]}, true
}

// validPort is a decimal port 1 to 65535 of at most five digits.
func validPort(digits string) bool {
	n, err := strconv.Atoi(digits)
	return err == nil && len(digits) <= 5 && n >= 1 && n <= 65535
}
