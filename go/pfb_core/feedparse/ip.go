package feedparse

import (
	"regexp"
	"strings"
)

// IPConfig is what the old path's pfb_ip_parse_line() reads for one feed: the list family (VType "_v4" or "_v6"), the
// parser (PFType "auto" or "regex"), whether it is a custom list, the Suppression CIDR Limit of each family ("Disabled"
// or a decimal string) and whether Suppression is on.
type IPConfig struct {
	VType, PFType    string
	Custom           bool
	FloorV4, FloorV6 string
	Suppression      bool
}

// IPLine is one parsed feed line: the entries to append, the line as the parse-error log shows it, and the counters.
type IPLine struct {
	Entries           []string
	Line              string
	Suppressed        bool
	ParseFail         int
	MappedDrops       int
	DetailedParseFail bool
	Messages          []string
}

// ParseIPLine is pfb_ip_parse_line_replay() for one line as fgets() returns it.
func ParseIPLine(raw string, cfg IPConfig) IPLine {
	p := parseIPLine(raw, cfg)
	out := IPLine{Line: p.line, Suppressed: p.suppressed, ParseFail: p.fail, DetailedParseFail: p.detailed, Messages: p.messages}
	for _, entry := range p.entries {
		// An IPv4-mapped entry on a v6 list never matches a packet: drop it and count it.
		head, _, _ := strings.Cut(entry, "/")
		if _, mapped := ipv4FromMapped(head); cfg.VType == "_v6" && mapped {
			out.ParseFail++
			out.MappedDrops++
			out.DetailedParseFail = true
			continue
		}
		out.Entries = append(out.Entries, entry)
	}
	return out
}

type ipParsed struct {
	entries    []string
	line       string
	suppressed bool
	fail       int
	detailed   bool
	messages   []string
}

var iblockRe = regexp.MustCompile(`^.*:((?:[0-9]{1,3}\.){3}[0-9]{1,3}-(?:[0-9]{1,3}\.){3}[0-9]{1,3})$`)

func parseIPLine(rawLine string, cfg IPConfig) ipParsed {
	line := phpTrim(rawLine)
	res := ipParsed{line: line}
	if isBlankOrComment(line) {
		return res
	}
	v4, v6 := cfg.VType == "_v4", cfg.VType == "_v6"
	auto := cfg.PFType == "auto"

	// A v6 token with text on both sides of a NUL is an address cut at the NUL: drop it, keep the other tokens.
	if v6 && strings.IndexByte(line, 0) >= 0 {
		line = phpTrim(dropNulCutTokens(line))
		rawLine = dropNulCutTokens(rawLine)
		if line == "" {
			return res
		}
	}

	parseError := false
	if v4 && auto {
		if m := iblockRe.FindStringSubmatch(line); m != nil {
			line = m[1]
		}
		line, _, _ = strings.Cut(line, " ")
		line, _, _ = strings.Cut(line, "#")
		line = phpTrim(line)
	}

	if v4 {
		whole := res.line
		if n := schemeLen(whole); strings.Contains(whole, "://") && n > 0 {
			// 'scheme://' + a non-canonical IPv4 host is decoded the way a client does; the regexes below then read only
			// the rest of the line, never the host or userinfo.
			rest := whole[n:]
			authority := rest[:strcspnLen(rest, "/\\?# \t\n\r\v\f")]
			host := authority
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				host = authority[at+1:]
			}
			host = stripPort(host)
			var ip string
			var numeric, valid bool
			if len(host) <= 253 && !strings.Contains(host, "-") {
				ip, numeric, valid = ipv4NumericHost(host)
			}
			if !numeric && strings.IndexByte(host, 0) >= 0 && !strings.Contains(host, "-") {
				if _, nul, _ := ipv4NumericHost(strings.ReplaceAll(host, "\x00", "")); nul {
					numeric, valid = true, false
				}
			}
			if numeric && (!valid || ip != host) {
				if !valid {
					res.fail++
					res.detailed = true
				} else {
					addr, ok, msgs := sanitizeIPv4(ip, cfg.Custom, cfg.FloorV4, cfg.Suppression)
					res.messages = append(res.messages, msgs...)
					res.messages = append(res.messages, "\n  IP literal decoded: [ "+host+" ] -> [ "+ip+" ]")
					if ok && !phpEmpty(addr) && validateIPv4(addr) {
						res.entries = append(res.entries, addr)
					}
				}
				rawLine = rest[len(authority):]
			}
		} else if mapped, ok := ipv4FromMapped(whole); ok {
			// A whole-line IPv4-mapped IPv6 address on a v4 list is its IPv4 address.
			res.messages = append(res.messages, "\n  IP literal decoded: [ "+whole+" ] -> [ "+mapped+" ]")
			line, rawLine = mapped, mapped
		}
	}

	// DShield start<TAB>end<TAB>prefix rows declare their own family: one exact CIDR is accepted, the opposite family left alone.
	if auto && strings.IndexByte(line, '\t') >= 0 {
		tab := strings.Split(line, "\t")
		family := ""
		if len(tab) >= 3 && ctypeDigit(tab[2]) && strings.IndexByte(tab[0], 0) < 0 && strings.IndexByte(tab[1], 0) < 0 {
			if validateIPv4(tab[0]) && validateIPv4(tab[1]) {
				family = "_v4"
			} else if validateIPv6(tab[0]) && validateIPv6(tab[1]) {
				family = "_v6"
			}
		}
		if family != "" {
			cidrs := ipRangeToSubnets(tab[0], tab[1])
			if len(cidrs) == 1 {
				if netw, bits, _ := strings.Cut(cidrs[0], "/"); bits == tab[2] && sameInetPton(netw, tab[0]) {
					res.line = line
					if family != cfg.VType {
						return res
					}
					var addr string
					var ok bool
					var msgs []string
					if v4 {
						addr, ok, msgs = sanitizeIPv4(cidrs[0], cfg.Custom, cfg.FloorV4, cfg.Suppression)
					} else {
						addr, ok, msgs = sanitizeIPv6(cidrs[0], cfg.Custom, cfg.FloorV6, cfg.Suppression)
					}
					res.messages = append(res.messages, msgs...)
					if ok && addr != "" && ((v4 && validateIPv4(addr)) || (v6 && validateIPv6(addr))) {
						res.entries = append(res.entries, addr)
					} else if v6 {
						res.suppressed = true
					}
					return res
				}
			}
		}
	}

	if v4 && auto {
		if strings.IndexByte(line, '-') >= 0 {
			m := strings.Split(line, "-")
			if len(m) == 2 && validateIPv4(m[0]) && validateIPv4(m[1]) {
				if cidrs := ipRangeToSubnets(m[0], m[1]); len(cidrs) > 0 {
					for _, cidr := range cidrs {
						addr, ok, msgs := sanitizeIPv4(cidr, cfg.Custom, cfg.FloorV4, cfg.Suppression)
						res.messages = append(res.messages, msgs...)
						if ok && !phpEmpty(addr) {
							if validateIPv4(addr) {
								res.entries = append(res.entries, addr)
							} else {
								parseError = true
							}
						}
					}
					if !parseError {
						res.line = line
						return res
					}
				}
			} else {
				parseError = true
			}
		}
		if !parseError {
			addr, ok, msgs := sanitizeIPv4(line, cfg.Custom, cfg.FloorV4, cfg.Suppression)
			res.messages = append(res.messages, msgs...)
			if ok && !phpEmpty(addr) && validateIPv4(addr) {
				res.entries = append(res.entries, addr)
				res.line = line
				return res
			}
			parseError = true
		}
	}

	if v4 && (!auto || parseError) {
		if strings.IndexByte(rawLine, '-') >= 0 && strings.IndexByte(rawLine, '.') >= 0 {
			if a, b, ok := ipv4RangeMatch(rawLine); ok {
				for _, cidr := range ipRangeToSubnets(a, b) {
					addr, okc, msgs := sanitizeIPv4(cidr, cfg.Custom, cfg.FloorV4, cfg.Suppression)
					res.messages = append(res.messages, msgs...)
					if okc && !phpEmpty(addr) && validateIPv4(addr) {
						res.entries = append(res.entries, addr)
					} else {
						res.fail++
					}
				}
				res.line = line
				return res
			}
		}
		if matches := ipv4Matches(rawLine); len(matches) > 0 {
			cf := strings.Contains(rawLine, "cf-footer-item")
			for _, match := range uniqueStrings(matches) {
				if cf {
					continue
				}
				addr, ok, msgs := sanitizeIPv4(match, cfg.Custom, cfg.FloorV4, cfg.Suppression)
				res.messages = append(res.messages, msgs...)
				if ok && !phpEmpty(addr) && validateIPv4(addr) {
					res.entries = append(res.entries, addr)
				}
			}
			res.line = line
			return res
		}
	}

	if v6 {
		if auto && strings.IndexByte(line, ':') >= 0 {
			line, _, _ = strings.Cut(line, "#")
			if validateIPv6(line) {
				v6Entry(&res, line, cfg)
				res.line = line
				return res
			}
		}
		if strings.Contains(line, "-") && strings.Contains(line, ":") {
			m := strings.Split(line, "-")
			if len(m) == 2 && strings.IndexByte(rawLine, 0) < 0 {
				for _, cidr := range ipRangeToSubnets(m[0], m[1]) {
					if phpEmpty(cidr) {
						continue
					}
					if validateIPv6(cidr) {
						v6Entry(&res, cidr, cfg)
					} else {
						parseError = true
					}
				}
				if !parseError {
					res.line = line
					return res
				}
			}
		}
		if matches := ipv6Matches(rawLine); len(matches) > 0 {
			cf := strings.Contains(rawLine, "cf-footer-item")
			for _, match := range uniqueStrings(matches) {
				match, _, _ = strings.Cut(match, "#")
				if !cf && validateIPv6(match) {
					v6Entry(&res, match, cfg)
				}
			}
			res.line = line
			return res
		}
	}

	// A bare hex/DWORD token is a parse failure despite its letters, but only when every dot-label is a number.
	bareNumeric := false
	if v4 {
		tok := stripMaskSuffix(line)
		if len(tok) <= 253 && bareNumericShape(tok) {
			if ip, numeric, valid := ipv4NumericHost(tok); numeric {
				bareNumeric = !valid || ip != line
			}
		}
	}
	if !phpEmpty(line) && (!hasTextByte(line) || bareNumeric) && !oppositeFamily(line, cfg.VType) {
		res.fail++
		res.detailed = true
	}
	res.line = line
	return res
}

// One validated v6 candidate: its sanitized entry, or the suppressed flag when sanitizing dropped it.
func v6Entry(res *ipParsed, candidate string, cfg IPConfig) {
	addr, ok, msgs := sanitizeIPv6(candidate, cfg.Custom, cfg.FloorV6, cfg.Suppression)
	res.messages = append(res.messages, msgs...)
	if ok && !phpEmpty(addr) {
		res.entries = append(res.entries, addr)
	} else {
		res.suppressed = true
	}
}

func sameInetPton(a, b string) bool {
	x, okx := phpInetPton(a)
	y, oky := phpInetPton(b)
	return okx == oky && string(x) == string(y)
}

func oppositeFamily(line, vtype string) bool {
	return (vtype == "_v4" && strings.Contains(line, ":") && validateIPv6(line)) ||
		(vtype == "_v6" && !strings.Contains(line, ":") && validateIPv4(line))
}

// preg_match('/[a-zA-Z,;|"\'?]/', $line)
func hasTextByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || strings.IndexByte(",;|\"'?", c) >= 0 {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// strcspn(): the length of the leading run holding none of chars.
func strcspnLen(s, chars string) int {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return i
	}
	return len(s)
}

// preg_replace('/:[0-9]*$/', ”, $host)
func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && (i == len(host)-1 || ctypeDigit(host[i+1:])) {
		return host[:i]
	}
	return host
}

// preg_replace('/\/[0-9]{1,2}$/', ”, $line)
func stripMaskSuffix(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 && len(s)-i-1 >= 1 && len(s)-i-1 <= 2 && ctypeDigit(s[i+1:]) {
		return s[:i]
	}
	return s
}

// The length of a leading `scheme://` ([a-z][a-z0-9+.-]*), else 0.
func schemeLen(s string) int {
	if s == "" || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		return 0
	}
	i := 1
	for i < len(s) && (isWordByte(s[i]) && s[i] != '_' || strings.IndexByte("+.-", s[i]) >= 0) {
		i++
	}
	if strings.HasPrefix(s[i:], "://") {
		return i + 3
	}
	return 0
}

// /^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+))*\.?$/i
func bareNumericShape(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		switch {
		case len(part) >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
			if !allHex(part[2:]) {
				return false
			}
		case !ctypeDigit(part):
			return false
		}
	}
	return true
}

func dropNulCutTokens(text string) string {
	var sb strings.Builder
	for i := 0; i < len(text); {
		j := i
		space := isPCRESpace(text[i])
		for j < len(text) && isPCRESpace(text[j]) == space {
			j++
		}
		if tok := text[i:j]; space || !nulCut(tok) {
			sb.WriteString(tok)
		}
		i = j
	}
	return sb.String()
}

func isPCRESpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// /[^\0-]\0+[^\0-]/: a maximal NUL run with a byte other than '-' on both sides.
func nulCut(tok string) bool {
	for i := 0; i < len(tok); {
		if tok[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(tok) && tok[j] == 0 {
			j++
		}
		if i > 0 && j < len(tok) && tok[i-1] != '-' && tok[j] != '-' {
			return true
		}
		i = j
	}
	return false
}

// pfb_is_blank_or_comment_line(): blank, or led by '#', '!' or '//', after the Unicode-aware strip.
func isBlankOrComment(line string) bool {
	s := pfbStrip(line)
	return s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "!") || strings.HasPrefix(s, "//")
}

// --- the feed regexes of pfb_ip_regex_config(), as backtracking matchers (RE2 has no lookaround) ---

type matcher func(s string, i int, k func(int) bool) bool

func ch(f func(byte) bool) matcher {
	return func(s string, i int, k func(int) bool) bool { return i < len(s) && f(s[i]) && k(i+1) }
}

func lit(c byte) matcher { return ch(func(b byte) bool { return b == c }) }

func rng(lo, hi byte) matcher { return ch(func(b byte) bool { return b >= lo && b <= hi }) }

func seq(ms ...matcher) matcher {
	return func(s string, i int, k func(int) bool) bool {
		var step func(n, i int) bool
		step = func(n, i int) bool {
			if n == len(ms) {
				return k(i)
			}
			return ms[n](s, i, func(j int) bool { return step(n+1, j) })
		}
		return step(0, i)
	}
}

func alt(ms ...matcher) matcher {
	return func(s string, i int, k func(int) bool) bool {
		for _, m := range ms {
			if m(s, i, k) {
				return true
			}
		}
		return false
	}
}

// Greedy repeat of lo to hi (hi < 0: unbounded).
func rep(lo, hi int, m matcher) matcher {
	return func(s string, i int, k func(int) bool) bool {
		var try func(i, n int) bool
		try = func(i, n int) bool {
			if (hi < 0 || n < hi) && m(s, i, func(j int) bool { return j > i && try(j, n+1) }) {
				return true
			}
			return n >= lo && k(i)
		}
		return try(i, 0)
	}
}

func opt(m matcher) matcher { return rep(0, 1, m) }

// A negative lookahead on one byte class.
func notAhead(f func(byte) bool) matcher {
	return func(s string, i int, k func(int) bool) bool { return (i >= len(s) || !f(s[i])) && k(i) }
}

func inSet(chars string) func(byte) bool {
	return func(b byte) bool { return isWordByte(b) || strings.IndexByte(chars, b) >= 0 }
}

var (
	wordDot      = inSet(".")
	wordDotSlash = inSet("./")
	wordColonDot = inSet(":.")

	digit4   = rng('0', '9')
	octetV4  = alt(seq(lit('2'), lit('5'), rng('0', '5')), seq(lit('2'), rng('0', '4'), digit4), seq(opt(rng('0', '1')), digit4, opt(digit4)))
	quadV4   = seq(rep(3, 3, seq(octetV4, lit('.'))), octetV4)
	rangeRe  = seq(quadV4, lit('-'), quadV4, notAhead(wordDot))
	ipv4Re   = seq(quadV4, opt(seq(lit('/'), alt(digit4, seq(rng('1', '2'), digit4), seq(lit('3'), rng('0', '2'))), notAhead(wordDotSlash))), notAhead(wordDot))
	hexRun   = rep(1, 4, ch(isHexDigit))
	colonHex = seq(lit(':'), hexRun)
	hexColon = seq(hexRun, lit(':'))
	octetDec = alt(seq(lit('2'), lit('5'), rng('0', '5')), seq(lit('2'), rng('0', '4'), digit4), seq(lit('1'), digit4, digit4), seq(opt(rng('1', '9')), digit4))
	dottedV4 = seq(octetDec, rep(3, 3, seq(lit('.'), octetDec)))
	ipv6Alt  = alt(
		seq(rep(7, 7, hexColon), alt(hexRun, lit(':'))),
		seq(rep(6, 6, hexColon), alt(colonHex, dottedV4, lit(':'))),
		seq(rep(5, 5, hexColon), alt(rep(1, 2, colonHex), seq(lit(':'), dottedV4), lit(':'))),
		seq(rep(4, 4, hexColon), alt(rep(1, 3, colonHex), seq(opt(colonHex), lit(':'), dottedV4), lit(':'))),
		seq(rep(3, 3, hexColon), alt(rep(1, 4, colonHex), seq(rep(0, 2, colonHex), lit(':'), dottedV4), lit(':'))),
		seq(rep(2, 2, hexColon), alt(rep(1, 5, colonHex), seq(rep(0, 3, colonHex), lit(':'), dottedV4), lit(':'))),
		seq(rep(1, 1, hexColon), alt(rep(1, 6, colonHex), seq(rep(0, 4, colonHex), lit(':'), dottedV4), lit(':'))),
		seq(lit(':'), alt(rep(1, 7, colonHex), seq(rep(0, 5, colonHex), lit(':'), dottedV4), lit(':'))),
	)
	ipv6Re = seq(ipv6Alt,
		opt(seq(lit('%'), rep(1, -1, ch(func(b byte) bool { return b != '\n' })))),
		opt(seq(lit('/'), alt(seq(lit('1'), alt(seq(lit('2'), rng('0', '8')), seq(rng('0', '1'), digit4))), seq(opt(rng('1', '9')), digit4)), notAhead(wordDotSlash))),
		notAhead(wordColonDot))
)

// scanAll runs m at every start whose previous byte is not in behind (the lookbehind) and yields each leftmost match.
func scanAll(m matcher, behind func(byte) bool, s string, yield func(start, end int) bool) {
	for i := 0; i <= len(s); {
		if i > 0 && behind(s[i-1]) {
			i++
			continue
		}
		end := -1
		if m(s, i, func(e int) bool { end = e; return true }) && end > i {
			if !yield(i, end) {
				return
			}
			i = end
			continue
		}
		i++
	}
}

func ipv4RangeMatch(s string) (a, b string, ok bool) {
	scanAll(rangeRe, wordDot, s, func(start, end int) bool {
		dash := start + strings.IndexByte(s[start:end], '-')
		a, b, ok = s[start:dash], s[dash+1:end], true
		return false
	})
	return
}

func allMatches(m matcher, behind func(byte) bool, s string) (out []string) {
	scanAll(m, behind, s, func(start, end int) bool {
		out = append(out, s[start:end])
		return true
	})
	return
}

// pfb_ip_regex_matches('v4', ...)
func ipv4Matches(s string) []string {
	if strings.Count(s, ".") < 3 {
		return nil
	}
	return allMatches(ipv4Re, wordDot, s)
}

// pfb_ip_regex_matches('v6', ...)
func ipv6Matches(s string) []string {
	if !strings.Contains(s, ":") {
		return nil
	}
	return allMatches(ipv6Re, wordColonDot, s)
}

// --- the parser type, from the dispatch in the apply script ---

// IPParseType is the parser the apply script picks for a feed: 'regex' for a regex-format list and for URLs whose
// extension (after pathinfo(), minus any query) is html, htm, php, aspx, cgi, csv, rules or empty, 'auto' otherwise;
// an iblocklist URL is 'auto'.
func IPParseType(format, url string) string {
	if format == "regex" {
		return "regex"
	}
	dir, ext, hasExt := phpPathinfo(url)
	if hasExt {
		ext, _, _ = strings.Cut(ext, "?")
	}
	if strings.Contains(dir, "iblocklist") {
		ext, hasExt = "iblock", true
	}
	// An undefined extension is null, which in_array() reads as equal to ''.
	if !hasExt {
		return "regex"
	}
	switch ext {
	case "html", "htm", "php", "aspx", "cgi", "csv", "rules", "":
		return "regex"
	}
	return "auto"
}

// pathinfo(): the dirname (php_dirname), and the extension of the basename if it has a dot.
func phpPathinfo(path string) (dirname, ext string, hasExt bool) {
	if path != "" {
		end := len(path) - 1
		for end >= 0 && path[end] == '/' {
			end--
		}
		switch {
		case end < 0:
			dirname = "/"
		default:
			for end >= 0 && path[end] != '/' {
				end--
			}
			if end < 0 {
				dirname = "."
			} else {
				for end >= 0 && path[end] == '/' {
					end--
				}
				if end < 0 {
					dirname = "/"
				} else {
					dirname = path[:end+1]
				}
			}
		}
	}
	base := strings.TrimRight(path, "/")
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		ext, hasExt = base[i+1:], true
	}
	return dirname, ext, hasExt
}
