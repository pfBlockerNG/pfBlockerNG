package feedfetch

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

type sourceKind int

const (
	kindRemote     sourceKind = iota // http/https through the vetted, pinned transfer
	kindSelfHosted                   // an http URL on the host itself, at the web root
	kindLocal                        // a file directly in one of Policy.LocalDirs
	kindRsync
)

type source struct {
	kind   sourceKind
	url    *url.URL // remote and self-hosted
	scheme string
	host   string // UTS #46-mapped (a non-ASCII host as its A-label); rsync: the host part
	port   int
	path   string       // local: the resolved file; remote: the URL requested, host mapped; rsync: the source as configured
	self   []netip.Addr // self-hosted: the addresses the host was classified self at
	file   os.FileInfo  // local: the file that was checked
}

var (
	schemeName  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*$`)
	portNumber  = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})$`)
	absoluteRef = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)
)

// rawURL is parse_url()'s view of an absolute URL: the host is taken verbatim, before any decoding.
type rawURL struct {
	scheme, user, host, port, path, query string
}

func parseRaw(s string) (rawURL, bool) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || !schemeName.MatchString(scheme) {
		return rawURL{}, false
	}
	r := rawURL{scheme: strings.ToLower(scheme)}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		r.user, authority = authority[:at], authority[at+1:]
	}
	r.host = authority
	if i := strings.LastIndex(authority, ":"); i >= 0 && !strings.HasPrefix(authority, "[") {
		r.host, r.port = authority[:i], authority[i+1:]
	} else if strings.HasPrefix(authority, "[") {
		if j := strings.Index(authority, "]"); j >= 0 {
			r.host = authority[:j+1]
			r.port = strings.TrimPrefix(authority[j+1:], ":")
		}
	}
	// FILTER_VALIDATE_URL refuses any other spelling; one such as "080" would also dial unpinned.
	if n, err := strconv.Atoi(r.port); r.port != "" && (!portNumber.MatchString(r.port) || err != nil || n > 65535) {
		return rawURL{}, false
	}
	tail, _, _ = strings.Cut(tail, "#")
	r.path, r.query, _ = strings.Cut(tail, "?")
	return r, true
}

var schemePorts = map[string]int{"http": 80, "https": 443, "ftp": 21, "rsync": 873}

func (r rawURL) portNum() int {
	if n, err := strconv.Atoi(r.port); err == nil {
		return n
	}
	return schemePorts[r.scheme]
}

// withHost is the URL with its host replaced, as pfb_feed_redirect_target rebuilds a redirect target on its mapped host.
func (r rawURL) withHost(host string) string {
	u := r.scheme + "://"
	if r.user != "" {
		u += r.user + "@"
	}
	u += host
	if r.port != "" {
		u += ":" + r.port
	}
	u += r.path
	if r.query != "" {
		u += "?" + r.query
	}
	return u
}

// literalReason refuses a host that a client would not dial as written and returns the host to resolve, vet and dial
// (pfb_feed_host_literal_reason: same checks, same order, same reasons). A non-ASCII host is converted by
// feedparse.IDNToASCII, the pfb-dns profile and not ICU's (owner decision, #3813); the result must be a plain DNS host
// name, and no IP literal.
func literalReason(host string) (mapped, reason string) {
	if strings.HasPrefix(host, "[") {
		return "", "feed host is a bracketed IPv6 literal"
	}
	mapped = host
	if strings.IndexFunc(host, func(r rune) bool { return r >= 0x80 }) >= 0 {
		var ok bool
		if mapped, ok = feedparse.IDNToASCII(host); !ok {
			return "", "feed host is not a valid IDN name"
		}
	}
	if strings.Contains(mapped, "%") {
		return "", "feed host is percent-encoded"
	}
	// The mapping can yield URL delimiters ('@', '/'): only a plain DNS host name stays.
	if mapped != host && !validHostname(mapped) {
		return "", "feed host is not a valid IDN name"
	}
	// A mapped host is never canonical: it differs from the host as written.
	if shaped, ip := ipv4Numeric(mapped); shaped && ip != host {
		return "", "feed host is a non-canonical IP literal"
	}
	return mapped, ""
}

// ipv4Numeric decodes a numeric-shaped host as the WHATWG URL parser and libcurl do (pfb_ipv4_numeric_host): shaped
// is false when the last label is neither decimal nor 0x-hex; ip is the dotted quad, or "" when shaped but invalid.
func ipv4Numeric(host string) (shaped bool, ip string) {
	if strings.Contains(host, ":") {
		return false, ""
	}
	parts := strings.Split(host, ".")
	trailingDot := len(parts) > 1 && parts[len(parts)-1] == ""
	if trailingDot {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	isHex := len(last) >= 2 && strings.EqualFold(last[:2], "0x") && allIn(last[2:], "0123456789abcdefABCDEF")
	if !(last != "" && allIn(last, "0123456789")) && !isHex {
		return false, ""
	}
	if len(parts) > 4 || (trailingDot && len(parts) < 4) {
		return true, ""
	}
	nums := make([]uint64, 0, len(parts))
	for _, p := range parts {
		n, ok := ipv4Number(p)
		if !ok {
			return true, ""
		}
		nums = append(nums, n)
	}
	v := nums[len(nums)-1]
	if v >= 1<<(8*(5-len(nums))) {
		return true, ""
	}
	for i, n := range nums[:len(nums)-1] {
		if n > 255 {
			return true, ""
		}
		v += n << (8 * (3 - i))
	}
	return true, netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

func ipv4Number(p string) (uint64, bool) {
	radix, digits, maxDigits := 10, "0123456789", 10
	switch {
	case len(p) >= 2 && strings.EqualFold(p[:2], "0x"):
		p, radix, digits, maxDigits = p[2:], 16, "0123456789abcdefABCDEF", 8
	case len(p) > 1 && p[0] == '0':
		p, radix, digits, maxDigits = p[1:], 8, "01234567", 11
	case p == "":
		return 0, false
	}
	if p == "" {
		return 0, true
	}
	if !allIn(p, digits) {
		return 0, false
	}
	if len(strings.TrimLeft(p, "0")) > maxDigits {
		return 1 << 40, true // out of range either way
	}
	n, _ := strconv.ParseUint(p, radix, 64)
	return n, true
}

const wordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

func allIn(s, set string) bool {
	for i := range len(s) {
		if !strings.ContainsRune(set, rune(s[i])) {
			return false
		}
	}
	return true
}

var (
	internalV4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")
	internalV6 = prefixes("::/128", "::1/128", "fc00::/7", "fe80::/10")
	loopbacks  = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// internal reports a non-public address (pfb_ip_is_internal); an IPv4-mapped address is checked as IPv4.
func internal(a netip.Addr) bool {
	ranges := internalV6
	if a = a.Unmap(); a.Is4() {
		ranges = internalV4
	}
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (p *Policy) self(a netip.Addr) bool {
	return slices.Contains(loopbacks, a) || slices.Contains(p.Self, a)
}

func (p *Policy) allowed(a netip.Addr) bool {
	for _, pre := range p.Allow {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

// candidates is the host's address set: the literal itself, or what the resolver returns.
func (p *Policy) candidates(ctx context.Context, host string) []netip.Addr {
	if a, err := netip.ParseAddr(host); err == nil && a.Zone() == "" {
		return []netip.Addr{a}
	}
	resolve := p.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := resolve(ctx, strings.TrimSuffix(host, "."))
	if err != nil {
		return nil
	}
	return addrs
}

// vet is the feed-host guard (pfb_feed_host_allowed): it refuses a host with any non-public address that is neither
// the host's own nor exempted, and returns the first address for the connection to be pinned to and the mapped host
// that address was resolved for ("" on a refusal).
func (p *Policy) vet(ctx context.Context, host string) (pin netip.Addr, mapped, reason string) {
	if host == "" {
		return netip.Addr{}, "", "feed host is empty"
	}
	mapped, reason = literalReason(host)
	if reason != "" {
		return netip.Addr{}, "", reason
	}
	addrs := p.candidates(ctx, mapped)
	if len(addrs) == 0 {
		return netip.Addr{}, "", "feed host did not resolve"
	}
	for _, a := range addrs {
		if internal(a) && !p.self(a) && !p.allowed(a) {
			return netip.Addr{}, "", "feed host resolves to a non-permitted address"
		}
	}
	return addrs[0], mapped, ""
}

// entry is the feed-URL gate (PFB_FILTER_URL) plus the source classification pfb_download() makes after it.
func (f *Fetcher) entry(ctx context.Context, req Request) (*source, string) {
	raw := strings.TrimSpace(req.URL)
	if strings.HasPrefix(raw, "file://") {
		if req.Rsync {
			return nil, ""
		}
		return f.localSource(raw)
	}

	src := &source{kind: kindRemote, path: raw}
	var dir string
	var r rawURL
	if host, module, ok := strings.Cut(raw, "::"); ok && req.Rsync && !strings.Contains(module, "::") &&
		host != "" && validHostname(host) {
		src.kind, src.scheme, src.host, dir = kindRsync, "rsync", host, phpDirname(module)
	} else {
		r, ok = parseRaw(raw)
		if !ok {
			return nil, ""
		}
		switch {
		case req.Rsync && r.scheme == "rsync":
			src.kind = kindRsync
		case req.Rsync || (r.scheme != "http" && r.scheme != "https"):
			return nil, "" // ftp is not supported yet; rsync is a format, not a URL scheme
		}
		if r.host == "" {
			return nil, ""
		}
		src.scheme, src.host, src.port, dir = r.scheme, r.host, r.portNum(), phpDirname(r.path)
	}
	mapped, reason := literalReason(src.host)
	if reason != "" {
		return nil, reason
	}
	// An rsync source goes on as written (the vetted address replaces its host); any other is requested on the mapped host.
	if mapped != src.host && src.kind != kindRsync {
		src.path = r.withHost(mapped)
	}
	src.host = mapped
	addrs := f.candidates(ctx, src.host)
	if len(addrs) == 0 {
		return nil, "feed host did not resolve"
	}
	selfOnly := src.host == "127.0.0.1" || src.host == "::1"
	if !selfOnly {
		selfOnly = true
		for _, a := range addrs {
			selfOnly = selfOnly && f.self(a)
		}
	}
	switch {
	case selfOnly && dir != "/":
		return nil, ""
	case selfOnly && src.kind == kindRemote:
		src.kind, src.self = kindSelfHosted, addrs // read from these addresses, never resolved again (#3911)
	case !selfOnly && !f.NoFilter:
		if _, _, reason := f.vet(ctx, src.host); reason != "" {
			return nil, reason
		}
	}
	if src.kind != kindRsync {
		u, err := url.Parse(src.path)
		if err != nil {
			return nil, ""
		}
		src.url = u
	}
	return src, ""
}

// localSource admits a file sitting directly in one of the local directories, symlinks resolved.
func (f *Fetcher) localSource(raw string) (*source, string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Host != "" && u.Host != "localhost") {
		return nil, ""
	}
	real, err := filepath.EvalSymlinks(u.Path)
	if err != nil {
		return nil, ""
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ""
	}
	for _, d := range f.LocalDirs {
		if rd, err := filepath.EvalSymlinks(d); err == nil && filepath.Dir(real) == rd {
			return &source{kind: kindLocal, path: real, file: info}, ""
		}
	}
	return nil, ""
}

// validHostname is FILTER_VALIDATE_DOMAIN with FILTER_FLAG_HOSTNAME.
func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			!allIn(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") {
			return false
		}
	}
	return true
}

// phpDirname is pathinfo($path, PATHINFO_DIRNAME): a self-hosted feed must sit at the web root ("/").
func phpDirname(p string) string {
	if p == "" {
		return ""
	}
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/"
	}
	i := strings.LastIndex(t, "/")
	switch {
	case i < 0:
		return "."
	case i == 0:
		return "/"
	}
	if d := strings.TrimRight(t[:i], "/"); d != "" {
		return d
	}
	return "/"
}

// resolveRelative resolves a redirect Location against the URL it came from (pfb_resolve_relative_url): absolute,
// scheme-relative, absolute-path, or relative to the base path's directory, without dot-segment removal.
func resolveRelative(ref, base string) string {
	if ref == "" {
		return ""
	}
	if absoluteRef.MatchString(ref) {
		return ref
	}
	b, ok := parseRaw(base)
	if !ok || b.host == "" {
		return ""
	}
	auth := b.host
	if b.port != "" {
		auth += ":" + b.port
	}
	switch {
	case strings.HasPrefix(ref, "//"):
		return b.scheme + ":" + ref
	case ref[0] == '/':
		return b.scheme + "://" + auth + ref
	}
	dir := b.path
	if dir == "" {
		dir = "/"
	}
	dir = dir[:strings.LastIndex(dir, "/")+1]
	if dir == "" || dir[0] != '/' {
		dir = "/" + dir
	}
	return b.scheme + "://" + auth + dir + ref
}

// redirectTarget resolves and checks one redirect hop (pfb_feed_redirect_target): only http(s), and with the filter on
// the target host is vetted and its address returned for the pin.
func (f *Fetcher) redirectTarget(ctx context.Context, location, current string) (string, rawURL, netip.Addr, string) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", rawURL{}, netip.Addr{}, "feed redirect has no target"
	}
	target := resolveRelative(location, current)
	if target == "" {
		return "", rawURL{}, netip.Addr{}, "feed redirect target could not be resolved"
	}
	r, ok := parseRaw(target)
	if !ok || r.host == "" || (r.scheme != "http" && r.scheme != "https") {
		return "", rawURL{}, netip.Addr{}, "feed redirect target is not an http(s) URL"
	}
	if f.NoFilter {
		return target, r, netip.Addr{}, "" // as cURL's own following: no vetting, no pin
	}
	pin, mapped, reason := f.vet(ctx, r.host)
	if reason == "" && mapped != r.host {
		target, r.host = r.withHost(mapped), mapped // the request stays on the name that was vetted, as PHP rebuilds it
	}
	return target, r, pin, reason
}

// pinRsync substitutes the vetted address for the host of an rsync source (pfb_rsync_pin_url).
func pinRsync(src string, ip netip.Addr) string {
	ipURL := ip.String()
	if ip.Is6() {
		ipURL = "[" + ipURL + "]"
	}
	if len(src) >= 8 && strings.EqualFold(src[:8], "rsync://") {
		rest := src[8:]
		authority, path := rest, ""
		if i := strings.Index(rest, "/"); i >= 0 {
			authority, path = rest[:i], rest[i:]
		}
		if authority == "" {
			return ""
		}
		user, hostport := "", authority
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			user, hostport = authority[:at+1], authority[at+1:]
		}
		port := ""
		if hostport != "" && hostport[0] != '[' {
			if c := strings.LastIndex(hostport, ":"); c >= 0 {
				port = hostport[c:]
			}
		}
		return "rsync://" + user + ipURL + port + path
	}
	host, module, ok := strings.Cut(src, "::")
	if !ok || host == "" {
		return ""
	}
	user := ""
	if at := strings.LastIndex(host, "@"); at >= 0 {
		user = host[:at+1]
	}
	return user + ip.String() + "::" + module
}
