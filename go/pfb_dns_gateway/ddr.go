package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3583: with --ddr the gateway answers every query at or under resolver.arpa. itself (RFC 9462), after the ACL and
// before the decider. _dns.resolver.arpa. SVCB over plain DNS designates the encrypted transports bound on the address the
// client queried; everything else under the zone is NODATA, apart from the apex SOA and NS.

const (
	ddrTTL        = 300
	ddrZone       = "resolver.arpa."
	ddrDesignated = "_dns.resolver.arpa."
	ddrUDPFloor   = 512  // what a UDP reply may carry without EDNS (RFC 1035 4.2.1), and the least with it
	ddrUDPCeiling = 1232 // advertised in the OPT of every reply with one, and the most a UDP reply carries
	ddrDoHPort    = 443
	ddrDoQPort    = 853
)

var (
	ddrZoneName  = dnsmessage.MustNewName(ddrZone)
	ddrLocalhost = dnsmessage.MustNewName("localhost.")
	ddrNobody    = dnsmessage.MustNewName("nobody.invalid.")
)

// ddr is what answers DDR queries; built once at start, read-only afterwards.
type ddr struct {
	target        dnsmessage.Name  // the firewall's FQDN, which every record names
	doh443        bool             // --ddr-doh-443: the DoH record has no port, whatever port DoH listens on
	certs         *certStore       // nil when no TLS transport is configured
	dot, doh, doq []netip.AddrPort // the bound listeners: unmapped, no zone
}

// ddrName is the --ddr value as an absolute name; one trailing dot is optional.
func ddrName(s string) (dnsmessage.Name, error) {
	bad := func(why string) error { return fmt.Errorf("--ddr %q: %s", s, why) }
	host := strings.TrimSuffix(s, ".")
	if host == "" {
		return dnsmessage.Name{}, bad("empty name")
	}
	if len(host) > 253 {
		return dnsmessage.Name{}, bad("longer than 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return dnsmessage.Name{}, bad("every label must be 1 to 63 bytes")
		}
	}
	return dnsmessage.NewName(host + ".")
}

// newDDR builds the answerer from the flags and the listeners that are bound; dot, doh and doq are their addresses.
func newDDR(target string, doh443 bool, certs *certStore, dot, doh, doq []netip.AddrPort) (*ddr, error) {
	name, err := ddrName(target)
	if err != nil {
		return nil, err
	}
	return &ddr{target: name, doh443: doh443, certs: certs, dot: ddrBound(dot), doh: ddrBound(doh), doq: ddrBound(doq)}, nil
}

// ddrOnListeners is newDDR over the TLS listeners start() bound (t is nil without any), so a port the kernel picked for a
// port-0 flag is the one a client is told.
func ddrOnListeners(cfg config, t *tlsListeners) (*ddr, error) {
	if t == nil {
		return newDDR(cfg.ddr, cfg.ddrDoH443, nil, nil, nil, nil)
	}
	var dot, doh, doq []netip.AddrPort
	for _, ln := range t.dot {
		dot = append(dot, ln.Addr().(*net.TCPAddr).AddrPort())
	}
	for _, ln := range t.doh {
		doh = append(doh, ln.Addr().(*net.TCPAddr).AddrPort())
	}
	for _, c := range t.doq {
		doq = append(doq, c.LocalAddr().(*net.UDPAddr).AddrPort())
	}
	return newDDR(cfg.ddr, cfg.ddrDoH443, t.certs, dot, doh, doq)
}

func ddrBound(in []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, len(in))
	for i, ap := range in {
		out[i] = netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
	}
	return out
}

// answer is the reply to wire when it is a query for a name at or under resolver.arpa., and nil when it is not (it does
// not parse, is not opcode QUERY, has not exactly one question, or asks about another name). local is the address a plain
// query arrived on (the zero Addr over DoT, DoH and DoQ); udp limits the size of the reply.
func (d *ddr) answer(wire []byte, local netip.Addr, udp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	name := q.Name.Data[:q.Name.Length]
	apex := asciiEqualFold(name, ddrZone)
	if i := len(name) - len(ddrZone); !apex && (i <= 0 || name[i-1] != '.' || !asciiEqualFold(name[i:], ddrZone)) {
		return nil
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return nil
	}
	size, edns := clientOPT(&p)

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: h.ID, Response: true, Authoritative: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
			RecursionAvailable: true, CheckingDisabled: h.CheckingDisabled,
		},
		Questions: []dnsmessage.Question{q},
	}
	switch {
	case q.Class != dnsmessage.ClassINET:
	case q.Type == dnsmessage.TypeSVCB && asciiEqualFold(name, ddrDesignated):
		msg.Answers, msg.Additionals = d.designate(q.Name, local)
	case apex && q.Type == dnsmessage.TypeSOA:
		msg.Answers = []dnsmessage.Resource{soaRecord(q.Name)}
	case apex && q.Type == dnsmessage.TypeNS:
		msg.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ddrTTL},
			Body:   &dnsmessage.NSResource{NS: ddrLocalhost},
		}}
	}
	if len(msg.Answers) == 0 {
		msg.Authorities = []dnsmessage.Resource{soaRecord(ddrZoneName)}
	}
	var opt []dnsmessage.Resource
	if edns {
		var oh dnsmessage.ResourceHeader
		_ = oh.SetEDNS0(ddrUDPCeiling, dnsmessage.RCodeSuccess, false)
		opt = []dnsmessage.Resource{{Header: oh, Body: &dnsmessage.OPTResource{}}}
		msg.Additionals = append(msg.Additionals, opt...)
	}
	out, err := msg.Pack()
	if err != nil {
		return buildServfail(wire)
	}
	limit := ddrUDPFloor
	if edns {
		limit = min(max(int(size), ddrUDPFloor), ddrUDPCeiling)
	}
	if udp && len(out) > limit {
		msg.Answers, msg.Authorities, msg.Additionals, msg.Truncated = nil, nil, opt, true
		out, _ = msg.Pack()
	}
	return out
}

// clientOPT is the UDP payload size the query's OPT record advertises; ok is false when it has none, or when what follows
// the question does not parse (the query then gets the answer a client without EDNS gets).
func clientOPT(p *dnsmessage.Parser) (size uint16, ok bool) {
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return 0, false
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return 0, false
		}
		if h.Type == dnsmessage.TypeOPT {
			return uint16(h.Class), true
		}
		if p.SkipAdditional() != nil {
			return 0, false
		}
	}
}

// asciiEqualFold compares a with lower, which is lower case: DNS folds ASCII only, which strings.EqualFold does not.
func asciiEqualFold(a []byte, lower string) bool {
	if len(a) != len(lower) {
		return false
	}
	for i, c := range a {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// soaRecord is the SOA of Unbound's resolver.arpa. zone, with a TTL of 300 so a negative answer is not cached for hours
// after a transport is switched on.
func soaRecord(owner dnsmessage.Name) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: ddrTTL},
		Body: &dnsmessage.SOAResource{NS: ddrLocalhost, MBox: ddrNobody, Serial: 1, Refresh: 3600, Retry: 1200, Expire: 604800,
			MinTTL: ddrTTL},
	}
}

// designate is the SVCB answer for owner on the plain address local, and the address record for the firewall's name that
// goes with it. Both are empty while no certificate is loaded (every handshake would fail) and when no transport listens
// on local.
func (d *ddr) designate(owner dnsmessage.Name, local netip.Addr) (answers, extra []dnsmessage.Resource) {
	if d.certs == nil || d.certs.cert.Load() == nil {
		return nil, nil
	}
	local = local.Unmap().WithZone("")
	if port, ok := ddrListening(d.doh, local); ok {
		if d.doh443 {
			port = ddrDoHPort
		}
		answers = append(answers, ddrRecord(owner, d.target, 1, "h2", port, ddrDoHPort, local, dohPath))
	}
	if port, ok := ddrListening(d.dot, local); ok {
		answers = append(answers, ddrRecord(owner, d.target, 2, "dot", port, defaultDoTPort, local, ""))
	}
	if port, ok := ddrListening(d.doq, local); ok {
		answers = append(answers, ddrRecord(owner, d.target, 3, "doq", port, ddrDoQPort, local, ""))
	}
	if len(answers) > 0 { // every record names the firewall, so the address of that name is owed
		h := dnsmessage.ResourceHeader{Name: d.target, Class: dnsmessage.ClassINET, TTL: ddrTTL}
		if local.Is4() {
			extra = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: local.As4()}}}
		} else {
			extra = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: local.As16()}}}
		}
	}
	return answers, extra
}

// ddrListening is the port of the listener on a (a listener bound to a wildcard is not matched).
func ddrListening(on []netip.AddrPort, a netip.Addr) (uint16, bool) {
	for _, ap := range on {
		if ap.Addr() == a {
			return ap.Port(), true
		}
	}
	return 0, false
}

// ddrRecord is one ServiceMode record (RFC 9460): the alpn id, a port unless it is the transport's own (RFC 9461 4.2
// makes `port` a mandatory key, so a client without support for it skips the record), the address hint, and for DoH the
// dohpath template (RFC 9461 5).
func ddrRecord(owner, target dnsmessage.Name, priority uint16, alpn string, port, std uint16, hint netip.Addr, dohpath string) dnsmessage.Resource {
	r := &dnsmessage.SVCBResource{Priority: priority, Target: target}
	r.SetParam(dnsmessage.SVCParamALPN, append([]byte{byte(len(alpn))}, alpn...))
	if port != std {
		r.SetParam(dnsmessage.SVCParamPort, []byte{byte(port >> 8), byte(port)})
	}
	if hint.Is4() {
		a := hint.As4()
		r.SetParam(dnsmessage.SVCParamIPv4Hint, a[:])
	} else {
		a := hint.As16()
		r.SetParam(dnsmessage.SVCParamIPv6Hint, a[:])
	}
	if dohpath != "" {
		r.SetParam(dnsmessage.SVCParamDOHPath, []byte(dohpath+"{?dns}"))
	}
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: ddrTTL}, Body: r}
}
