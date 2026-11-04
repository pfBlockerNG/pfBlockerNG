package main

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3583: with --ddr the gateway answers every query at or under resolver.arpa. itself (RFC 9462), after the ACL and
// before the decider. _dns.resolver.arpa. SVCB over plain DNS designates the encrypted transports bound on the address the
// client queried; everything else under the zone is NODATA, apart from the apex SOA and NS. Every record names the DNS name
// (--dns-name, issue #3694).

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

// ddr is what answers DDR queries; built once at start. Only the listener addresses (change) and the set of addresses DoH is
// advertised on at 443 (setDoH443) change afterwards.
type ddr struct {
	target  dnsmessage.Name // the DNS name (--dns-name), which every record names
	certs   *certStore      // nil when no TLS transport is configured
	port443 uint16          // the port of a DoH listener that is advertised as 443: 443, but for a test
	addrs   atomic.Pointer[ddrAddrs]
	doh443  atomic.Pointer[map[netip.Addr]struct{}] // --ddr-doh-443 and the address table: DoH is advertised without a port on these
}

// ddrAddrs are the listeners DDR designates: unmapped, no zone. A stored value is never edited, so a query that loaded it
// reads one consistent set.
type ddrAddrs struct{ dot, doh, doq []netip.AddrPort }

// newDDR builds the answerer from the flags and the listeners that are bound; dot, doh and doq are their addresses. The set of
// addresses advertised on 443 starts empty.
func newDDR(target string, certs *certStore, dot, doh, doq []netip.AddrPort) (*ddr, error) {
	name, err := dnsName(target)
	if err != nil {
		return nil, err
	}
	d := &ddr{target: name, certs: certs, port443: ddrDoHPort}
	d.addrs.Store(&ddrAddrs{dot: ddrBound(dot), doh: ddrBound(doh), doq: ddrBound(doq)})
	d.setDoH443(nil)
	return d, nil
}

// setDoH443 replaces the addresses DDR advertises DoH on without a port, and returns the set it replaced. Its writers are
// start() and the control socket's one goroutine, so the replaced set is the one the caller's change is measured against.
func (d *ddr) setDoH443(set map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	if set == nil {
		set = map[netip.Addr]struct{}{}
	}
	old := d.doh443.Swap(&set)
	if old == nil {
		return nil
	}
	return *old
}

// ddrOnListeners is newDDR over the TLS listeners start() bound (t is nil without any), so a port the kernel picked for a
// port-0 flag is the one a client is told, with the --ddr-doh-443 addresses.
func ddrOnListeners(cfg config, t *tlsListeners) (*ddr, error) {
	var certs *certStore
	var dot, doh, doq []netip.AddrPort
	if t != nil {
		certs = t.certs
		for _, ln := range t.dot {
			dot = append(dot, ln.Addr().(*net.TCPAddr).AddrPort())
		}
		for _, ln := range t.doh {
			doh = append(doh, ln.Addr().(*net.TCPAddr).AddrPort())
		}
		for _, c := range t.doq {
			doq = append(doq, c.LocalAddr().(*net.UDPAddr).AddrPort())
		}
	}
	d, err := newDDR(cfg.dnsName, certs, dot, doh, doq)
	if err != nil {
		return nil, err
	}
	set, err := doh443Set(cfg.ddrDoH443)
	if err != nil {
		return nil, err
	}
	d.setDoH443(set)
	d.port443 = uint16(cfg.port443())
	return d, nil
}

// doh443Set is the set --ddr-doh-443 values make: IP addresses with no zone, IPv4-mapped ones unmapped. The first bad value is
// the error.
func doh443Set(values []string) (map[netip.Addr]struct{}, error) {
	set := make(map[netip.Addr]struct{}, len(values))
	for _, v := range values {
		ip, err := parseNameIP(v)
		if err != nil {
			return nil, fmt.Errorf("--ddr-doh-443 %.64q: %w", v, err)
		}
		set[ip] = struct{}{}
	}
	return set, nil
}

func ddrBound(in []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, len(in))
	for i, ap := range in {
		out[i] = netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
	}
	return out
}

// change makes designation follow a listener that was added or removed live; udp+tcp is not designated. A nil d (no --ddr)
// has nothing to follow. The writer is the control socket's one goroutine (the listenerSet's contract), so a plain Store
// cannot lose an update.
func (d *ddr) change(add bool, kind string, ap netip.AddrPort) {
	if d == nil {
		return
	}
	old := d.addrs.Load()
	next := &ddrAddrs{dot: old.dot, doh: old.doh, doq: old.doq}
	var on *[]netip.AddrPort
	switch kind {
	case "dot":
		on = &next.dot
	case "doh":
		on = &next.doh
	case "doq":
		on = &next.doq
	default:
		return
	}
	one := ddrBound([]netip.AddrPort{ap})[0]
	if add {
		*on = append(slices.Clone(*on), one)
	} else {
		*on = slices.DeleteFunc(slices.Clone(*on), func(have netip.AddrPort) bool { return have == one })
	}
	d.addrs.Store(next)
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

	msg := replyTo(h, q)
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
	return packReply(wire, msg, size, edns, udp)
}

// replyTo is the reply to the query behind h and q that this gateway makes itself (DDR and the DNS name): authoritative,
// recursion available, RD and CD as the query had them, the question as asked. The caller fills the sections.
func replyTo(h dnsmessage.Header, q dnsmessage.Question) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: h.ID, Response: true, Authoritative: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
			RecursionAvailable: true, CheckingDisabled: h.CheckingDisabled,
		},
		Questions: []dnsmessage.Question{q},
	}
}

// packReply is msg on the wire, with the OPT record the query's EDNS earned. size and edns are clientOPT's; a UDP reply over
// what the client can take (at least 512 bytes, at most 1232) is the empty answer with TC set. A message that cannot be packed
// is SERVFAIL.
func packReply(wire []byte, msg dnsmessage.Message, size uint16, edns, udp bool) []byte {
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

// dohAdvertised is the port DDR advertises DoH on at local, and whether DoH listens there. It is 443 when a listener on local is
// on the 443 port, or local is in the set of addresses advertised on 443 (clients reach those through something on 443): the
// record then has no port. Otherwise it is the port of the DoH listener on local. Several listeners on local are one record.
func (d *ddr) dohAdvertised(on []netip.AddrPort, local netip.Addr) (port uint16, listening bool) {
	for _, ap := range on {
		if ap.Addr() != local {
			continue
		}
		if ap.Port() == d.port443 {
			return ddrDoHPort, true
		}
		if !listening {
			port, listening = ap.Port(), true
		}
	}
	if _, advertised := (*d.doh443.Load())[local]; listening && advertised {
		return ddrDoHPort, true
	}
	return port, listening
}

// designate is the SVCB answer for owner on the plain address local, and the address record for the firewall's name that
// goes with it. Both are empty while no certificate is loaded (every handshake would fail), when no transport listens
// on local, and when local names no address a client queried: the zero Addr, or the wildcard that a datagram socket bound
// to one reports as its own address.
func (d *ddr) designate(owner dnsmessage.Name, local netip.Addr) (answers, extra []dnsmessage.Resource) {
	if d.certs == nil || d.certs.cert.Load() == nil {
		return nil, nil
	}
	local = local.Unmap().WithZone("")
	if !local.IsValid() || local.IsUnspecified() {
		return nil, nil
	}
	a := d.addrs.Load()
	if port, ok := d.dohAdvertised(a.doh, local); ok {
		answers = append(answers, ddrRecord(owner, d.target, 1, "h2", port, ddrDoHPort, local, dohPath))
	}
	if port, ok := ddrListening(a.dot, local); ok {
		answers = append(answers, ddrRecord(owner, d.target, 2, "dot", port, defaultDoTPort, local, ""))
	}
	if port, ok := ddrListening(a.doq, local); ok {
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
