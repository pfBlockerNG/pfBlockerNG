package main

import (
	"bytes"
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3583: with --ddr the gateway answers resolver.arpa. (RFC 9462) itself. Every expected record below is written
// out from the RFC or the contract, never taken from the code under test.

const (
	ddrTarget    = "fw.example.lan" // as PHP passes it: no trailing dot
	ddrFQDN      = "fw.example.lan."
	ddrAsk       = "_dns.resolver.arpa."
	ddrL4        = "192.0.2.1"
	ddrElsewhere = "198.51.100.1"
	ddrSOA       = "resolver.arpa. 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300"
	ddrNS        = "resolver.arpa. 300 IN NS localhost."
	ddrDoHPath   = "/dns-query{?dns}"
)

// ddrSVCB is one designation record as a client reads it.
type ddrSVCB struct {
	prio    uint16
	target  string
	alpn    string
	port    uint16 // 0: no port parameter
	hint    string // "": no ipv4hint or ipv6hint
	dohpath string // "": no dohpath parameter
}

func ddrDoHRec(target string, port uint16, hint, dohpath string) ddrSVCB {
	return ddrSVCB{prio: 1, target: target, alpn: "h2", port: port, hint: hint, dohpath: dohpath}
}

func ddrDoTRec(target string, port uint16, hint string) ddrSVCB {
	return ddrSVCB{prio: 2, target: target, alpn: "dot", port: port, hint: hint}
}

func ddrDoQRec(target string, port uint16, hint string) ddrSVCB {
	return ddrSVCB{prio: 3, target: target, alpn: "doq", port: port, hint: hint}
}

// ddrWant is everything a DDR reply holds besides its header and question; the OPT record is not in additional.
type ddrWant struct {
	svcb       []ddrSVCB
	answers    []string // the other Answer records, as text
	authority  []string
	additional []string
}

var ddrNODATA = ddrWant{authority: []string{ddrSOA}}

// ddrAddrRR is the text of the Additional address record for the firewall name.
func ddrAddrRR(owner, addr string) string {
	a := netip.MustParseAddr(addr)
	kind := "AAAA"
	if a.Is4() {
		kind = "A"
	}
	return fmt.Sprintf("%s 300 IN %s %s", owner, kind, a)
}

func ddrAt(addr string, port uint16) []netip.AddrPort {
	return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(addr), port)}
}

func mustDDR(t *testing.T, target string, doh443 bool, certs *certStore, dot, doh, doq []netip.AddrPort) *ddr {
	t.Helper()
	d, err := newDDR(target, doh443, certs, dot, doh, doq)
	if err != nil {
		t.Fatalf("newDDR(%q, %v): %v", target, doh443, err)
	}
	return d
}

func ddrLoaded(t *testing.T) *certStore {
	t.Helper()
	_, m := goodPEM(t)
	return m.certs
}

// ddrQueryWith packs one question, class IN; with opt != 0 an OPT record advertising that UDP payload size follows.
func ddrQueryWith(t testing.TB, h dnsmessage.Header, name string, typ dnsmessage.Type, opt uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{Header: h, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
	if opt != 0 {
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(int(opt), dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		msg.Additionals = []dnsmessage.Resource{{Header: rh, Body: &dnsmessage.OPTResource{}}}
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func ddrQuery(t testing.TB, id uint16, name string, typ dnsmessage.Type, opt uint16) []byte {
	t.Helper()
	return ddrQueryWith(t, dnsmessage.Header{ID: id, RecursionDesired: true}, name, typ, opt)
}

// ddrText is the zone-file form of an SOA, NS, A or AAAA record.
func ddrText(t *testing.T, rr dnsmessage.Resource) string {
	t.Helper()
	if rr.Header.Class != dnsmessage.ClassINET {
		t.Fatalf("record %s has class %v, want IN", rr.Header.Name, rr.Header.Class)
	}
	prefix := fmt.Sprintf("%s %d IN", rr.Header.Name, rr.Header.TTL)
	switch b := rr.Body.(type) {
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s SOA %s %s %d %d %d %d %d", prefix, b.NS, b.MBox, b.Serial, b.Refresh, b.Retry, b.Expire, b.MinTTL)
	case *dnsmessage.NSResource:
		return fmt.Sprintf("%s NS %s", prefix, b.NS)
	case *dnsmessage.AResource:
		return fmt.Sprintf("%s A %s", prefix, netip.AddrFrom4(b.A))
	case *dnsmessage.AAAAResource:
		return fmt.Sprintf("%s AAAA %s", prefix, netip.AddrFrom16(b.AAAA))
	}
	t.Fatalf("record %s has an unexpected body %T", rr.Header.Name, rr.Body)
	return ""
}

// ddrDecode reads an SVCB answer the way RFC 9460 section 2.2 defines its parameters; any other key is a failure.
func ddrDecode(t *testing.T, rr dnsmessage.Resource, owner string) ddrSVCB {
	t.Helper()
	b, ok := rr.Body.(*dnsmessage.SVCBResource)
	if !ok {
		t.Fatalf("an SVCB answer has the body %T", rr.Body)
	}
	if rr.Header.Name.String() != owner || rr.Header.Class != dnsmessage.ClassINET || rr.Header.TTL != 300 {
		t.Fatalf("SVCB record header: got owner %s class %v ttl %d, want owner %s class IN ttl 300", rr.Header.Name, rr.Header.Class, rr.Header.TTL, owner)
	}
	got := ddrSVCB{prio: b.Priority, target: b.Target.String()}
	for _, p := range b.Params {
		switch {
		case p.Key == dnsmessage.SVCParamALPN:
			if len(p.Value) < 2 || int(p.Value[0]) != len(p.Value)-1 {
				t.Fatalf("alpn %x is not one length-prefixed protocol id", p.Value)
			}
			got.alpn = string(p.Value[1:])
		case p.Key == dnsmessage.SVCParamPort:
			if len(p.Value) != 2 {
				t.Fatalf("port %x is not 2 bytes", p.Value)
			}
			got.port = uint16(p.Value[0])<<8 | uint16(p.Value[1])
		case p.Key == dnsmessage.SVCParamIPv4Hint && len(p.Value) == 4 && got.hint == "":
			got.hint = netip.AddrFrom4([4]byte(p.Value)).String()
		case p.Key == dnsmessage.SVCParamIPv6Hint && len(p.Value) == 16 && got.hint == "":
			got.hint = netip.AddrFrom16([16]byte(p.Value)).String()
		case p.Key == dnsmessage.SVCParamDOHPath:
			got.dohpath = string(p.Value)
		default:
			t.Fatalf("unexpected or malformed SvcParam %v = %x (one hint, 4 or 16 bytes, is allowed)", p.Key, p.Value)
		}
	}
	return got
}

// requireDDR checks a reply against its query: the header, the question echoed as received, then every section.
func requireDDR(t *testing.T, query, reply []byte, want ddrWant) dnsmessage.Message {
	t.Helper()
	if reply == nil {
		t.Fatal("no reply: the gateway did not answer the query itself")
	}
	q, m := parseReply(t, query), parseReply(t, reply)
	h := m.Header
	if h.ID != q.ID || !h.Response || !h.Authoritative || !h.RecursionAvailable || h.Truncated || h.AuthenticData || h.OpCode != 0 ||
		h.RCode != dnsmessage.RCodeSuccess || h.RecursionDesired != q.RecursionDesired || h.CheckingDisabled != q.CheckingDisabled {
		t.Fatalf("header:\n got  %+v\n want the id, RD and CD of %+v with QR, AA and RA set, NOERROR, TC clear", h, q.Header)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name.String() != q.Questions[0].Name.String() ||
		m.Questions[0].Type != q.Questions[0].Type || m.Questions[0].Class != q.Questions[0].Class {
		t.Fatalf("question: got %+v, want the query's %+v echoed as received", m.Questions, q.Questions)
	}
	owner := q.Questions[0].Name.String()
	var svcb []ddrSVCB
	var answers, authority, additional []string
	for _, rr := range m.Answers {
		if rr.Header.Type == dnsmessage.TypeSVCB {
			svcb = append(svcb, ddrDecode(t, rr, owner))
		} else {
			answers = append(answers, ddrText(t, rr))
		}
	}
	for _, rr := range m.Authorities {
		authority = append(authority, ddrText(t, rr))
	}
	for _, rr := range m.Additionals {
		if rr.Header.Type != dnsmessage.TypeOPT {
			additional = append(additional, ddrText(t, rr))
		}
	}
	if !slices.Equal(svcb, want.svcb) {
		t.Fatalf("SVCB answers:\n got  %+v\n want %+v", svcb, want.svcb)
	}
	for _, s := range []struct {
		name      string
		got, want []string
	}{{"other answers", answers, want.answers}, {"authority", authority, want.authority}, {"additional", additional, want.additional}} {
		if !slices.Equal(s.got, s.want) {
			t.Fatalf("%s:\n got  %q\n want %q", s.name, s.got, s.want)
		}
	}
	return m
}

// ddrOPTs are the OPT records of m and the UDP payload size each advertises.
func ddrOPTs(m dnsmessage.Message) (sizes []uint16) {
	for _, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			sizes = append(sizes, uint16(rr.Header.Class))
		}
	}
	return sizes
}

// --- criterion 1: the records, built from literal listeners and a certificate store, no sockets ---

func TestDDRDesignationRecordsAreRFC9460WireForEveryTransportOnTheQueriedAddress(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t),
		ddrAt(ddrL4, 853), ddrAt(ddrL4, 4443), ddrAt(ddrL4, 853))
	query := ddrQuery(t, 0x0DD1, ddrAsk, dnsmessage.TypeSVCB, 0)
	reply := d.answer(query, netip.MustParseAddr(ddrL4), true)
	requireDDR(t, query, reply, ddrWant{
		svcb:       []ddrSVCB{ddrDoHRec(ddrFQDN, 4443, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)},
		additional: []string{ddrAddrRR(ddrFQDN, ddrL4)},
	})

	// The same records as bytes: alpn is length-prefixed ids, port is 2 bytes big-endian (4443 = 0x115b), the hint is the
	// address itself, dohpath is the template's text. A decoder that shared a mistake with the encoder would not see these.
	ip4 := []byte{192, 0, 2, 1}
	want := [][]dnsmessage.SVCParam{
		{{Key: 1, Value: []byte("\x02h2")}, {Key: 3, Value: []byte{0x11, 0x5b}}, {Key: 4, Value: ip4}, {Key: 7, Value: []byte("/dns-query{?dns}")}},
		{{Key: 1, Value: []byte("\x03dot")}, {Key: 4, Value: ip4}},
		{{Key: 1, Value: []byte("\x03doq")}, {Key: 4, Value: ip4}},
	}
	m := parseReply(t, reply)
	if len(m.Answers) != len(want) {
		t.Fatalf("got %d answers, want %d", len(m.Answers), len(want))
	}
	for i, rr := range m.Answers {
		got := rr.Body.(*dnsmessage.SVCBResource)
		if got.Priority != uint16(i+1) || !paramsEqual(got.Params, want[i]) {
			t.Fatalf("record %d: priority %d params %v, want priority %d params %v", i, got.Priority, got.Params, i+1, want[i])
		}
	}
}

func TestDDRIPv6QueriedAddressGetsAnIPv6HintAsBytesAndAnAAAA(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt("2001:db8::1", 8853), nil, nil)
	query := ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0)
	reply := d.answer(query, netip.MustParseAddr("2001:db8::1"), true)
	m := requireDDR(t, query, reply, ddrWant{
		svcb:       []ddrSVCB{ddrDoTRec(ddrFQDN, 8853, "2001:db8::1")},
		additional: []string{ddrAddrRR(ddrFQDN, "2001:db8::1")},
	})
	want := []dnsmessage.SVCParam{
		{Key: 1, Value: []byte("\x03dot")}, {Key: 3, Value: []byte{0x22, 0x95}}, // 8853 = 0x2295
		{Key: 6, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	if got := m.Answers[0].Body.(*dnsmessage.SVCBResource).Params; !paramsEqual(got, want) {
		t.Fatalf("params: got %v, want %v", got, want)
	}
}

func paramsEqual(a, b []dnsmessage.SVCParam) bool {
	return slices.EqualFunc(a, b, func(x, y dnsmessage.SVCParam) bool { return x.Key == y.Key && bytes.Equal(x.Value, y.Value) })
}

func TestDDRRecordsFollowTheListenersOfTheQueriedAddress(t *testing.T) {
	certs := ddrLoaded(t)
	onL := func(port uint16) []netip.AddrPort { return ddrAt(ddrL4, port) }
	elsewhere := func(port uint16) []netip.AddrPort { return ddrAt(ddrElsewhere, port) }
	withAdd := func(svcb ...ddrSVCB) ddrWant {
		return ddrWant{svcb: svcb, additional: []string{ddrAddrRR(ddrFQDN, ddrL4)}}
	}
	cases := []struct {
		name          string
		target        string
		dot, doh, doq []netip.AddrPort
		local         string // "" is the zero address a DoT, DoH or DoQ query has
		want          ddrWant
	}{
		{name: "every transport on the queried address", dot: onL(853), doh: onL(4443), doq: onL(853), local: ddrL4,
			want: withAdd(ddrDoHRec(ddrFQDN, 4443, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4))},
		{name: "DoH on 443 has no port", doh: onL(443), local: ddrL4,
			want: withAdd(ddrDoHRec(ddrFQDN, 0, ddrL4, ddrDoHPath))},
		{name: "DoT and DoQ off 853 carry their port", dot: onL(8853), doq: onL(8853), local: ddrL4,
			want: withAdd(ddrDoTRec(ddrFQDN, 8853, ddrL4), ddrDoQRec(ddrFQDN, 8853, ddrL4))},
		{name: "DoT on 443 carries its port", dot: onL(443), local: ddrL4,
			want: withAdd(ddrDoTRec(ddrFQDN, 443, ddrL4))},
		{name: "only DoT listens on the queried address", dot: onL(853), doh: elsewhere(4443), doq: elsewhere(853), local: ddrL4,
			want: withAdd(ddrDoTRec(ddrFQDN, 0, ddrL4))},
		{name: "the target given with a trailing dot still has exactly one", target: ddrFQDN, dot: onL(853), local: ddrL4,
			want: withAdd(ddrDoTRec(ddrFQDN, 0, ddrL4))},
		{name: "an IPv4-mapped listener address is the IPv4 address", dot: ddrAt("::ffff:192.0.2.1", 853), local: ddrL4,
			want: withAdd(ddrDoTRec(ddrFQDN, 0, ddrL4))},
		{name: "an IPv4-mapped queried address is the IPv4 address", dot: onL(853), local: "::ffff:192.0.2.1",
			want: withAdd(ddrDoTRec(ddrFQDN, 0, ddrL4))},
		{name: "a zone on the listener address does not matter", dot: ddrAt("fe80::1%eth0", 853), local: "fe80::1",
			want: ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, 0, "fe80::1")}, additional: []string{ddrAddrRR(ddrFQDN, "fe80::1")}}},
		// a datagram socket bound to a wildcard reports the wildcard as its local address, not the address the client queried
		{name: "an unspecified IPv4 queried address gets NODATA from wildcard listeners", dot: ddrAt("0.0.0.0", 853), doh: ddrAt("0.0.0.0", 4443), doq: ddrAt("0.0.0.0", 853), local: "0.0.0.0",
			want: ddrNODATA},
		{name: "an unspecified IPv6 queried address gets NODATA from wildcard listeners", dot: ddrAt("::", 853), doh: ddrAt("::", 4443), doq: ddrAt("::", 853), local: "::",
			want: ddrNODATA},
		{name: "no transport listens on the queried address", dot: elsewhere(853), doh: elsewhere(4443), doq: elsewhere(853), local: ddrL4,
			want: ddrNODATA},
		{name: "a DoT, DoH or DoQ query has no queried address and gets NODATA", dot: onL(853), doh: onL(4443), doq: onL(853), local: "",
			want: ddrNODATA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustDDR(t, cmp.Or(c.target, ddrTarget), false, certs, c.dot, c.doh, c.doq)
			var local netip.Addr
			if c.local != "" {
				local = netip.MustParseAddr(c.local)
			}
			query := ddrQuery(t, 0x0DD2, ddrAsk, dnsmessage.TypeSVCB, 0)
			for _, udp := range []bool{true, false} {
				requireDDR(t, query, d.answer(query, local, udp), c.want)
			}
		})
	}
}

// A listener with no certificate fails every handshake, so it is not offered; a push can load one later, and the next
// query sees it.
func TestDDRNodataUntilACertificateIsLoadedThenRecordsAfterAPush(t *testing.T) {
	store := newEmptyCertStore(func(string, ...any) {})
	d := mustDDR(t, ddrTarget, false, store, ddrAt(ddrL4, 853), ddrAt(ddrL4, 4443), ddrAt(ddrL4, 853))
	local := netip.MustParseAddr(ddrL4)
	query := ddrQuery(t, 7, ddrAsk, dnsmessage.TypeSVCB, 0)

	requireDDR(t, query, d.answer(query, local, true), ddrNODATA) // before: no certificate

	path, _ := goodPEM(t)
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.push(pem); err != nil {
		t.Fatal(err)
	}
	requireDDR(t, query, d.answer(query, local, true), ddrWant{
		svcb:       []ddrSVCB{ddrDoHRec(ddrFQDN, 4443, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)},
		additional: []string{ddrAddrRR(ddrFQDN, ddrL4)},
	})
}

func TestDDRNodataWithoutAnyTLSTransportOrCertificateAndWithDoH443(t *testing.T) {
	local := netip.MustParseAddr(ddrL4)
	query := ddrQuery(t, 8, ddrAsk, dnsmessage.TypeSVCB, 0)
	t.Run("no certificate store at all", func(t *testing.T) {
		d := mustDDR(t, ddrTarget, false, nil, nil, nil, nil)
		requireDDR(t, query, d.answer(query, local, true), ddrNODATA)
	})
	t.Run("--ddr-doh-443 does not make an empty store serve", func(t *testing.T) {
		d := mustDDR(t, ddrTarget, true, newEmptyCertStore(func(string, ...any) {}),
			ddrAt(ddrL4, 853), ddrAt(ddrL4, 4443), ddrAt(ddrL4, 853))
		requireDDR(t, query, d.answer(query, local, true), ddrNODATA)
	})
}

// --- --ddr-doh-443: the DoH record without its port, and nothing else changed ---

func TestDDRDoH443LeavesThePortOutOfTheDoHRecordOnly(t *testing.T) {
	certs := ddrLoaded(t)
	onL := func(port uint16) []netip.AddrPort { return ddrAt(ddrL4, port) }
	elsewhere := func(port uint16) []netip.AddrPort { return ddrAt(ddrElsewhere, port) }
	fwAdd := []string{ddrAddrRR(ddrFQDN, ddrL4)}
	cases := []struct {
		name          string
		doh443        bool
		dot, doh, doq []netip.AddrPort
		want          ddrWant
	}{
		{"before-state: without the flag DoH on 4443 carries its port", false, onL(853), onL(4443), onL(853),
			ddrWant{svcb: []ddrSVCB{ddrDoHRec(ddrFQDN, 4443, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)}, additional: fwAdd}},
		{"with the flag the same listeners give a DoH record with no port", true, onL(853), onL(4443), onL(853),
			ddrWant{svcb: []ddrSVCB{ddrDoHRec(ddrFQDN, 0, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)}, additional: fwAdd}},
		{"DoH on 443 with the flag has no port either", true, onL(853), onL(443), onL(853),
			ddrWant{svcb: []ddrSVCB{ddrDoHRec(ddrFQDN, 0, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)}, additional: fwAdd}},
		{"the flag leaves the DoT and DoQ ports alone", true, onL(8853), onL(4443), onL(8853),
			ddrWant{svcb: []ddrSVCB{ddrDoHRec(ddrFQDN, 0, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 8853, ddrL4), ddrDoQRec(ddrFQDN, 8853, ddrL4)}, additional: fwAdd}},
		{"the flag does not offer DoH where it is not bound", true, onL(853), elsewhere(4443), onL(853),
			ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)}, additional: fwAdd}},
		{"only DoH on the queried address keeps its hint and the Additional record", true, elsewhere(853), onL(4443), elsewhere(853),
			ddrWant{svcb: []ddrSVCB{ddrDoHRec(ddrFQDN, 0, ddrL4, ddrDoHPath)}, additional: fwAdd}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustDDR(t, ddrTarget, c.doh443, certs, c.dot, c.doh, c.doq)
			query := ddrQuery(t, 0x0DD9, ddrAsk, dnsmessage.TypeSVCB, 0)
			requireDDR(t, query, d.answer(query, netip.MustParseAddr(ddrL4), true), c.want)
		})
	}
}

// --- criterion 2: everything else at or under resolver.arpa. ---

var ddrOtherNames = []struct {
	name  string
	qname string
	typ   dnsmessage.Type
	want  ddrWant
}{
	{"another type at _dns.resolver.arpa.", ddrAsk, dnsmessage.TypeA, ddrNODATA},
	{"another name under the zone", "foo.resolver.arpa.", dnsmessage.TypeSVCB, ddrNODATA},
	{"a deeper name", "a.b.resolver.arpa.", dnsmessage.TypeA, ddrNODATA},
	{"the apex A", "resolver.arpa.", dnsmessage.TypeA, ddrNODATA},
	{"the apex SVCB", "resolver.arpa.", dnsmessage.TypeSVCB, ddrNODATA},
	{"the apex in capitals", "RESOLVER.ARPA.", dnsmessage.TypeA, ddrNODATA},
	{"the apex SOA", "resolver.arpa.", dnsmessage.TypeSOA, ddrWant{answers: []string{ddrSOA}}},
	{"the apex NS", "resolver.arpa.", dnsmessage.TypeNS, ddrWant{answers: []string{ddrNS}}},
}

func TestDDROtherNamesAndTypesGetNODATAWithTheSOAAndTheApexItsSOAAndNS(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), ddrAt(ddrL4, 4443), ddrAt(ddrL4, 853))
	for _, c := range ddrOtherNames {
		t.Run(c.name, func(t *testing.T) {
			query := ddrQuery(t, 0x0DD3, c.qname, c.typ, 0)
			for _, udp := range []bool{true, false} {
				requireDDR(t, query, d.answer(query, netip.MustParseAddr(ddrL4), udp), c.want)
			}
		})
	}
}

func TestDDRMatchesTheZoneCaseInsensitivelyAndEchoesTheNameAsReceived(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), nil, nil)
	query := ddrQuery(t, 9, "_DNS.Resolver.ARPA.", dnsmessage.TypeSVCB, 0)
	reply := d.answer(query, netip.MustParseAddr(ddrL4), true)
	// requireDDR compares the question and each owner with the received spelling
	requireDDR(t, query, reply, ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ddrL4)}, additional: []string{ddrAddrRR(ddrFQDN, ddrL4)}})
	if !bytes.Contains(reply, []byte("\x04_DNS\x08Resolver\x04ARPA\x00")) {
		t.Fatalf("the question must keep the case the client sent (0x20 mixed case): %x", reply)
	}
}

// RFC 6891 and 1035: the header of the reply follows the query's, whatever its flags.
func TestDDRReplyHeaderFollowsTheQuery(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), nil, nil)
	for _, h := range []dnsmessage.Header{
		{ID: 0xBEEF, RecursionDesired: true},
		{ID: 0x0001, RecursionDesired: false},
		{ID: 0xFFFF, RecursionDesired: false, CheckingDisabled: true},
		{ID: 0x1234, RecursionDesired: true, CheckingDisabled: true},
	} {
		t.Run(fmt.Sprintf("id %#x rd %v cd %v", h.ID, h.RecursionDesired, h.CheckingDisabled), func(t *testing.T) {
			query := ddrQueryWith(t, h, ddrAsk, dnsmessage.TypeSVCB, 0)
			requireDDR(t, query, d.answer(query, netip.MustParseAddr(ddrL4), true),
				ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ddrL4)}, additional: []string{ddrAddrRR(ddrFQDN, ddrL4)}})
		})
	}
}

// --- EDNS and size ---

func TestDDRReplyCarriesAnOPTAdvertising1232OnlyWhenTheQueryHadOne(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), nil, nil)
	local := netip.MustParseAddr(ddrL4)
	want := ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ddrL4)}, additional: []string{ddrAddrRR(ddrFQDN, ddrL4)}}
	for _, c := range []struct {
		name string
		opt  uint16
		want []uint16
	}{{"no OPT in the query", 0, nil}, {"OPT 4096", 4096, []uint16{1232}}, {"OPT 512", 512, []uint16{1232}}, {"OPT 1232", 1232, []uint16{1232}}} {
		t.Run(c.name, func(t *testing.T) {
			query := ddrQuery(t, 3, ddrAsk, dnsmessage.TypeSVCB, c.opt)
			m := requireDDR(t, query, d.answer(query, local, true), want)
			if got := ddrOPTs(m); !slices.Equal(got, c.want) {
				t.Fatalf("OPT records advertise %v, want %v", got, c.want)
			}
			if c.opt != 0 {
				if opt := m.Additionals[len(m.Additionals)-1]; opt.Header.Type != dnsmessage.TypeOPT || opt.Header.TTL != 0 {
					t.Fatalf("the OPT is the last Additional record with extended RCODE 0, version 0 and no DO bit: %+v", opt.Header)
				}
			}
		})
	}
}

func ddrLongName(labels ...int) string {
	parts := make([]string, len(labels))
	for i, n := range labels {
		parts[i] = strings.Repeat("a", n)
	}
	return strings.Join(parts, ".")
}

// Over UDP the limit is 512 without EDNS and the client's OPT size clamped to 512..1232; over a stream there is none.
// A reply over the limit is replaced by its header, question and OPT with TC set.
func TestDDRUDPReplyOverTheLimitIsTruncatedAndAStreamReplyIsNot(t *testing.T) {
	long := ddrLongName(49, 49, 49, 49, 3) // 203 characters: three records of about 250 bytes
	huge := ddrLongName(62, 62, 62, 62, 1) // 253: the longest name; with IPv6 hints the reply passes 1232
	cases := []struct {
		name      string
		target    string
		local     string
		opt       uint16
		limit     int // what the reply may be over UDP
		truncated bool
	}{
		{"a short answer fits in 512", ddrTarget, ddrL4, 0, 512, false},
		{"an OPT below 512 is raised to 512", ddrTarget, ddrL4, 100, 512, false},
		{"a long answer without EDNS is over 512", long, ddrL4, 0, 512, true},
		{"an OPT of 4096 lets the long answer through", long, ddrL4, 4096, 1232, false},
		{"an OPT of 600 is the limit when it is between", long, ddrL4, 600, 600, true},
		{"an OPT of 4096 is lowered to 1232", huge, "2001:db8::1", 4096, 1232, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local := netip.MustParseAddr(c.local)
			d := mustDDR(t, c.target, false, ddrLoaded(t), ddrAt(c.local, 8853), ddrAt(c.local, 4443), ddrAt(c.local, 8853))
			query := ddrQuery(t, 0x0DD4, ddrAsk, dnsmessage.TypeSVCB, c.opt)
			target := strings.TrimSuffix(c.target, ".") + "."
			full := ddrWant{
				svcb:       []ddrSVCB{ddrDoHRec(target, 4443, c.local, ddrDoHPath), ddrDoTRec(target, 8853, c.local), ddrDoQRec(target, 8853, c.local)},
				additional: []string{ddrAddrRR(target, c.local)},
			}

			stream := d.answer(query, local, false)
			requireDDR(t, query, stream, full)
			if c.truncated && len(stream) <= c.limit {
				t.Fatalf("fixture: the full reply is %d bytes, not over the limit %d: the case proves nothing", len(stream), c.limit)
			}

			udp := d.answer(query, local, true)
			if len(udp) > c.limit {
				t.Fatalf("a UDP reply of %d bytes is over the limit %d", len(udp), c.limit)
			}
			if !c.truncated {
				requireDDR(t, query, udp, full)
				return
			}
			m := parseReply(t, udp)
			if !m.Truncated || !m.Response || !m.Authoritative || m.RCode != dnsmessage.RCodeSuccess || m.ID != 0x0DD4 ||
				len(m.Answers)+len(m.Authorities) != 0 || len(m.Questions) != 1 || m.Questions[0].Name.String() != ddrAsk {
				t.Fatalf("a truncated reply is the header with TC, the question and nothing else: %+v", m)
			}
			wantOPT := []uint16(nil)
			if c.opt != 0 {
				wantOPT = []uint16{1232}
			}
			if got := ddrOPTs(m); !slices.Equal(got, wantOPT) || len(m.Additionals) != len(wantOPT) {
				t.Fatalf("a truncated reply keeps only the OPT: got additionals %+v, want OPT sizes %v", m.Additionals, wantOPT)
			}
		})
	}
}

// --- wire that is not ours ---

func ddrWires(t *testing.T) map[string][]byte {
	t.Helper()
	pack := func(m dnsmessage.Message) []byte {
		wire, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	q := func(name string) dnsmessage.Question {
		return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeSVCB, Class: dnsmessage.ClassINET}
	}
	valid := ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0)
	return map[string][]byte{
		"no question":                     pack(dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}}),
		"two questions":                   pack(dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{q(ddrAsk), q("resolver.arpa.")}}),
		"opcode NOTIFY":                   pack(dnsmessage.Message{Header: dnsmessage.Header{ID: 1, OpCode: 4}, Questions: []dnsmessage.Question{q(ddrAsk)}}),
		"opcode STATUS":                   pack(dnsmessage.Message{Header: dnsmessage.Header{ID: 1, OpCode: 2}, Questions: []dnsmessage.Question{q(ddrAsk)}}),
		"a response":                      pack(dnsmessage.Message{Header: dnsmessage.Header{ID: 1, Response: true}, Questions: []dnsmessage.Question{q(ddrAsk)}}),
		"the header alone, QDCOUNT 1":     valid[:12],
		"a question cut inside its name":  valid[:16],
		"a question without its class":    valid[:len(valid)-2],
		"outside: resolver.arpa.example.": ddrQuery(t, 1, "resolver.arpa.example.", dnsmessage.TypeSVCB, 0),
		"outside: xresolver.arpa.":        ddrQuery(t, 1, "xresolver.arpa.", dnsmessage.TypeSVCB, 0),
		"outside: arpa.":                  ddrQuery(t, 1, "arpa.", dnsmessage.TypeSVCB, 0),
		"outside: the root":               ddrQuery(t, 1, ".", dnsmessage.TypeSVCB, 0),
		"outside: example.":               ddrQuery(t, 1, "example.", dnsmessage.TypeSVCB, 0),
		// U+017F (a long s) folds to s in Unicode: DNS folds ASCII only
		"outside: reſolver.arpa. (U+017F)": ddrQuery(t, 1, "re\u017folver.arpa.", dnsmessage.TypeSVCB, 0),
	}
}

func TestDDRDoesNotAnswerWhatIsNotAQueryForItsZone(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), ddrAt(ddrL4, 4443), ddrAt(ddrL4, 853))
	local := netip.MustParseAddr(ddrL4)
	if d.answer(ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0), local, true) == nil { // control: this ddr does answer a good query
		t.Fatal("the query for _dns.resolver.arpa. itself was not answered: the cases below prove nothing")
	}
	for name, wire := range ddrWires(t) {
		t.Run(name, func(t *testing.T) {
			if reply := d.answer(wire, local, true); reply != nil {
				t.Fatalf("answered %x with %x, want nil: the packet is not a query for resolver.arpa.", wire, reply)
			}
		})
	}
	t.Run("empty and short packets", func(t *testing.T) {
		for n := range 12 {
			if reply := d.answer(make([]byte, n), local, true); reply != nil {
				t.Fatalf("a %d-byte packet was answered with %x", n, reply)
			}
		}
	})
}

// A truncated copy of a good query never panics, and whatever is answered parses; a cut inside the question is not ours.
func TestDDRSurvivesEveryPrefixOfAQuery(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), ddrAt(ddrL4, 853), nil, nil)
	local := netip.MustParseAddr(ddrL4)
	questionEnd := len(ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0))
	if d.answer(ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0), local, true) == nil { // control: the whole query is answered
		t.Fatal("the whole query was not answered: the prefixes below prove nothing")
	}
	for _, opt := range []uint16{0, 4096} {
		full := ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, opt)
		for n := range len(full) + 1 {
			reply := d.answer(full[:n], local, true)
			if n < questionEnd && reply != nil {
				t.Fatalf("a prefix of %d bytes, inside the question, was answered", n)
			}
			if reply != nil {
				parseReply(t, reply)
			}
		}
	}
}

// --- through the gateway: real sockets ---

// ddrRig is a rig whose gateway answers DDR, with DoT, DoH and DoQ on 127.0.0.1 (the plain listener's address) and a
// decider that echoes whatever it is asked, so a DDR query that reaches it is seen by the reply.
type ddrRig struct {
	*rig
	m             tlsMaterial
	dot, doh, doq netip.AddrPort
}

// newDDRRig binds the TLS sockets first, so the ddr is built from their addresses and set on the gateway before any
// goroutine that reads it starts (production does the same: start() sets g.ddr before serving).
func newDDRRig(t *testing.T, doh443 bool) *ddrRig {
	t.Helper()
	m := newTLSMaterial(t)
	dotLn, err := bindTCP("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	dohLn, err := bindTCP("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	doqConn, err := bindUDP("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &ddrRig{m: m,
		dot: dotLn.Addr().(*net.TCPAddr).AddrPort(), doh: dohLn.Addr().(*net.TCPAddr).AddrPort(), doq: doqConn.LocalAddr().(*net.UDPAddr).AddrPort()}
	ddrAnswers, err := newDDR(ddrTarget, doh443, m.certs, []netip.AddrPort{d.dot}, []netip.AddrPort{d.doh}, []netip.AddrPort{d.doq})
	if err != nil {
		t.Fatal(err)
	}
	d.rig = newRig(t, rigConfig{acl: aclMixed, beforeServe: func(g *gateway) { g.ddr = ddrAnswers }})
	d.rig.autoAnswer(echoAnswer)
	d.g.serveDoT(dotLn, m.certs.dot())
	d.g.serveDoH(dohLn, m.certs.doh(), parseTrusted(nil, d.logs.logf))
	d.g.serveDoQ(doqConn, m.certs.doq())
	return d
}

// records is what a client of the rig is told to use.
func (r *ddrRig) records() ddrWant {
	return ddrWant{
		svcb: []ddrSVCB{
			ddrDoHRec(ddrFQDN, r.doh.Port(), "127.0.0.1", ddrDoHPath),
			ddrDoTRec(ddrFQDN, r.dot.Port(), "127.0.0.1"),
			ddrDoQRec(ddrFQDN, r.doq.Port(), "127.0.0.1"),
		},
		additional: []string{ddrAddrRR(ddrFQDN, "127.0.0.1")},
	}
}

// requireDeciderSawOnlyTheBarrier proves that none of the queries sent before reached the decider: it records them in
// order, and each of those was answered before this call, so the barrier is the first it can have seen.
func (r *rig) requireDeciderSawOnlyTheBarrier() {
	r.t.Helper()
	barrier := buildQuery(r.t, 0x0B0B, "barrier.example.", true)
	r.roundTrip(transport{"udp", false}, clientAllowed, barrier)
	if q := r.nextQuery(); !bytes.Equal(q.wire, barrier) {
		r.t.Fatalf("the decider's first query is %x, want the barrier %x: a DDR query must never reach it", q.wire, barrier)
	}
	r.requireNoOtherQuery()
}

func TestDDRQueryOverUDPAndTCPGetsTheRecordsOfTheListenersItReached(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newDDRRig(t, false)
			query := ddrQuery(t, 0x0DD5, ddrAsk, dnsmessage.TypeSVCB, 0)
			requireDDR(t, query, r.roundTrip(tr, clientAllowed, query), r.records())
			r.requireDeciderSawOnlyTheBarrier()
		})
	}
}

func TestDDRSVCBQueryOverDoTDoHAndDoQGetsNODATAAndTheDeciderSeesNone(t *testing.T) {
	r := newDDRRig(t, false)
	query := ddrQuery(t, 0, ddrAsk, dnsmessage.TypeSVCB, 0) // DoQ requires Message ID 0

	t.Run("DoT", func(t *testing.T) {
		c := dialDoT(t, r.dot, r.m, clientAllowed)
		tcpSend(t, c, query)
		requireDDR(t, query, tcpReply(t, c), ddrNODATA)
	})
	t.Run("DoH", func(t *testing.T) {
		c := newDoHClient(t, r.doh, r.m, dohOptions{source: clientAllowed, h2: true})
		resp, body := c.do(c.post(dohPath, dohMediaType, query))
		if resp.StatusCode != 200 {
			t.Fatalf("DoH status %d, want 200", resp.StatusCode)
		}
		requireDDR(t, query, body, ddrNODATA)
	})
	t.Run("DoQ", func(t *testing.T) {
		c := dialDoQ(t, r.doq, r.m, clientAllowed)
		requireDDR(t, query, c.query(query), ddrNODATA)
	})
	r.requireDeciderSawOnlyTheBarrier()
}

func TestDDROtherNamesAnsweredOverUDPNeverReachTheDecider(t *testing.T) {
	r := newDDRRig(t, false)
	for _, c := range ddrOtherNames {
		query := ddrQuery(t, 0x0DD6, c.qname, c.typ, 0)
		requireDDR(t, query, r.roundTrip(transport{"udp", false}, clientAllowed, query), c.want)
	}
	mixed := ddrQuery(t, 0x0DD7, "_DNS.Resolver.ARPA.", dnsmessage.TypeSVCB, 0)
	requireDDR(t, mixed, r.roundTrip(transport{"udp", false}, clientAllowed, mixed), r.records())
	r.requireDeciderSawOnlyTheBarrier()
}

func TestDDRNamesOutsideTheZoneReachTheDecider(t *testing.T) {
	r := newDDRRig(t, false)
	for i, name := range []string{"resolver.arpa.example.", "xresolver.arpa."} {
		query := ddrQuery(t, uint16(0x0E00+i), name, dnsmessage.TypeSVCB, 0)
		got := r.roundTrip(transport{"udp", false}, clientAllowed, query)
		if want := echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
			t.Fatalf("%s: got %x, want the decider's echo %x", name, got, want)
		}
		if q := r.nextQuery(); !bytes.Equal(q.wire, query) {
			t.Fatalf("%s: the decider saw %x, want %x", name, q.wire, query)
		}
	}
	control := ddrQuery(t, 0x0E10, ddrAsk, dnsmessage.TypeSVCB, 0) // the same rig answers a name inside the zone itself
	requireDDR(t, control, r.roundTrip(transport{"udp", false}, clientAllowed, control), r.records())
	r.requireNoOtherQuery()
}

// ddrNXDOMAIN is what Unbound 1.25.2 answers _dns.resolver.arpa. SVCB (spec "Off state"): NXDOMAIN and the zone SOA.
func ddrNXDOMAIN(wire []byte) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(wire); err != nil {
		panic(err)
	}
	out, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError},
		Questions: q.Questions,
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("resolver.arpa."), Class: dnsmessage.ClassINET, TTL: 10800},
			Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("localhost."), MBox: dnsmessage.MustNewName("nobody.invalid."),
				Serial: 1, Refresh: 3600, Retry: 1200, Expire: 604800, MinTTL: 10800},
		}},
	}).Pack()
	if err != nil {
		panic(err)
	}
	return out
}

// Criterion 3: no --ddr means the gateway never looks at resolver.arpa.; the client gets what the decider answers, byte for byte.
func TestDDROffLeavesResolverArpaToTheDeciderAndRelaysItsAnswerUnchanged(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoAnswer(func(q decidedQuery) []byte { return ddrNXDOMAIN(q.wire) })
			query := ddrQuery(t, 0x0FF0, ddrAsk, dnsmessage.TypeSVCB, 0)
			got := r.roundTrip(tr, clientAllowed, query)
			if want := ddrNXDOMAIN(query); !bytes.Equal(got, want) {
				t.Fatalf("reply:\n got  %x\n want the decider's %x", got, want)
			}
			if q := r.nextQuery(); !bytes.Equal(q.wire, query) {
				t.Fatalf("the decider saw %x, want %x", q.wire, query)
			}
		})
	}
}

// Criterion 4: the ACL comes first, as it does for every other query.
func TestDDRKeepsTheResolverACL(t *testing.T) {
	query := ddrQuery(t, 0x0DD8, ddrAsk, dnsmessage.TypeSVCB, 0)
	for _, tr := range transports {
		t.Run("a refused client gets REFUSED over "+tr.name, func(t *testing.T) {
			r := newDDRRig(t, false)
			requireRefused(t, query, r.roundTrip(tr, clientRefused, query))
			r.requireDeciderSawOnlyTheBarrier()
		})
		t.Run("an allowed client gets the records over "+tr.name, func(t *testing.T) {
			r := newDDRRig(t, false)
			requireDDR(t, query, r.roundTrip(tr, clientAllowed, query), r.records())
		})
	}
	t.Run("a denied UDP client gets nothing", func(t *testing.T) {
		r := newDDRRig(t, false)
		denied := r.udpClient(clientDenied)
		if _, err := denied.Write(query); err != nil {
			t.Fatal(err)
		}
		udpJudged(t, r.udpClient(clientRefused)) // the read loop has judged the denied datagram
		requireNoUDPReply(t, denied)
	})
	t.Run("a TCP client denied while connected is hung up on", func(t *testing.T) {
		r := newDDRRig(t, false)
		c := r.tcpClient("") // 127.0.0.1, open across the rewrite
		tcpSend(t, c, query)
		requireDDR(t, query, tcpReply(t, c), r.records()) // before the rule: answered
		if err := os.WriteFile(r.aclPath, []byte("access-control: 127.0.0.1/32 deny\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r.g.acl.Refresh()
		tcpSend(t, c, query)
		requireTCPClosed(t, c)
	})
}

// screen: a packet that is not a query for the zone is the decider's, or nobody's when it is a response.
func TestDDRScreenSendsWhatIsNotOursToTheDeciderAndNeverAnswersAResponse(t *testing.T) {
	r := newDDRRig(t, false)
	client, local := netip.MustParseAddr(clientAllowed), netip.MustParseAddr("127.0.0.1")
	for name, wire := range ddrWires(t) {
		want := toDecider
		if name == "a response" {
			want = discard
		}
		t.Run(name, func(t *testing.T) {
			disp, reply := r.g.screen(client, local, true, wire)
			if disp != want || reply != nil {
				t.Fatalf("screen: got disposition %d reply %x, want disposition %d and no reply", disp, reply, want)
			}
		})
	}
	t.Run("a query for the zone is answered at once", func(t *testing.T) {
		query := ddrQuery(t, 5, ddrAsk, dnsmessage.TypeSVCB, 0)
		disp, reply := r.g.screen(client, local, true, query)
		if disp != replyNow {
			t.Fatalf("screen: got disposition %d, want replyNow (%d)", disp, replyNow)
		}
		requireDDR(t, query, reply, r.records())
	})
}

// --- start(): the ddr is built from the listeners that were bound ---

func ddrLogLine(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line starts with %q in:\n%s", prefix, text)
	return ""
}

func TestDDRStartAnswersFromTheBoundListenersIncludingPortsPickedByTheKernel(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	path, _ := goodPEM(t)
	cfg.tlsPEM = path
	cfg.dotListen, cfg.dotPort = cfg.listen, freePort(t)
	cfg.dohListen, cfg.dohPort = cfg.listen, 0
	cfg.doqListen, cfg.doqPort = cfg.listen, 0
	cfg.ddr = ddrTarget
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	text := logs.text()
	plain := listenAddr(t, ddrLogLine(t, text, "listening udp+tcp "))
	doh := listeningAddr(t, ddrLogLine(t, text, "listening doh "), "doh")
	doq := listeningAddr(t, ddrLogLine(t, text, "listening doq "), "doq")
	if doh.Port() == 0 || doq.Port() == 0 {
		t.Fatalf("--doh-port 0 and --doq-port 0 report the port picked: doh=%s doq=%s", doh, doq)
	}

	query := ddrQuery(t, 0x0DDA, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, udpQuery(t, plain, query), ddrWant{
		svcb: []ddrSVCB{
			ddrDoHRec(ddrFQDN, doh.Port(), "127.0.0.1", ddrDoHPath),
			ddrDoTRec(ddrFQDN, uint16(cfg.dotPort), "127.0.0.1"),
			ddrDoQRec(ddrFQDN, doq.Port(), "127.0.0.1"),
		},
		additional: []string{ddrAddrRR(ddrFQDN, "127.0.0.1")},
	})
}

// A plain socket bound to a wildcard address: over UDP its local address is the wildcard, so no address was queried that
// can be named (NODATA, and never a hint of 0.0.0.0); over TCP the connection's own address is the one the client
// queried, so a listener on that address designates and a wildcard listener, which is not matched to it, does not.
func TestDDRPlainWildcardSocketDesignatesOnlyOverTCPAndOnlyAnExplicitListener(t *testing.T) {
	cases := []struct {
		name      string
		tlsListen string
		wantTCP   func(dot netip.AddrPort) ddrWant
	}{
		{"wildcard DoT, DoH and DoQ", "0.0.0.0", func(netip.AddrPort) ddrWant { return ddrNODATA }},
		{"DoT on 127.0.0.1", "127.0.0.1", func(dot netip.AddrPort) ddrWant {
			return ddrWant{svcb: []ddrSVCB{ddrDoTRec(ddrFQDN, dot.Port(), "127.0.0.1")}, additional: []string{ddrAddrRR(ddrFQDN, "127.0.0.1")}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, logs := lifecycleConfig(t, "serve")
			path, _ := goodPEM(t)
			cfg.listen, cfg.tlsPEM, cfg.ddr = []string{"0.0.0.0"}, path, ddrTarget
			cfg.dotListen, cfg.dotPort = []string{c.tlsListen}, freePort(t)
			if c.tlsListen == "0.0.0.0" {
				cfg.dohListen, cfg.dohPort = cfg.dotListen, 0
				cfg.doqListen, cfg.doqPort = cfg.dotListen, 0
			}
			srv, err := start(cfg, logs.logf)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.shutdown()
			bound := listenAddr(t, ddrLogLine(t, logs.text(), "listening udp+tcp "))
			if !bound.Addr().IsUnspecified() {
				t.Fatalf("fixture: the plain socket is on %s, want a wildcard", bound)
			}
			to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bound.Port())
			query := ddrQuery(t, 0x0DDD, ddrAsk, dnsmessage.TypeSVCB, 0)

			requireDDR(t, query, udpQuery(t, to, query), ddrNODATA)

			conn, err := net.DialTimeout("tcp4", to.String(), watchdog)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tcpSend(t, conn, query)
			requireDDR(t, query, tcpReply(t, conn), c.wantTCP(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(cfg.dotPort))))
		})
	}
}

func TestDDRStartWithoutTLSListenersAnswersNODATA(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.ddr = ddrTarget
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	plain := listenAddr(t, ddrLogLine(t, logs.text(), "listening udp+tcp "))
	query := ddrQuery(t, 0x0DDB, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, udpQuery(t, plain, query), ddrNODATA)
}

func TestDDRStartWithAnUnusableNameFailsAndLeavesNothingBound(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.port = freePort(t)
	cfg.ddr = "a..b"
	srv, err := start(cfg, logs.logf)
	if err == nil {
		srv.shutdown()
		t.Fatal("start with --ddr a..b succeeded, want an error: an empty label is no name")
	}
	if !strings.Contains(err.Error(), "--ddr") {
		t.Fatalf("the error must name the flag: %v", err)
	}
	l, err := bindPlain("127.0.0.1", cfg.port)
	if err != nil {
		t.Fatalf("the plain port is still held after the failed start: %v", err)
	}
	l.close()
}

// the process the rc script starts: flags in, DDR answers out
func TestDDRGatewayProcessTakesTheFlagsAndAnswersFromTheBoundListeners(t *testing.T) {
	ports := distinctPorts(t, 2)
	path, _ := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", fmt.Sprint(ports[1]), "--unbound-conf", filepath.Join(t.TempDir(), "absent"),
		"--dot-listen", "127.0.0.1", "--dot-port", fmt.Sprint(ports[0]), "--tls-pem", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0",
		"--ddr", ddrTarget, "--ddr-doh-443",
	}, decider("serve"))
	plain := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("listening dot ")
	gw.waitLine("listening doh ")
	gw.waitLine("ready upstream ")

	query := ddrQuery(t, 0x0DDC, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, udpQuery(t, plain, query), ddrWant{
		svcb: []ddrSVCB{
			ddrDoHRec(ddrFQDN, 0, "127.0.0.1", ddrDoHPath), // DoH is on a port the kernel picked, and the flag leaves it out
			ddrDoTRec(ddrFQDN, uint16(ports[0]), "127.0.0.1"),
		},
		additional: []string{ddrAddrRR(ddrFQDN, "127.0.0.1")},
	})
}
