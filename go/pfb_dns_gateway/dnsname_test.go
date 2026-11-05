package main

import (
	"bytes"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: the gateway answers A and AAAA for the DNS name itself, from the address the query reached, after the ACL and
// DDR and before the decider. Every expectation below is written out from the contract, never taken from the code under
// test; each query that must reach the decider has a sibling in the same table that the same fixture does answer.

func mustNames(t *testing.T, name string, answers ...string) *nameAnswers {
	t.Helper()
	n, err := newNameAnswers(name, answers)
	if err != nil {
		t.Fatalf("newNameAnswers(%q, %q): %v", name, answers, err)
	}
	return n
}

// newNameRig is a rig whose gateway answers the DNS name from names (nil: no name answers) and whose decider echoes whatever
// it is asked, so a query that reaches it is seen by its reply.
func newNameRig(t *testing.T, names *nameAnswers) *rig {
	t.Helper()
	r := newRig(t, rigConfig{acl: aclMixed, beforeServe: func(g *gateway) { g.names = names }})
	r.autoAnswer(echoAnswer)
	return r
}

// screenAs runs wire through screen as an allowed client that reached local ("" is the zero address) over plain UDP (plain,
// udp), plain TCP (plain) or an encrypted transport (neither).
func screenAs(g *gateway, local string, plain, udp bool, wire []byte) (disposition, []byte) {
	var at netip.Addr
	if local != "" {
		at = netip.MustParseAddr(local)
	}
	return g.screen(netip.MustParseAddr(clientAllowed), at, plain, udp, wire)
}

func requireDeciders(t *testing.T, disp disposition, reply []byte, what string) {
	t.Helper()
	if disp != toDecider || reply != nil {
		t.Fatalf("%s: screen gave disposition %d and reply %x, want toDecider (%d) and no reply", what, disp, reply, toDecider)
	}
}

// the three ways a query reaches screen
var screenPaths = []struct {
	name       string
	plain, udp bool
}{{"plain UDP", true, true}, {"plain TCP", true, false}, {"an encrypted transport", false, false}}

// N5-N10: a table entry answers its address of the family asked, or local NODATA when that family is absent.
// An address with no entry remains the decider's.
func TestNameAnswerIsTheEntryOfTheAddressTheQueryReachedInTheFamilyAsked(t *testing.T) {
	r := newNameRig(t, mustNames(t, "fw.example.lan",
		"10.0.0.1=10.0.0.1,2001:db8:1::1", // a LAN interface: its own two addresses
		"2001:db8:1::1=10.0.0.1,2001:db8:1::1",
		"10.0.0.53=10.0.0.53,2001:db8:53::53", // the IPv4 Resolver VIP, and the IPv6 one beside it
		"10.0.0.54=10.0.0.54",                 // a VIP that has no IPv6 partner
	))
	rows := []struct {
		label, local string
		typ          dnsmessage.Type
		want         string // "" is the decider's
	}{
		{"N5 A on the LAN IPv4 is that IPv4 though a VIP is active", "10.0.0.1", dnsmessage.TypeA, "10.0.0.1"},
		{"N6 AAAA on the LAN IPv4 is the LAN's IPv6", "10.0.0.1", dnsmessage.TypeAAAA, "2001:db8:1::1"},
		{"N7 A on the LAN IPv6 is the LAN's IPv4", "2001:db8:1::1", dnsmessage.TypeA, "10.0.0.1"},
		{"AAAA on the LAN IPv6 is the LAN's IPv6", "2001:db8:1::1", dnsmessage.TypeAAAA, "2001:db8:1::1"},
		{"N8 A on the IPv4 VIP is the VIP", "10.0.0.53", dnsmessage.TypeA, "10.0.0.53"},
		{"N9 AAAA on the IPv4 VIP is the IPv6 VIP", "10.0.0.53", dnsmessage.TypeAAAA, "2001:db8:53::53"},
		{"A on that same VIP is the VIP", "10.0.0.54", dnsmessage.TypeA, "10.0.0.54"},
		{"N10 an address with no entry", "10.9.9.9", dnsmessage.TypeA, ""},
		{"N10 an IPv6 address with no entry", "2001:db8:9::9", dnsmessage.TypeAAAA, ""},
		{"N10 loopback", "127.0.0.1", dnsmessage.TypeA, ""},
		{"N10 IPv6 loopback", "::1", dnsmessage.TypeAAAA, ""},
		{"no address at all", "", dnsmessage.TypeA, ""},
		{"the IPv4 wildcard a datagram socket bound to one reports", "0.0.0.0", dnsmessage.TypeA, ""},
		{"the IPv6 wildcard", "::", dnsmessage.TypeAAAA, ""},
		{"an IPv4-mapped address is the IPv4 address", "::ffff:10.0.0.1", dnsmessage.TypeA, "10.0.0.1"},
	}
	for _, path := range screenPaths {
		for _, row := range rows {
			t.Run(path.name+": "+row.label, func(t *testing.T) {
				query := nameQuery(t, nameFQDN, row.typ)
				disp, reply := screenAs(r.g, row.local, path.plain, path.udp, query)
				if row.want == "" {
					requireDeciders(t, disp, reply, row.label)
					return
				}
				if disp != replyNow {
					t.Fatalf("screen gave disposition %d, want replyNow (%d)", disp, replyNow)
				}
				requireNameAnswer(t, query, reply, nameFQDN, row.want)
			})
		}
	}
}

func nameQ(name string, typ dnsmessage.Type, class dnsmessage.Class) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: class}
}

// nameWire packs the questions under h; a Message that has other than one is what a hostile client sends.
func nameWire(t *testing.T, h dnsmessage.Header, qs ...dnsmessage.Question) []byte {
	t.Helper()
	wire, err := (&dnsmessage.Message{Header: h, Questions: qs}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// N11, N12 and the hostile query shapes: what is not exactly one IN question of opcode QUERY for the name, in A or AAAA, is
// the decider's. Each refusal row has its answered sibling: the first rows.
func TestOnlyAQueryForTheNameInAOrAAAAIsAnswered(t *testing.T) {
	r := newNameRig(t, mustNames(t, "fw.example.lan", "10.0.0.1=10.0.0.1,2001:db8:1::1"))
	a := func(name string) dnsmessage.Question { return nameQ(name, dnsmessage.TypeA, dnsmessage.ClassINET) }
	rows := []struct {
		label  string
		opcode dnsmessage.OpCode
		qs     []dnsmessage.Question
		want   string // the address answered; "" is the decider's
		owner  string // the owner of the answer: the name as asked
	}{
		{"A", 0, []dnsmessage.Question{a("fw.example.lan.")}, "10.0.0.1", "fw.example.lan."},
		{"AAAA", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)}, "2001:db8:1::1", "fw.example.lan."},
		{"N12 mixed case, case kept in the owner", 0, []dnsmessage.Question{a("Fw.EXAMPLE.lan.")}, "10.0.0.1", "Fw.EXAMPLE.lan."},
		{"N12 upper case AAAA", 0, []dnsmessage.Question{nameQ("FW.EXAMPLE.LAN.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)}, "2001:db8:1::1", "FW.EXAMPLE.LAN."},
		{"N11 a subdomain", 0, []dnsmessage.Question{a("sub.fw.example.lan.")}, "", ""},
		{"the parent domain", 0, []dnsmessage.Question{a("example.lan.")}, "", ""},
		{"a name that only ends like it", 0, []dnsmessage.Question{a("xfw.example.lan.")}, "", ""},
		{"the name with a trailing label", 0, []dnsmessage.Question{a("fw.example.lan.sub.")}, "", ""},
		{"the root", 0, []dnsmessage.Question{a(".")}, "", ""},
		{"N11 MX", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeMX, dnsmessage.ClassINET)}, "", ""},
		{"N11 TXT", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeTXT, dnsmessage.ClassINET)}, "", ""},
		{"N11 HTTPS", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)}, "", ""},
		{"SVCB", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeSVCB, dnsmessage.ClassINET)}, "", ""},
		{"NS", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeNS, dnsmessage.ClassINET)}, "", ""},
		{"SOA", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeSOA, dnsmessage.ClassINET)}, "", ""},
		{"CNAME", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeCNAME, dnsmessage.ClassINET)}, "", ""},
		{"ANY", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeALL, dnsmessage.ClassINET)}, "", ""},
		{"class CH", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeA, dnsmessage.ClassCHAOS)}, "", ""},
		{"class HS", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeA, dnsmessage.ClassHESIOD)}, "", ""},
		{"class ANY", 0, []dnsmessage.Question{nameQ("fw.example.lan.", dnsmessage.TypeA, dnsmessage.ClassANY)}, "", ""},
		{"opcode IQUERY", 1, []dnsmessage.Question{a("fw.example.lan.")}, "", ""},
		{"opcode STATUS", 2, []dnsmessage.Question{a("fw.example.lan.")}, "", ""},
		{"opcode NOTIFY", 4, []dnsmessage.Question{a("fw.example.lan.")}, "", ""},
		{"opcode UPDATE", 5, []dnsmessage.Question{a("fw.example.lan.")}, "", ""},
		{"QDCOUNT 2: the name twice", 0, []dnsmessage.Question{a("fw.example.lan."), a("fw.example.lan.")}, "", ""},
		{"QDCOUNT 2: the name, then MX", 0, []dnsmessage.Question{a("fw.example.lan."), nameQ("fw.example.lan.", dnsmessage.TypeMX, dnsmessage.ClassINET)}, "", ""},
		{"QDCOUNT 2: another name, then the name", 0, []dnsmessage.Question{a("other.example.lan."), a("fw.example.lan.")}, "", ""},
		{"QDCOUNT 0", 0, nil, "", ""},
	}
	for _, row := range rows {
		t.Run(row.label, func(t *testing.T) {
			wire := nameWire(t, dnsmessage.Header{ID: 0x3694, RecursionDesired: true, OpCode: row.opcode}, row.qs...)
			disp, reply := screenAs(r.g, "10.0.0.1", true, true, wire)
			if row.want == "" {
				requireDeciders(t, disp, reply, row.label)
				return
			}
			if disp != replyNow {
				t.Fatalf("screen gave disposition %d, want replyNow (%d)", disp, replyNow)
			}
			requireNameAnswer(t, wire, reply, row.owner, row.want)
		})
	}
	t.Run("a response is never answered, even for the name", func(t *testing.T) {
		wire := nameWire(t, dnsmessage.Header{ID: 1, Response: true}, a("fw.example.lan."))
		if disp, reply := screenAs(r.g, "10.0.0.1", true, true, wire); disp != discard || reply != nil {
			t.Fatalf("screen gave disposition %d and reply %x, want discard (%d) and no reply", disp, reply, discard)
		}
	})
}

// DNS folds ASCII only: a name that differs in a byte that is not ASCII is another name, in either direction.
func TestNameMatchFoldsASCIIOnly(t *testing.T) {
	const kelvin = "\u212Aelvin.example.lan." // KELVIN SIGN: strings.ToLower makes it "k"
	for label, c := range map[string]struct {
		name  string
		asked map[string]bool // the question name -> answered
	}{
		"ASCII name":              {"kelvin.example.lan", map[string]bool{"kelvin.example.lan.": true, "KELVIN.example.LAN.": true, kelvin: false}},
		"Kelvin sign in the name": {"\u212Aelvin.example.lan", map[string]bool{kelvin: true, "\u212AELVIN.EXAMPLE.LAN.": true, "kelvin.example.lan.": false, "Kelvin.example.lan.": false}},
	} {
		t.Run(label, func(t *testing.T) {
			r := newNameRig(t, mustNames(t, c.name, "10.0.0.1=10.0.0.1"))
			for asked, answered := range c.asked {
				query := nameQuery(t, asked, dnsmessage.TypeA)
				disp, reply := screenAs(r.g, "10.0.0.1", true, true, query)
				if !answered {
					requireDeciders(t, disp, reply, asked)
				} else if disp != replyNow {
					t.Fatalf("%q: screen gave disposition %d, want replyNow", asked, disp)
				} else {
					requireNameAnswer(t, query, reply, asked, "10.0.0.1")
				}
			}
		})
	}
	t.Run("the configured name's case does not matter", func(t *testing.T) {
		r := newNameRig(t, mustNames(t, "FW.Example.LAN.", "10.0.0.1=10.0.0.1"))
		query := nameQuery(t, "fw.example.lan.", dnsmessage.TypeA)
		disp, reply := screenAs(r.g, "10.0.0.1", true, true, query)
		if disp != replyNow {
			t.Fatalf("screen gave disposition %d, want replyNow", disp)
		}
		requireNameAnswer(t, query, reply, "fw.example.lan.", "10.0.0.1")
	})
}

// The reply follows the query: RD and CD copied, and an OPT record exactly when the query had one (DDR's replies do the same).
func TestNameReplyHeaderAndEDNSFollowTheQuery(t *testing.T) {
	r := newNameRig(t, mustNames(t, "fw.example.lan", "10.0.0.1=10.0.0.1"))
	for label, c := range map[string]struct {
		h    dnsmessage.Header
		opt  uint16
		want []uint16 // the UDP payload sizes of the reply's OPT records
	}{
		"RD set, no EDNS":           {dnsmessage.Header{ID: 7, RecursionDesired: true}, 0, nil},
		"RD clear, CD set, no EDNS": {dnsmessage.Header{ID: 8, CheckingDisabled: true}, 0, nil},
		"EDNS 4096":                 {dnsmessage.Header{ID: 9, RecursionDesired: true}, 4096, []uint16{1232}},
		"EDNS 512":                  {dnsmessage.Header{ID: 10, RecursionDesired: true}, 512, []uint16{1232}},
	} {
		t.Run(label, func(t *testing.T) {
			query := ddrQueryWith(t, c.h, nameFQDN, dnsmessage.TypeA, c.opt)
			disp, reply := screenAs(r.g, "10.0.0.1", true, true, query)
			if disp != replyNow {
				t.Fatalf("screen gave disposition %d, want replyNow", disp)
			}
			requireNameAnswer(t, query, reply, nameFQDN, "10.0.0.1")
			if got := ddrOPTs(parseReply(t, reply)); len(got) != len(c.want) || (len(got) == 1 && got[0] != c.want[0]) {
				t.Fatalf("OPT payload sizes in the reply: got %v, want %v", got, c.want)
			}
		})
	}
}

// A query cut anywhere before its question ends is never answered, and no prefix of it panics.
func TestNameScreenSurvivesEveryPrefixOfAQuery(t *testing.T) {
	r := newNameRig(t, mustNames(t, "fw.example.lan", "10.0.0.1=10.0.0.1"))
	wire := nameQuery(t, nameFQDN, dnsmessage.TypeA)
	if disp, _ := screenAs(r.g, "10.0.0.1", true, true, wire); disp != replyNow {
		t.Fatalf("fixture: the whole query gave disposition %d, want replyNow", disp)
	}
	for i := range wire {
		if disp, reply := screenAs(r.g, "10.0.0.1", true, true, wire[:i]); reply != nil {
			t.Fatalf("the first %d of %d bytes got the reply %x (disposition %d)", i, len(wire), reply, disp)
		}
	}
}

// N2 (gateway half): no name, or a name no listen address answers for, leaves every query to the decider.
func TestWithoutANameTableEntryTheDeciderGetsTheNameQuery(t *testing.T) {
	query := nameQuery(t, nameFQDN, dnsmessage.TypeA)
	for label, c := range map[string]struct {
		names    *nameAnswers
		answered bool
	}{
		"no DNS name":                                          {nil, false},
		"a DNS name and an empty table":                        {mustNames(t, "fw.example.lan"), false},
		"a table for another address":                          {mustNames(t, "fw.example.lan", "127.0.0.2=127.0.0.2"), false},
		"the same fixture with an entry for the rig's address": {mustNames(t, "fw.example.lan", "127.0.0.1="+nameV4), true},
	} {
		for _, tr := range transports {
			t.Run(label+" over "+tr.name, func(t *testing.T) {
				r := newNameRig(t, c.names)
				got := r.roundTrip(tr, clientAllowed, query)
				if c.answered {
					requireNameAnswer(t, query, got, nameFQDN, nameV4)
					r.requireDeciderSawOnlyTheBarrier()
					return
				}
				q := r.nextQuery()
				if !bytes.Equal(q.wire, query) || !bytes.Equal(got, echoAnswer(q)) {
					t.Fatalf("the decider saw %x and the client got %x, want the decider's echo of %x", q.wire, got, query)
				}
			})
		}
	}
}

func newNameDDRRig(t *testing.T, answers ...string) *ddrRig {
	t.Helper()
	return newDDRRigNames(t, ddrTarget, mustNames(t, ddrTarget, answers...))
}

// asks sends one query as an allowed client over each transport the DDR rig serves and returns the reply.
func (r *ddrRig) asks() map[string]func(t *testing.T, query []byte) []byte {
	return map[string]func(*testing.T, []byte) []byte{
		"UDP": func(t *testing.T, q []byte) []byte { return r.roundTrip(transports[0], clientAllowed, q) },
		"TCP": func(t *testing.T, q []byte) []byte { return r.roundTrip(transports[1], clientAllowed, q) },
		"DoT": func(t *testing.T, q []byte) []byte {
			c := dialDoT(t, r.dot, r.m, clientAllowed)
			tcpSend(t, c, q)
			return tcpReply(t, c)
		},
		"DoH": func(t *testing.T, q []byte) []byte {
			c := newDoHClient(t, r.doh, r.m, dohOptions{source: clientAllowed, h2: true})
			resp, body := c.do(c.post(dohPath, dohMediaType, q))
			if resp.StatusCode != 200 {
				t.Fatalf("DoH status %d, want 200", resp.StatusCode)
			}
			return body
		},
		"DoQ": func(t *testing.T, q []byte) []byte { return dialDoQ(t, r.doq, r.m, clientAllowed).query(q) },
	}
}

// N16 and N1: the name is answered over every transport from the listener's own address, and DDR still designates over plain
// DNS only: it is told no address on the encrypted transports even though the name answer now is.
func TestNameIsAnsweredOverEveryTransportAndDDRStaysOnPlainDNS(t *testing.T) {
	r := newNameDDRRig(t, "127.0.0.1="+nameV4+","+nameV6)
	a := ddrQuery(t, 0, nameFQDN, dnsmessage.TypeA, 0) // DoQ requires Message ID 0
	aaaa := ddrQuery(t, 0, nameFQDN, dnsmessage.TypeAAAA, 0)
	svcb := ddrQuery(t, 0, ddrAsk, dnsmessage.TypeSVCB, 0)
	for name, ask := range r.asks() {
		t.Run(name, func(t *testing.T) {
			requireNameAnswer(t, a, ask(t, a), nameFQDN, nameV4)
			requireNameAnswer(t, aaaa, ask(t, aaaa), nameFQDN, nameV6)
			want := ddrNODATA
			if name == "UDP" || name == "TCP" {
				want = r.records()
			}
			requireDDR(t, svcb, ask(t, svcb), want)
		})
	}
	r.requireDeciderSawOnlyTheBarrier()
}

// N16: the lookup is by the address the query reached on every transport: a listener whose address has no entry gets its
// query to the decider.
func TestNameQueryOnAListenerWithoutAnEntryReachesTheDeciderOverEveryTransport(t *testing.T) {
	r := newNameDDRRig(t, "127.0.0.2="+nameV4)
	query := ddrQuery(t, 0, nameFQDN, dnsmessage.TypeA, 0)
	for name, ask := range r.asks() {
		t.Run(name, func(t *testing.T) {
			got := ask(t, query)
			want := echoAnswer(r.nextQuery())
			if name == "DoQ" {
				want = withID0(want)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reply %x, want the decider's echo %x", got, want)
			}
		})
	}
}

// N17: the ACL comes first, as it does for DDR: a client it refuses gets REFUSED and one it denies gets nothing, and neither
// is ever told the name's address; the allowed client is.
func TestNameKeepsTheResolverACL(t *testing.T) {
	query := nameQuery(t, nameFQDN, dnsmessage.TypeA)
	table := "127.0.0.1=" + nameV4
	for _, tr := range transports {
		t.Run("a refused client gets REFUSED over "+tr.name, func(t *testing.T) {
			r := newNameDDRRig(t, table)
			requireRefused(t, query, r.roundTrip(tr, clientRefused, query))
			r.requireDeciderSawOnlyTheBarrier()
		})
		t.Run("an allowed client gets the name over "+tr.name, func(t *testing.T) {
			r := newNameDDRRig(t, table)
			requireNameAnswer(t, query, r.roundTrip(tr, clientAllowed, query), nameFQDN, nameV4)
		})
	}
	t.Run("a refused client gets REFUSED over DoT", func(t *testing.T) {
		r := newNameDDRRig(t, table)
		c := dialDoT(t, r.dot, r.m, clientRefused)
		tcpSend(t, c, query)
		requireRefused(t, query, tcpReply(t, c))
		r.requireDeciderSawOnlyTheBarrier()
	})
	t.Run("a denied UDP client gets nothing", func(t *testing.T) {
		r := newNameDDRRig(t, table)
		denied := r.udpClient(clientDenied)
		if _, err := denied.Write(query); err != nil {
			t.Fatal(err)
		}
		udpJudged(t, r.udpClient(clientRefused)) // the read loop has judged the denied datagram
		requireNoUDPReply(t, denied)
	})
	t.Run("a TCP client denied while connected is hung up on", func(t *testing.T) {
		r := newNameDDRRig(t, table)
		c := r.tcpClient("") // 127.0.0.1, open across the rewrite
		tcpSend(t, c, query)
		requireNameAnswer(t, query, tcpReply(t, c), nameFQDN, nameV4) // before the rule: answered
		if err := os.WriteFile(r.aclPath, []byte("access-control: 127.0.0.1/32 deny\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r.g.acl.Refresh()
		tcpSend(t, c, query)
		requireTCPClosed(t, c)
	})
}

// A trusted front end's PROXY header may name a client of the other family than the TCP connection that carries it (an IPv6
// client through an IPv4 hop). The name is answered for the address the query reached, the listener's own; the mixed-family
// destination that proxyEndpoints gives the PROXYv2 header to Unbound must not key that answer.
func TestDoHNameAnswerIsKeyedByTheListenerEvenWhenTheHeaderNamesTheOtherFamily(t *testing.T) {
	rows := []struct {
		label  string
		header []byte
	}{
		{"a client of the other family, named by the header", pp2TCP("[2001:db8::5]:51000", "[::1]:443")},
		{"a client of the connection's own family, named by the header", pp2TCP("192.0.2.10:51000", "127.0.0.1:443")},
	}
	for _, c := range rows {
		t.Run(c.label, func(t *testing.T) {
			names := mustNames(t, "fw.example.lan", "127.0.0.1=198.51.100.7,2001:db8:1::1")
			r := newRig(t, rigConfig{acl: aclMixed, beforeServe: func(g *gateway) { g.names = names }})
			m := newTLSMaterial(t)
			addr := r.serveDoH(m, "127.0.0.0/8")
			r.autoAnswer(echoAnswer)
			client := newDoHClient(t, addr, m, dohOptions{prefix: c.header})
			resp, body := client.do(client.get(dnsParam(buildQuery(t, 7, "fw.example.lan.", true))))
			if resp.StatusCode != 200 {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}
			reply := parseReply(t, body)
			var got netip.Addr
			for _, rr := range reply.Answers {
				if a, ok := rr.Body.(*dnsmessage.AResource); ok {
					got = netip.AddrFrom4(a.A)
				}
			}
			if want := netip.MustParseAddr("198.51.100.7"); got != want {
				t.Fatalf("A for the name: got %v (answers %v), want %v from the listener's entry 127.0.0.1", got, reply.Answers, want)
			}
			r.requireNoOtherQuery()
		})
	}
}
