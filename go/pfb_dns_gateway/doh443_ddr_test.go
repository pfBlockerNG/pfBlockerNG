package main

import (
	"io"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: DDR's DoH record on an address L. If a DoH listener on L has port 443, or L is in the 443 set (--ddr-doh-443
// and the address table), the record carries no `port` (a client uses 443); otherwise it carries the port of the DoH listener on
// L. There is exactly one DoH record per L, whatever listens there.

func addrSet(addrs ...string) map[netip.Addr]struct{} {
	set := map[netip.Addr]struct{}{}
	for _, a := range addrs {
		set[netip.MustParseAddr(a)] = struct{}{}
	}
	return set
}

func addrPorts(host string, ports ...uint16) []netip.AddrPort {
	var out []netip.AddrPort
	for _, p := range ports {
		out = append(out, netip.AddrPortFrom(netip.MustParseAddr(host), p))
	}
	return out
}

// dohRecords is what a client of L is told when DoH is advertised on dohPort (0: no port), with DoT and DoQ on their ports.
func dohRecords(dohPort uint16) ddrWant {
	return ddrWant{
		svcb:       []ddrSVCB{ddrDoHRec(ddrFQDN, dohPort, ddrL4, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)},
		additional: []string{ddrAddrRR(ddrFQDN, ddrL4)},
	}
}

// noDoH is dohRecords without the DoH record.
var noDoH = ddrWant{
	svcb:       []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ddrL4), ddrDoQRec(ddrFQDN, 0, ddrL4)},
	additional: []string{ddrAddrRR(ddrFQDN, ddrL4)},
}

func TestDDRDoHRecordIsOnPort443OnlyForAListenerOn443OrAnAddressOfTheSet(t *testing.T) {
	certs := ddrLoaded(t)
	cases := []struct {
		name string
		doh  []netip.AddrPort
		set  map[netip.Addr]struct{}
		want ddrWant
	}{
		{"D1 L is not in the set: the configured port", addrPorts(ddrL4, 4443), addrSet(), dohRecords(4443)},
		{"D1 the set names another address", addrPorts(ddrL4, 4443), addrSet(ddrElsewhere), dohRecords(4443)},
		{"D1 the set names an IPv6 address, L is IPv4", addrPorts(ddrL4, 4443), addrSet("2001:db8::1"), dohRecords(4443)},
		{"D2 L is in the set: no port", addrPorts(ddrL4, 4443), addrSet(ddrL4), dohRecords(0)},
		{"D2 L is one of several", addrPorts(ddrL4, 4443), addrSet(ddrElsewhere, ddrL4, "2001:db8::1"), dohRecords(0)},
		{"D2 the set has L but nothing listens there: no DoH record", addrPorts(ddrElsewhere, 4443), addrSet(ddrL4), noDoH},
		{"D3 a listener on 443 as well as the configured port: one record, no port", addrPorts(ddrL4, 4443, 443), addrSet(), dohRecords(0)},
		{"D3 the same listeners in the other order", addrPorts(ddrL4, 443, 4443), addrSet(), dohRecords(0)},
		{"D3 a listener on 443 alone", addrPorts(ddrL4, 443), addrSet(), dohRecords(0)},
		{"D3 a listener on 443 and L in the set: still one record", addrPorts(ddrL4, 4443, 443), addrSet(ddrL4), dohRecords(0)},
		{"a 443 listener on another address does not change L's record", append(addrPorts(ddrL4, 4443), addrPorts(ddrElsewhere, 443)...), addrSet(), dohRecords(4443)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustDDR(t, ddrTarget, certs, ddrAt(ddrL4, 853), c.doh, ddrAt(ddrL4, 853))
			d.setDoH443(c.set)
			query := ddrQuery(t, 0x0DD9, ddrAsk, dnsmessage.TypeSVCB, 0)
			requireDDR(t, query, d.answer(query, netip.MustParseAddr(ddrL4), true), c.want)
		})
	}
}

// The set and the listeners are read at each query: a replaced set, and a 443 listener added or removed live, move the record.
func TestDDRDoHRecordFollowsTheSetAndTheLive443Listeners(t *testing.T) {
	d := mustDDR(t, ddrTarget, ddrLoaded(t), ddrAt(ddrL4, 853), addrPorts(ddrL4, 4443), ddrAt(ddrL4, 853))
	local := netip.MustParseAddr(ddrL4)
	query := ddrQuery(t, 7, ddrAsk, dnsmessage.TypeSVCB, 0)
	require := func(when string, want ddrWant) {
		t.Helper()
		t.Log(when)
		requireDDR(t, query, d.answer(query, local, true), want)
	}
	require("before: the configured port", dohRecords(4443))

	if old := d.setDoH443(addrSet(ddrL4)); len(old) != 0 {
		t.Fatalf("setDoH443 returned %v as the set it replaced, want the empty one the start made", old)
	}
	require("L joins the set", dohRecords(0))

	if old := d.setDoH443(addrSet(ddrElsewhere)); len(old) != 1 || !hasAddr(old, local) {
		t.Fatalf("setDoH443 returned %v as the set it replaced, want {%s}", old, ddrL4)
	}
	require("the set is replaced, not merged: L is out of it", dohRecords(4443))

	d.setDoH443(addrSet())
	d.change(true, "doh", netip.AddrPortFrom(local, 443))
	require("a 443 listener is added live", dohRecords(0))
	d.change(false, "doh", netip.AddrPortFrom(local, 443))
	require("the 443 listener is removed again", dohRecords(4443))

	d.change(false, "doh", netip.AddrPortFrom(local, 4443))
	d.change(true, "doh", netip.AddrPortFrom(local, 443))
	require("only the 443 listener remains", dohRecords(0))
}

// --ddr-doh-443 reaches the answerer through ddrOnListeners, whatever port the kernel picked for the DoH listeners.
func TestDDROnListenersTakesThe443AddressesOfTheFlags(t *testing.T) {
	m := newTLSMaterial(t)
	cfg, err := parseConfig([]string{"--listen", "127.0.0.1", "--dns-name", "fw.example.lan", "--ddr",
		"--ddr-doh-443", "127.0.0.1", "--ddr-doh-443", "::ffff:127.0.0.2", "--", "decider"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var lns []*net.TCPListener
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(host)})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		lns = append(lns, ln)
	}
	d, err := ddrOnListeners(cfg, &tlsListeners{certs: m.certs, doh: lns})
	if err != nil {
		t.Fatal(err)
	}
	for host, noPort := range map[string]bool{"127.0.0.1": true, "127.0.0.2": true, "127.0.0.3": false} {
		answers, _ := d.designate(dnsmessage.MustNewName(ddrAsk), netip.MustParseAddr(host))
		if len(answers) != 1 {
			t.Fatalf("%s: got %d DoH records, want one", host, len(answers))
		}
		hasPort := false
		for _, p := range answers[0].Body.(*dnsmessage.SVCBResource).Params {
			hasPort = hasPort || p.Key == dnsmessage.SVCParamPort
		}
		if hasPort == noPort {
			t.Fatalf("%s: port present %v, want %v", host, hasPort, !noPort)
		}
	}
}

func hasAddr(set map[netip.Addr]struct{}, a netip.Addr) bool {
	_, ok := set[a]
	return ok
}
