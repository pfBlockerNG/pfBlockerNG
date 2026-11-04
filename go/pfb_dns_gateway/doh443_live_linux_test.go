package main

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: --doh-listen-443 ADDR serves DoH on ADDR:443 as well, bound at start like the other listeners and added or
// removed live by the control socket. DDR advertises DoH without a port wherever a DoH listener is on 443. Nothing here may
// bind the real port 443 (a test is not root, and 443 may be taken): config.doh443Port is the port the gateway treats as 443,
// and the rows use a free one. Linux only, as the rig.

// liveDoH443 starts the rig with DDR on, a free port as its 443, and DoH also on that port at hosts, as --doh-listen-443 does.
// port is set to the number picked, which is none of the rig's.
func liveDoH443(port *int, hosts ...string) liveOpt {
	return func(t *testing.T, cfg *config) {
		liveDDR(t, cfg)
		taken := []int{cfg.port, cfg.dotPort, cfg.dohPort, cfg.doqPort}
		for {
			p := liveFreePorts(t, 1)[0]
			if !slices.Contains(taken, p) {
				*port, cfg.doh443Port = p, p
				break
			}
		}
		cfg.dohListen443 = append(cfg.dohListen443, hosts...)
	}
}

// with443 is r with its 443 port known to at() as `doh443`. port is read now, after the start that sets it.
func (r *liveRig) with443(port *int) *liveRig {
	r.port["doh443"] = *port
	return r
}

// liveUDPQuery is one plain DNS query to ap, IPv4 or IPv6, and its reply.
func liveUDPQuery(t *testing.T, ap netip.AddrPort, wire []byte) []byte {
	t.Helper()
	c, err := net.DialUDP(liveNet("udp", ap), nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	return udpReply(t, c)
}

// requireDoHRecord asks DDR on host over plain DNS and requires its one DoH record to carry dohPort (0: no port, 443 is
// advertised; -1: no DoH record), then the records of the other kinds that listen on host on the rig's ports.
func (r *liveRig) requireDoHRecord(when, host string, dohPort int, others ...string) {
	t := r.t
	t.Helper()
	t.Log(when)
	want := ddrWant{additional: []string{ddrAddrRR(ddrFQDN, host)}}
	if dohPort >= 0 {
		want.svcb = append(want.svcb, ddrDoHRec(ddrFQDN, uint16(dohPort), host, ddrDoHPath))
	}
	if slices.Contains(others, "dot") {
		want.svcb = append(want.svcb, ddrDoTRec(ddrFQDN, uint16(r.port["dot"]), host))
	}
	if slices.Contains(others, "doq") {
		want.svcb = append(want.svcb, ddrDoQRec(ddrFQDN, uint16(r.port["doq"]), host))
	}
	if len(want.svcb) == 0 {
		want = ddrNODATA
	}
	query := ddrQuery(t, 0x0DD0, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, liveUDPQuery(t, r.at("udp+tcp", host), query), want)
}

// D3: DoH is served on the 443 port of an --doh-listen-443 address as well as on the configured port, with the same certificate,
// and DDR advertises 443 there: one record, no port.
func TestDoHIsAlsoServedOn443AndDDRAdvertises443(t *testing.T) {
	var y int
	r := newLiveRig(t, liveDoH443(&y, "127.0.0.1")).with443(&y)
	at443, atConfigured := r.at("doh443", "127.0.0.1"), r.at("doh", "127.0.0.1")
	if !r.hasLine("listening doh " + at443.String()) {
		t.Fatalf("no `listening doh %s` line:\n%s", at443, r.logs.text())
	}
	r.ask("doh", at443)
	r.ask("doh", atConfigured)
	if got, want := r.list(), listReply(append(r.defaultKeys(), liveKey("doh", at443)), nil); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
	r.requireDoHRecord("D3 DoH listens on both ports", "127.0.0.1", 0, "dot", "doq")

	// the same handler and trusted front ends as --doh-listen: the client an X-Forwarded-For names is believed from the front end
	// and from nobody else, on either port. The ACL refuses 203.0.113.9.
	const named = "203.0.113.9"
	for _, ap := range []netip.AddrPort{atConfigured, at443} {
		rcode := func(source string) byte {
			c := r.doh(ap, source)
			resp, body := c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", named))
			if resp.StatusCode != 200 || len(body) < 12 {
				t.Fatalf("DoH on %s as %s: status %d body %x", ap, source, resp.StatusCode, body)
			}
			return body[3] & 0x0f
		}
		if got := rcode(liveFront); got != 5 {
			t.Fatalf("DoH on %s from the trusted front end naming %s: rcode %d, want 5 (REFUSED)", ap, named, got)
		}
		if got := rcode("127.0.0.3"); got != 0 {
			t.Fatalf("DoH on %s from a client that is not trusted naming %s: rcode %d, want 0", ap, named, got)
		}
	}

	// the 443 listener is tracked like any other: a remove closes it and DDR is back to the configured port
	r.remove("doh", at443)
	r.requireGone("doh", at443)
	r.requireDoHRecord("the 443 listener is removed", "127.0.0.1", r.port["doh"], "dot", "doq")
	r.ask("doh", atConfigured)
}

// D3 on IPv6: the same, and the key of the listener is spelled with brackets.
func TestDoHIsAlsoServedOn443OfAnIPv6Address(t *testing.T) {
	liveNeedAddr(t, "::1")
	var y int
	r := newLiveRig(t, liveAlso("udp+tcp", "::1"), liveAlso("doh", "::1"), liveDoH443(&y, "::1")).with443(&y)
	at443 := r.at("doh443", "::1")
	if !r.hasLine("listening doh [::1]:" + strconv.Itoa(y)) {
		t.Fatalf("no `listening doh [::1]:%d` line:\n%s", y, r.logs.text())
	}
	r.ask("doh", at443)
	r.requireDoHRecord("D3 on ::1", "::1", 0)
}

// D4: the 443 bind is refused at start (the port is taken): the gateway still starts and serves, the refusal is listed under
// the listener's key, and DDR advertises the configured port there. Once the port is free a live add serves it, clears the
// refusal, and DDR advertises 443.
func TestARefused443BindIsListedAndDDRAdvertisesTheConfiguredPort(t *testing.T) {
	var y int
	var held net.Listener
	r := newLiveRig(t, liveDoH443(&y, "127.0.0.1"), func(t *testing.T, cfg *config) {
		held = liveHoldTCP(t, "127.0.0.1", cfg.doh443Port)
	}).with443(&y)
	at443 := r.at("doh443", "127.0.0.1")
	if r.hasLine("listening doh " + at443.String()) {
		t.Fatalf("`listening doh %s` was logged although the port is held:\n%s", at443, r.logs.text())
	}
	if got, want := r.list(), listReply(r.defaultKeys(), map[string]string{liveKey("doh", at443): liveInUse}); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
	r.requireDoHRecord("D4 the refused 443 is not advertised", "127.0.0.1", r.port["doh"], "dot", "doq")
	r.ask("doh", r.at("doh", "127.0.0.1"))

	_ = held.Close()
	r.add("doh", at443)
	r.ask("doh", at443)
	if got, want := r.list(), listReply(append(r.defaultKeys(), liveKey("doh", at443)), nil); got != want {
		t.Fatalf("after the live add: list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
	r.requireDoHRecord("the live add of the 443 listener", "127.0.0.1", 0, "dot", "doq")
}

// D8: a listener on 443 is added and removed live, with no restart. A doh add is taken on the configured port of its family and
// on 443; any other port, and 443 for any other kind, is refused. Nothing needed --doh-listen-443 at start.
func TestALive443AddAndRemoveFollowsDDR(t *testing.T) {
	var y int
	r := newLiveRig(t, liveDoH443(&y)).with443(&y)
	const host = "127.0.0.2"
	configured, at443 := r.at("doh", host), r.at("doh443", host)
	r.add("udp+tcp", r.at("udp+tcp", host)) // somewhere to ask DDR
	strangerAt := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(r.stranger))
	reply := r.refuse("doh on a port that is neither the configured one nor 443", false, func() []livePart {
		return []livePart{{r.addFrame("doh", strangerAt), liveSockets(t, "doh", strangerAt)}}
	})
	if !strings.Contains(reply, strconv.Itoa(r.stranger)) {
		t.Fatalf("the refusal %q does not name the port %d", reply, r.stranger)
	}
	for _, kind := range []string{"dot", "doq"} {
		reply := r.refuse(kind+" on the 443 port", false, func() []livePart {
			return []livePart{{r.addFrame(kind, at443), liveSockets(t, kind, at443)}}
		})
		if !strings.Contains(reply, strconv.Itoa(y)) {
			t.Fatalf("the refusal %q does not name the port %d", reply, y)
		}
	}

	r.add("doh", configured)
	r.requireDoHRecord("the configured port only", host, r.port["doh"])
	r.add("doh", at443)
	r.ask("doh", at443)
	r.requireDoHRecord("D8 the 443 listener is added: one record, no port", host, 0)

	r.remove("doh", configured)
	r.requireDoHRecord("the configured listener is removed: 443 is all that is left", host, 0)
	r.add("doh", configured)
	r.remove("doh", at443)
	r.requireGone("doh", at443)
	r.requireDoHRecord("D8 the 443 listener is removed: the configured port again", host, r.port["doh"])
	r.ask("doh", configured)

	r.requireDoHRecord("after the refused adds", host, r.port["doh"])
}

// A gateway without DoH does not take a DoH add on 443 either.
func TestADoHAddOn443IsRefusedWithoutDoH(t *testing.T) {
	var y int
	r := newLiveRig(t, liveOnly("dot"), liveDoH443(&y)).with443(&y)
	at443 := r.at("doh443", "127.0.0.2")
	reply := r.refuse("doh on 443 without --doh-listen", false, func() []livePart {
		return []livePart{{r.addFrame("doh", at443), liveSockets(t, "doh", at443)}}
	})
	if !strings.Contains(reply, "doh") {
		t.Fatalf("the refusal %q does not name the kind", reply)
	}
}
