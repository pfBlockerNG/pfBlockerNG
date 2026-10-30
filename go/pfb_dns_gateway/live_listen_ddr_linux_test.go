package main

import (
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// With --ddr, `_dns.resolver.arpa. SVCB` names the encrypted listeners that serve on the address it was asked on: the ones
// the gateway serves now, so a live add is designated and a live remove no longer is.

func liveDDR(_ *testing.T, cfg *config) { cfg.ddr = ddrTarget }

// requireDesignates asks `_dns.resolver.arpa. SVCB` over plain UDP on host and requires exactly the records of kinds (the
// encrypted listeners on host, in the order DDR ranks them), with the firewall's address record; none is NODATA.
func (r *liveRig) requireDesignates(when, host string, kinds ...string) {
	t := r.t
	t.Helper()
	t.Log(when)
	want := ddrNODATA
	if len(kinds) > 0 {
		want = ddrWant{additional: []string{ddrAddrRR(ddrFQDN, host)}}
		for _, kind := range []string{"doh", "dot", "doq"} {
			if !slices.Contains(kinds, kind) {
				continue
			}
			port := uint16(r.port[kind])
			rec := map[string]ddrSVCB{
				"doh": ddrDoHRec(ddrFQDN, port, host, ddrDoHPath), "dot": ddrDoTRec(ddrFQDN, port, host), "doq": ddrDoQRec(ddrFQDN, port, host),
			}[kind]
			want.svcb = append(want.svcb, rec)
		}
	}
	query := ddrQuery(t, 0x0DD0, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, udpQuery(t, r.at("udp+tcp", host), query), want)
}

func TestDDRDesignatesTheListenersServedNowAfterLiveAddsAndRemoves(t *testing.T) {
	r := newLiveRig(t, liveDDR)
	const bound, added = "127.0.0.1", "127.0.0.2"
	r.requireDesignates("start: everything the start bound", bound, "doh", "dot", "doq")

	r.add("udp+tcp", r.at("udp+tcp", added)) // somewhere to ask: nothing encrypted listens there yet
	r.requireDesignates("a plain listener alone designates nothing", added)
	for i, kind := range []string{"dot", "doh", "doq"} {
		r.add(kind, r.at(kind, added))
		r.requireDesignates("added "+kind+" "+added, added, []string{"dot", "doh", "doq"}[:i+1]...)
	}
	r.requireDesignates("the start's own address is unchanged by the adds", bound, "doh", "dot", "doq")

	r.remove("dot", r.at("dot", bound))
	r.requireDesignates("removed the start's dot", bound, "doh", "doq")
	r.requireDesignates("the added address keeps all three", added, "doh", "dot", "doq")

	r.remove("doh", r.at("doh", added))
	r.requireDesignates("removed the added doh", added, "dot", "doq")
	r.requireDesignates("the start's address is unchanged by that remove", bound, "doh", "doq")
}
