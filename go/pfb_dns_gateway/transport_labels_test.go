package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// What the decider is told of a query: the transport label the module logs and counts it under, the client, and the
// listener and its interface description (both empty when the query did not reach an address of the gateway).
func TestTheDeciderIsToldTheTransportLabelAndTheListener(t *testing.T) {
	client, wire := netip.MustParseAddr("::ffff:192.0.2.1"), buildQuery(t, 0x8008, "label.example.", true)
	interfaces := map[netip.Addr]string{
		netip.MustParseAddr("127.0.0.1"): "LAN", netip.IPv4Unspecified(): "WAN", netip.IPv6Unspecified(): "WAN6",
	}
	for _, c := range []struct {
		transport                clientTransport
		listener                 netip.Addr
		wantLabel                string
		wantListener, wantIfname string
	}{
		{clientUDP, netip.MustParseAddr("127.0.0.1"), "UDP", "127.0.0.1", "LAN"},
		{clientTCP, netip.MustParseAddr("127.0.0.1"), "TCP", "127.0.0.1", "LAN"},
		{clientDoT, netip.MustParseAddr("127.0.0.1"), "DoT", "127.0.0.1", "LAN"},
		{clientDoH, netip.MustParseAddr("::ffff:127.0.0.1"), "DoH", "127.0.0.1", "LAN"},
		{clientDoQ, netip.MustParseAddr("127.0.0.1"), "DoQ", "127.0.0.1", "LAN"},
		{clientUDP, netip.Addr{}, "UDP", "", ""},
		{clientTCP, netip.IPv4Unspecified(), "TCP", "", ""},
		{clientDoT, netip.IPv6Unspecified(), "DoT", "", ""},
		{clientDoH, netip.Addr{}, "DoH", "", ""},
		{clientDoQ, netip.IPv4Unspecified(), "DoQ", "", ""},
	} {
		t.Run(c.wantLabel+"/"+c.wantListener, func(t *testing.T) {
			p := newPeer(t)
			asked := make(chan transportQuery, 1)
			p.auto = func(q transportQuery, _ func([]byte) []byte) []byte { asked <- q; return nil }
			g := newGateway(nil, p.decide, nil, time.Second, nil)
			g.listenerInterfaces.Store(&interfaces)
			g.resolve(context.Background(), client, c.listener, c.transport, wire, noForward(t))
			got := <-asked
			if got.transport != c.wantLabel || got.ip != "192.0.2.1" || got.listenerIP != c.wantListener || got.listenerInterface != c.wantIfname || string(got.wire) != string(wire) {
				t.Fatalf("the decider was asked transport=%q client=%q listener=%q interface=%q, want %q 192.0.2.1 %q %q",
					got.transport, got.ip, got.listenerIP, got.listenerInterface, c.wantLabel, c.wantListener, c.wantIfname)
			}
		})
	}
}
