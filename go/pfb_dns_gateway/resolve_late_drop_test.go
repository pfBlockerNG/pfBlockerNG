package main

import (
	"context"
	"net/netip"
	"testing"
)

// A decider DROP is no reply, however late it comes. A query whose whole-query limit has run out by the time the
// decider returns gets SERVFAIL only when the decider answered: a drop after the limit stays a drop, as it was before the
// decider moved into the process. The limit is zero here, so it is over before the decider is called.
func TestADeciderDropAfterTheQueryLimitIsStillNoReply(t *testing.T) {
	client, wire := netip.MustParseAddr(clientAllowed), buildQuery(t, 0x0009, "late.example.", true)
	for _, c := range []struct {
		name   string
		answer []byte
		want   []byte
	}{
		{"drop", nil, nil},
		{"answer", []byte("too late"), buildServfail(wire)},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newGateway(nil, func([]byte, string, func([]byte) []byte, string, string, string) []byte { return c.answer }, nil, 0, nil)
			g.grace = 0
			if got := g.resolve(context.Background(), client, netip.Addr{}, clientUDP, wire, noForward(t)); string(got) != string(c.want) || (got == nil) != (c.want == nil) {
				t.Fatalf("reply %x after the limit, want %x", got, c.want)
			}
		})
	}
}
