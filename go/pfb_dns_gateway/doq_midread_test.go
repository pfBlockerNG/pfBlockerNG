package main

import "testing"

// A deny that lands while the gateway reads a stream is judged when that read ends, before the stream is parsed or
// dropped. Each row is synchronized the same way: the head of the stream is sent, one round trip on a second stream
// follows, the ACL then denies the client, and the tail and the FIN arrive. The round trip cannot start until the
// gateway has accepted the first stream, so the first stream's admission check has run while its client was allowed.
// The short frame, the runt and the non-zero Message ID never reach screen, so only the check at the end of the read
// can close them.
func TestDoQDenyLandingMidReadClosesTheConnection(t *testing.T) {
	valid := framed(doqQuery(t, "midread.example."))
	withID := framed(buildQuery(t, 0x1234, "midread.example.", true))
	rows := []struct {
		name       string
		head, tail []byte
	}{
		{"a valid query", valid[:6], valid[6:]},
		{"a query with a non-zero Message ID", withID[:6], withID[6:]},
		{"a two-byte message", []byte{0, 2}, []byte{0, 0}},
		{"a frame short of its announced length, then FIN", []byte{0, 32, 1, 2}, nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{})
			r.autoAnswer(echoAnswer)
			c := dialDoQ(t, addr, m, clientAllowed)
			s := c.stream()
			put(t, s, row.head)
			c.query(doqQuery(t, "sync.example."))
			r.nextQuery()
			rewriteACL(t, r, aclMixed+"access-control: "+clientAllowed+"/32 deny\n")
			if len(row.tail) > 0 {
				put(t, s, row.tail)
			}
			_ = s.Close()
			requireDeniedConnClosed(t, r, c)
		})
	}
}

// The path moves to an address the ACL allows, the stream is read there, and then the ACL denies that address: the
// connection's current address is read again when the read ends. A round trip sent on the old path after the first
// stream is answered only once that stream was accepted, so the first stream's admission check runs before the move.
// The move is observed on the client the decider receives, which is the address the gateway screened that query at,
// so the test waits on an observed event, not a sleep. No stream is opened after the deny.
func TestDoQPathMovedToADeniedAddressMidReadClosesTheConnection(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true") // the rebinding socket is not a *net.UDPConn
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	pc := listenRebinding(t, clientAllowed)
	c := dialDoQPacket(t, addr, m, pc)
	s := c.stream()
	put(t, s, []byte{0, 3, 0}) // three bytes announced, one sent: the gateway is reading this stream
	if _, err := doqRound(t, c, doqQuery(t, "sync.example.")); err != nil {
		t.Fatalf("query on the allowed path: %v", err)
	}
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("before the path change the decider saw %s, want %s", q.ip, clientAllowed)
	}
	pc.bind(otherClient)
	moved := false
	for range 16 {
		if _, err := doqRound(t, c, doqQuery(t, "probe.example.")); err != nil {
			t.Fatalf("probe after the path change: %v", err)
		}
		if r.nextQuery().ip == otherClient {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatalf("no probe stream was screened at %s after the path moved", otherClient)
	}
	rewriteACL(t, r, aclMixed+"access-control: "+otherClient+"/32 deny\n")
	put(t, s, []byte{0, 0}) // the read ends on the denied current address
	_ = s.Close()
	requireDeniedConnClosed(t, r, c)
}
