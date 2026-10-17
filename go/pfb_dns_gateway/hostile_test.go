package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// answerWith makes the rig's decider answer every query with fixed bytes.
func answerWith(reply []byte) func(decidedQuery) []byte {
	return func(decidedQuery) []byte { return reply }
}

// expectOnlyTheBarrierToReachTheDecider: the barrier query is answered last, so everything sent before it on the same socket
// has been read and judged (datagrams are read in order).
func (r *rig) expectOnlyTheBarrierToReachTheDecider(barrier []byte) {
	r.t.Helper()
	if q := r.nextQuery(); !bytes.Equal(q.wire, barrier) {
		r.t.Fatalf("the decider's first query is %d bytes, want the %d-byte barrier query: a hostile packet reached it", len(q.wire), len(barrier))
	}
	r.requireNoOtherQuery()
}

// Packets the gateway answers nothing to and never shows the decider: no header, or a response (reflection).
func TestUDPPacketsThatCannotBeQueriesAreDroppedBeforeTheDecider(t *testing.T) {
	response := buildQuery(t, 1, "example.", true)
	response[2] |= 0x80
	cases := map[string][]byte{
		"0 bytes":      nil,
		"11 bytes":     make([]byte, 11),
		"response bit": response,
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoAnswer(answerWith([]byte("ok")))
			c := r.udpClient("")
			if _, err := c.Write(packet); err != nil {
				t.Fatal(err)
			}
			barrier := buildQuery(t, 2, "barrier.example.", true)
			if _, err := c.Write(barrier); err != nil {
				t.Fatal(err)
			}
			if got := udpReply(t, c); string(got) != "ok" {
				t.Fatalf("the barrier query: got %q", got)
			}
			requireNoUDPReply(t, c) // nothing answered the hostile packet
			r.expectOnlyTheBarrierToReachTheDecider(barrier)
		})
	}
}

func TestLargestUDPDatagramIsForwardedToTheDecider(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(answerWith([]byte("ok")))
	c := r.udpClient("")
	big := make([]byte, 65507) // the most an IPv4 UDP datagram can carry; 65535 cannot be sent
	if _, err := c.Write(big); err != nil {
		t.Fatal(err)
	}
	if got := udpReply(t, c); string(got) != "ok" {
		t.Fatalf("reply: got %q", got)
	}
	if q := r.nextQuery(); !bytes.Equal(q.wire, big) {
		t.Fatalf("the decider got %d bytes, want the %d-byte datagram intact", len(q.wire), len(big))
	}
}

// qdcount 0 and similar malformed-but-headed queries are the decider's to judge (it answers FORMERR).
func TestQueryWithNoQuestionIsLeftToTheDecider(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			formerr := []byte("decider says FORMERR")
			r.autoAnswer(answerWith(formerr))
			noQuestion := make([]byte, 12)
			binary.BigEndian.PutUint16(noQuestion, 0x0abc)
			noQuestion[2] = 0x01 // RD
			if got := r.roundTrip(tr, "", noQuestion); !bytes.Equal(got, formerr) {
				t.Fatalf("client reply: got %q, want the decider's", got)
			}
			if q := r.nextQuery(); !bytes.Equal(q.wire, noQuestion) {
				t.Fatalf("the decider got %x, want %x", q.wire, noQuestion)
			}
		})
	}
}

func TestTCPLengthPrefixZeroIsIgnoredAndTheConnectionStaysUsable(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(answerWith([]byte("ok")))
	c := r.tcpClient("")
	if _, err := c.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	barrier := buildQuery(t, 2, "barrier.example.", true)
	tcpSend(t, c, barrier)
	if got := tcpReply(t, c); string(got) != "ok" { // TCP is ordered: a reply to the empty frame would come first
		t.Fatalf("the barrier query: got %q", got)
	}
	r.expectOnlyTheBarrierToReachTheDecider(barrier)
}

func TestLargestTCPQueryIsForwardedToTheDecider(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(answerWith([]byte("ok")))
	c := r.tcpClient("")
	big := make([]byte, 65535)
	tcpSend(t, c, big)
	if got := tcpReply(t, c); string(got) != "ok" {
		t.Fatalf("reply: got %q", got)
	}
	if q := r.nextQuery(); !bytes.Equal(q.wire, big) {
		t.Fatalf("the decider got %d bytes, want the %d-byte query intact", len(q.wire), len(big))
	}
}

// A client that promises 65535 bytes, sends 10 and stalls is cut off by the idle timeout.
func TestTCPClientThatStallsMidQueryIsClosedAfterTheIdleTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: 100 * time.Millisecond})
	r.autoAnswer(answerWith([]byte("ok")))
	c := r.tcpClient("")
	if _, err := c.Write(append([]byte{0xff, 0xff}, make([]byte, 10)...)); err != nil {
		t.Fatal(err)
	}
	requireTCPClosed(t, c)
	r.requireNoOtherQuery()
	eventually(t, "the stalled connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == 0 })
}

func TestTCPClientThatSendsOneByteAndHangsUpFreesItsSlot(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(answerWith([]byte("ok")))
	c := r.tcpClient("")
	if _, err := c.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	barrier := buildQuery(t, 2, "barrier.example.", true)
	if got := r.roundTrip(transport{"tcp", true}, "", barrier); string(got) != "ok" { // accepted after the hostile one
		t.Fatalf("the gateway after the hostile client: got %q", got)
	}
	// The barrier connection is still open, so 1 means the hostile one has released its slot.
	eventually(t, "the half-sent connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == 1 })
	r.expectOnlyTheBarrierToReachTheDecider(barrier)
}

// A client that asks and never reads is dropped once the gateway cannot write to it within the idle timeout.
func TestTCPClientThatNeverReadsIsDroppedAfterTheIdleTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: 100 * time.Millisecond})
	r.autoAnswer(answerWith(make([]byte, 60000))) // 300 of these overflow every socket buffer on the path
	c := r.tcpClient("")
	query := binary.BigEndian.AppendUint16(nil, 12)
	query = append(query, buildQuery(t, 1, "a.", true)[:12]...)
	for range 300 {
		if _, err := c.Write(query); err != nil {
			break
		}
	}
	if got := r.roundTrip(transport{"tcp", true}, "", buildQuery(t, 2, "barrier.example.", true)); len(got) != 60000 {
		t.Fatalf("the barrier connection, accepted after the hostile one: got %d bytes", len(got))
	}
	eventually(t, "the connection of a client that never reads to be dropped", func() bool { return r.g.tcpConns.Load() == 1 })
}

// A client that connects and never sends a byte holds a slot only for the idle timeout.
func TestTCPClientThatConnectsAndSaysNothingIsClosedAfterTheIdleTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: 100 * time.Millisecond})
	c := r.tcpClient("")
	requireTCPClosed(t, c)
	r.requireNoOtherQuery()
	eventually(t, "the silent connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == 0 })
}
