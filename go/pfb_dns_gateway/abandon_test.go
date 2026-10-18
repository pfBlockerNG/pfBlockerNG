package main

import "testing"

// F7: a FORWARD that reached the query but was never picked up when it was abandoned still gets its (empty) REPLY,
// or the decider waits for it until its own timeout; with nothing pending no frame is sent.
func TestAbandoningAQueryWithAnUnpickedForwardAnswersThatForwardEmpty(t *testing.T) {
	d, p, _ := readyPeer(t)
	pending := &call{forward: make(chan []byte, 1), final: make(chan []byte, 1)}
	id, err := d.register(pending)
	if err != nil {
		t.Fatal(err)
	}
	if pending.deliver([]byte("forward nobody picked up")) {
		t.Fatal("a live query refused a FORWARD")
	}
	d.abandon(id, pending)
	p.expect(tReply, id, nil)

	idle := &call{forward: make(chan []byte, 1), final: make(chan []byte, 1)}
	idleID, err := d.register(idle)
	if err != nil {
		t.Fatal(err)
	}
	d.abandon(idleID, idle) // nothing pending: no REPLY
	next := decide(d, t.Context(), "192.0.2.12", []byte("n"), noForward(t))
	if typ, _, _ := p.recv(); typ != tQuery {
		t.Fatalf("the next frame from the gateway has type %d, want QUERY: an abandoned query with no FORWARD pending sent a REPLY", typ)
	}
	_ = next
}
