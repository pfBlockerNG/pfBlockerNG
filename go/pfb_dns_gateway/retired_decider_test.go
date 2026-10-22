package main

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"
)

// issue #3566: a query that read the active decider just before a restart replaced it, and reaches it only once it is
// retired (and closed), is asked of the decider that is active now, once; a decider that failed on its own is no
// reason to ask another one.

// answerOne plays the active decider for one QUERY: it answers with the query echoed and QR set, and hands back the
// wire it was asked.
func answerOne(p *peer) <-chan []byte {
	asked := make(chan []byte, 1)
	go func() {
		_ = p.conn.SetReadDeadline(time.Now().Add(watchdog))
		typ, id, payload, err := fakeFrame(p.conn)
		if err != nil || typ != tQuery {
			close(asked)
			return
		}
		wire := payload[2+int(payload[1]):]
		answer := bytes.Clone(wire)
		answer[2] |= 0x80
		_, _ = p.conn.Write(pack(tAnswer, id, answer))
		asked <- wire
	}()
	return asked
}

func registrations(d *Decider) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nextID
}

func TestAQueryThatReachesARetiredDeciderIsAskedOfTheActiveOne(t *testing.T) {
	old, _, _ := readyPeer(t)
	active, activePeer, logs := readyPeer(t)
	g := newGateway(nil, active, nil, time.Second, logs.logf)
	old.markRetired() // what a restart does to the decider it replaces, then the retirement closes it
	old.Close()
	asked := answerOne(activePeer)

	wire := buildQuery(t, 0x3566, "stale.example.", true)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	answer, err := g.decide(ctx, old, netip.MustParseAddr("192.0.2.1"), false, wire, noForward(t))
	if want := echoWithQR(seenQuery{wire: wire})[0]; err != nil || !bytes.Equal(answer, want) {
		t.Fatalf("query on a retired decider: got %x (err %v), want the active decider's answer %x", answer, err, want)
	}
	if got := <-asked; !bytes.Equal(got, wire) {
		t.Fatalf("the active decider was asked %x, want %x", got, wire)
	}
	if n := registrations(old); n != 0 {
		t.Fatalf("the retired decider took %d queries, want none", n)
	}
}

func TestAQueryOnADeciderThatFailedOnItsOwnIsNotAskedOfAnother(t *testing.T) {
	dead, deadPeer, _ := readyPeer(t)
	active, _, logs := readyPeer(t)
	g := newGateway(nil, active, nil, time.Second, logs.logf)
	_ = deadPeer.conn.Close() // the decider went away by itself: no restart replaced it
	waitClosed(t, dead.Done(), "the dead decider's session end")

	wire := buildQuery(t, 0x3567, "dead.example.", true)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	if answer, err := g.decide(ctx, dead, netip.MustParseAddr("192.0.2.1"), false, wire, noForward(t)); err == nil {
		t.Fatalf("query on a decider that failed on its own: got %x and no error, want the failure (SERVFAIL)", answer)
	}
	if n := registrations(active); n != 0 {
		t.Fatalf("the active decider was asked %d queries for a decider that failed on its own, want none", n)
	}
}
