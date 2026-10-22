package main

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
)

// issue #3566: an ANSWER the decider delivered to a query is the query's, even when the session ends before the query looks
// at it. A retired decider is closed the moment its table is empty, which is the moment its last answer is delivered.

// heldWrite holds the first Write after it is on the wire: the query's goroutine has sent its QUERY and not yet looked
// for the answer.
type heldWrite struct {
	net.Conn
	hold func()
}

func (c heldWrite) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.hold()
	return n, err
}

// answerAndClose plays the decider's ANSWER to the query id carries, waits until the call has it and the table is empty,
// then closes the session as the retirement does.
func answerAndClose(t *testing.T, d *Decider, p *peer, id uint32, wire []byte) {
	t.Helper()
	answer := bytes.Clone(wire)
	answer[2] |= 0x80
	p.send(tAnswer, id, answer)
	eventually(t, "the ANSWER to finish the call", func() bool { return d.lookup(id) == nil })
	waitClosed(t, d.drained(), "the table to drain")
	d.Close()
	waitClosed(t, d.Done(), "the session to end")
}

// The answer is in the call and the session has ended when the query looks: both are ready, and the answer must win
// every time, not half of them.
func TestADeliveredAnswerIsNotLostWhenTheSessionEndsBeforeTheQueryLooks(t *testing.T) {
	const rounds = 60
	lost := 0
	for range rounds {
		parent, end, err := newSocketpair()
		if err != nil {
			t.Fatal(err)
		}
		other, err := net.FileConn(end)
		if err != nil {
			t.Fatal(err)
		}
		_ = end.Close()
		wrote, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		d := NewDecider(heldWrite{Conn: parent, hold: func() { once.Do(func() { close(wrote); <-release }) }}, func(string, ...any) {})
		p := &peer{t: t, conn: other}
		p.send(tReady, 0, nil)
		waitClosed(t, d.Ready(), "READY")
		wire := buildQuery(t, 0x0d01, "window.example.", true)
		res := decide(d, context.Background(), "127.0.0.1", wire, noForward(t))
		waitClosed(t, wrote, "the QUERY to be written")
		typ, id, _ := p.recv()
		if typ != tQuery {
			t.Fatalf("frame type %d from the gateway, want QUERY", typ)
		}
		answerAndClose(t, d, p, id, wire)
		close(release)
		if r := result(t, res); r.err != nil || !bytes.Equal(r.answer, echoWithQR(seenQuery{wire: wire})[0]) {
			lost++
		}
		_ = other.Close()
	}
	if lost != 0 {
		t.Fatalf("%d of %d answers were delivered to the query and lost to the session end, want 0", lost, rounds)
	}
}

// The decider answers on its own while the query still serves its FORWARD; the session ends before the REPLY can be
// sent. The REPLY is moot, the answer is not.
func TestADeliveredAnswerSurvivesAReplyThatCannotBeSent(t *testing.T) {
	d, p, _ := readyPeer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	wire := buildQuery(t, 0x0c01, "inhand.example.", true)
	res := decide(d, context.Background(), "127.0.0.1", wire, func(context.Context, []byte) []byte {
		close(entered)
		<-release
		return nil
	})
	typ, id, _ := p.recv()
	if typ != tQuery {
		t.Fatalf("frame type %d from the gateway, want QUERY", typ)
	}
	p.send(tForward, id, wire)
	waitClosed(t, entered, "the FORWARD to reach the query")
	answerAndClose(t, d, p, id, wire)
	close(release)
	want := bytes.Clone(wire)
	want[2] |= 0x80
	if r := result(t, res); r.err != nil || !bytes.Equal(r.answer, want) {
		t.Fatalf("query answered by the decider: got %x (err %v), want %x", r.answer, r.err, want)
	}
}
