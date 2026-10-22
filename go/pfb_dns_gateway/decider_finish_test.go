package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

// issue #3566: once finish has taken a query off the table, the table may be empty, the drain sees it, and the retirement
// closes the session; the answer must already be in the query's hands by then, or a REPLY that then fails loses it.
func TestAnAnswerIsInTheQuerysHandsBeforeItsCallLeavesTheTable(t *testing.T) {
	d, p, _ := readyPeer(t)
	inFinish, leaveFinish := make(chan struct{}), make(chan struct{})
	leave := sync.OnceFunc(func() { close(leaveFinish) })
	t.Cleanup(leave)
	d.mu.Lock()
	d.finished = func() { close(inFinish); <-leaveFinish }
	d.mu.Unlock()

	entered, release := make(chan struct{}), make(chan struct{})
	wire := buildQuery(t, 0x0e01, "gap.example.", true)
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
	want := bytes.Clone(wire)
	want[2] |= 0x80
	p.send(tAnswer, id, want)
	waitClosed(t, inFinish, "the ANSWER to take the call off the table")
	waitClosed(t, d.drained(), "the table to drain")
	d.Close()      // what the retirement does the moment the table is empty
	close(release) // the query sends its REPLY on a closed session
	r := result(t, res)
	leave()
	if r.err != nil || !bytes.Equal(r.answer, want) {
		t.Fatalf("query the decider answered: got %x (err %v), want %x", r.answer, r.err, want)
	}
}
