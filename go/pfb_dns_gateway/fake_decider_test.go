package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

const watchdog = 10 * time.Second // stuck-run guard for waits; never asserted on

// The frame names of the script a test plays as the decider: the gateway's QUERY and REPLY come out of peer.recv, the test's
// FORWARD, ANSWER and DROP go in through peer.send. They are the vocabulary of the old decision protocol, kept because a
// test reads best as that conversation; nothing is framed, the gateway calls peer.decide in its own process.
const (
	tQuery, tForward, tReply, tAnswer, tDrop byte = 1, 2, 3, 4, 5
)

// peerFrame is one step of the script from the gateway's side: a QUERY (query) or a REPLY (payload).
type peerFrame struct {
	typ     byte
	id      uint32
	payload []byte
	query   transportQuery
}

type peerCall struct {
	forward chan []byte // the test's FORWARD wires
	final   chan []byte // the test's ANSWER; a nil send is DROP
}

// peer is the decider of a test: the gateway's decide seam, driven by the test one frame at a time (send, recv, expect), or
// by a function that answers every query (auto).
type peer struct {
	t    *testing.T
	out  chan peerFrame // the gateway's QUERYs and REPLYs, in order
	done chan struct{}  // closed by release: queries still held return as dropped

	mu    sync.Mutex
	next  uint32
	calls map[uint32]*peerCall
	auto  func(q transportQuery, fwd func([]byte) []byte) []byte
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	p := &peer{t: t, out: make(chan peerFrame, 4096), done: make(chan struct{}), calls: map[uint32]*peerCall{}}
	t.Cleanup(p.release)
	return p
}

// release lets every held query go (dropped), so that a test that leaves queries unanswered cannot hold a shutdown.
func (p *peer) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

// decide is the gateway's decide seam.
func (p *peer) decide(wire []byte, clientIP string, fwd func([]byte) []byte, transport, listenerIP, listenerInterface string) []byte {
	p.mu.Lock()
	p.next++
	id := p.next
	auto := p.auto
	c := &peerCall{forward: make(chan []byte, 1), final: make(chan []byte, 1)}
	p.calls[id] = c
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.calls, id); p.mu.Unlock() }()
	q := transportQuery{
		id: id, transport: transport, ip: clientIP,
		listenerIP: listenerIP, listenerInterface: listenerInterface, wire: bytes.Clone(wire),
	}
	if auto != nil {
		return auto(q, fwd)
	}
	p.out <- peerFrame{typ: tQuery, id: id, query: q}
	for {
		select {
		case w := <-c.forward:
			p.out <- peerFrame{typ: tReply, id: id, payload: fwd(w)}
		case answer := <-c.final:
			return answer
		case <-p.done:
			return nil
		}
	}
}

// send plays a frame of the decider: FORWARD, ANSWER or DROP for the query id. Frames for a query that is over are ignored.
func (p *peer) send(typ byte, id uint32, payload []byte) {
	p.t.Helper()
	p.mu.Lock()
	c := p.calls[id]
	p.mu.Unlock()
	if c == nil {
		return
	}
	switch typ {
	case tForward:
		c.forward <- bytes.Clone(payload)
	case tAnswer:
		c.final <- append([]byte{}, payload...)
	case tDrop:
		c.final <- nil
	default:
		p.t.Fatalf("peer.send: frame type %d is not the decider's", typ)
	}
}

func (p *peer) recvFrame() peerFrame {
	p.t.Helper()
	select {
	case f := <-p.out:
		return f
	case <-time.After(watchdog):
		p.t.Fatal("STUCK/ENVIRONMENT: the gateway sent the decider nothing")
		return peerFrame{}
	}
}

// recvQuery is the next frame, which must be a QUERY.
func (p *peer) recvQuery() transportQuery {
	p.t.Helper()
	f := p.recvFrame()
	if f.typ != tQuery {
		p.t.Fatalf("frame from the gateway: type %d, want QUERY", f.typ)
	}
	return f.query
}

// expect reads one frame and fails unless it is the REPLY to id with exactly payload.
func (p *peer) expect(typ byte, id uint32, payload []byte) {
	p.t.Helper()
	f := p.recvFrame()
	if f.typ != typ || f.id != id || !bytes.Equal(f.payload, payload) {
		p.t.Fatalf("frame from the gateway: got type=%d id=%d payload=%x, want type=%d id=%d payload=%x", f.typ, f.id, f.payload, typ, id, payload)
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(watchdog):
		t.Fatalf("STUCK/ENVIRONMENT: %s never happened", what)
	}
}

func noForward(t *testing.T) forwarder {
	return func(ctx context.Context, wire []byte) []byte {
		t.Error("the gateway must not forward here")
		return nil
	}
}
