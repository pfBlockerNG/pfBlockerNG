package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

const watchdog = 10 * time.Second // stuck-run guard for waits; never asserted on

// peerEvent is one step of the script from the gateway's side: a query the gateway asks of the decider (query), or the reply
// to a forward the decider asked for (reply).
type peerEvent struct {
	id    uint32
	query *transportQuery
	reply []byte
}

type peerCall struct {
	forwards chan []byte // the wires the test has the decider forward
	final    chan []byte // the answer the test gives; nil is a drop
}

// peer is the decider of a test: the gateway's decide seam, driven by the test one call at a time (forward, answer, drop,
// recvQuery, expectForwarded), or by a function that answers every query (auto).
type peer struct {
	t      *testing.T
	events chan peerEvent // what the gateway did, in order
	done   chan struct{}  // closed by release: queries still held return as dropped

	mu    sync.Mutex
	next  uint32
	calls map[uint32]*peerCall
	auto  func(q transportQuery, fwd func([]byte) []byte) []byte
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	p := &peer{t: t, events: make(chan peerEvent, 4096), done: make(chan struct{}), calls: map[uint32]*peerCall{}}
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
	c := &peerCall{forwards: make(chan []byte, 1), final: make(chan []byte, 1)}
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
	p.events <- peerEvent{id: id, query: &q}
	for {
		select {
		case w := <-c.forwards:
			p.events <- peerEvent{id: id, reply: fwd(w)}
		case answer := <-c.final:
			return answer
		case <-p.done:
			return nil
		}
	}
}

// call is the held query id, nil when it is over: what the test says about a query that is over is ignored.
func (p *peer) call(id uint32) *peerCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[id]
}

// forward has the decider forward wire to Unbound for the query id.
func (p *peer) forward(id uint32, wire []byte) {
	if c := p.call(id); c != nil {
		c.forwards <- bytes.Clone(wire)
	}
}

// answer has the decider answer the query id with wire.
func (p *peer) answer(id uint32, wire []byte) {
	if c := p.call(id); c != nil {
		c.final <- append([]byte{}, wire...)
	}
}

// drop has the decider give the query id no answer.
func (p *peer) drop(id uint32) {
	if c := p.call(id); c != nil {
		c.final <- nil
	}
}

func (p *peer) recvEvent() peerEvent {
	p.t.Helper()
	select {
	case e := <-p.events:
		return e
	case <-time.After(watchdog):
		p.t.Fatal("STUCK/ENVIRONMENT: the gateway did nothing the decider could see")
		return peerEvent{}
	}
}

// recvQuery is the next thing the gateway does, which must be asking the decider a query.
func (p *peer) recvQuery() transportQuery {
	p.t.Helper()
	e := p.recvEvent()
	if e.query == nil {
		p.t.Fatalf("the gateway returned %x to a forward, want a query", e.reply)
	}
	return *e.query
}

// expectForwarded reads the next thing the gateway does and fails unless it is returning exactly reply to the forward of query id.
func (p *peer) expectForwarded(id uint32, reply []byte) {
	p.t.Helper()
	e := p.recvEvent()
	if e.query != nil || e.id != id || !bytes.Equal(e.reply, reply) {
		p.t.Fatalf("the gateway did: query=%v id=%d reply=%x, want reply %x to the forward of query %d", e.query != nil, e.id, e.reply, reply, id)
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
