package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 32 queries pipelined on one connection, each answered with a reply of its own size: every reply comes back whole,
// whichever order the handlers finish in. Run under -race, it is also the guard on the write path the handlers share.
func TestPipelinedRepliesOfDifferentSizesComeBackWhole(t *testing.T) {
	const queries = 32
	filler := func(id uint16) []byte { return bytes.Repeat([]byte{byte(id)}, int(id)*1500) }
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoAnswer(func(q decidedQuery) []byte { return append(echoAnswer(q), filler(queryID(q.wire))...) })
			c := k.dial(t, r)
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				for id := uint16(1); id <= queries; id++ {
					if _, err := c.Write(framed(buildQuery(t, id, "example.", true))); err != nil {
						return
					}
				}
			}()
			seen := map[uint16]bool{}
			for range queries {
				reply := tcpReply(t, c)
				id := queryID(reply)
				if want := append(echoAnswer(decidedQuery{wire: buildQuery(t, id, "example.", true)}), filler(id)...); !bytes.Equal(reply, want) {
					t.Fatalf("the reply to query %d is %d bytes and differs from what the decider answered (%d bytes)", id, len(reply), len(want))
				}
				seen[id] = true
			}
			<-sent
			if len(seen) != queries {
				t.Fatalf("%d distinct replies for %d queries", len(seen), queries)
			}
		})
	}
}

// A connection that failed is closed and not put back; one that answered is kept for the next forward. The failure is the
// exchange being ended while Unbound is silent, as the timeout would end it (the connection is closed the same way), once
// Unbound has the query: no real deadline sits under either exchange, so none races the one that must succeed.
func TestPoolKeepsAConnectionThatAnsweredAndNeverOneThatFailed(t *testing.T) {
	var asked atomic.Int32
	f := newFakeUpstream(t, answering(func(q seenQuery) [][]byte {
		if asked.Add(1) == 1 {
			return nil // the first query is never answered
		}
		return echoWithQR(q)
	}))
	u := newUpstream(f.addr, watchdog)
	p := u.newPool(headerFor(t, "ipv4 tcp"))
	t.Cleanup(p.close)
	query := buildQuery(t, 1, "example.", true)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	silent := make(chan []byte, 1)
	go func() { silent <- p.exchange(ctx, query) }()
	f.next() // Unbound has the query and says nothing: the exchange is parked waiting for its reply
	cancel()
	if got := awaitBytes(t, silent); got != nil {
		t.Fatalf("a silent Unbound answered %x", got)
	}
	if n := len(p.idle); n != 0 {
		t.Fatalf("a connection that failed went back to the pool (%d idle)", n)
	}
	if got := p.exchange(context.Background(), query); !bytes.Equal(got, echoWithQR(seenQuery{wire: query})[0]) {
		t.Fatalf("the exchange after a failed one got %x", got)
	}
	if n := len(p.idle); n != 1 {
		t.Fatalf("a connection that answered must be kept, %d idle", n)
	}
	p.close()
	if n := len(p.idle); n != 0 {
		t.Fatalf("close left %d connections", n)
	}
}

// A client that resets its connection while queries are in flight (one short of the pipeline limit: a connection at
// the limit is not read, so it learns of the reset when a query finishes): the read fails, every handler is cancelled,
// and the connection frees its slot. The handlers also reach the write path together, which -race may flag if its
// failure flag is unguarded; race detection is intermittent, so the assertion here is the freed slot.
func TestAClientThatResetsWithQueriesInFlightFreesItsSlot(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	held := make(chan struct{})
	t.Cleanup(sync.OnceFunc(func() { close(held) }))
	r.autoAnswer(func(q decidedQuery) []byte { <-held; return echoAnswer(q) })
	c := r.tcpClient("").(*net.TCPConn)
	for id := uint16(1); id < pipelineDepth; id++ {
		tcpSend(t, c, buildQuery(t, id, "held.example.", true))
	}
	for range pipelineDepth - 1 {
		r.nextQuery()
	}
	if err := c.SetLinger(0); err != nil { // Close now sends RST
		t.Fatal(err)
	}
	_ = c.Close()
	eventually(t, "the reset client's slot to be freed", func() bool { return r.g.tcpConns.Load() == 0 })
}

// deadlineless ignores deadlines, so a write on it blocks until the connection is closed: crypto/tls would otherwise
// give up on a close_notify by itself after 5 s, which hides whether closeTLS has a bound of its own.
type deadlineless struct{ net.Conn }

func (deadlineless) SetDeadline(time.Time) error      { return nil }
func (deadlineless) SetReadDeadline(time.Time) error  { return nil }
func (deadlineless) SetWriteDeadline(time.Time) error { return nil }

// A peer that never reads cannot hold a close: closeTLS cuts the connection after its bound.
func TestCloseTLSGivesUpOnAPeerThatDoesNotRead(t *testing.T) {
	m := newTLSMaterial(t)
	serverConf := m.certs.dot().Clone()
	serverConf.SessionTicketsDisabled = true // a ticket would block the handshake on a pipe nobody reads
	clientEnd, serverEnd := net.Pipe()
	raw := deadlineless{serverEnd}
	t.Cleanup(func() { _ = clientEnd.Close(); _ = raw.Close() })
	go func() { _ = tls.Client(clientEnd, m.clientConfig()).Handshake() }() // then reads nothing
	tc := tls.Server(raw, serverConf)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { closeTLS(tc, raw, 50*time.Millisecond); close(done) }()
	waitClosed(t, done, "closeTLS to give up on a peer that does not read the alert")
}

// stop() does not wait for ever: a handler held in a write nothing can interrupt is given stopBound, then its client is
// closed, then stopBound again, and the gateway says what it left behind.
func TestStopGivesUpOnAHandlerNothingCanInterrupt(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	r.g.stopBound = 50 * time.Millisecond
	d := r.g.dec
	d.wmu.Lock() // the handler's QUERY can never be written
	t.Cleanup(sync.OnceFunc(d.wmu.Unlock))
	c := r.tcpClient("")
	tcpSend(t, c, buildQuery(t, 1, "held.example.", true))
	eventually(t, "the query to be held in its write", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.calls) == 1
	})
	stopped := make(chan struct{})
	go func() { r.g.stop(); close(stopped) }()
	waitClosed(t, stopped, "stop() to give up on the handler")
	if !strings.Contains(r.logs.joined(), "not waiting for them") {
		t.Fatalf("stop() gave up without saying so; log: %q", r.logs.joined())
	}
	requireTCPClosed(t, c) // the client was closed in the second stage
}
