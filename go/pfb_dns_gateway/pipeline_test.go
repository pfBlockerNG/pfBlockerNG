package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// streamKinds are the transports that carry many length-framed queries on one connection: plain TCP and DoT.
type streamKind struct {
	name string
	dial func(t *testing.T, r *rig) net.Conn
}

var streamKinds = []streamKind{
	{"tcp", func(t *testing.T, r *rig) net.Conn { return r.tcpClient("") }},
	{"dot", func(t *testing.T, r *rig) net.Conn {
		m := newTLSMaterial(t)
		return dialDoT(t, r.serveDoT(m), m, "")
	}},
}

// pipelineDepth is how many queries one TCP or DoT connection has in flight at once; the next one is not read
// until one of them is answered.
const pipelineDepth = 4

func queryID(wire []byte) uint16 { return binary.BigEndian.Uint16(wire) }

// RFC 7766 6.2.1.1: a server SHOULD process the queries of one connection concurrently and MAY answer them out of
// order. Query 1 is held at the decider; query 2, sent behind it, is answered first.
func TestAQueryBehindASlowOneIsAnsweredFirst(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			release := make(chan struct{})
			releaseOnce := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseOnce)
			r.autoAnswer(func(q decidedQuery) []byte {
				if queryID(q.wire) == 1 {
					<-release
				}
				return echoAnswer(q)
			})
			c := k.dial(t, r)
			tcpSend(t, c, buildQuery(t, 1, "slow.example.", true))
			tcpSend(t, c, buildQuery(t, 2, "fast.example.", true))
			if id := queryID(tcpReply(t, c)); id != 2 {
				t.Fatalf("first reply is for query %d, want 2: the query behind the held one must not wait for it", id)
			}
			releaseOnce()
			if id := queryID(tcpReply(t, c)); id != 1 {
				t.Fatalf("second reply is for query %d, want 1", id)
			}
		})
	}
}

// A connection has pipelineDepth queries in flight; the ones behind them stay unread (TCP's flow control pushes back)
// until one is answered, and none is dropped.
func TestAConnectionHasAtMostFourQueriesInFlightAndReadsOnWhenOneFinishes(t *testing.T) {
	const total = pipelineDepth + 3
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			tokens := make(chan struct{}, total)
			entered := make(chan uint16, total) // a query's id, sent once the decider holds it
			var inflight, peak atomic.Int64
			r.autoAnswer(func(q decidedQuery) []byte {
				n := inflight.Add(1)
				for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
				}
				entered <- queryID(q.wire)
				<-tokens
				inflight.Add(-1)
				return echoAnswer(q)
			})
			await := func() uint16 {
				t.Helper()
				select {
				case id := <-entered:
					return id
				case <-time.After(watchdog):
					t.Fatal("STUCK: the decider never got another query")
					return 0
				}
			}
			c := k.dial(t, r)
			for id := 1; id <= total; id++ {
				tcpSend(t, c, buildQuery(t, uint16(id), "example.", true))
			}
			first := map[uint16]bool{} // the queries start together, so they may enter in any order
			for range pipelineDepth {
				first[await()] = true
			}
			for id := uint16(1); id <= pipelineDepth; id++ {
				if !first[id] {
					t.Fatalf("the decider's first %d queries are %v, want ids 1 to %d: the connection must be read in order", pipelineDepth, first, pipelineDepth)
				}
			}
			tokens <- struct{}{} // one query finishes: the connection is read again
			replied := map[uint16]bool{queryID(tcpReply(t, c)): true}
			if got := await(); got != pipelineDepth+1 {
				t.Fatalf("after one query finished the decider got id %d, want %d", got, pipelineDepth+1)
			}
			for range total - 1 {
				tokens <- struct{}{}
			}
			for len(replied) < total {
				id := queryID(tcpReply(t, c))
				if replied[id] {
					t.Fatalf("query %d was answered twice", id)
				}
				replied[id] = true
			}
			for id := uint16(1); id <= total; id++ {
				if !replied[id] {
					t.Fatalf("query %d was never answered: work the gateway accepted was dropped", id)
				}
			}
			if got := peak.Load(); got != pipelineDepth {
				t.Fatalf("the decider had at most %d queries of one connection in flight, want exactly %d", got, pipelineDepth)
			}
		})
	}
}

// A client that goes away abandons its queries at once and frees its slot, instead of leaving them to run out
// their whole-query limit.
func TestAClientThatLeavesAbandonsItsQueriesAndFreesItsSlot(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			held := make(chan struct{})
			t.Cleanup(sync.OnceFunc(func() { close(held) }))
			r.autoAnswer(func(q decidedQuery) []byte { <-held; return echoAnswer(q) })
			c := k.dial(t, r)
			tcpSend(t, c, buildQuery(t, 1, "held.example.", true))
			r.nextQuery()
			if n := r.g.tcpConns.Load(); n != 1 {
				t.Fatalf("one client is connected but %d slots are held", n)
			}
			_ = c.Close()
			eventually(t, "the leaving client's slot to be freed while its query is still undecided", func() bool { return r.g.tcpConns.Load() == 0 })
		})
	}
}

// Two forwards in flight at once from one client connection travel on two Unbound connections, each opened with the
// PROXYv2 header of that client: the upstream connection is taken per forward, not per query or per client connection.
func TestTwoForwardsInFlightFromOneConnectionUseTwoUpstreamConnections(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			held := make(chan struct{})
			release := sync.OnceFunc(func() { close(held) })
			t.Cleanup(release)
			r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{answering(func(q seenQuery) [][]byte {
				<-held
				return echoWithQR(q)
			})}})
			r.autoForward()
			c := k.dial(t, r)
			tcpSend(t, c, buildQuery(t, 1, "one.example.", true))
			tcpSend(t, c, buildQuery(t, 2, "two.example.", true))
			a, b := r.up.next(), r.up.next() // both reached Unbound while neither was answered
			if conns, headers := r.up.counts(); conns != 2 || headers != 2 {
				t.Fatalf("two forwards in flight need two upstream connections with one header each, got %d connections / %d headers", conns, headers)
			}
			want := wantHeader(t, transport{"tcp", true}, c.LocalAddr(), netip.MustParseAddrPort(c.RemoteAddr().String()))
			for _, seen := range []seenQuery{a, b} {
				if !seen.tcp || !bytes.Equal(seen.header, want) {
					t.Fatalf("Unbound saw tcp=%v header=%x, want TCP behind the client's header %x", seen.tcp, seen.header, want)
				}
			}
			release()
			got := map[uint16]bool{queryID(tcpReply(t, c)): true, queryID(tcpReply(t, c)): true}
			if !got[1] || !got[2] {
				t.Fatalf("replies for queries %v, want 1 and 2", got)
			}
		})
	}
}
