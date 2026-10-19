package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"strings"
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
					t.Fatal("STUCK/ENVIRONMENT: the decider never got another query")
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

// gatewayIsDraining reports whether a connection of this process has read its client's EOF and now waits, in serveConn
// itself and not in its cleanup after a return, for the queries the client still has in flight. A gateway that drains
// changes nothing else a test can see (the slot stays held), so this is the barrier that makes "the gateway has seen
// the close" observable before anything is asserted about what it keeps.
func gatewayIsDraining() bool {
	buf := make([]byte, 1<<20)
	for {
		if n := runtime.Stack(buf, true); n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, goroutine := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(goroutine, "\n")
		for i, line := range lines {
			// A frame is two lines, the function and its file; the caller of Wait is the next frame.
			if strings.HasPrefix(line, "sync.(*WaitGroup).Wait(") && i+2 < len(lines) && strings.Contains(lines[i+2], "(*gateway).serveConn(") {
				return true
			}
		}
	}
	return false
}

// A client that closes its connection looks like one that half-closed (both are a FIN), so its queries are decided
// first: until the decider answers, its slot is held and its query is still being waited for; the answer is taken as
// the decision, never as the answer to an abandoned query; only then is the connection closed and the slot freed.
func TestAClosedClientFreesItsSlotOnceItsQueriesAreDecided(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			held := make(chan struct{})
			release := sync.OnceFunc(func() { close(held) })
			t.Cleanup(release)
			var answered atomic.Bool // the decider has sent its answer
			r.autoAnswer(func(q decidedQuery) []byte {
				<-held
				answered.Store(true)
				return echoAnswer(q)
			})
			c := k.dial(t, r)
			tcpSend(t, c, buildQuery(t, 1, "held.example.", true))
			inFlight := r.g.dec.lookup(r.nextQuery().id)
			if n := r.g.tcpConns.Load(); n != 1 {
				t.Fatalf("one client is connected but %d slots are held", n)
			}
			_ = c.Close()
			eventually(t, "the gateway to read the client's close and wait for the query it holds", gatewayIsDraining)

			abandoned := func() bool {
				inFlight.mu.Lock()
				defer inFlight.mu.Unlock()
				return inFlight.abandoned
			}
			if answered.Load() || abandoned() {
				t.Fatalf("the client has closed and nothing is decided, yet its query is no longer waited for (answered=%v abandoned=%v)", answered.Load(), abandoned())
			}
			if n := r.g.tcpConns.Load(); n != 1 {
				t.Fatalf("the closed client's slot is released (%d held) while its query is undecided", n)
			}

			release()
			eventually(t, "the closed client's slot to be freed after its query was decided", func() bool { return r.g.tcpConns.Load() == 0 })
			if !answered.Load() || abandoned() {
				t.Fatalf("the slot was freed without the decider's answer being taken as the decision (answered=%v abandoned=%v)", answered.Load(), abandoned())
			}
		})
	}
}

// Two truncated forwards in flight at once from one client connection retry over two Unbound TCP connections, each
// opened with the TCP PROXYv2 header of that client: the upstream connection is taken per forward, not per query or per
// client connection. Their UDP legs carry the UDP header of the same client.
func TestTwoTruncatedForwardsInFlightFromOneConnectionUseTwoUpstreamTCPConnections(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			held := make(chan struct{})
			release := sync.OnceFunc(func() { close(held) })
			t.Cleanup(release)
			r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{answering(func(q seenQuery) [][]byte {
				reply := echoWithQR(q)[0]
				if !q.tcp {
					reply[2] |= 0x02
					return [][]byte{reply[:12]}
				}
				<-held
				return [][]byte{append(reply, "full-answer"...)}
			})}})
			r.autoForward()
			c := k.dial(t, r)
			tcpSend(t, c, buildQuery(t, 1, "one.example.", true))
			tcpSend(t, c, buildQuery(t, 2, "two.example.", true))
			var udp, tcp []seenQuery
			for range 4 { // both queries were asked over UDP, and both TCP retries reached Unbound while neither was answered
				if seen := r.up.next(); seen.tcp {
					tcp = append(tcp, seen)
				} else {
					udp = append(udp, seen)
				}
			}
			if len(udp) != 2 || len(tcp) != 2 {
				t.Fatalf("Unbound saw %d UDP and %d TCP queries, want 2 and 2", len(udp), len(tcp))
			}
			if conns, headers := r.up.counts(); conns != 2 || headers != 2 {
				t.Fatalf("two retries in flight need two upstream connections with one header each, got %d connections / %d headers", conns, headers)
			}
			gw := netip.MustParseAddrPort(c.RemoteAddr().String())
			for _, leg := range []struct {
				seen []seenQuery
				tr   transport
			}{{udp, transport{"udp", false}}, {tcp, transport{"tcp", true}}} {
				want := wantHeader(t, leg.tr, c.LocalAddr(), gw)
				for _, seen := range leg.seen {
					if !bytes.Equal(seen.header, want) {
						t.Fatalf("%s leg header:\n got  %x\n want %x", leg.tr.name, seen.header, want)
					}
				}
			}
			release()
			got := map[uint16]bool{}
			for range 2 {
				reply := tcpReply(t, c)
				if !bytes.HasSuffix(reply, []byte("full-answer")) {
					t.Fatalf("reply %x is not the whole TCP answer", reply)
				}
				got[queryID(reply)] = true
			}
			if !got[1] || !got[2] {
				t.Fatalf("replies for queries %v, want 1 and 2", got)
			}
		})
	}
}
