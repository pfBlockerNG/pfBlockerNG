package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// stallDoQPackets forwards datagrams until the server has admitted the connection, then drops what the client
// still sends. The handshake cannot finish, and the server's handshake idle timeout is what frees the slot.
type stallDoQPackets struct {
	net.PacketConn
	admitted func() bool
	mu       sync.Mutex
	drop     bool
}

func (s *stallDoQPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drop || s.admitted() {
		s.drop = true
		return len(p), nil
	}
	return s.PacketConn.WriteTo(p, addr)
}

// A connection that never finishes its handshake must give the DoQ connection slot back once the shortened
// handshake idle timeout passes. quic-go's implicit idle timeout is 5s, and the wait below is shorter than that:
// a listener that leaves the default still holds the slot when this fails.
func TestDoQStalledHandshakeFreesItsConnectionSlot(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	r := newRig(t, rigConfig{acl: aclMixed})
	const idle = 150 * time.Millisecond
	r.g.doqHandshakeIdle = idle
	m := newTLSMaterial(t)
	addr := r.serveDoQ(m)
	r.autoAnswer(echoAnswer)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	pc := &stallDoQPackets{PacketConn: udp, admitted: func() bool { return r.g.doqConns.n.Load() > 0 }}
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	t.Cleanup(cancel)
	go func() {
		conn, dialErr := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), doqConfig(m), &quic.Config{MaxIdleTimeout: time.Minute})
		if dialErr == nil {
			_ = conn.CloseWithError(0, "test over")
		}
	}()

	eventually(t, "the stalled handshake to take a DoQ connection slot", func() bool { return r.g.doqConns.n.Load() > 0 })
	// Past the shortened idle timeout, short of quic-go's implicit 5s. A slot still held means the shorten did not apply.
	deadline := time.Now().Add(2 * time.Second)
	for r.g.doqConns.n.Load() > 0 {
		if !time.Now().Before(deadline) {
			t.Fatalf("a handshake that never finishes still holds %d DoQ connection slots past the shortened idle timeout (%s); the implicit 5s timeout would still be holding it", r.g.doqConns.n.Load(), idle)
		}
		time.Sleep(time.Millisecond)
	}
}

// A stream that stops after a few bytes must not keep its stream slot for a raised --timeout. The read is bounded
// by the handshake budget as well, which this test shortens; --timeout is far longer than the watchdog.
func TestDoQPartialQueryDoesNotHoldItsStreamForARaisedTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.handshake = 150 * time.Millisecond
	r.g.timeout = time.Hour
	m := newTLSMaterial(t)
	addr := r.serveDoQ(m)
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)

	partial, err := c.conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	put(t, partial, []byte{0, 32}) // two bytes of a length prefix, then nothing
	requireStreamReset(t, partial, rfcDoQRequestCancelled)

	barrier := doqQuery(t, "barrier.example.")
	if got := c.query(barrier); !bytes.Equal(got[2:], echoWithQR(seenQuery{wire: barrier})[0][2:]) {
		t.Fatalf("the next stream was not answered after the partial one was released: %x", got)
	}
	if q := r.nextQuery(); !bytes.Equal(q.wire[2:], barrier[2:]) {
		t.Fatalf("the decider's first query is %x: the partial stream reached it", q.wire)
	}
	r.requireNoOtherQuery()
}

// A short --timeout still ends a partial query when the handshake budget is the longer of the two.
func TestDoQShortTimeoutStillEndsAPartialQuery(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.timeout = 200 * time.Millisecond
	m := newTLSMaterial(t)
	addr := r.serveDoQ(m)
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)

	partial, err := c.conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	put(t, partial, []byte{0, 32})
	// The handshake budget is 10s. A read bound only by it is still open when this deadline passes.
	_ = partial.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadAll(partial)
	var se *quic.StreamError
	if !errors.As(err, &se) || !se.Remote || se.ErrorCode != rfcDoQRequestCancelled {
		t.Fatalf("partial query ended with %v, want a stream reset by the server with DOQ_REQUEST_CANCELLED before the handshake budget", err)
	}
}

// The query and its FIN are already in hand before Unbound answers. A raised --timeout still waits for that
// answer after the shorter read budget has passed, and the client gets the reply.
func TestDoQFinishedQueryIsAnsweredWhenUnboundOutlastsTheReadBudget(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.handshake = 150 * time.Millisecond
	r.g.timeout = time.Hour
	m := newTLSMaterial(t)
	addr := r.serveDoQ(m)
	release := make(chan struct{})
	r.autoAnswer(func(q decidedQuery) []byte {
		<-release
		return echoAnswer(q)
	})
	c := dialDoQ(t, addr, m, clientAllowed)
	query := doqQuery(t, "slow.example.")
	got := make(chan []byte, 1)
	go func() {
		s := c.stream()
		sendDoQ(t, s, query)
		data, err := readDoQ(t, s)
		if err != nil && !errors.Is(err, io.EOF) {
			got <- nil
			return
		}
		got <- unframe(t, data)
	}()
	_ = r.nextQuery() // the query and its FIN were read; Unbound has not answered
	time.Sleep(r.g.handshake)
	close(release)
	select {
	case reply := <-got:
		if want := withID0(echoWithQR(seenQuery{wire: query})[0]); !bytes.Equal(reply, want) {
			t.Fatalf("reply %x, want the decider's answer with Message ID 0: %x", reply, want)
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: a finished query whose Unbound wait outlasts the read budget was not answered")
	}
}
