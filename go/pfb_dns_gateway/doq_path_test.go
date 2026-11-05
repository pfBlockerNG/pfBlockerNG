package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// rebindingConn is one QUIC socket that can move to a new local address. Writes leave from the current socket;
// reads from every socket the connection has used stay visible, which is what the server sees on a NAT rebind.
// quic-go switches RemoteAddr only after the packet that validated the new path, so the first stream after a
// rebind can still be screened as the handshake address.
type rebindingConn struct {
	t            *testing.T
	mu           sync.Mutex
	cur          *net.UDPConn
	all          []*net.UDPConn
	pkts         chan rebindingPacket
	done         chan struct{}
	wake         chan struct{}
	readDeadline time.Time
	once         sync.Once
}

type rebindingPacket struct {
	data []byte
	addr net.Addr
}

func listenRebinding(t *testing.T, ip string) *rebindingConn {
	t.Helper()
	c := &rebindingConn{
		t:    t,
		pkts: make(chan rebindingPacket, 64),
		done: make(chan struct{}),
		wake: make(chan struct{}),
	}
	c.bind(ip)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (c *rebindingConn) bind(ip string) {
	c.t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.cur = udp
	c.all = append(c.all, udp)
	c.mu.Unlock()
	go c.pump(udp)
}

func (c *rebindingConn) pump(udp *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case c.pkts <- rebindingPacket{data: pkt, addr: addr}:
		case <-c.done:
			return
		}
	}
}

func (c *rebindingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dl := c.readDeadline
		wake := c.wake
		c.mu.Unlock()
		var timer <-chan time.Time
		if !dl.IsZero() {
			if d := time.Until(dl); d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			} else {
				timer = time.After(d)
			}
		}
		select {
		case pkt := <-c.pkts:
			return copy(b, pkt.data), pkt.addr, nil
		case <-wake:
		case <-timer:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.done:
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *rebindingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	udp := c.cur
	c.mu.Unlock()
	return udp.WriteTo(b, addr)
}

func (c *rebindingConn) Close() error {
	c.once.Do(func() { close(c.done) })
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	for _, udp := range c.all {
		if e := udp.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (c *rebindingConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur.LocalAddr()
}

func (c *rebindingConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *rebindingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *rebindingConn) SetWriteDeadline(time.Time) error { return nil }

func dialDoQPacket(t *testing.T, addr netip.AddrPort, m tlsMaterial, pc net.PacketConn) *doqClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), doqConfig(m), &quic.Config{MaxIdleTimeout: time.Minute})
	if err != nil {
		t.Fatalf("DoQ connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test over") })
	return &doqClient{t: t, conn: conn}
}

// doqRound is one query on its own stream. An error is the stream or the connection ending without a full reply.
func doqRound(t *testing.T, c *doqClient, wire []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.Write(framed(wire)); err != nil {
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	_ = s.SetReadDeadline(time.Now().Add(watchdog))
	data, err := io.ReadAll(s)
	if err != nil {
		return nil, err
	}
	return unframe(t, data), nil
}

func doqHeld(g *gateway, ip string) int {
	key := netip.MustParseAddr(ip)
	g.doqAddrs.mu.Lock()
	defer g.doqAddrs.mu.Unlock()
	return g.doqAddrs.held[key]
}

// TestDoQScreensEachStreamAtItsCurrentAddress: the address copied at the handshake is not the address of every
// later stream. Screen and PROXYv2 use the connection's remote address when the stream is served. ACL deny of that
// address closes the connection, which releases the admission slot taken for the handshake address.
func TestDoQScreensEachStreamAtItsCurrentAddress(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true") // the rebinding socket is not a *net.UDPConn

	t.Run("an allowed peer is answered", func(t *testing.T) {
		r, m, addr := newDoQRig(t, rigConfig{})
		r.autoAnswer(echoAnswer)
		c := dialDoQ(t, addr, m, clientAllowed)
		query := doqQuery(t, "allowed.example.")
		got := c.query(query)
		q := r.nextQuery()
		if q.ip != clientAllowed || !bytes.Equal(q.wire[2:], query[2:]) {
			t.Fatalf("the decider got client=%s wire=%x; want client %s and the query", q.ip, q.wire, clientAllowed)
		}
		if want := withID0(echoAnswer(q)); !bytes.Equal(got, want) {
			t.Fatalf("reply: got %x, want the decider's answer with Message ID 0: %x", got, want)
		}
	})

	t.Run("a changed address the ACL allows is screened and forwarded", func(t *testing.T) {
		r, m, addr := newDoQRig(t, rigConfig{})
		r.autoForward()
		pc := listenRebinding(t, clientAllowed)
		c := dialDoQPacket(t, addr, m, pc)
		first := doqQuery(t, "before.example.")
		got, err := doqRound(t, c, first)
		if err != nil {
			t.Fatalf("query before the path change: %v", err)
		}
		q := r.nextQuery()
		seen := r.up.next()
		src, _, tcp := parsePP2(t, seen.header)
		if tcp || q.ip != clientAllowed || src.Addr() != netip.MustParseAddr(clientAllowed) {
			t.Fatalf("before the path change: decider=%s tcp=%v src=%s, want %s", q.ip, tcp, src, clientAllowed)
		}
		if want := withID0(echoWithQR(seen)[0]); !bytes.Equal(got, want) {
			t.Fatalf("reply before the path change: got %x, want %x", got, want)
		}

		pc.bind(otherClient)
		var screened []string
		deadline := time.Now().Add(watchdog)
		for i := 0; time.Now().Before(deadline); i++ {
			query := doqQuery(t, "moved.example.")
			got, err := doqRound(t, c, query)
			if err != nil {
				t.Fatalf("query %d after the path change: %v", i, err)
			}
			q := r.nextQuery()
			seen := r.up.next()
			screened = append(screened, q.ip)
			if q.ip != otherClient {
				continue
			}
			src, dst, tcp := parsePP2(t, seen.header)
			if tcp || src.Addr() != netip.MustParseAddr(otherClient) || dst != addr {
				t.Fatalf("Unbound saw tcp=%v src=%s dst=%s; want UDP, %s -> %s, not the handshake address %s", tcp, src, dst, otherClient, addr, clientAllowed)
			}
			if want := withID0(echoWithQR(seen)[0]); !bytes.Equal(got, want) {
				t.Fatalf("reply: got %x, want Unbound's reply with Message ID 0: %x", got, want)
			}
			return
		}
		t.Fatalf("streams were screened as %v, want %s after the path change", screened, otherClient)
	})

	t.Run("a changed address the ACL drops closes the connection and releases its slot", func(t *testing.T) {
		r, m, addr := newDoQRig(t, rigConfig{perAddr: 1})
		r.autoAnswer(echoAnswer)
		pc := listenRebinding(t, clientAllowed)
		c := dialDoQPacket(t, addr, m, pc)
		if _, err := doqRound(t, c, doqQuery(t, "before.example.")); err != nil {
			t.Fatalf("query before the path change: %v", err)
		}
		pc.bind(clientDenied)
		deadline := time.Now().Add(watchdog)
		for time.Now().Before(deadline) {
			if c.conn.Context().Err() != nil {
				break
			}
			if _, err := doqRound(t, c, doqQuery(t, "denied.example.")); err != nil {
				break
			}
		}
		requireConnClosed(t, c.conn, rfcDoQRequestCancelled)
		for {
			select {
			case q := <-r.queries:
				if q.ip != clientAllowed {
					t.Fatalf("the decider saw %s; a denied current address is not forwarded", q.ip)
				}
			default:
				goto drained
			}
		}
	drained:
		eventually(t, "the closed connection to release the handshake address slot", func() bool {
			return r.g.doqConns.n.Load() == 0 && doqHeld(r.g, clientAllowed) == 0 && doqHeld(r.g, clientDenied) == 0
		})
		again := dialDoQ(t, addr, m, clientAllowed)
		got := again.query(doqQuery(t, "after.example."))
		q := r.nextQuery()
		if q.ip != clientAllowed || !bytes.Equal(got[2:], withID0(echoAnswer(q))[2:]) {
			t.Fatalf("after the slot was released: client=%s reply=%x", q.ip, got)
		}
	})

	t.Run("a changed address the ACL refuses is answered and the connection stays up", func(t *testing.T) {
		r, m, addr := newDoQRig(t, rigConfig{})
		r.autoAnswer(echoAnswer)
		pc := listenRebinding(t, clientAllowed)
		c := dialDoQPacket(t, addr, m, pc)
		if _, err := doqRound(t, c, doqQuery(t, "before.example.")); err != nil {
			t.Fatalf("query before the path change: %v", err)
		}
		pc.bind(clientRefused)
		query := doqQuery(t, "refused.example.")
		var refused bool
		deadline := time.Now().Add(watchdog)
		for time.Now().Before(deadline) {
			got, err := doqRound(t, c, query)
			if err != nil {
				t.Fatalf("refuse closed the stream: %v", err)
			}
			if len(got) >= 4 && got[3]&0x0f == 5 {
				requireRefused(t, query, got)
				refused = true
				break
			}
		}
		if !refused {
			t.Fatal("no stream was screened as the refused address")
		}
		if c.conn.Context().Err() != nil {
			t.Fatal("ACL refuse closed the connection")
		}
		got, err := doqRound(t, c, query)
		if err != nil {
			t.Fatalf("the connection did not answer another stream: %v", err)
		}
		requireRefused(t, query, got)
		for {
			select {
			case q := <-r.queries:
				if q.ip == clientRefused {
					t.Fatalf("the decider saw the refused address %s", q.ip)
				}
			default:
				return
			}
		}
	})
}
