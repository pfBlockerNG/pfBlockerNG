package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// DNS over QUIC (RFC 9250): ALPN doq, one bidirectional stream per query, each message behind a 2-byte length.

// RFC 9250 4.3 error codes.
const (
	doqNoError          = 0x0
	doqInternalError    = 0x1
	doqProtocolError    = 0x2
	doqRequestCancelled = 0x3

	maxDoQStreams           = 100              // concurrent query streams per connection
	doqIdleTimeout          = 30 * time.Second // QUIC idle timeout; RFC 9250 4.4 asks for it to be negotiated
	defaultDoQHandshakeIdle = 5 * time.Second  // quic-go's handshake idle timeout, set explicitly; not g.handshake (10s)

	// One stream carries one DNS message (maxWire). The connection window is every stream it may hold.
	// A zero quic.Config receive window selects quic-go's default, which is not a DNS message.
	doqStreamReceiveWindow = maxWire
	doqConnReceiveWindow   = maxWire * maxDoQStreams
)

// doqConns is the accepted connections of one DoQ listener. quic-go's Listener.Close leaves accepted connections
// open and Transport.Close ends them without a CONNECTION_CLOSE, so stop() closes each one itself, before either.
type doqConns struct {
	mu   sync.Mutex
	open map[*quic.Conn]struct{}
}

func (c *doqConns) add(conn *quic.Conn) {
	c.mu.Lock()
	c.open[conn] = struct{}{}
	c.mu.Unlock()
}

func (c *doqConns) remove(conn *quic.Conn) {
	c.mu.Lock()
	delete(c.open, conn)
	c.mu.Unlock()
}

// closeAll ends every connection with DOQ_NO_ERROR (RFC 9250 4.3: a graceful close) and returns once each
// CONNECTION_CLOSE has been sent.
func (c *doqConns) closeAll() {
	c.mu.Lock()
	open := slices.Collect(maps.Keys(c.open))
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, conn := range open {
		wg.Go(func() { _ = conn.CloseWithError(doqNoError, "") })
	}
	wg.Wait()
}

// doqQUICConfig is the listener config, one for every connection. A keepalive would also keep a finished
// connection up, so it is not set. The idle timeout is the resolve budget when that is longer than
// doqIdleTimeout, and doqIdleTimeout otherwise: an in-flight query is not cut off, and a quiet connection
// still ends. The stream cap, a receive window of one DNS message per stream, enough of them for every
// stream the connection may hold, and an explicit HandshakeIdleTimeout: an admitted connection holds its
// slot until the handshake finishes or this idle timeout.
func (g *gateway) doqQUICConfig() *quic.Config {
	budget := 2*g.timeout + g.grace
	return &quic.Config{
		MaxIncomingStreams:             maxDoQStreams,
		MaxIncomingUniStreams:          -1,
		MaxIdleTimeout:                 max(doqIdleTimeout, budget),
		HandshakeIdleTimeout:           g.doqHandshakeIdle,
		InitialStreamReceiveWindow:     doqStreamReceiveWindow,
		MaxStreamReceiveWindow:         doqStreamReceiveWindow,
		InitialConnectionReceiveWindow: doqConnReceiveWindow,
		MaxConnectionReceiveWindow:     doqConnReceiveWindow,
	}
}

// doqQueryContext is the context resolveShared sees for one DoQ query. It ends when the gateway stops, the
// connection ends, or the stream ends (the peer's STOP_SENDING), so a dropped connection or a
// cancelled stream releases the shared in-flight slot instead of holding it for 2*timeout+grace. The server
// passes the stream's context, which quic-go makes a child of the connection's.
func doqQueryContext(gateway, stream context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(gateway)
	stop := context.AfterFunc(stream, cancel)
	return ctx, func() {
		stop() // unregisters the AfterFunc, so a long-lived parent does not keep one callback per query
		// cancel() drops this child of the gateway context when the caller stops the query.
		// AfterFunc runs only when a parent ends, so removing cancel() leaves every query
		// context registered until the gateway itself stops.
		cancel()
	}
}

// serveDoQ serves QUIC on udp until stop() or the returned closeNow; when QUIC cannot listen on udp it is closed, the
// reason is logged and returned. No 0-RTT (a replayed query is not harmless here) and no unidirectional streams
// (RFC 9250 4.3.3 makes opening one a protocol error). Connections are admitted before their handshake.
func (g *gateway) serveDoQ(udp *net.UDPConn, conf *tls.Config) (closeNow func(), err error) {
	// A slot taken at the first Initial packet is only safe when its source is real: a Retry proves it first.
	tr := &quic.Transport{Conn: udp, ConnContext: g.admitDoQ, VerifySourceAddress: func(net.Addr) bool { return true }}
	ln, err := tr.Listen(conf, g.doqQUICConfig())
	if err != nil {
		g.logf("DoQ on %s: %v", udp.LocalAddr(), err)
		_ = udp.Close()
		return nil, err
	}
	conns := &doqConns{open: map[*quic.Conn]struct{}{}}
	acceptEnded := make(chan struct{})
	closeNow = g.closeOnStop(func() {
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = ln.Close() // refuses the handshakes still running; Accept hands out what is queued, then ends
			if g.doqListenerClosed != nil {
				g.doqListenerClosed()
			}
			<-acceptEnded // so every connection is registered, or already closed
			conns.closeAll()
		}()
		t := time.NewTimer(g.stopBound)
		defer t.Stop()
		select {
		case <-closed:
		case <-t.C:
			g.logf("DoQ on %s: connections still open after %s; closing the socket", udp.LocalAddr(), g.stopBound)
		}
		_ = tr.Close() // sends no CONNECTION_CLOSE: every connection was closed above
		_ = udp.Close()
	})
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer close(acceptEnded)
		for {
			conn, err := ln.Accept(context.Background()) // not g.ctx: after Close it still hands out the queue
			if err != nil {
				if g.shuttingDown(err) || errors.Is(err, quic.ErrServerClosed) {
					return
				}
				g.logf("accept on %s: %v", ln.Addr(), err)
				g.pause()
				continue
			}
			if g.doqAccepted != nil {
				g.doqAccepted()
			}
			conns.add(conn)
			context.AfterFunc(conn.Context(), func() { conns.remove(conn) }) // the context ends after the close is on the wire
			g.wg.Add(1)
			go g.serveQUICConn(conn)
		}
	}()
	return closeNow, nil
}

// admitDoQ runs before the handshake (quic-go's ConnContext): an address the ACL denies never holds a slot, and a
// connection over the cap is refused with CONNECTION_REFUSED. The slot is freed when the connection ends or its
// handshake fails, which is when ctx ends.
func (g *gateway) admitDoQ(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if g.acl.Lookup(addrPortOf(info.RemoteAddr).Addr().Unmap().WithZone("")) == ACLDrop {
		return nil, errors.New("client denied by the ACL")
	}
	peer := addrPortOf(info.RemoteAddr).Addr()
	if !g.doqAddrs.take(peer, g.doqPerAddr, "DoQ connections", g.logf) {
		return nil, errors.New("DoQ connection limit of the address reached")
	}
	if !g.doqConns.take(g.logf) {
		g.doqAddrs.release(peer)
		return nil, errors.New("DoQ connection limit reached")
	}
	context.AfterFunc(ctx, func() {
		g.doqConns.release()
		g.doqAddrs.release(peer)
	})
	return ctx, nil
}

func (g *gateway) serveQUICConn(conn *quic.Conn) {
	defer g.wg.Done()
	defer func() { _ = conn.CloseWithError(doqNoError, "") }()
	local := addrPortOf(conn.LocalAddr())
	for {
		s, err := conn.AcceptStream(g.ctx)
		if err != nil {
			return
		}
		g.wg.Add(1)
		go g.serveDoQStream(conn, s, local)
	}
}

// doqDenied reports whether the ACL denies the connection's current address. RemoteAddr moves when the path migrates,
// so the address is read at each check, not once at admission.
func (g *gateway) doqDenied(conn *quic.Conn) bool {
	return g.acl.Lookup(addrPortOf(conn.RemoteAddr()).Addr().Unmap().WithZone("")) == ACLDrop
}

// doqHangUp resets the stream and closes its connection. The admission slot is held until the connection's context
// ends, so a stream reset alone would keep the slot.
func doqHangUp(conn *quic.Conn, s *quic.Stream) {
	reset(s, doqRequestCancelled)
	_ = conn.CloseWithError(doqRequestCancelled, "")
}

// serveDoQStream answers one query stream. A malformed stream is reset with DOQ_PROTOCOL_ERROR and the connection
// carries on; a non-zero Message ID, or an edns-tcp-keepalive option, closes the connection (RFC 9250 4.3.3 lists the
// first as a protocol error to be answered with CONNECTION_CLOSE and DOQ_PROTOCOL_ERROR, 5.5.2 the second). An ACL
// deny of the connection's current address closes it whatever the stream holds, before the stream is parsed.
func (g *gateway) serveDoQStream(conn *quic.Conn, s *quic.Stream, local netip.AddrPort) {
	defer g.wg.Done()
	// A denied address is refused before the read too, so its stream holds no read budget.
	if g.doqDenied(conn) {
		doqHangUp(conn, s)
		return
	}
	// A query that never finishes must not keep a stream slot for a raised --timeout. The read stops at the Unbound
	// wait or the handshake budget, whichever is shorter. Only the query read is bounded: Unbound still has g.timeout.
	_ = s.SetReadDeadline(time.Now().Add(min(g.timeout, g.handshake)))
	wire, err := readDoQQuery(s)
	// The connection's current path, read once the read ends. A path change during the read is judged here, before the
	// stream is parsed or dropped as malformed.
	src, dst := proxyEndpoints(addrPortOf(conn.RemoteAddr()), local)
	if g.acl.Lookup(src.Addr()) == ACLDrop {
		doqHangUp(conn, s)
		return
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			reset(s, doqRequestCancelled) // the read only hit its deadline
		} else {
			reset(s, doqProtocolError)
		}
		return
	}
	if len(wire) >= 2 && wire[0]|wire[1] != 0 {
		_ = conn.CloseWithError(doqProtocolError, "Message ID must be 0")
		return
	}
	if hasTCPKeepalive(wire) {
		_ = conn.CloseWithError(doqProtocolError, "edns-tcp-keepalive is not allowed")
		return
	}
	disp, reply := g.screen(src.Addr(), dst.Addr(), false, false, wire)
	switch disp {
	case discard:
		reset(s, doqProtocolError)
		return
	case hangUp:
		doqHangUp(conn, s)
		return
	case toDecider:
		// RFC 9250 4.2.1: "When forwarding a DNS message from DoQ over another transport, a DNS Message ID MUST be
		// generated according to the rules of the protocol that is in use."
		binary.BigEndian.PutUint16(wire, uint16(1+rand.IntN(65535)))
		fwd := func(ctx context.Context, q []byte) []byte { return g.up.exchangeUDPThenTCP(ctx, src, dst, q) }
		qctx, stopQuery := doqQueryContext(g.ctx, s.Context())
		defer stopQuery()
		var admitted bool
		if reply, admitted = g.resolveShared(qctx, src.Addr(), wire, fwd); !admitted {
			reply = buildServfail(wire) // over the shared in-flight cap
		} else if reply == nil {
			reset(s, doqRequestCancelled) // the decider dropped the query
			return
		}
	}
	if len(reply) >= 2 {
		binary.BigEndian.PutUint16(reply, 0) // and a DoQ client gets Message ID 0 back
	}
	_ = s.SetWriteDeadline(time.Now().Add(g.tcpIdle))
	if _, err := s.Write(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply)))); err != nil {
		reset(s, doqInternalError)
		return
	}
	if _, err := s.Write(reply); err != nil {
		reset(s, doqInternalError)
		return
	}
	_ = s.Close() // the FIN RFC 9250 4.2 requires after the last response
}

// errDoQExtraBytes is readDoQQuery's error for a message followed by another byte, or by no FIN.
var errDoQExtraBytes = errors.New("DoQ stream carries more than one message or is not finished")

// readDoQQuery reads one length-prefixed message and then the FIN that must follow it. The buffer grows with the
// data that arrives, not with the length the peer claims. A deadline before the message is complete is
// os.ErrDeadlineExceeded, so the caller resets with DOQ_REQUEST_CANCELLED. A short message, extra bytes, or a
// missing FIN (a deadline once the message is complete and only the FIN is absent counts as that) is some
// other error, and the caller resets with DOQ_PROTOCOL_ERROR.
func readDoQQuery(s io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(s, size[:]); err != nil {
		return nil, err
	}
	var msg bytes.Buffer
	if _, err := io.CopyN(&msg, s, int64(binary.BigEndian.Uint16(size[:]))); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := s.Read(extra[:]); n == 0 && err == io.EOF {
		return msg.Bytes(), nil
	}
	return nil, errDoQExtraBytes
}

func reset(s *quic.Stream, code quic.StreamErrorCode) {
	s.CancelRead(code)
	s.CancelWrite(code)
}
