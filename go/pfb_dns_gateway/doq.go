package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

// DNS over QUIC (RFC 9250): ALPN doq, one bidirectional stream per query, each message behind a 2-byte length.

// RFC 9250 4.3 error codes.
const (
	doqInternalError    = 0x1
	doqProtocolError    = 0x2
	doqRequestCancelled = 0x3

	maxDoQStreams  = 100              // concurrent query streams per connection
	doqIdleTimeout = 30 * time.Second // QUIC idle timeout; RFC 9250 4.4 asks for it to be negotiated
)

// serveDoQ serves QUIC on udp until stop(). No 0-RTT (a replayed query is not harmless here) and no unidirectional
// streams (RFC 9250 4.3.3 makes opening one a protocol error). Connections are admitted before their handshake.
func (g *gateway) serveDoQ(udp *net.UDPConn, conf *tls.Config) {
	// A slot taken at the first Initial packet is only safe when its source is real: a Retry proves it first.
	tr := &quic.Transport{Conn: udp, ConnContext: g.admitDoQ, VerifySourceAddress: func(net.Addr) bool { return true }}
	ln, err := tr.Listen(conf, &quic.Config{MaxIncomingStreams: maxDoQStreams, MaxIncomingUniStreams: -1, MaxIdleTimeout: doqIdleTimeout})
	if err != nil {
		g.logf("DoQ on %s: %v", udp.LocalAddr(), err)
		_ = udp.Close()
		return
	}
	g.closeOnStop(func() { _ = ln.Close(); _ = tr.Close(); _ = udp.Close() }) // ln.Close also closes every connection of the listener
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := ln.Accept(g.ctx)
			if err != nil {
				if g.shuttingDown(err) || errors.Is(err, quic.ErrServerClosed) {
					return
				}
				g.logf("accept on %s: %v", ln.Addr(), err)
				g.pause()
				continue
			}
			g.wg.Add(1)
			go g.serveQUICConn(conn)
		}
	}()
}

// admitDoQ runs before the handshake (quic-go's ConnContext): an address the ACL denies never holds a slot, and a
// connection over the cap is refused with CONNECTION_REFUSED. The slot is freed when the connection ends or its
// handshake fails, which is when ctx ends.
func (g *gateway) admitDoQ(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if g.acl.Lookup(addrPortOf(info.RemoteAddr).Addr().Unmap().WithZone("")) == ACLDrop {
		return nil, errors.New("client denied by the ACL")
	}
	if !g.doqConns.take(g.logf) {
		return nil, errors.New("DoQ connection limit reached")
	}
	context.AfterFunc(ctx, g.doqConns.release)
	return ctx, nil
}

func (g *gateway) serveQUICConn(conn *quic.Conn) {
	defer g.wg.Done()
	defer func() { _ = conn.CloseWithError(0, "") }()
	peer, local := addrPortOf(conn.RemoteAddr()), addrPortOf(conn.LocalAddr())
	for {
		s, err := conn.AcceptStream(g.ctx)
		if err != nil {
			return
		}
		g.wg.Add(1)
		go g.serveDoQStream(conn, s, peer, local)
	}
}

// serveDoQStream answers one query stream. A malformed stream is reset with DOQ_PROTOCOL_ERROR and the connection
// carries on; a non-zero Message ID closes the connection (RFC 9250 4.3.3 lists it as a protocol error to be
// answered with CONNECTION_CLOSE and DOQ_PROTOCOL_ERROR).
func (g *gateway) serveDoQStream(conn *quic.Conn, s *quic.Stream, peer, local netip.AddrPort) {
	defer g.wg.Done()
	_ = s.SetReadDeadline(time.Now().Add(g.timeout)) // a client sends the query and its FIN at once: no idle wait as on a TCP connection
	wire, ok := readDoQQuery(s)
	if !ok {
		reset(s, doqProtocolError)
		return
	}
	if len(wire) >= 2 && wire[0]|wire[1] != 0 {
		_ = conn.CloseWithError(doqProtocolError, "Message ID must be 0")
		return
	}
	src, dst := proxyEndpoints(peer, local)
	disp, reply := g.screen(src.Addr(), wire)
	switch disp {
	case discard:
		reset(s, doqProtocolError)
		return
	case hangUp:
		reset(s, doqRequestCancelled)
		return
	case toDecider:
		// RFC 9250 4.2.1: "When forwarding a DNS message from DoQ over another transport, a DNS Message ID MUST be
		// generated according to the rules of the protocol that is in use."
		binary.BigEndian.PutUint16(wire, uint16(1+rand.IntN(65535)))
		fwd := func(ctx context.Context, q []byte) []byte { return g.up.exchangeUDPThenTCP(ctx, src, dst, q) }
		var admitted bool
		if reply, admitted = g.resolveShared(g.ctx, src.Addr(), wire, fwd); !admitted {
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

// readDoQQuery reads one length-prefixed message and then the FIN that must follow it. The buffer grows with the data
// that arrives, not with the length the peer claims.
func readDoQQuery(s io.Reader) ([]byte, bool) {
	var size [2]byte
	if _, err := io.ReadFull(s, size[:]); err != nil {
		return nil, false
	}
	var msg bytes.Buffer
	if _, err := io.CopyN(&msg, s, int64(binary.BigEndian.Uint16(size[:]))); err != nil {
		return nil, false
	}
	var extra [1]byte
	if n, err := s.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, false
	}
	return msg.Bytes(), true
}

func reset(s *quic.Stream, code quic.StreamErrorCode) {
	s.CancelRead(code)
	s.CancelWrite(code)
}
