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
	doqExcessiveLoad    = 0x4

	maxDoQStreams  = 100              // concurrent query streams per connection
	doqIdleTimeout = 30 * time.Second // QUIC idle timeout; RFC 9250 4.4 asks for it to be negotiated
)

// serveDoQ serves QUIC on udp until stop(). No 0-RTT (a replayed query is not harmless here) and no unidirectional
// streams (RFC 9250 4.3.3 makes opening one a protocol error). Connections over the cap are closed with
// DOQ_EXCESSIVE_LOAD.
func (g *gateway) serveDoQ(udp *net.UDPConn, conf *tls.Config) {
	tr := &quic.Transport{Conn: udp}
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
			if !g.doqConns.take(g.logf) {
				_ = conn.CloseWithError(doqExcessiveLoad, "")
				continue
			}
			g.wg.Add(1)
			go g.serveQUICConn(conn)
		}
	}()
}

func (g *gateway) serveQUICConn(conn *quic.Conn) {
	defer g.wg.Done()
	defer g.doqConns.release()
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
	_ = s.SetReadDeadline(time.Now().Add(g.tcpIdle))
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
		if reply = g.resolve(g.ctx, src.Addr(), wire, fwd); reply == nil {
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
