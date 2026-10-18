package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// plainListener is one --listen address: UDP and TCP on the same port.
type plainListener struct {
	udp *net.UDPConn
	tcp *net.TCPListener
}

// bindAddr checks host (an IP address) and port; an IPv4-mapped IPv6 host binds as IPv4.
func bindAddr(host string, port int) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil || port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("cannot listen on %s: not an IP address and port", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

func ipFamily(proto string, ap netip.AddrPort) string {
	if ap.Addr().Is6() {
		return proto + "6"
	}
	return proto + "4"
}

// bindTCP binds host on port; port 0 picks one.
func bindTCP(host string, port int) (*net.TCPListener, error) {
	ap, err := bindAddr(host, port)
	if err != nil {
		return nil, err
	}
	tcp, err := net.ListenTCP(ipFamily("tcp", ap), net.TCPAddrFromAddrPort(ap))
	if err != nil {
		return nil, listenError(net.JoinHostPort(host, strconv.Itoa(port)), err)
	}
	return tcp, nil
}

// bindUDP binds host on port; port 0 picks one.
func bindUDP(host string, port int) (*net.UDPConn, error) {
	ap, err := bindAddr(host, port)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP(ipFamily("udp", ap), net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, listenError(net.JoinHostPort(host, strconv.Itoa(port)), err)
	}
	return udp, nil
}

// bindPlain binds host on port, TCP first and UDP on the port TCP got, so port 0 picks one for both.
func bindPlain(host string, port int) (*plainListener, error) {
	tcp, err := bindTCP(host, port)
	if err != nil {
		return nil, err
	}
	udp, err := bindUDP(host, int(tcp.Addr().(*net.TCPAddr).AddrPort().Port()))
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	return &plainListener{udp: udp, tcp: tcp}, nil
}

func listenError(hostport string, err error) error {
	var op *net.OpError
	if errors.As(err, &op) {
		err = op.Err
	}
	return fmt.Errorf("cannot listen on %s: %w", hostport, err)
}

func (l *plainListener) addr() netip.AddrPort { return l.tcp.Addr().(*net.TCPAddr).AddrPort() }

func (l *plainListener) close() {
	_ = l.tcp.Close()
	_ = l.udp.Close()
}

// serve starts answering on l until stop().
func (g *gateway) serve(l *plainListener) {
	g.closeOnStop(l.close)
	g.wg.Add(2)
	go g.serveUDP(l.udp)
	go g.serveTCP(l.tcp, nil)
}

// closeOnStop registers what stop() closes: a listener, or a server that owns its connections.
func (g *gateway) closeOnStop(closeFn func()) {
	g.mu.Lock()
	g.closers = append(g.closers, closeFn)
	g.mu.Unlock()
}

// stop ends serving: listeners and client connections are closed, queries in flight are cancelled.
func (g *gateway) stop() {
	g.cancel()
	g.mu.Lock()
	for _, closeFn := range g.closers {
		closeFn()
	}
	for c := range g.clients {
		_ = c.Close()
	}
	g.mu.Unlock()
	g.wg.Wait()
}

// pause backs off after an accept or read error, so a persistent one cannot spin the CPU.
func (g *gateway) pause() {
	select {
	case <-time.After(time.Second):
	case <-g.ctx.Done():
	}
}

func (g *gateway) shuttingDown(err error) bool {
	return g.ctx.Err() != nil || errors.Is(err, net.ErrClosed)
}

// --- UDP ---

func (g *gateway) serveUDP(conn *net.UDPConn) {
	defer g.wg.Done()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if g.shuttingDown(err) {
				return
			}
			g.logf("udp read on %s: %v", local, err)
			g.pause()
			continue
		}
		wire := bytes.Clone(buf[:n])
		src, dst := proxyEndpoints(from, local)
		switch disp, reply := g.screen(src.Addr(), wire); disp {
		case replyNow:
			_, _ = conn.WriteToUDPAddrPort(reply, from)
		case toDecider:
			g.startUDPQuery(conn, from, src, dst, wire)
		}
	}
}

func (g *gateway) startUDPQuery(conn *net.UDPConn, from, src, dst netip.AddrPort, wire []byte) {
	header, err := proxyHeader(src, dst, false)
	if err != nil {
		return
	}
	if g.udpInflight.Add(1) > maxUDPInflight {
		g.udpInflight.Add(-1)
		if g.udpOverload.CompareAndSwap(false, true) {
			g.logf("%d UDP queries in flight: dropping new ones until they drain", maxUDPInflight)
		}
		return
	}
	g.queries.Add(1)
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.queries.Done()
		fwd := func(ctx context.Context, w []byte) []byte { return g.up.exchangeUDP(ctx, header, w) }
		reply := g.resolve(g.ctx, src.Addr(), wire, fwd)
		if g.udpInflight.Add(-1) == 0 { // the slot is free before the reply goes out
			g.udpOverload.Store(false)
		}
		if reply != nil {
			_, _ = conn.WriteToUDPAddrPort(reply, from)
		}
	}()
}

// --- TCP ---

// serveTCP accepts length-framed DNS connections; with tlsConf they speak TLS first (DoT), under the same cap.
func (g *gateway) serveTCP(ln *net.TCPListener, tlsConf *tls.Config) {
	defer g.wg.Done()
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if g.shuttingDown(err) {
				return
			}
			g.logf("accept on %s: %v", ln.Addr(), err)
			g.pause()
			continue
		}
		peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		if g.acl.Lookup(peer.Addr().Unmap().WithZone("")) == ACLDrop { // a denied client never holds a slot
			_ = conn.Close()
			continue
		}
		if g.tcpConns.Add(1) > maxTCPConns {
			g.tcpConns.Add(-1)
			if g.tcpOverload.CompareAndSwap(false, true) {
				g.logf("TCP client limit of %d reached: closing new connections until the clients drain", maxTCPConns)
			}
			_ = conn.Close()
			continue
		}
		g.wg.Add(1)
		go g.serveConn(conn, peer, tlsConf)
	}
}

// track registers conn for stop(); false when the gateway is already stopping.
func (g *gateway) track(conn net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return false
	}
	g.clients[conn] = struct{}{}
	return true
}

// serveConn answers one client connection: length-framed queries one at a time over one upstream connection. The
// slot was taken at accept, so the TLS handshake (bounded by g.handshake) happens inside it.
func (g *gateway) serveConn(conn *net.TCPConn, peer netip.AddrPort, tlsConf *tls.Config) {
	defer g.wg.Done()
	defer func() {
		_ = conn.Close()
		g.mu.Lock()
		delete(g.clients, conn)
		g.mu.Unlock()
		if g.tcpConns.Add(-1) == 0 {
			g.tcpOverload.Store(false)
		}
	}()
	if !g.track(conn) {
		return
	}
	var stream net.Conn = conn
	if tlsConf != nil {
		tc := tls.Server(conn, tlsConf)
		_ = tc.SetDeadline(time.Now().Add(g.handshake))
		if tc.HandshakeContext(g.ctx) != nil {
			return
		}
		stream = tc
	}
	src, dst := proxyEndpoints(peer, conn.LocalAddr().(*net.TCPAddr).AddrPort())
	header, err := proxyHeader(src, dst, true)
	if err != nil {
		return
	}
	up := g.up.newTCP(header)
	defer up.close()
	for {
		wire, err := g.readQuery(stream)
		if err != nil {
			return
		}
		disp, reply := g.screen(src.Addr(), wire)
		switch disp {
		case hangUp:
			return
		case toDecider:
			reply = g.resolve(g.ctx, src.Addr(), wire, up.exchange)
		}
		if reply != nil && g.writeReply(stream, reply) != nil {
			return
		}
	}
}

func (g *gateway) readQuery(conn net.Conn) ([]byte, error) {
	var size [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(g.tcpIdle))
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, binary.BigEndian.Uint16(size[:]))
	_ = conn.SetReadDeadline(time.Now().Add(g.tcpIdle))
	_, err := io.ReadFull(conn, wire)
	return wire, err
}

// writeReply gives a client that never reads one idle timeout, then gives up on it.
func (g *gateway) writeReply(conn net.Conn, reply []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(g.tcpIdle))
	_, err := conn.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply))), reply...))
	return err
}
