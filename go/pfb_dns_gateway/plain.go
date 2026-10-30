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
	"slices"
	"strconv"
	"sync"
	"syscall"
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

// bindPlainPicks is how many port numbers bindPlain tries for port 0 before it gives up.
const bindPlainPicks = 8

// bindPlain binds host on port, TCP first and UDP on the port TCP got, so port 0 picks one for both.
func bindPlain(host string, port int) (*plainListener, error) {
	return bindPlainWith(host, port, bindUDP)
}

// bindPlainWith is bindPlain with the UDP bind a test replaces. Port 0 takes TCP's number for UDP too, and another socket
// may hold that number for UDP: a new pick is a new number, up to bindPlainPicks of them. A port that was asked for is not
// exchanged for another, and no other error is retried.
func bindPlainWith(host string, port int, listenUDP func(host string, port int) (*net.UDPConn, error)) (*plainListener, error) {
	for pick := 1; ; pick++ {
		tcp, err := bindTCP(host, port)
		if err != nil {
			return nil, err
		}
		udp, err := listenUDP(host, int(tcp.Addr().(*net.TCPAddr).AddrPort().Port()))
		if err == nil {
			return &plainListener{udp: udp, tcp: tcp}, nil
		}
		_ = tcp.Close()
		if port != 0 || pick == bindPlainPicks || !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
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

// serve starts answering on l until stop() or the returned closeNow, whichever comes first.
func (g *gateway) serve(l *plainListener) (closeNow func()) {
	closeNow = g.closeOnStop(l.close)
	g.wg.Add(2)
	go g.serveUDP(l.udp)
	go g.serveTCP(l.tcp, nil)
	return closeNow
}

// closer is one thing stop() closes. run closes it at most once, whoever calls it.
type closer struct{ run func() }

// closeOnStop registers what stop() closes: a listener, or a server that owns its connections. The returned closeNow
// closes it at once and takes it off the list. A gateway that is stopping has taken its list already: what is registered
// then is closed here.
func (g *gateway) closeOnStop(closeFn func()) (closeNow func()) {
	c := &closer{run: sync.OnceFunc(closeFn)}
	g.mu.Lock()
	if g.ctx.Err() != nil {
		g.mu.Unlock()
		c.run()
		return c.run
	}
	g.closers = append(g.closers, c)
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		g.closers = slices.DeleteFunc(g.closers, func(x *closer) bool { return x == c })
		g.mu.Unlock()
		c.run()
	}
}

// stop ends serving: listeners are closed and queries in flight are cancelled. TCP and DoT connections answer what
// they hold with SERVFAIL and close, DoT with close_notify; DoQ connections get a CONNECTION_CLOSE (its closer waits
// up to stopBound for them). What is still running after stopBound is closed, and after another stopBound stop gives
// up waiting.
func (g *gateway) stop() {
	g.cancel()
	g.mu.Lock()
	closers := slices.Clone(g.closers) // a closer may wait: not under g.mu, which new connections and handlers take
	g.mu.Unlock()
	for _, c := range closers {
		c.run()
	}
	done := make(chan struct{})
	go func() { g.wg.Wait(); close(done) }()
	if g.waited(done) {
		return
	}
	g.mu.Lock()
	for c := range g.clients {
		_ = c.Close()
	}
	g.mu.Unlock()
	if !g.waited(done) {
		g.logf("stop: serving goroutines still running after %s; not waiting for them", 2*g.stopBound)
	}
}

// waited reports whether done was closed within stopBound.
func (g *gateway) waited(done <-chan struct{}) bool {
	t := time.NewTimer(g.stopBound)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
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
		switch disp, reply := g.screen(src.Addr(), dst.Addr(), true, wire); disp {
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
	if !g.udpAddrs.take(src.Addr(), g.udpPerAddr, "UDP queries", g.logf) {
		return
	}
	if g.udpInflight.Add(1) > maxUDPInflight {
		g.udpInflight.Add(-1)
		g.udpAddrs.release(src.Addr())
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
		// The first FORWARD carries the client's own bytes (Unbound saw its UDP size) and its reply goes to the decider as
		// it is. Every later one is a query the decider built (the SafeSearch chase, whose answers it must read whole):
		// a truncated reply to it is asked again over TCP, as a client of a transport without a connection of its own is.
		first := true
		fwd := func(ctx context.Context, w []byte) []byte {
			if first {
				first = false
				return g.up.exchangeUDP(ctx, header, w)
			}
			return g.up.exchangeUDPThenTCP(ctx, src, dst, w)
		}
		reply := g.resolve(g.ctx, src.Addr(), true, wire, fwd)
		g.udpAddrs.release(src.Addr())
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
		if !g.tcpAddrs.take(peer.Addr(), g.tcpPerAddr, "TCP and DoT connections", g.logf) {
			_ = conn.Close()
			continue
		}
		if g.tcpConns.Add(1) > maxTCPConns {
			g.tcpConns.Add(-1)
			g.tcpAddrs.release(peer.Addr())
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

// enter registers a request handler that stop() waits for, one the serving goroutine does not own (DoH: an
// http.Server does not wait for its handlers); false when the gateway is already stopping. The caller calls g.wg.Done.
func (g *gateway) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return false
	}
	g.wg.Add(1)
	return true
}

// closeTLS ends a TLS connection with close_notify (RFC 8446 6.1). A peer that does not take it within bound is cut
// off at the TCP level: tls.Conn.Close alone gives it 5 s, and the rc stop loop kills after 5 s.
func closeTLS(tc *tls.Conn, raw net.Conn, bound time.Duration) {
	cut := time.AfterFunc(bound, func() { _ = raw.Close() })
	_ = tc.Close()
	cut.Stop()
}

// handshakeTLS runs tc's handshake and reports whether it completed. stop() ends one that is still going by moving the
// connection's deadline back, the way serveConn wakes its reads, and not by a context given to crypto/tls: that closes the
// raw connection when the context is cancelled before HandshakeContext returns even if the handshake had finished, and a
// connection closed under its TLS session ends with no close_notify (RFC 8446 6.1). A handshake that did finish is served
// (serveConn sees the stop at its first read) and closed with the alert.
func (g *gateway) handshakeTLS(tc *tls.Conn) bool {
	woken := make(chan struct{})
	stop := context.AfterFunc(g.ctx, func() {
		defer close(woken)
		_ = tc.SetDeadline(time.Unix(1, 0))
	})
	err := tc.Handshake()
	if !stop() {
		<-woken // it has run or is running: it must not land on the close_notify's write
	}
	return err == nil
}

// serveConn answers one client connection: up to connPipeline queries at once, each reply written when it is ready
// (RFC 7766 6.2.1.1). Unbound is asked over UDP, as a DoH or DoQ client's query is; a truncated reply is asked again
// over the connection's own Unbound TCP connections. At the limit the connection is not read until a query is
// answered. A client that closes its sending side between frames still gets its answers before the connection is
// closed; any other read error, or a reply that cannot be written, abandons what is in flight. The slot was taken at
// accept, so the TLS handshake (bounded by g.handshake) happens inside it.
func (g *gateway) serveConn(conn *net.TCPConn, peer netip.AddrPort, tlsConf *tls.Config) {
	defer g.wg.Done()
	defer func() {
		g.mu.Lock()
		delete(g.clients, conn)
		g.mu.Unlock()
		g.tcpAddrs.release(peer.Addr())
		if g.tcpConns.Add(-1) == 0 {
			g.tcpOverload.Store(false)
		}
	}()
	defer conn.Close()
	if !g.track(conn) {
		return
	}
	var stream net.Conn = conn
	if tlsConf != nil {
		tc := tls.Server(conn, tlsConf)
		_ = tc.SetDeadline(time.Now().Add(g.handshake))
		if !g.handshakeTLS(tc) {
			return
		}
		defer closeTLS(tc, conn, g.closeBound)
		stream = tc
	}
	src, dst := proxyEndpoints(peer, conn.LocalAddr().(*net.TCPAddr).AddrPort())
	var local netip.Addr // the address a plain TCP query reached; a DoT one has none
	if tlsConf == nil {
		local = dst.Addr()
	}
	header, err := proxyHeader(src, dst, true)
	if err != nil {
		return
	}
	udpHeader, err := proxyHeader(src, dst, false)
	if err != nil {
		return
	}
	pool := g.up.newPool(header)
	fwd := func(ctx context.Context, wire []byte) []byte {
		return g.up.exchangeUDPThenPool(ctx, udpHeader, pool, wire)
	}
	ctx, cancel := context.WithCancel(g.ctx)
	var (
		handlers sync.WaitGroup
		wmu      sync.Mutex // frames are written one at a time, each by one Write
		broken   bool       // a reply could not be written; guarded by wmu
		slots    = make(chan struct{}, connPipeline)
	)
	defer func() { // the handlers end before the stream closes: a Close during a Write sends no close_notify
		cancel()
		handlers.Wait()
		pool.close()
	}()
	context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) }) // ends the read below: the client left, a write failed, or stop()
	write := func(reply []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		if !broken && g.writeReply(stream, reply) != nil {
			broken = true
			cancel() // a client that cannot be written to is as good as gone
		}
	}
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wire, err := g.readQuery(ctx, stream)
		if err != nil {
			if errors.Is(err, io.EOF) { // the client half-closed after its last frame: what it asked is still owed an answer
				handlers.Wait()
			}
			return
		}
		switch disp, reply := g.screen(src.Addr(), local, false, wire); disp {
		case hangUp:
			return
		case replyNow:
			write(reply)
			<-slots
		case discard:
			<-slots
		case toDecider:
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-slots }()
				if reply := g.resolve(ctx, src.Addr(), false, wire, fwd); reply != nil {
					write(reply)
				}
			}()
		}
	}
}

// readQuery reads one length-framed query. io.EOF means the client closed between frames; EOF inside a frame is
// io.ErrUnexpectedEOF.
func (g *gateway) readQuery(ctx context.Context, conn net.Conn) ([]byte, error) {
	var size [2]byte
	if err := g.readFull(ctx, conn, size[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, binary.BigEndian.Uint16(size[:]))
	err := g.readFull(ctx, conn, wire)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return wire, err
}

// readFull fills buf within one idle timeout. A ctx that ended wakes the read by moving the deadline back; the check
// after the new deadline is set keeps that wake-up from being overwritten.
func (g *gateway) readFull(ctx context.Context, conn net.Conn, buf []byte) error {
	_ = conn.SetReadDeadline(time.Now().Add(g.tcpIdle))
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, buf)
	return err
}

// writeReply gives a client that never reads one idle timeout, then gives up on it.
func (g *gateway) writeReply(conn net.Conn, reply []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(g.tcpIdle))
	_, err := conn.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply))), reply...))
	return err
}
