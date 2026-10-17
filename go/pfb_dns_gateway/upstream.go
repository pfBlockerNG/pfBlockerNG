package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// proxyEndpoints returns (client, local) as one IP family for the PROXYv2 header: IPv4-mapped IPv6 becomes IPv4,
// scope ids go, and a local address of the other family (a dual-stack wildcard) becomes the client family's
// unspecified address with port 0.
func proxyEndpoints(client, local netip.AddrPort) (src, dst netip.AddrPort) {
	src = netip.AddrPortFrom(client.Addr().Unmap().WithZone(""), client.Port())
	dst = netip.AddrPortFrom(local.Addr().Unmap().WithZone(""), local.Port())
	if src.Addr().Is4() != dst.Addr().Is4() {
		unspecified := netip.IPv6Unspecified()
		if src.Addr().Is4() {
			unspecified = netip.IPv4Unspecified()
		}
		dst = netip.AddrPortFrom(unspecified, 0)
	}
	return src, dst
}

var errMixedFamilies = errors.New("PROXYv2 header needs both addresses in one family")

// proxyHeader is the PROXYv2 header announcing that src (the real client) reached dst, over TCP or UDP.
func proxyHeader(src, dst netip.AddrPort, tcp bool) ([]byte, error) {
	if src.Addr().Is4() != dst.Addr().Is4() {
		return nil, errMixedFamilies
	}
	var from, to net.Addr
	if tcp {
		from, to = net.TCPAddrFromAddrPort(src), net.TCPAddrFromAddrPort(dst)
	} else {
		from, to = net.UDPAddrFromAddrPort(src), net.UDPAddrFromAddrPort(dst)
	}
	return proxyproto.HeaderProxyFromAddrs(2, from, to).Format()
}

// upstream is Unbound's PROXY-protocol port. Every method answers nil for "no reply": silence, an error, or ctx ending.
type upstream struct {
	addr    string
	timeout time.Duration // per exchange
}

func newUpstream(addr string, timeout time.Duration) *upstream {
	return &upstream{addr: addr, timeout: timeout}
}

var datagrams = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

// interrupt makes blocked I/O on conn fail as soon as ctx ends; call stop when done.
func interrupt(ctx context.Context, conn net.Conn) (stop func() bool) {
	return context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
}

// exchangeUDP sends header+wire from a fresh connected socket and returns the first reply that carries the
// query's id; anything else is ignored.
func (u *upstream) exchangeUDP(ctx context.Context, header, wire []byte) []byte {
	if len(wire) < 2 {
		return nil
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.timeout)) // before interrupt(): a cancel must not be overwritten
	defer interrupt(ctx, conn)()
	if _, err := conn.Write(slices.Concat(header, wire)); err != nil {
		return nil
	}
	buf := datagrams.Get().(*[]byte)
	defer datagrams.Put(buf)
	for {
		n, err := conn.Read(*buf)
		if err != nil {
			return nil
		}
		if n >= 2 && (*buf)[0] == wire[0] && (*buf)[1] == wire[1] {
			return bytes.Clone((*buf)[:n])
		}
	}
}

// exchangeUDPThenTCP is for transports without a connection of their own: UDP first, and a reply with TC set is
// asked for again over a new TCP connection behind a header of its own.
func (u *upstream) exchangeUDPThenTCP(ctx context.Context, src, dst netip.AddrPort, wire []byte) []byte {
	header, err := proxyHeader(src, dst, false)
	if err != nil {
		return nil
	}
	reply := u.exchangeUDP(ctx, header, wire)
	if len(reply) < 3 || reply[2]&0x02 == 0 {
		return reply
	}
	if header, err = proxyHeader(src, dst, true); err != nil {
		return nil
	}
	conn := u.newTCP(header)
	defer conn.close()
	return conn.exchange(ctx, wire)
}

// tcpUpstream is the upstream connection of one client connection: opened on first use, header first, reused.
// Exchanges must not overlap.
type tcpUpstream struct {
	u      *upstream
	header []byte
	conn   net.Conn
}

func (u *upstream) newTCP(header []byte) *tcpUpstream { return &tcpUpstream{u: u, header: header} }

func (t *tcpUpstream) close() {
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
}

// exchange sends one length-framed query. A connection Unbound closed while idle gets one fresh try; a fresh
// connection that fails does not.
func (t *tcpUpstream) exchange(ctx context.Context, wire []byte) []byte {
	for range 2 {
		reused := t.conn != nil
		if reply, ok := t.try(ctx, wire); ok {
			return reply
		}
		t.close() // a timed-out connection may still deliver a late reply for this query: never reuse it
		if !reused || ctx.Err() != nil {
			return nil
		}
	}
	return nil
}

func (t *tcpUpstream) try(ctx context.Context, wire []byte) ([]byte, bool) {
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	if t.conn == nil {
		dialer := net.Dialer{Timeout: t.u.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", t.u.addr)
		if err != nil {
			return nil, false
		}
		t.conn = conn
		msg = slices.Concat(t.header, msg) // the header goes out once, in front of the first query
	}
	conn := t.conn
	_ = conn.SetDeadline(time.Now().Add(t.u.timeout))
	defer interrupt(ctx, conn)()
	if _, err := conn.Write(append(msg, wire...)); err != nil {
		return nil, false
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, false
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, false
	}
	return reply, true
}
