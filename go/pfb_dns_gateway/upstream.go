package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
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

// Largest UDP payload one datagram can carry. IPv4's total length includes a 20-byte header; IPv6's payload
// length does not include its 40-byte header. Both include the 8-byte UDP header.
const (
	udpPayloadMax4 = 65535 - 20 - 8
	udpPayloadMax6 = 65535 - 8
)

// exchangeUDP sends header+wire from a fresh connected socket and returns the first reply to the query (udpReplyFor);
// anything else is ignored.
func (u *upstream) exchangeUDP(ctx context.Context, header, wire []byte) []byte {
	reply, _ := u.exchangeUDPResult(ctx, header, wire)
	return reply
}

// exchangeUDPResult is exchangeUDP plus whether the datagram could not be sent because it was too long.
// A dial failure or any other write error is no reply, not "too long".
func (u *upstream) exchangeUDPResult(ctx context.Context, header, wire []byte) (reply []byte, tooLong bool) {
	if udpDatagramTooLong(u.addr, header, wire) {
		return nil, true
	}
	if len(wire) < dnsHeaderLen {
		return nil, false
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.timeout)) // before interrupt(): a cancel must not be overwritten
	defer interrupt(ctx, conn)()
	if _, err := conn.Write(slices.Concat(header, wire)); err != nil {
		return nil, errors.Is(err, syscall.EMSGSIZE)
	}
	var question upstreamQuestion
	ok := question.read(wire)
	buf := datagrams.Get().(*[]byte)
	defer datagrams.Put(buf)
	for {
		n, err := conn.Read(*buf)
		if err != nil {
			return nil, false
		}
		if udpReplyFor(wire, (*buf)[:n], &question, ok) {
			return bytes.Clone((*buf)[:n]), false
		}
	}
}

func udpPayloadMax(addr string) int {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return udpPayloadMax4
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Is4() || ip.Is4In6() {
		return udpPayloadMax4
	}
	return udpPayloadMax6
}

func udpDatagramTooLong(addr string, header, wire []byte) bool {
	maxPayload := udpPayloadMax(addr)
	return len(header) > maxPayload || len(wire) > maxPayload-len(header)
}

const dnsHeaderLen = 12 // RFC 1035 4.1.1

// upstreamQuestion keeps label boundaries and every label octet (RFC 2181 section 11), folding only ASCII name content.
// Text-name parsers may reject legal labels such as "a.b"; that is not a malformed DNS question.
type upstreamQuestion struct {
	name       [255]byte
	length     uint16
	typ, class uint16
}

func (q *upstreamQuestion) read(wire []byte) bool {
	if len(wire) < dnsHeaderLen || binary.BigEndian.Uint16(wire[4:]) == 0 {
		return false
	}
	pos, end, size, hops := dnsHeaderLen, 0, 0, 0
	for {
		if pos >= len(wire) {
			return false
		}
		n := int(wire[pos])
		switch n & 0xc0 {
		case 0xc0:
			if pos+1 >= len(wire) {
				return false
			}
			target := (n&0x3f)<<8 | int(wire[pos+1])
			// RFC 1035 pointers refer to prior name data, never the header. Bound pointer-only chains as dnswire.py does.
			hops++
			if target < dnsHeaderLen || target >= pos || hops > 127 {
				return false
			}
			if end == 0 {
				end = pos + 2
			}
			pos = target
		case 0:
			pos++
			if n == 0 {
				q.name[size] = 0
				q.length = uint16(size + 1)
				if end == 0 {
					end = pos
				}
				if end+4 > len(wire) {
					return false
				}
				q.typ = binary.BigEndian.Uint16(wire[end:])
				q.class = binary.BigEndian.Uint16(wire[end+2:])
				return true
			}
			if pos+n > len(wire) || size+1+n >= len(q.name) {
				return false
			}
			q.name[size] = byte(n)
			size++
			for _, c := range wire[pos : pos+n] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				q.name[size] = c
				size++
			}
			pos += n
		default:
			return false
		}
	}
}

// udpReplyFor requires a whole header, the query ID and QR. Questionless errors (including Unbound's bare FORMERR and
// NOTIMP) and truncated replies need no question. Otherwise decoded labels, type and class must match; an unreadable
// question counts only as the original bytes echoed back, not as an arbitrary error reply.
func udpReplyFor(query, reply []byte, question *upstreamQuestion, ok bool) bool {
	if len(query) < dnsHeaderLen || len(reply) < dnsHeaderLen || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
		return false
	}
	if binary.BigEndian.Uint16(reply[4:]) == 0 {
		return reply[3]&0x0f != 0 || truncated(reply)
	}
	var got upstreamQuestion
	if !got.read(reply) {
		return truncated(reply) || bytes.Equal(reply[dnsHeaderLen:], query[dnsHeaderLen:])
	}
	return ok && got == *question
}

// truncated reports whether reply is Unbound's answer with TC set, which a client of a size-limited UDP exchange
// must ask for again over TCP.
func truncated(reply []byte) bool { return len(reply) >= 3 && reply[2]&0x02 != 0 }

// exchangeUDPThenTCP is for transports without a connection of their own. UDP is skipped when header+wire cannot
// be one datagram. A truncated reply, or a write refused because the datagram was too long, is asked again over
// a new TCP connection behind a header of its own. Any other UDP failure is no reply.
func (u *upstream) exchangeUDPThenTCP(ctx context.Context, src, dst netip.AddrPort, wire []byte) []byte {
	header, err := proxyHeader(src, dst, false)
	if err != nil {
		return nil
	}
	return u.udpThen(ctx, header, wire, func() []byte {
		tcpHeader, tcpErr := proxyHeader(src, dst, true)
		if tcpErr != nil {
			return nil
		}
		conn := u.newTCP(tcpHeader)
		defer conn.close()
		return conn.exchange(ctx, wire)
	})
}

// exchangeUDPThenPool is exchangeUDPThenTCP for a client that has a connection of its own. The TCP retry uses one
// of the client's pool connections, which stay open for the next truncated or oversized answer.
func (u *upstream) exchangeUDPThenPool(ctx context.Context, udpHeader []byte, p *tcpPool, wire []byte) []byte {
	return u.udpThen(ctx, udpHeader, wire, func() []byte { return p.exchange(ctx, wire) })
}

// udpThen asks over UDP, then calls tcp when the datagram cannot be sent or the reply is truncated.
func (u *upstream) udpThen(ctx context.Context, header, wire []byte, tcp func() []byte) []byte {
	reply, tooLong := u.exchangeUDPResult(ctx, header, wire)
	if tooLong || truncated(reply) {
		return tcp()
	}
	return reply
}

// tcpUpstream is one upstream connection: opened on first use, header first, reused. Exchanges must not overlap.
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

// tcpPool is the upstream TCP connections of one client connection, for the answers Unbound truncates over UDP:
// single-flight tcpUpstreams, one taken per retry and put back after it. At most connPipeline retries are in flight, so
// the pool never holds more. It dials nothing until the first truncated or oversized answer.
type tcpPool struct {
	u      *upstream
	header []byte
	mu     sync.Mutex
	idle   []*tcpUpstream
}

func (u *upstream) newPool(header []byte) *tcpPool { return &tcpPool{u: u, header: header} }

// exchange sends wire on an idle connection, or on a new one. A connection that failed is closed and not put back.
func (p *tcpPool) exchange(ctx context.Context, wire []byte) []byte {
	var t *tcpUpstream
	p.mu.Lock()
	if n := len(p.idle); n > 0 {
		t, p.idle = p.idle[n-1], p.idle[:n-1]
	}
	p.mu.Unlock()
	if t == nil {
		t = p.u.newTCP(p.header)
	}
	reply := t.exchange(ctx, wire)
	if t.conn != nil {
		p.mu.Lock()
		p.idle = append(p.idle, t)
		p.mu.Unlock()
	}
	return reply
}

// close closes the idle connections; call it once no exchange is running.
func (p *tcpPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.idle {
		t.close()
	}
	p.idle = nil
}

var errMismatchedID = errors.New("upstream reply does not carry the query id")

// exchange sends one length-framed query. A reused connection is dialed once more only after an immediate EOF
// or a reset, and only while the query context is still active. A deadline closes the socket and is not retried.
func (t *tcpUpstream) exchange(ctx context.Context, wire []byte) []byte {
	for range 2 {
		reused := t.conn != nil
		reply, err := t.try(ctx, wire)
		if err == nil {
			return reply
		}
		t.close() // a failed connection may still deliver a late reply for this query: never reuse it
		if !reused || ctx.Err() != nil || !reusedTCPLost(err) {
			return nil
		}
	}
	return nil
}

// reusedTCPLost reports an immediate end of stream or a reset. A deadline is not one: it must not dial again.
func reusedTCPLost(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// try writes one query and reads one reply. The reply counts only when it is at least 2 bytes and its id
// matches; a mismatch closes the connection so a pool cannot reuse it.
func (t *tcpUpstream) try(ctx context.Context, wire []byte) ([]byte, error) {
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	if t.conn == nil {
		dialer := net.Dialer{Timeout: t.u.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", t.u.addr)
		if err != nil {
			return nil, err
		}
		t.conn = conn
		msg = slices.Concat(t.header, msg) // the header goes out once, in front of the first query
	}
	conn := t.conn
	_ = conn.SetDeadline(time.Now().Add(t.u.timeout))
	defer interrupt(ctx, conn)()
	if _, err := conn.Write(append(msg, wire...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if len(wire) < 2 || len(reply) < 2 || reply[0] != wire[0] || reply[1] != wire[1] {
		t.close()
		return nil, errMismatchedID
	}
	return reply, nil
}
