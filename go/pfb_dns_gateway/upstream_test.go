package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

const proxySignature = "0d0a0d0a000d0a515549540a"

// seenQuery is what the fake Unbound received: the PROXYv2 header and the DNS wire behind it.
type seenQuery struct {
	header []byte
	wire   []byte
	tcp    bool
}

// fakeUpstream stands in for Unbound's proxy-protocol port: UDP and TCP on one loopback port.
type fakeUpstream struct {
	t       *testing.T
	udp     *net.UDPConn
	tcp     *net.TCPListener
	addr    string
	queries chan seenQuery

	// answer returns the datagrams (UDP) or, for its first element, the frame (TCP) sent back; none = silence.
	// closeAfter closes each TCP connection once it has answered this many queries; hangUp closes it right
	// after the header. All three are set by options, before the serving goroutines start.
	answer     func(seenQuery) [][]byte
	closeAfter int
	hangUp     bool

	mu      sync.Mutex
	conns   int
	headers int
}

func echoWithQR(q seenQuery) [][]byte {
	reply := bytes.Clone(q.wire)
	reply[2] |= 0x80
	return [][]byte{reply}
}

type upstreamOption func(*fakeUpstream)

func answering(fn func(seenQuery) [][]byte) upstreamOption {
	return func(f *fakeUpstream) { f.answer = fn }
}

func silent() upstreamOption { return answering(func(seenQuery) [][]byte { return nil }) }

func closingAfter(n int) upstreamOption { return func(f *fakeUpstream) { f.closeAfter = n } }

func hangingUp() upstreamOption { return func(f *fakeUpstream) { f.hangUp = true } }

func newFakeUpstream(t *testing.T, opts ...upstreamOption) *fakeUpstream {
	t.Helper()
	var (
		tcp *net.TCPListener
		udp *net.UDPConn
	)
	for range 20 { // the same port for both: pick a TCP port, take the UDP one next to it
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.Addr().(*net.TCPAddr).Port})
		if err == nil {
			tcp, udp = l, u
			break
		}
		_ = l.Close()
	}
	if tcp == nil {
		t.Fatal("no loopback port free for both TCP and UDP")
	}
	f := &fakeUpstream{
		t: t, udp: udp, tcp: tcp, answer: echoWithQR, queries: make(chan seenQuery, 256),
		addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)),
	}
	for _, o := range opts {
		o(f)
	}
	go f.serveUDP()
	go f.serveTCP()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	return f
}

func proxyHeaderLen(b []byte) int { return 16 + int(binary.BigEndian.Uint16(b[14:16])) }

func (f *fakeUpstream) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, from, err := f.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := bytes.Clone(buf[:n])
		hl := proxyHeaderLen(data)
		q := seenQuery{header: data[:hl], wire: data[hl:]}
		f.queries <- q
		for _, reply := range f.answer(q) {
			_, _ = f.udp.WriteToUDP(reply, from)
		}
	}
}

func (f *fakeUpstream) serveTCP() {
	for {
		conn, err := f.tcp.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns++
		f.mu.Unlock()
		go f.serveConn(conn)
	}
}

func (f *fakeUpstream) serveConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return
	}
	header := append(fixed, make([]byte, proxyHeaderLen(fixed)-16)...)
	if _, err := io.ReadFull(r, header[16:]); err != nil {
		return
	}
	f.mu.Lock()
	f.headers++
	f.mu.Unlock()
	if f.hangUp {
		return
	}
	for answered := 0; f.closeAfter == 0 || answered < f.closeAfter; answered++ {
		var size [2]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return
		}
		wire := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(r, wire); err != nil {
			return
		}
		q := seenQuery{header: header, wire: wire, tcp: true}
		f.queries <- q
		if replies := f.answer(q); len(replies) > 0 {
			_, _ = conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(replies[0]))))
			_, _ = conn.Write(replies[0])
		}
	}
}

func (f *fakeUpstream) counts() (conns, headers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns, f.headers
}

func (f *fakeUpstream) next() seenQuery {
	f.t.Helper()
	select {
	case q := <-f.queries:
		return q
	case <-time.After(watchdog):
		f.t.Fatal("STUCK: the fake Unbound never saw a query")
		return seenQuery{}
	}
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// Header vectors computed by hand from the PROXY protocol spec, section 2.2:
// signature | 0x21 (v2, PROXY) | family+protocol | length | src addr | dst addr | src port | dst port.
var headerVectors = map[string]struct {
	src, dst string
	tcp      bool
	hex      string
}{
	"ipv4 udp": {"192.0.2.10:54321", "192.0.2.1:53", false, proxySignature + "2112000cc000020ac0000201d4310035"},
	"ipv4 tcp": {"203.0.113.5:40000", "198.51.100.1:53", true, proxySignature + "2111000ccb007105c63364019c400035"},
	"ipv6 udp": {"[2001:db8::1]:5353", "[2001:db8::53]:53", false, proxySignature + "2122002420010db800000000000000000000000120010db800000000000000000000005314e90035"},
	"ipv6 tcp": {"[2001:db8::1]:40000", "[2001:db8::53]:53", true, proxySignature + "2121002420010db800000000000000000000000120010db80000000000000000000000539c400035"},
}

// G13: the PROXYv2 header bytes, per family and transport.
func TestProxyHeaderBytes(t *testing.T) {
	for name, v := range headerVectors {
		t.Run(name, func(t *testing.T) {
			got, err := proxyHeader(ap(v.src), ap(v.dst), v.tcp)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.hex {
				t.Fatalf("header for %s -> %s (tcp=%v):\n got  %x\n want %s", v.src, v.dst, v.tcp, got, v.hex)
			}
		})
	}
}

func TestProxyHeaderRejectsMixedFamilies(t *testing.T) {
	if got, err := proxyHeader(ap("192.0.2.10:1"), ap("[2001:db8::1]:53"), false); err == nil {
		t.Fatalf("a header for mixed families must be an error, got %x", got)
	}
}

// G13: which addresses go into the header, including the family-mismatch and IPv4-mapped cases.
func TestProxyEndpoints(t *testing.T) {
	cases := []struct{ name, client, local, wantSrc, wantDst string }{
		{"ipv4", "192.0.2.10:54321", "192.0.2.1:53", "192.0.2.10:54321", "192.0.2.1:53"},
		{"ipv6", "[2001:db8::10]:54321", "[2001:db8::1]:53", "[2001:db8::10]:54321", "[2001:db8::1]:53"},
		{"v4-mapped client on an IPv4 listener", "[::ffff:192.0.2.10]:54321", "192.0.2.1:53", "192.0.2.10:54321", "192.0.2.1:53"},
		{"v4-mapped client and listener", "[::ffff:192.0.2.10]:54321", "[::ffff:192.0.2.1]:53", "192.0.2.10:54321", "192.0.2.1:53"},
		{"scope ids are dropped", "[fe80::10%eth0]:54321", "[fe80::1%eth0]:53", "[fe80::10]:54321", "[fe80::1]:53"},
		{"IPv4 client, IPv6 listener: destination is 0.0.0.0 port 0", "192.0.2.10:54321", "[2001:db8::1]:53", "192.0.2.10:54321", "0.0.0.0:0"},
		{"IPv6 client, IPv4 listener: destination is :: port 0", "[2001:db8::10]:54321", "192.0.2.1:53", "[2001:db8::10]:54321", "[::]:0"},
		{"v4-mapped client on a dual-stack wildcard", "[::ffff:192.0.2.10]:54321", "[::]:53", "192.0.2.10:54321", "0.0.0.0:0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, dst := proxyEndpoints(ap(c.client), ap(c.local))
			if src != ap(c.wantSrc) || dst != ap(c.wantDst) {
				t.Fatalf("got %s -> %s, want %s -> %s", src, dst, c.wantSrc, c.wantDst)
			}
		})
	}
}

func TestProxyHeaderOfAFamilyMismatchPutsTheUnspecifiedAddressOfTheClientFamilyInFront(t *testing.T) {
	src, dst := proxyEndpoints(ap("192.0.2.10:54321"), ap("[2001:db8::1]:53"))
	got, err := proxyHeader(src, dst, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := proxySignature + "2112000cc000020a00000000d4310000"; hex.EncodeToString(got) != want {
		t.Fatalf("IPv4 client:\n got  %x\n want %s", got, want)
	}
	src, dst = proxyEndpoints(ap("[2001:db8::1]:5353"), ap("192.0.2.1:53"))
	got, err = proxyHeader(src, dst, true)
	if err != nil {
		t.Fatal(err)
	}
	want := proxySignature + "2121002420010db8000000000000000000000001" + "00000000000000000000000000000000" + "14e90000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("IPv6 client:\n got  %x\n want %s", got, want)
	}
}

func headerFor(t testing.TB, name string) []byte {
	t.Helper()
	return mustHex(t, headerVectors[name].hex)
}

func withID(wire []byte, id uint16) []byte {
	out := bytes.Clone(wire)
	binary.BigEndian.PutUint16(out, id)
	return out
}

func exchange(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(watchdog):
		t.Fatal("STUCK: the exchange never returned")
		return nil
	}
}

func inBackground(f func() []byte) <-chan []byte {
	out := make(chan []byte, 1)
	go func() { out <- f() }()
	return out
}

func TestUDPExchangeSendsTheHeaderThenTheQueryAndReturnsUnboundsReply(t *testing.T) {
	f := newFakeUpstream(t)
	u := newUpstream(f.addr, watchdog)
	query := buildQuery(t, 0x4242, "example.", true)
	header := headerFor(t, "ipv4 udp")
	got := u.exchangeUDP(context.Background(), header, query)
	seen := f.next()
	if !bytes.Equal(seen.header, header) || !bytes.Equal(seen.wire, query) || seen.tcp {
		t.Fatalf("Unbound saw header=%x wire=%x tcp=%v, want header=%x wire=%x tcp=false", seen.header, seen.wire, seen.tcp, header, query)
	}
	if want := echoWithQR(seen)[0]; !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want %x", got, want)
	}
}

// G14: only a reply with the query's own id counts.
func TestUDPExchangeIgnoresRepliesThatDoNotCarryTheQueryID(t *testing.T) {
	f := newFakeUpstream(t, answering(func(q seenQuery) [][]byte {
		right := echoWithQR(q)[0]
		return [][]byte{withID(right, 0x0001), {0x42}, right}
	}))
	u := newUpstream(f.addr, watchdog)
	query := buildQuery(t, 0x4242, "example.", true)
	got := u.exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), query)
	want := echoWithQR(seenQuery{wire: query})[0]
	if !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want the one with id 0x4242: %x", got, want)
	}
}

func TestUDPExchangeWithOnlyWrongIDRepliesIsNoReply(t *testing.T) {
	f := newFakeUpstream(t, answering(func(q seenQuery) [][]byte { return [][]byte{withID(echoWithQR(q)[0], 0x0001)} }))
	u := newUpstream(f.addr, 300*time.Millisecond)
	if got := u.exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), buildQuery(t, 0x4242, "example.", true)); got != nil {
		t.Fatalf("a reply with the wrong id was accepted: %x", got)
	}
}

func TestUDPExchangeSilenceIsNoReply(t *testing.T) {
	f := newFakeUpstream(t, silent())
	u := newUpstream(f.addr, 50*time.Millisecond)
	if got := u.exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), buildQuery(t, 1, "example.", true)); got != nil {
		t.Fatalf("got %x from a silent Unbound, want nil", got)
	}
}

func TestExchangesStopWhenTheContextEnds(t *testing.T) {
	f := newFakeUpstream(t, silent())
	u := newUpstream(f.addr, time.Hour)
	query := buildQuery(t, 1, "example.", true)
	ctx, cancel := context.WithCancel(context.Background())
	udp := inBackground(func() []byte { return u.exchangeUDP(ctx, headerFor(t, "ipv4 udp"), query) })
	f.next()
	cancel()
	if got := exchange(t, udp); got != nil {
		t.Fatalf("UDP exchange after cancel: got %x, want nil", got)
	}

	ctx, cancel = context.WithCancel(context.Background())
	conn := u.newTCP(headerFor(t, "ipv4 tcp"))
	defer conn.close()
	tcp := inBackground(func() []byte { return conn.exchange(ctx, query) })
	f.next()
	cancel()
	if got := exchange(t, tcp); got != nil {
		t.Fatalf("TCP exchange after cancel: got %x, want nil", got)
	}
}

func TestExchangesWithNothingListeningAreNoReply(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()
	u := newUpstream(addr, watchdog)
	query := buildQuery(t, 1, "example.", true)
	if got := u.exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), query); got != nil {
		t.Fatalf("UDP: got %x, want nil", got)
	}
	conn := u.newTCP(headerFor(t, "ipv4 tcp"))
	defer conn.close()
	if got := conn.exchange(context.Background(), query); got != nil {
		t.Fatalf("TCP: got %x, want nil", got)
	}
}

// G15: a truncated UDP reply is answered by asking again over a new TCP connection with its own header.
func TestTruncatedUDPReplyIsRetriedOverTCPWithItsOwnHeader(t *testing.T) {
	f := newFakeUpstream(t, answering(func(q seenQuery) [][]byte {
		reply := echoWithQR(q)[0]
		if q.tcp {
			return [][]byte{append(reply, "full answer"...)}
		}
		reply[2] |= 0x02 // TC
		return [][]byte{reply}
	}))
	u := newUpstream(f.addr, watchdog)
	query := buildQuery(t, 0x4242, "example.", true)
	got := u.exchangeUDPThenTCP(context.Background(), ap("203.0.113.5:40000"), ap("198.51.100.1:53"), query)
	udp, tcp := f.next(), f.next()
	if udp.tcp || !tcp.tcp {
		t.Fatalf("order of transports: UDP first, then TCP; got tcp=%v then tcp=%v", udp.tcp, tcp.tcp)
	}
	if want := headerFor(t, "ipv4 tcp"); !bytes.Equal(tcp.header, want) {
		t.Fatalf("TCP retry header:\n got  %x\n want %x", tcp.header, want)
	}
	if want := mustHex(t, headerVectors["ipv4 tcp"].hex[:26]+"12"+headerVectors["ipv4 tcp"].hex[28:]); !bytes.Equal(udp.header, want) {
		t.Fatalf("UDP header:\n got  %x\n want %x", udp.header, want)
	}
	if !bytes.Equal(tcp.wire, query) {
		t.Fatalf("the retry carries the same query: got %x, want %x", tcp.wire, query)
	}
	if !bytes.HasSuffix(got, []byte("full answer")) || got[2]&0x02 != 0 {
		t.Fatalf("the caller must get the TCP reply, got %x", got)
	}
}

func TestUntruncatedUDPReplyNeverOpensATCPConnection(t *testing.T) {
	f := newFakeUpstream(t)
	u := newUpstream(f.addr, watchdog)
	query := buildQuery(t, 0x4242, "example.", true)
	got := u.exchangeUDPThenTCP(context.Background(), ap("203.0.113.5:40000"), ap("198.51.100.1:53"), query)
	if want := echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want %x", got, want)
	}
	f.next()
	select { // the exchange has returned, so a TCP retry would already have reached the fake
	case q := <-f.queries:
		t.Fatalf("an untruncated reply must not be asked for again, but Unbound saw %+v", q)
	default:
	}
}

func TestTruncatedUDPReplyWhoseTCPRetryFailsIsNoReply(t *testing.T) {
	f := newFakeUpstream(t, hangingUp(), answering(func(q seenQuery) [][]byte {
		reply := echoWithQR(q)[0]
		reply[2] |= 0x02
		return [][]byte{reply}
	}))
	u := newUpstream(f.addr, watchdog)
	got := u.exchangeUDPThenTCP(context.Background(), ap("203.0.113.5:40000"), ap("198.51.100.1:53"), buildQuery(t, 1, "example.", true))
	if got != nil {
		t.Fatalf("a truncated reply is not an answer: got %x, want nil", got)
	}
}

// G16: one upstream connection per client connection, header once.
func TestTCPUpstreamReusesOneConnectionAndSendsTheHeaderOnce(t *testing.T) {
	f := newFakeUpstream(t)
	u := newUpstream(f.addr, watchdog)
	header := headerFor(t, "ipv4 tcp")
	conn := u.newTCP(header)
	defer conn.close()
	for i := range 3 {
		query := buildQuery(t, uint16(100+i), "example.", true)
		got := conn.exchange(context.Background(), query)
		seen := f.next()
		if !bytes.Equal(seen.wire, query) || !bytes.Equal(got, echoWithQR(seen)[0]) {
			t.Fatalf("exchange %d: Unbound saw %x and replied %x for %x", i, seen.wire, got, query)
		}
		if !bytes.Equal(seen.header, header) || !seen.tcp {
			t.Fatalf("exchange %d: header %x tcp=%v, want %x tcp=true", i, seen.header, seen.tcp, header)
		}
	}
	if conns, headers := f.counts(); conns != 1 || headers != 1 {
		t.Fatalf("3 queries used %d connections and %d headers, want 1 and 1", conns, headers)
	}
}

func TestTCPUpstreamClosedWhileIdleIsReopenedOnceWithAFreshHeader(t *testing.T) {
	f := newFakeUpstream(t, closingAfter(1))
	u := newUpstream(f.addr, watchdog)
	conn := u.newTCP(headerFor(t, "ipv4 tcp"))
	defer conn.close()
	for i := range 2 {
		query := buildQuery(t, uint16(200+i), "example.", true)
		if got := conn.exchange(context.Background(), query); !bytes.Equal(got, echoWithQR(seenQuery{wire: query})[0]) {
			t.Fatalf("exchange %d: got %x", i, got)
		}
	}
	if conns, headers := f.counts(); conns != 2 || headers != 2 {
		t.Fatalf("an idle-closed connection: %d connections and %d headers, want 2 and 2", conns, headers)
	}
}

func TestTCPUpstreamThatFailsOnAFreshConnectionIsNotRetried(t *testing.T) {
	f := newFakeUpstream(t, hangingUp())
	u := newUpstream(f.addr, watchdog)
	conn := u.newTCP(headerFor(t, "ipv4 tcp"))
	defer conn.close()
	if got := conn.exchange(context.Background(), buildQuery(t, 1, "example.", true)); got != nil {
		t.Fatalf("got %x, want nil", got)
	}
	if conns, _ := f.counts(); conns != 1 {
		t.Fatalf("a failing fresh connection was attempted %d times, want 1", conns)
	}
}

func TestTCPUpstreamSilenceIsNoReplyAndDropsTheConnection(t *testing.T) {
	f := newFakeUpstream(t, silent())
	u := newUpstream(f.addr, 50*time.Millisecond)
	conn := u.newTCP(headerFor(t, "ipv4 tcp"))
	defer conn.close()
	for i := range 2 {
		if got := conn.exchange(context.Background(), buildQuery(t, uint16(i), "example.", true)); got != nil {
			t.Fatalf("exchange %d: got %x from a silent Unbound, want nil", i, got)
		}
	}
	// A connection that timed out may hold a late reply for the wrong query: it must not be reused.
	f.next() // the fake counts a connection's header before it reports the query behind it
	f.next()
	if conns, headers := f.counts(); conns != 2 || headers != 2 {
		t.Fatalf("%d connections and %d headers after two silent exchanges, want 2 and 2", conns, headers)
	}
}
