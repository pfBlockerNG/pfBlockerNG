package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// pfSense-shaped ACL used by the rigs: loopback aliases stand in for LAN clients, and the documentation ranges are the
// clients a trusted front end names (a client no row names is refused, as Unbound refuses it).
const (
	aclDocumentation = "access-control: 192.0.2.0/24 allow\naccess-control: 198.51.100.0/24 allow\n" +
		"access-control: 203.0.113.0/24 allow\naccess-control: 2001:db8::/32 allow\n"
	aclMixed = "#LAN\naccess-control: 127.0.0.0/8 allow_snoop \n" + aclDocumentation +
		"access-control: 127.0.0.9/32 refuse\n" +
		"access-control: 127.0.0.10/32 deny\n"
	clientRefused, clientDenied, clientAllowed = "127.0.0.9", "127.0.0.10", "127.0.0.5"
)

type rigConfig struct {
	acl         string
	timeout     time.Duration // the gateway's wait for Unbound; default: the watchdog
	grace       time.Duration // added to 2 x timeout for the whole query; default: the gateway's
	tcpIdle     time.Duration // default: the gateway's
	upstream    []upstreamOption
	perAddr     int              // lifts the per-address shares of the UDP, DoH/DoQ query, TCP and DoH/DoQ connection budgets to this; 0 = the gateway's own (a test of a global cap sets noAddrCap)
	beforeServe func(g *gateway) // runs on the gateway before its plain listener serves: set what serving goroutines read
}

// noAddrCap leaves a test of a global cap to the global cap: no single address reaches its own share first.
const noAddrCap = 1 << 20

// rig is a gateway on a loopback port with a fake Unbound and the test playing the decider.
type rig struct {
	t       *testing.T
	g       *gateway
	p       *peer
	up      *fakeUpstream
	addr    netip.AddrPort
	aclPath string
	logs    *capturedLog
	queries chan decidedQuery
}

type decidedQuery struct {
	id   uint32
	ip   string
	wire []byte
}

func newRig(t *testing.T, cfg rigConfig) *rig {
	t.Helper()
	logs := &capturedLog{}
	aclPath := writeACLFile(t, cfg.acl)
	p := newPeer(t)

	up := newFakeUpstream(t, cfg.upstream...)
	timeout := cfg.timeout
	if timeout == 0 {
		timeout = watchdog
	}
	g := newGateway(NewACL(aclPath, logs.logf), p.decide, newUpstream(up.addr, timeout), timeout, logs.logf)
	if cfg.grace != 0 {
		g.grace = cfg.grace
	}
	if cfg.tcpIdle != 0 {
		g.tcpIdle = cfg.tcpIdle
	}
	if cfg.perAddr != 0 {
		g.udpPerAddr, g.muxPerAddr, g.tcpPerAddr, g.dohPerAddr, g.doqPerAddr = cfg.perAddr, cfg.perAddr, cfg.perAddr, cfg.perAddr, cfg.perAddr
	}
	l, err := bindPlain("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.beforeServe != nil {
		cfg.beforeServe(g)
	}
	g.serve(l)
	t.Cleanup(func() { p.release(); g.stop() })
	return &rig{t: t, g: g, p: p, up: up, addr: l.addr(), aclPath: aclPath, logs: logs, queries: make(chan decidedQuery, 1024)}
}

// recvQuery reads the next frame and requires it to be a QUERY.
func (r *rig) recvQuery() decidedQuery {
	r.t.Helper()
	q := r.p.recvQuery()
	return decidedQuery{id: q.id, ip: q.ip, wire: q.wire}
}

// autoAnswer plays a decider that answers every query with fn's bytes (a drop for nil); queries are recorded.
// Use it instead of recvQuery()/send(), never with them.
func (r *rig) autoAnswer(fn func(q decidedQuery) []byte) {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	r.p.auto = func(tq transportQuery, _ func([]byte) []byte) []byte {
		q := decidedQuery{id: tq.id, ip: tq.ip, wire: tq.wire}
		r.queries <- q
		return fn(q)
	}
}

func echoAnswer(q decidedQuery) []byte { return echoWithQR(seenQuery{wire: q.wire})[0] }

func (r *rig) nextQuery() decidedQuery {
	r.t.Helper()
	select {
	case q := <-r.queries:
		return q
	case <-time.After(watchdog):
		r.t.Fatal("STUCK/ENVIRONMENT: the decider never saw a query")
		return decidedQuery{}
	}
}

func (r *rig) requireNoOtherQuery() {
	r.t.Helper()
	select {
	case q := <-r.queries:
		r.t.Fatalf("the decider saw a query it must not have seen: client=%s wire=%x", q.ip, q.wire)
	default:
	}
}

func (r *rig) udpClient(source string) *net.UDPConn {
	r.t.Helper()
	local := &net.UDPAddr{}
	if source != "" {
		local.IP = net.ParseIP(source)
	}
	c, err := net.DialUDP("udp4", local, net.UDPAddrFromAddrPort(r.addr))
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

func (r *rig) tcpClient(source string) net.Conn {
	r.t.Helper()
	d := net.Dialer{Timeout: watchdog}
	if source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	c, err := d.Dial("tcp4", r.addr.String())
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

func udpReply(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("UDP read: %v", err)
	}
	return bytes.Clone(buf[:n])
}

var udpProbeID atomic.Uint32

// udpProbeRetry is how long udpJudged waits for the reply to a probe before it sends another.
const udpProbeRetry = 500 * time.Millisecond

// udpJudged returns once the gateway's read loop has judged every datagram sent before the call. The loop reads datagrams
// in order and answers a client the ACL refuses by itself, so the reply to a probe from such a client says that the
// datagrams before the probe are done. The kernel may drop a datagram under load, the probe or its reply: the probe is
// sent again every half second until one is answered. Only a reply to a probe sent in this call counts, so a late reply
// to an earlier call's probe cannot pass for it.
func udpJudged(t *testing.T, probe *net.UDPConn) {
	t.Helper()
	retry := time.NewTicker(udpProbeRetry)
	defer retry.Stop()
	udpJudgedOn(t, probe, retry.C)
}

// udpJudgedOn is udpJudged with the event that sends the probe again injected: each receive from retry is one retry (a nil
// channel never retries).
func udpJudgedOn(t *testing.T, probe *net.UDPConn, retry <-chan time.Time) {
	t.Helper()
	first := uint16(udpProbeID.Add(1))
	deadline := time.Now().Add(watchdog)
	for next := first; ; next = uint16(udpProbeID.Add(1)) {
		if _, err := probe.Write(buildQuery(t, next, "example.", true)); err != nil {
			t.Fatal(err)
		}
		if ownReplyBeforeRetry(t, probe, first, retry, deadline) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("STUCK/ENVIRONMENT: the gateway never answered the probe that says its earlier datagrams were judged")
		}
	}
}

// ownReplyBeforeRetry reads probe until a reply to a probe of this call (id first or later) arrives, and reports true; it
// reports false when retry fires, or the watchdog does, first. The firing of retry ends the read in progress.
func ownReplyBeforeRetry(t *testing.T, probe *net.UDPConn, first uint16, retry <-chan time.Time, watchdogAt time.Time) bool {
	t.Helper()
	_ = probe.SetReadDeadline(watchdogAt)
	stop, woken := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(woken)
		select {
		case <-retry:
			_ = probe.SetReadDeadline(time.Unix(1, 0)) // wakes the blocked read
		case <-stop:
		}
	}()
	defer func() { close(stop); <-woken }()
	buf := make([]byte, 65535)
	for {
		n, err := probe.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		if err != nil {
			t.Fatalf("UDP read: %v", err)
		}
		if n >= 2 && binary.BigEndian.Uint16(buf) >= first {
			return true
		}
	}
}

// requireNoUDPReply asserts that nothing is waiting on c: call it only after a completion barrier. It asks the kernel what
// is queued right now: a Read with an expired deadline never reaches the socket, whatever is queued, so it would pass for
// any reply.
func requireNoUDPReply(t *testing.T, c *net.UDPConn) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Time{}) // a deadline left by an earlier read would end RawConn.Read before it looks
	buf := make([]byte, 65535)
	var n int
	var rerr error
	if err := raw.Read(func(fd uintptr) bool { // true: look once and never wait
		n, _, rerr = syscall.Recvfrom(int(fd), buf, 0)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if rerr == nil {
		t.Fatalf("a reply of %d bytes arrived where none is allowed", n)
	} else if !errors.Is(rerr, syscall.EAGAIN) {
		t.Fatalf("UDP read: %v", rerr)
	}
}

func tcpSend(t *testing.T, c net.Conn, wire []byte) {
	t.Helper()
	if _, err := c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire)))); err != nil {
		t.Fatalf("TCP write: %v", err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatalf("TCP write: %v", err)
	}
}

func tcpReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		t.Fatalf("TCP read length: %v", err)
	}
	wire := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, wire); err != nil {
		t.Fatalf("TCP read body: %v", err)
	}
	return wire
}

// awaitBytes waits for a client reply read in the background; a failure there ends that goroutine, so the wait is bounded.
func awaitBytes(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: the client never got its reply")
		return nil
	}
}

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// requireTCPClosed asserts that the gateway closed c without sending anything.
func requireTCPClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	n, err := c.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("STUCK/ENVIRONMENT: the gateway left the connection open for the whole watchdog (read %d bytes)", n)
	}
	if !isClosed(err) {
		t.Fatalf("the gateway must close the connection silently: read %d bytes, err=%v", n, err)
	}
}

type transport struct {
	name string
	tcp  bool
}

var transports = []transport{{"udp", false}, {"tcp", true}}

// roundTrip sends one query as `source` over the transport and returns the reply.
func (r *rig) roundTrip(tr transport, source string, wire []byte) []byte {
	r.t.Helper()
	if tr.tcp {
		c := r.tcpClient(source)
		tcpSend(r.t, c, wire)
		return tcpReply(r.t, c)
	}
	c := r.udpClient(source)
	if _, err := c.Write(wire); err != nil {
		r.t.Fatal(err)
	}
	return udpReply(r.t, c)
}

func wantHeader(t *testing.T, tr transport, client net.Addr, gw netip.AddrPort) []byte {
	t.Helper()
	var cport int
	switch a := client.(type) {
	case *net.UDPAddr:
		cport = a.Port
	case *net.TCPAddr:
		cport = a.Port
	}
	proto := byte(0x12)
	if tr.tcp {
		proto = 0x11
	}
	h := append(mustHex(t, proxySignature), 0x21, proto, 0, 12, 127, 0, 0, 1, 127, 0, 0, 1)
	h = binary.BigEndian.AppendUint16(h, uint16(cport))
	return binary.BigEndian.AppendUint16(h, gw.Port())
}

// G2: a decider that answers by itself, for both transports; it is told the client's address.
func TestClientGetsTheDecidersAnswer(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoAnswer(func(q decidedQuery) []byte { return append(echoAnswer(q), "block"...) })
			query := buildQuery(t, 0x1111, "blocked.example.", true)
			got := r.roundTrip(tr, clientAllowed, query)
			q := r.nextQuery()
			if q.ip != clientAllowed || !bytes.Equal(q.wire, query) {
				t.Fatalf("QUERY: got client=%s wire=%x, want client=%s wire=%x", q.ip, q.wire, clientAllowed, query)
			}
			if want := append(echoAnswer(q), "block"...); !bytes.Equal(got, want) {
				t.Fatalf("reply: got %x, want the decider's answer %x", got, want)
			}
		})
	}
}

// G3: FORWARD reaches Unbound behind a PROXYv2 header naming the client; REPLY carries Unbound's bytes back. Both
// transports ask Unbound over UDP: a TCP client reaches it as a DoH or DoQ client does, TCP only for a truncated reply.
func TestForwardReachesUnboundAsTheClientAndTheReplyComesBack(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			query := buildQuery(t, 0x2222, "allowed.example.", true)
			var client net.Addr
			done := make(chan []byte, 1)
			if tr.tcp {
				c := r.tcpClient("")
				client = c.LocalAddr()
				tcpSend(t, c, query)
				go func() { done <- tcpReply(t, c) }()
			} else {
				c := r.udpClient("")
				client = c.LocalAddr()
				if _, err := c.Write(query); err != nil {
					t.Fatal(err)
				}
				go func() { done <- udpReply(t, c) }()
			}
			q := r.recvQuery()
			r.p.send(tForward, q.id, q.wire)
			seen := r.up.next()
			if !bytes.Equal(seen.wire, query) || seen.tcp {
				t.Fatalf("Unbound saw wire=%x tcp=%v, want wire=%x over UDP", seen.wire, seen.tcp, query)
			}
			if want := wantHeader(t, transport{"udp", false}, client, r.addr); !bytes.Equal(seen.header, want) {
				t.Fatalf("PROXYv2 header:\n got  %x\n want %x", seen.header, want)
			}
			unboundReply := echoWithQR(seen)[0]
			r.p.expect(tReply, q.id, unboundReply)
			r.p.send(tAnswer, q.id, unboundReply)
			if got := awaitBytes(t, done); !bytes.Equal(got, unboundReply) {
				t.Fatalf("client reply: got %x, want %x", got, unboundReply)
			}
		})
	}
}

// G4: the SafeSearch chase is a second FORWARD of the same query; each is exchanged in turn.
func TestChaseQueryIsExchangedAfterTheFirstReply(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	c := r.udpClient("")
	query, chase := buildQuery(t, 0x3333, "duck.example.", true), buildQuery(t, 0x4444, "safe.duck.example.", true)
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	q := r.recvQuery()
	r.p.send(tForward, q.id, q.wire)
	first := r.up.next()
	r.p.expect(tReply, q.id, echoWithQR(first)[0])
	r.p.send(tForward, q.id, chase)
	second := r.up.next()
	if !bytes.Equal(first.wire, query) || !bytes.Equal(second.wire, chase) {
		t.Fatalf("Unbound saw %x then %x, want the query then the chase", first.wire, second.wire)
	}
	r.p.expect(tReply, q.id, echoWithQR(second)[0])
	r.p.send(tAnswer, q.id, []byte("cname+target"))
	if got := udpReply(t, c); string(got) != "cname+target" {
		t.Fatalf("client reply: got %q", got)
	}
}

// G5: DROP means silence; UDP is checked after a completion barrier, TCP keeps its connection.
func TestDeciderDropSendsNothingAndKeepsTheTCPConnection(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		c := r.udpClient("")
		if _, err := c.Write(buildQuery(t, 1, "dropped.example.", true)); err != nil {
			t.Fatal(err)
		}
		q := r.recvQuery()
		r.p.send(tDrop, q.id, nil)
		r.g.queries.Wait() // the handler of the dropped query has finished: a stray reply would be queued by now
		requireNoUDPReply(t, c)

		if _, err := c.Write(buildQuery(t, 2, "next.example.", true)); err != nil {
			t.Fatal(err)
		}
		q = r.recvQuery()
		r.p.send(tAnswer, q.id, []byte("next answer"))
		if got := udpReply(t, c); string(got) != "next answer" {
			t.Fatalf("a later query on the same socket: got %q", got)
		}
	})
	t.Run("tcp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		c := r.tcpClient("")
		tcpSend(t, c, buildQuery(t, 1, "dropped.example.", true))
		q := r.recvQuery()
		r.p.send(tDrop, q.id, nil)
		tcpSend(t, c, buildQuery(t, 2, "next.example.", true)) // TCP is ordered: a reply to the first would come first
		q = r.recvQuery()
		r.p.send(tAnswer, q.id, []byte("next answer"))
		if got := tcpReply(t, c); string(got) != "next answer" {
			t.Fatalf("the connection after a DROP: got %q", got)
		}
	})
}

func servfailFor(t *testing.T, wire []byte) {
	t.Helper()
	m := parseReply(t, wire)
	if !m.Response || m.RCode != dnsmessage.RCodeServerFailure || len(m.Questions) != 1 {
		t.Fatalf("want a SERVFAIL echoing the question, got %+v", m)
	}
}

// G6 + G6b: a query whose whole-query limit (2 x timeout + grace) is over when the decider returns gets the SERVFAIL the
// gateway builds, whatever the decider answered; the decider's late forward is not exchanged with Unbound.
func TestAnAnswerAfterTheQueryLimitIsServfailAndTheLateForwardIsNotExchanged(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			// grace of minus two timeouts makes the limit zero: the query is over before the decider runs, however slow it is.
			r := newRig(t, rigConfig{acl: aclMixed, timeout: time.Hour, grace: -2 * time.Hour})
			forwarded := make(chan []byte, 1)
			r.p.mu.Lock()
			r.p.auto = func(q transportQuery, fwd func([]byte) []byte) []byte {
				forwarded <- fwd(q.wire) // the decider wakes up late
				return []byte("a late answer")
			}
			r.p.mu.Unlock()
			query := buildQuery(t, 0x5555, "slow.example.", true)
			reply := r.roundTrip(tr, "", query)
			servfailFor(t, reply)
			if id := binary.BigEndian.Uint16(reply); id != 0x5555 {
				t.Fatalf("SERVFAIL id: got %#x, want 0x5555", id)
			}
			if got := <-forwarded; got != nil {
				t.Fatalf("a forward after the query limit returned %x, want none", got)
			}
			select {
			case seen := <-r.up.queries:
				t.Fatalf("Unbound was asked for an abandoned query: %x", seen.wire)
			default:
			}
		})
	}
}

// G9: a denied client is dropped before anyone is asked.
func TestDeniedClientGetsNothingAndTheDeciderNeverSeesTheQuery(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		r.autoAnswer(echoAnswer)
		denied, allowed := r.udpClient(clientDenied), r.udpClient(clientAllowed)
		if _, err := denied.Write(buildQuery(t, 1, "blocked.example.", true)); err != nil {
			t.Fatal(err)
		}
		if _, err := allowed.Write(buildQuery(t, 2, "allowed.example.", true)); err != nil {
			t.Fatal(err)
		}
		udpReply(t, allowed) // datagrams are read in order, so the denied one has been handled
		requireNoUDPReply(t, denied)
		if q := r.nextQuery(); q.ip != clientAllowed {
			t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
		}
		r.requireNoOtherQuery()
	})
	t.Run("tcp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		r.autoAnswer(echoAnswer)
		denied := r.tcpClient(clientDenied)
		requireTCPClosed(t, denied) // refused at accept: it never holds a slot
		allowed := r.tcpClient(clientAllowed)
		tcpSend(t, allowed, buildQuery(t, 2, "allowed.example.", true))
		tcpReply(t, allowed)
		if q := r.nextQuery(); q.ip != clientAllowed {
			t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
		}
		r.requireNoOtherQuery()
	})
}

func requireRefused(t *testing.T, query, reply []byte) {
	t.Helper()
	m := parseReply(t, reply)
	if m.ID != binary.BigEndian.Uint16(query) || !m.Response || !m.RecursionDesired || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("want REFUSED with the query's id and RD set, got %+v", m.Header)
	}
	q := parseReply(t, query)
	if !refusedSectionsMatch(q, m) {
		t.Fatalf("want only query questions %v, got questions=%v answers=%v authorities=%v additionals=%v", q.Questions, m.Questions, m.Answers, m.Authorities, m.Additionals)
	}
}

func refusedSectionsMatch(query, reply dnsmessage.Message) bool {
	return slices.Equal(reply.Questions, query.Questions) && len(reply.Answers) == 0 &&
		len(reply.Authorities) == 0 && len(reply.Additionals) == 0
}

// G10: a refused client gets REFUSED from the gateway, never the decider's (block) answer.
func TestRefusedClientGetsRefusedAndTheDeciderNeverSeesTheQuery(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoAnswer(echoAnswer)
			query := buildQuery(t, 0x6666, "blocked.example.", true)
			requireRefused(t, query, r.roundTrip(tr, clientRefused, query))
			r.roundTrip(tr, clientAllowed, buildQuery(t, 2, "allowed.example.", true)) // barrier
			if q := r.nextQuery(); q.ip != clientAllowed {
				t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
			}
			r.requireNoOtherQuery()
		})
	}
}

// G11: nothing to echo, so the REFUSED is the bare header.
func TestRefusedClientWithAnUnparseableQuestionGetsAHeaderOnlyReply(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			cut := buildQuery(t, 0x7777, "blocked.example.", true)[:16]
			reply := r.roundTrip(tr, clientRefused, cut)
			m := parseReply(t, reply)
			if len(reply) != 12 || m.ID != 0x7777 || m.RCode != dnsmessage.RCodeRefused || len(m.Questions) != 0 {
				t.Fatalf("want a 12-byte REFUSED for id 0x7777, got %d bytes: %x", len(reply), reply)
			}
		})
	}
}

// G12: a rewrite of the ACL file applies after Refresh, on connections already open too.
func TestACLRewrittenWhileServingApplies(t *testing.T) {
	r := newRig(t, rigConfig{acl: "access-control: 127.0.0.0/8 allow\n"})
	r.autoAnswer(echoAnswer)
	query := buildQuery(t, 0x8888, "blocked.example.", true)
	c := r.tcpClient("") // 127.0.0.1, open across the rewrites
	tcpSend(t, c, query)
	if got := tcpReply(t, c); !bytes.Equal(got, echoWithQR(seenQuery{wire: query})[0]) {
		t.Fatalf("before the rewrite the decider answers, got %x", got)
	}

	rewrite := func(content string) {
		if err := os.WriteFile(r.aclPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		r.g.acl.Refresh()
	}
	rewrite("access-control: 127.0.0.0/8 allow\naccess-control: 127.0.0.1/32 refuse\n")
	tcpSend(t, c, query)
	requireRefused(t, query, tcpReply(t, c))
	requireRefused(t, query, r.roundTrip(transport{"udp", false}, "", query))

	rewrite("access-control: 127.0.0.1/32 deny\n")
	tcpSend(t, c, query)
	requireTCPClosed(t, c) // deny closes a connection that was open when the rule arrived

	rewrite("access-control: 127.0.0.0/8 allow_snoop\n")
	if got := r.roundTrip(transport{"tcp", true}, "", query); !bytes.Equal(got, echoWithQR(seenQuery{wire: query})[0]) {
		t.Fatalf("after the rule is removed the decider answers again, got %x", got)
	}
}
