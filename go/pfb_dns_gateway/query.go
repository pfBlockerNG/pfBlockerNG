package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// forwarder sends one wire to Unbound as the client and returns Unbound's reply; nil means none.
type forwarder func(ctx context.Context, wire []byte) []byte

// decideFunc is (*decider.Frontend).Resolve: the decision for one query, nil for a dropped packet. fwd asks Unbound as
// the client; transport is one of transportNames, listenerIP and listenerInterface are "" when the query did not
// reach an address of the gateway.
type decideFunc func(wire []byte, clientIP string, fwd func([]byte) []byte, transport, listenerIP, listenerInterface string) []byte

// clientTransport names the accepted listener, not the upstream exchange.
type clientTransport byte

const (
	clientTCP clientTransport = iota
	clientUDP
	clientDoT
	clientDoH
	clientDoQ
)

// transportNames are the labels the decider logs and counts a query under.
var transportNames = [...]string{clientTCP: "TCP", clientUDP: "UDP", clientDoT: "DoT", clientDoH: "DoH", clientDoQ: "DoQ"}

const maxWire = 65535 // the largest DNS message

const (
	maxUDPInflight   = 512                    // concurrent UDP queries, each holding an upstream socket; more are dropped
	maxMuxInflight   = 512                    // DoH and DoQ queries in flight together; more get 503 (DoH) or SERVFAIL (DoQ)
	maxTCPConns      = 128                    // TCP and DoT connections at once; more are closed at accept
	connPipeline     = 4                      // queries of one TCP or DoT connection in flight at once; the connection is not read past them
	maxDoHConns      = 128                    // DoH connections at once; more are closed at accept
	maxDoQConns      = 128                    // DoQ connections at once; more are refused before their handshake
	defaultTCPIdle   = 30 * time.Second       // Unbound's tcp-idle-timeout default
	defaultGrace     = time.Second            // added to 2 x timeout for the whole query
	defaultHandshake = 10 * time.Second       // TLS handshake, PROXY header and request headers of a new connection
	defaultCloseWait = 250 * time.Millisecond // a DoT peer gets this long to take close_notify before the TCP connection is cut
	defaultStopWait  = 500 * time.Millisecond // each of stop()'s two waits; under the rc stop loop's 5 s KILL
	// What one client address may hold of each shared budget, keyed by the full address (a pfSense LAN is one /64: keying by
	// prefix would make every IPv6 host there share one budget). Half of each budget, so no address takes a whole one.
	maxUDPPerAddr = maxUDPInflight / 2
	maxMuxPerAddr = maxMuxInflight / 2
	maxTCPPerAddr = maxTCPConns / 2
	maxDoHPerAddr = maxDoHConns / 2
	maxDoQPerAddr = maxDoQConns / 2
)

// connLimit caps the connections of one transport; the refusals of one burst are logged once.
type connLimit struct {
	what string
	max  int64
	n    atomic.Int64
	over atomic.Bool // set when the burst is logged, cleared when the clients have drained
}

func newConnLimit(what string, max int64) *connLimit { return &connLimit{what: what, max: max} }

// take reserves a slot; false means the limit is reached and the connection must be refused.
func (c *connLimit) take(logf func(format string, args ...any)) bool {
	if c.n.Add(1) <= c.max {
		return true
	}
	c.n.Add(-1)
	if c.over.CompareAndSwap(false, true) {
		logf("%s client limit of %d reached: refusing new connections until the clients drain", c.what, c.max)
	}
	return false
}

func (c *connLimit) release() {
	if c.n.Add(-1) == 0 {
		c.over.Store(false)
	}
}

// addrLimit caps what one client address holds of a shared budget. A newcomer over its share is refused; what the address
// already holds is never touched. The refusals of one burst are logged once, without naming the address, and the latch
// re-arms when nothing is held any more.
type addrLimit struct {
	mu   sync.Mutex
	held map[netip.Addr]int
	over bool
}

// addrKey is the address as the ACL and the decider see it: IPv4-mapped IPv6 is IPv4, a zone is not part of who it is.
func addrKey(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// take reserves one of the max slots of a; false means a holds them all.
func (l *addrLimit) take(a netip.Addr, max int, what string, logf func(format string, args ...any)) bool {
	a = addrKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[a] < max {
		if l.held == nil {
			l.held = map[netip.Addr]int{}
		}
		l.held[a]++
		return true
	}
	if !l.over {
		l.over = true
		logf("client address limit of %d %s reached: refusing that address's new ones until they drain", max, what)
	}
	return false
}

func (l *addrLimit) release(a netip.Addr) {
	a = addrKey(a)
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.held[a] - 1; n > 0 {
		l.held[a] = n
		return
	}
	delete(l.held, a)
	if len(l.held) == 0 {
		l.over = false
	}
}

// gateway is the serving state shared by every listener: who may ask, who decides, where Unbound is.
type gateway struct {
	acl                                                        *ACL
	decide                                                     decideFunc // the in-process decider's Resolve
	up                                                         *upstream
	timeout                                                    time.Duration // wait for Unbound per exchange
	grace                                                      time.Duration
	tcpIdle                                                    time.Duration // idle limit for reading a query and for writing a reply
	handshake                                                  time.Duration // limit for a TLS handshake, a PROXY header, request headers and a DoQ query read
	doqHandshakeIdle                                           time.Duration // QUIC handshake idle timeout, read when the DoQ listener starts; production is 5s
	closeBound                                                 time.Duration // limit for sending close_notify
	stopBound                                                  time.Duration // limit for each of stop()'s waits for the serving goroutines
	logf                                                       func(format string, args ...any)
	udpPerAddr, muxPerAddr, tcpPerAddr, dohPerAddr, doqPerAddr int    // per-address shares of the budgets below; a test lifts one to look at the global cap alone
	doqAccepted                                                func() // test seam: DoQ's accept loop calls it with a connection taken and not yet registered
	doqListenerClosed                                          func() // test seam: DoQ's closer calls it once ln.Close() has returned, before it waits for the accept loop

	ddr                *ddr         // issue #3583: answers resolver.arpa. itself, after the ACL and before the decider; nil = off
	names              *nameAnswers // issue #3694: answers A and AAAA for the DNS name, after the ACL and DDR; nil = no DNS name
	listenerInterfaces atomic.Pointer[map[netip.Addr]string]

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup // every serving goroutine; stop() waits for them
	queries idleGroup      // UDP queries from their datagram to the end of their handler, reply included

	udpInflight, tcpConns                            atomic.Int64
	udpOverload, tcpOverload                         atomic.Bool // one log line per burst: set when logged, cleared when drained
	muxInflight                                      atomic.Int64
	muxOverload                                      atomic.Bool
	dohConns, doqConns                               *connLimit
	udpAddrs, muxAddrs, tcpAddrs, dohAddrs, doqAddrs addrLimit // what each client address holds of the budgets above

	mu      sync.Mutex
	closers []*closer // what stop() closes besides client connections: listeners, servers
	clients map[net.Conn]struct{}

	deciderFailure struct { // when decideSafely last logged a panic of the decider
		sync.Mutex
		logged time.Time
	}
}

// idleGroup is a WaitGroup whose Add may race with Wait: a test waits for the queries sent so far, then sends
// more, and no happens-before edge runs through the network between the two.
type idleGroup struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n returns to 0; made by the first waiter
}

func (q *idleGroup) Add(delta int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n += delta; q.n == 0 && q.idle != nil {
		close(q.idle)
		q.idle = nil
	}
}

func (q *idleGroup) Done() { q.Add(-1) }

func (q *idleGroup) Wait() {
	q.mu.Lock()
	if q.n == 0 {
		q.mu.Unlock()
		return
	}
	if q.idle == nil {
		q.idle = make(chan struct{})
	}
	idle := q.idle
	q.mu.Unlock()
	<-idle
}

func newGateway(acl *ACL, decide decideFunc, up *upstream, timeout time.Duration, logf func(format string, args ...any)) *gateway {
	g := &gateway{
		acl: acl, up: up, timeout: timeout, grace: defaultGrace, tcpIdle: defaultTCPIdle, handshake: defaultHandshake, doqHandshakeIdle: defaultDoQHandshakeIdle, logf: logf,
		closeBound: defaultCloseWait, stopBound: defaultStopWait,
		udpPerAddr: maxUDPPerAddr, muxPerAddr: maxMuxPerAddr, tcpPerAddr: maxTCPPerAddr, dohPerAddr: maxDoHPerAddr, doqPerAddr: maxDoQPerAddr,
		clients:  map[net.Conn]struct{}{},
		dohConns: newConnLimit("DoH", maxDoHConns), doqConns: newConnLimit("DoQ", maxDoQConns),
	}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.decide = decide
	return g
}

// disposition is what a client's packet is owed before the decider is asked.
type disposition int

const (
	toDecider disposition = iota // ask the decider
	replyNow                     // send the returned reply
	discard                      // send nothing; a TCP connection stays open
	hangUp                       // ACL deny: send nothing; a TCP connection is closed
)

// screen applies what never needs the decider: no header or a response (never answered, so no reflection
// loops), then the Resolver ACL, then DDR when it is on (issue #3583), then the DNS name's A and AAAA (issue #3694). local is
// the address the query reached on any transport; plain says it came over plain DNS, the only transport DDR designates on
// (it is handed no address on the others), and udp says it came as a datagram.
func (g *gateway) screen(client, local netip.Addr, plain, udp bool, wire []byte) (disposition, []byte) {
	if len(wire) < 12 || wire[2]&0x80 != 0 {
		return discard, nil
	}
	switch g.acl.Lookup(client) {
	case ACLDrop:
		return hangUp, nil
	case ACLRefuse:
		return replyNow, buildRefused(wire)
	}
	if g.ddr != nil {
		designated := local
		if !plain {
			designated = netip.Addr{}
		}
		if reply := g.ddr.answer(wire, designated, udp); reply != nil {
			return replyNow, reply
		}
	}
	if g.names != nil {
		if reply := g.names.answer(wire, local, udp); reply != nil {
			return replyNow, reply
		}
	}
	return toDecider, nil
}

// resolve asks the decider and serves its FORWARDs through fwd. nil means the decider dropped the query; a query whose
// 2 x timeout + grace has run out by the time the decider returns gets SERVFAIL built here.
func (g *gateway) resolve(ctx context.Context, client, listener netip.Addr, transport clientTransport, wire []byte, fwd forwarder) []byte {
	ctx, cancel := context.WithTimeout(ctx, 2*g.timeout+g.grace)
	defer cancel()
	listener = listener.Unmap().WithZone("")
	local, label := "", ""
	if listener.IsValid() && !listener.IsUnspecified() {
		local = listener.String()
		if table := g.listenerInterfaces.Load(); table != nil {
			label = (*table)[listener]
		}
	}
	answer := g.decideSafely(wire, addrKey(client).String(), func(w []byte) []byte { return fwd(ctx, w) }, transportNames[transport], local, label)
	if answer == nil { // a DROP stays no reply, however late
		return nil
	}
	if ctx.Err() != nil {
		return buildServfail(wire)
	}
	return answer
}

// deciderFailureLogInterval is the least time between two lines about a failed decider call: the Python decider's
// FAILURE_LOG_INTERVAL, so a decider that fails on every query does not fill the log.
const deciderFailureLogInterval = 30 * time.Second

// decideSafely is g.decide that a panic of the decider cannot take the process down through: as an exception of the
// Python decider was, the query is answered SERVFAIL and the panic value is logged, at most once per deciderFailureLogInterval.
func (g *gateway) decideSafely(wire []byte, clientIP string, fwd func([]byte) []byte, transport, listenerIP, listenerInterface string) (answer []byte) {
	defer func() {
		if r := recover(); r != nil {
			answer = buildServfail(wire)
			g.deciderFailure.Lock()
			log := g.deciderFailure.logged.IsZero() || time.Since(g.deciderFailure.logged) >= deciderFailureLogInterval
			if log {
				g.deciderFailure.logged = time.Now()
			}
			g.deciderFailure.Unlock()
			if log {
				g.logf("decider failed on a query, answering SERVFAIL: %v", r)
			}
		}
	}()
	return g.decide(wire, clientIP, fwd, transport, listenerIP, listenerInterface)
}

// resolveShared is resolve under the cap DoH and DoQ share: they carry many queries on one connection, so their
// queries in flight (each holds an upstream socket) are counted apart from UDP's. ok is false over the cap.
func (g *gateway) resolveShared(ctx context.Context, client, listener netip.Addr, transport clientTransport, wire []byte, fwd forwarder) (reply []byte, ok bool) {
	if !g.muxAddrs.take(client, g.muxPerAddr, "DoH and DoQ queries", g.logf) {
		return nil, false
	}
	defer g.muxAddrs.release(client)
	if g.muxInflight.Add(1) > maxMuxInflight {
		g.muxInflight.Add(-1)
		if g.muxOverload.CompareAndSwap(false, true) {
			g.logf("%d DoH and DoQ queries in flight: refusing new ones until they drain", maxMuxInflight)
		}
		return nil, false
	}
	defer func() {
		if g.muxInflight.Add(-1) == 0 {
			g.muxOverload.Store(false)
		}
	}()
	return g.resolve(ctx, client, listener, transport, wire, fwd), true
}
