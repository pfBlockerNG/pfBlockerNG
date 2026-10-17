package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxUDPInflight = 512              // concurrent UDP queries, each holding an upstream socket; more are dropped
	maxTCPConns    = 128              // TCP connections at once; more are closed at accept
	defaultTCPIdle = 30 * time.Second // Unbound's tcp-idle-timeout default
	defaultGrace   = time.Second      // added to 2 x timeout for the whole query
)

// gateway is the serving state shared by every listener: who may ask, who decides, where Unbound is.
type gateway struct {
	acl     *ACL
	dec     *Decider
	up      *upstream
	timeout time.Duration // wait for Unbound per exchange
	grace   time.Duration
	tcpIdle time.Duration // idle limit for reading a query and for writing a reply
	logf    func(format string, args ...any)

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup // every serving goroutine; stop() waits for them
	queries idleGroup      // UDP queries from their datagram to the end of their handler, reply included

	udpInflight, tcpConns    atomic.Int64
	udpOverload, tcpOverload atomic.Bool // one log line per burst: set when logged, cleared when drained

	mu        sync.Mutex
	listeners []*plainListener
	clients   map[net.Conn]struct{}
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

func newGateway(acl *ACL, dec *Decider, up *upstream, timeout time.Duration, logf func(format string, args ...any)) *gateway {
	g := &gateway{
		acl: acl, dec: dec, up: up, timeout: timeout, grace: defaultGrace, tcpIdle: defaultTCPIdle, logf: logf,
		clients: map[net.Conn]struct{}{},
	}
	g.ctx, g.cancel = context.WithCancel(context.Background())
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
// loops), then the Resolver ACL.
func (g *gateway) screen(client netip.Addr, wire []byte) (disposition, []byte) {
	if len(wire) < 12 || wire[2]&0x80 != 0 {
		return discard, nil
	}
	switch g.acl.Lookup(client) {
	case ACLDrop:
		return hangUp, nil
	case ACLRefuse:
		return replyNow, buildRefused(wire)
	}
	return toDecider, nil
}

// resolve asks the decider and serves its FORWARDs through fwd. nil means the decider dropped the query; a
// decider that fails or does not decide within 2 x timeout + grace gets SERVFAIL built here.
func (g *gateway) resolve(ctx context.Context, client netip.Addr, wire []byte, fwd forwarder) []byte {
	ctx, cancel := context.WithTimeout(ctx, 2*g.timeout+g.grace)
	defer cancel()
	answer, err := g.dec.Decide(ctx, client, wire, fwd)
	if err != nil {
		return buildServfail(wire)
	}
	return answer
}
