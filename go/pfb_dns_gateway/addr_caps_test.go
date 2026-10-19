package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// One address cannot take the whole of a shared budget: a newcomer over its share is refused, nothing already accepted
// is evicted (owner decision), and every other address is served. Shares are half of each budget, keyed by the full
// address: a pfSense LAN is one /64, so keying by prefix would make every IPv6 host there share one share. The address
// that is over says so in one log line per burst, and no address is named in it.

const otherClient = "127.0.0.6" // allowed by aclMixed, like clientAllowed

func addrLimitLogs(r *rig) int { return strings.Count(r.logs.joined(), "client address limit") }

// 300 queries from one address, held by the decider: the decider sees 256, the 257th and the rest are dropped, another
// address is answered meanwhile, and the address gets its share back when its queries finish.
func TestOneAddressCannotHoldMoreThanItsShareOfUDPQueries(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	release := make(chan struct{})
	r.autoAnswer(func(q decidedQuery) []byte {
		if q.ip == clientAllowed {
			<-release
		}
		return echoAnswer(q)
	})
	c := r.udpClient(clientAllowed)
	_ = c.SetReadBuffer(4 << 20) // 256 replies arrive together: each costs a datagram's worth of buffer, and the default is about that
	send := func(id int) {
		if _, err := c.Write(buildQuery(t, uint16(id), "example.", true)); err != nil {
			t.Fatal(err)
		}
	}
	for batch := 0; batch < maxUDPInflight/2; batch += 8 { // paced, so the kernel's socket buffer never drops one
		for i := 1; i <= 8; i++ {
			send(batch + i)
		}
		for range 8 {
			r.nextQuery()
		}
	}
	for id := maxUDPInflight/2 + 1; id <= 300; id++ {
		send(id)
	}
	// A refused client is answered by the read loop itself: once its REFUSED arrives, the 44 datagrams above (read
	// earlier, in order) have been judged.
	udpJudged(t, r.udpClient(clientRefused))
	r.requireNoOtherQuery()
	if n := addrLimitLogs(r); n != 1 {
		t.Fatalf("44 queries over the share in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}
	if n := r.g.udpInflight.Load(); n != maxUDPInflight/2 {
		t.Fatalf("%d UDP queries in flight, want the %d the address was admitted", n, maxUDPInflight/2)
	}

	// Another address is still answered, though the global budget has 256 slots left and this one has none
	other := r.udpClient(otherClient)
	if _, err := other.Write(buildQuery(t, 7, "example.", true)); err != nil {
		t.Fatal(err)
	}
	if q := r.nextQuery(); q.ip != otherClient {
		t.Fatalf("the decider saw client %s, want %s", q.ip, otherClient)
	}
	if got := udpReply(t, other); len(got) == 0 {
		t.Fatal("another address must be answered while one is over its share")
	}

	// Nothing was evicted: every held query is answered when the decider is ready, and the address has its share back
	close(release)
	for id := 1; id <= maxUDPInflight/2; id++ {
		if got := udpReply(t, c); len(got) < 2 {
			t.Fatalf("held query %d: empty reply", id)
		}
	}
	eventually(t, "the address to drain", func() bool { return r.g.udpInflight.Load() == 0 })
	send(301)
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("a query after the drain reached the decider as %s, want %s", q.ip, clientAllowed)
	}
}

// 64 of the 128 TCP connections for one address: the 65th is closed at accept, silently, another address is served, and
// a closed connection gives its slot back.
func TestOneAddressCannotHoldMoreThanItsShareOfTCPConnections(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	conns := make([]interface{ Close() error }, 0, maxTCPConns/2)
	for range maxTCPConns / 2 {
		conns = append(conns, r.tcpClient(clientAllowed))
	}
	over := r.tcpClient(clientAllowed)
	requireTCPClosed(t, over) // connections are accepted in order: once this one is shut, the first 64 hold their slots
	requireTCPClosed(t, r.tcpClient(clientAllowed))
	if n := r.g.tcpConns.Load(); n != maxTCPConns/2 {
		t.Fatalf("%d TCP connections counted, want %d: the refused ones must not hold a slot", n, maxTCPConns/2)
	}
	if n := addrLimitLogs(r); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}

	other := r.tcpClient(otherClient)
	tcpSend(t, other, buildQuery(t, 9, "example.", true))
	if got := tcpReply(t, other); len(got) == 0 {
		t.Fatal("another address must be served while one is over its share")
	}

	_ = conns[3].Close()
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == maxTCPConns/2 })
	again := r.tcpClient(clientAllowed)
	tcpSend(t, again, buildQuery(t, 10, "example.", true))
	if got := tcpReply(t, again); len(got) == 0 {
		t.Fatal("a connection that arrives after the address's slot was freed must be served")
	}
	// The address is back at its share, exactly: a release that gave back more than the one connection closed would let
	// it hold one over.
	requireTCPClosed(t, r.tcpClient(clientAllowed))
}

// DoT connections take the same TCP slots, so an address's DoT and plain TCP connections count together.
func TestOneAddressCannotHoldMoreThanItsShareOfDoTConnections(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)
	var conns []*tls.Conn
	for range maxTCPConns/2 - 1 {
		conns = append(conns, dialDoT(t, addr, m, clientAllowed))
	}
	r.tcpClient(clientAllowed) // plain TCP from the same address: the 64th
	d := net.Dialer{Timeout: watchdog, LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientAllowed)}}
	refusedAtAccept := func() error {
		over, err := d.Dial("tcp4", addr.String())
		if err == nil {
			defer over.Close()
			err = tlsClientHandshake(over, m)
		}
		return err
	}
	if refusedAtAccept() == nil {
		t.Fatal("a 65th connection of the address completed a TLS handshake, want it closed at accept")
	}
	other := dialDoT(t, addr, m, otherClient)
	tcpSend(t, other, buildQuery(t, 11, "example.", true))
	if got := tcpReply(t, other); len(got) == 0 {
		t.Fatal("another address must be served over DoT while one is over its share")
	}

	// A closed DoT connection gives back its share, and exactly one: the address takes it again and is then refused again.
	_ = conns[3].Close()
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == maxTCPConns/2 })
	again := dialDoT(t, addr, m, clientAllowed)
	tcpSend(t, again, buildQuery(t, 12, "example.", true))
	if got := tcpReply(t, again); len(got) == 0 {
		t.Fatal("a DoT connection that arrives after the address's share was freed must be served")
	}
	if refusedAtAccept() == nil {
		t.Fatal("after one DoT connection closed and another opened, a further one of the address completed a TLS handshake: the release gave back more than one share")
	}
}

// DoH and DoQ queries share one budget, and an address's share of it is the same for both: queries it holds on either
// count together. This goes straight to resolveShared, which both call. Two IPv6 addresses of one /64 have a share each.
func TestOneAddressCannotHoldMoreThanItsShareOfTheDoHAndDoQBudget(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	hold, held := make(chan struct{}), make(chan string, 2*maxMuxInflight)
	r.autoAnswer(func(q decidedQuery) []byte {
		held <- q.ip
		<-hold
		return echoAnswer(q)
	})
	noForward := func(context.Context, []byte) []byte { t.Error("nothing is forwarded"); return nil }
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2") // one /64
	var wg sync.WaitGroup
	hold256 := func(client netip.Addr, tag string) {
		for i := range maxMuxInflight / 2 {
			wire := buildQuery(t, uint16(i+1), fmt.Sprintf("%s%d.example.", tag, i), true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if reply, ok := r.g.resolveShared(r.g.ctx, client, wire, noForward); !ok || len(reply) == 0 {
					t.Errorf("%s %d: ok=%v, want it admitted and answered", client, i, ok)
				}
			}()
		}
		for range maxMuxInflight / 2 {
			select {
			case <-held:
			case <-time.After(watchdog):
				t.Fatalf("STUCK: the decider never saw the %s queries: they were refused or are still waiting", client)
			}
		}
	}
	hold256(a, "a")
	over := buildQuery(t, 1, "over.example.", true)
	for range 2 {
		if reply, ok := r.g.resolveShared(r.g.ctx, a, over, noForward); ok || reply != nil {
			t.Fatalf("a 257th query of one address got ok=%v reply=%x, want it refused", ok, reply)
		}
	}
	if n := strings.Count(r.logs.joined(), "client address limit"); n != 1 {
		t.Fatalf("two refusals in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}
	if strings.Contains(r.logs.joined(), "2001:db8") {
		t.Fatalf("the log line must not name the client: %s", r.logs.joined())
	}
	hold256(b, "b") // the same /64: its own share, and the global budget is then full
	if reply, ok := r.g.resolveShared(r.g.ctx, netip.MustParseAddr(otherClient), over, noForward); ok || reply != nil {
		t.Fatalf("with the global budget full a third address got ok=%v, want it refused too", ok)
	}
	close(hold)
	wg.Wait()
	if n := r.g.muxInflight.Load(); n != 0 {
		t.Fatalf("%d queries still counted after every one was answered", n)
	}
	if reply, ok := r.g.resolveShared(r.g.ctx, a, over, noForward); !ok || len(reply) == 0 {
		t.Fatalf("the address must have its share back after the drain: ok=%v", ok)
	}
}

// The same on the real DoH and DoQ transports: one address holds 258 queries across both, the 257th is refused with each
// transport's own overload answer, and another address is answered on both.
func TestOneAddressIsRefusedOnDoHAndDoQOnceItHoldsItsShare(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	m := newTLSMaterial(t)
	dohAddr, doqAddr := r.serveDoH(m), r.serveDoQ(m)
	release := make(chan struct{})
	r.autoAnswer(func(q decidedQuery) []byte {
		if bytes.Contains(q.wire, []byte("held")) {
			<-release
		}
		return echoAnswer(q)
	})
	const clients, perClient = 3, 43 // 3 DoH + 3 DoQ connections x 43 = 258 from one address
	var held sync.WaitGroup
	failures := make(chan string, 2*clients*perClient)
	var dohClients []*dohClient
	var doqClients []*doqClient
	for range clients {
		c := newDoHClient(t, dohAddr, m, dohOptions{h2: true, source: clientAllowed})
		if resp, _ := c.do(c.get(dnsParam(buildQuery(t, 0, "warm.example.", true)))); resp.StatusCode != 200 {
			t.Fatalf("warm-up request: status %d", resp.StatusCode)
		}
		r.nextQuery()
		dohClients = append(dohClients, c)
		doqClients = append(doqClients, dialDoQ(t, doqAddr, m, clientAllowed))
	}
	admitted := 0
	for i, c := range dohClients {
		for j := range perClient {
			query := buildQuery(t, 0, fmt.Sprintf("held%d-%d.example.", i, j), true)
			req := c.get(dnsParam(query))
			held.Add(1)
			go func() {
				defer held.Done()
				resp, err := c.http.Do(req)
				if err != nil {
					failures <- "DoH: " + err.Error()
					return
				}
				defer resp.Body.Close()
				if _, err := io.ReadAll(resp.Body); err != nil || resp.StatusCode != http.StatusOK {
					failures <- fmt.Sprintf("DoH held query %d-%d: status %d, err %v, want 200", i, j, resp.StatusCode, err)
				}
			}()
			r.nextQuery()
			admitted++
		}
	}
	for i, c := range doqClients {
		for j := range perClient {
			if admitted == maxMuxInflight/2 {
				break
			}
			query := doqQuery(t, fmt.Sprintf("held%d-%d.example.", i, j))
			s := c.stream()
			sendDoQ(t, s, query)
			held.Add(1)
			go func() {
				defer held.Done()
				if data, err := readDoQ(t, s); !errors.Is(err, io.EOF) || len(data) < 2 {
					failures <- fmt.Sprintf("DoQ held query %d-%d: err %v, data %x, want the echo", i, j, err, data)
				}
			}()
			r.nextQuery()
			admitted++
		}
	}
	if admitted != maxMuxInflight/2 {
		t.Fatalf("%d queries admitted before the check, want %d", admitted, maxMuxInflight/2)
	}

	over := dohClients[0]
	resp, _ := over.do(over.get(dnsParam(buildQuery(t, 0, "over.example.", true))))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("DoH query over the address's share: status %d, Retry-After %q, want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	servfailFor(t, doqClients[0].query(doqQuery(t, "over.example.")))
	r.requireNoOtherQuery()

	otherDoH := newDoHClient(t, dohAddr, m, dohOptions{h2: true, source: otherClient})
	if resp, _ := otherDoH.do(otherDoH.get(dnsParam(buildQuery(t, 0, "fine.example.", true)))); resp.StatusCode != http.StatusOK {
		t.Fatalf("another address over DoH: status %d, want 200", resp.StatusCode)
	}
	if got := dialDoQ(t, doqAddr, m, otherClient).query(doqQuery(t, "fine.example.")); len(got) < 2 {
		t.Fatalf("another address over DoQ: reply %x", got)
	}

	close(release)
	held.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
}

// A query or connection that the global budget refuses must not cost its address a share: the address took one before
// the global check and gives it back when that refuses. If it did not, a flood from other addresses that fills the global
// budget would also use up the shares of everyone who asked meanwhile, for as long as the process runs.
func TestARefusalByTheGlobalBudgetDoesNotCostTheAddressItsShare(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		release := make(chan struct{})
		r.autoAnswer(func(q decidedQuery) []byte {
			if q.ip != "127.0.0.7" {
				<-release
			}
			return echoAnswer(q)
		})
		for _, source := range []string{clientAllowed, otherClient} { // two addresses fill the global budget at their share each
			c := r.udpClient(source)
			for batch := 0; batch < maxUDPInflight/2; batch += 8 {
				for i := 1; i <= 8; i++ {
					if _, err := c.Write(buildQuery(t, uint16(batch+i), "example.", true)); err != nil {
						t.Fatal(err)
					}
				}
				for range 8 {
					r.nextQuery()
				}
			}
		}
		third, refused := r.udpClient("127.0.0.7"), r.udpClient(clientRefused)
		for batch := 0; batch < 304; batch += 8 { // each one is refused by the global budget, 304 in all: more than a share
			for i := 1; i <= 8; i++ {
				if _, err := third.Write(buildQuery(t, uint16(batch+i), "example.", true)); err != nil {
					t.Fatal(err)
				}
			}
			udpJudged(t, refused) // paced: the kernel's socket buffer never drops one, so every datagram is judged before the next batch
		}
		r.requireNoOtherQuery()
		close(release)
		eventually(t, "the budget to drain", func() bool { return r.g.udpInflight.Load() == 0 })
		if _, err := third.Write(buildQuery(t, 999, "example.", true)); err != nil {
			t.Fatal(err)
		}
		if q := r.nextQuery(); q.ip != "127.0.0.7" {
			t.Fatalf("the decider saw %s, want the third address: its share leaked", q.ip)
		}
	})
	t.Run("tcp", func(t *testing.T) {
		r := newRig(t, rigConfig{acl: aclMixed})
		r.autoAnswer(echoAnswer)
		var held []net.Conn
		for _, source := range []string{clientAllowed, otherClient} {
			for range maxTCPConns / 2 {
				held = append(held, r.tcpClient(source))
			}
		}
		for range maxTCPConns / 2 * 2 { // 128 turned away by the global cap: more than a share
			requireTCPClosed(t, r.tcpClient("127.0.0.7"))
		}
		for _, c := range held {
			_ = c.Close()
		}
		eventually(t, "the connections to drain", func() bool { return r.g.tcpConns.Load() == 0 })
		again := r.tcpClient("127.0.0.7")
		tcpSend(t, again, buildQuery(t, 5, "example.", true))
		if got := tcpReply(t, again); len(got) == 0 {
			t.Fatal("the third address must be served once the budget drained: its share leaked")
		}
	})
}
