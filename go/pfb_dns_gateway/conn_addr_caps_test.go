package main

import (
	"net"
	"testing"
)

// One address cannot hold all 128 DoH or all 128 DoQ connections: it may hold half, a newcomer over its share is refused
// and every other address still connects. A DoH peer in the trusted front-end prefixes is exempt, since its connections
// carry many clients (the client is named by the PROXY header or X-Forwarded-For, and the query shares count that
// client). DoQ has no front end: its client is the QUIC peer, whose address a Retry has validated, so it has no exemption.

func dialRawFrom(t *testing.T, addr, source string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: watchdog, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// 64 of the 128 DoH connections for one address: the 65th is closed at accept, another address is served, and a closed
// connection gives its share back.
func TestOneAddressCannotHoldMoreThanItsShareOfDoHConnections(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	conns := make([]net.Conn, 0, maxDoHConns/2)
	for range maxDoHConns / 2 {
		conns = append(conns, dialRawFrom(t, addr.String(), clientAllowed))
	}
	for range 2 {
		requireTCPClosed(t, dialRawFrom(t, addr.String(), clientAllowed)) // accepted in order: once this one is shut, the first 64 hold their shares
	}
	if n := r.g.dohConns.n.Load(); n != maxDoHConns/2 {
		t.Fatalf("%d DoH connections counted, want %d: a refused one must not hold a slot", n, maxDoHConns/2)
	}
	if n := addrLimitLogs(r); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}

	other := newDoHClient(t, addr, m, dohOptions{source: otherClient})
	if resp, _ := other.do(other.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("another address got status %d while one is over its share, want 200", resp.StatusCode)
	}
	other.http.CloseIdleConnections()

	_ = conns[5].Close()
	eventually(t, "the closed connection's share to be freed", func() bool { return r.g.dohConns.n.Load() <= maxDoHConns/2-1 })
	again := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	if resp, _ := again.do(again.get(dnsParam(buildQuery(t, 0, "again.example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("an address whose connection closed got status %d, want 200: the share was not released", resp.StatusCode)
	}
	// Back at its share, exactly: a release that gave back more than the one connection closed would let it hold one over.
	requireTCPClosed(t, dialRawFrom(t, addr.String(), clientAllowed))
}

// A peer in --doh-trusted may hold more than a share: a front end's connections carry many clients. An address that
// is not in it keeps its share, so the exemption cannot be claimed by connecting.
func TestATrustedDoHPeerIsExemptFromTheConnectionShareAndAnUntrustedOneIsNot(t *testing.T) {
	r, m, addr := newDoHRig(t, clientAllowed) // 127.0.0.5 is the front end
	r.autoAnswer(echoAnswer)
	const over = maxDoHConns/2 + 6
	var front []net.Conn
	for range over {
		front = append(front, dialRawFrom(t, addr.String(), clientAllowed))
	}
	eventually(t, "every connection of the trusted peer to be counted", func() bool { return r.g.dohConns.n.Load() == over })
	if n := addrLimitLogs(r); n != 0 {
		t.Fatalf("a trusted peer was held to a share: %s", r.logs.joined())
	}
	for _, c := range front { // the global budget is 128: the untrusted address below needs room for its whole share
		_ = c.Close()
	}
	eventually(t, "the trusted peer's connections to drain", func() bool { return r.g.dohConns.n.Load() == 0 })

	for range maxDoHConns / 2 {
		dialRawFrom(t, addr.String(), otherClient) // an untrusted address up to its share
	}
	requireTCPClosed(t, dialRawFrom(t, addr.String(), otherClient))
	if n := addrLimitLogs(r); n != 1 {
		t.Fatalf("an untrusted address over its share must be refused and logged once, got %d lines: %s", n, r.logs.joined())
	}
	trusted := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	if resp, _ := trusted.do(trusted.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("the trusted peer got status %d, want 200", resp.StatusCode)
	}
}

// 64 of the 128 DoQ connections for one address: the 65th is refused before its handshake, another address connects,
// and a closed connection gives its share back.
func TestOneAddressCannotHoldMoreThanItsShareOfDoQConnections(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	conns := make([]*doqClient, 0, maxDoQConns/2)
	for range maxDoQConns / 2 {
		conns = append(conns, dialDoQ(t, addr, m, clientAllowed))
	}
	for range 2 {
		requireDoQRefusedBeforeTheHandshake(t, addr, m, clientAllowed)
	}
	if n := r.g.doqConns.n.Load(); n != maxDoQConns/2 {
		t.Fatalf("%d DoQ connections counted, want %d: a refused one must not hold a slot", n, maxDoQConns/2)
	}
	if n := addrLimitLogs(r); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}

	if got := dialDoQ(t, addr, m, otherClient).query(doqQuery(t, "other.example.")); len(got) < 2 {
		t.Fatalf("another address over DoQ: reply %x", got)
	}
	conns[3].query(doqQuery(t, "inside.example.")) // a connection inside the share is untouched

	_ = conns[7].conn.CloseWithError(0, "")
	// 64 of the address and one of the other: closing one of the 64 leaves 64
	eventually(t, "the closed connection's share to be freed", func() bool { return r.g.doqConns.n.Load() <= maxDoQConns/2 })
	if got := dialDoQ(t, addr, m, clientAllowed).query(doqQuery(t, "again.example.")); len(got) < 2 {
		t.Fatalf("an address whose connection closed got %x: the share was not released", got)
	}
	// Back at its share, exactly: a release that gave back more than the one connection closed would let it hold one over.
	requireDoQRefusedBeforeTheHandshake(t, addr, m, clientAllowed)
}

// A connection that the global budget refuses must not cost its address a share: the share is taken before the global
// check and given back when that refuses. If it were not, a third address turned away while two others fill the
// budget would find its own share gone for good.
func TestARefusalByTheGlobalConnectionBudgetDoesNotCostTheAddressItsShare(t *testing.T) {
	t.Run("doh", func(t *testing.T) {
		r, m, addr := newDoHRig(t)
		r.autoAnswer(echoAnswer)
		var held []net.Conn
		for _, source := range []string{clientAllowed, otherClient} { // two addresses fill the 128 at their share each
			for range maxDoHConns / 2 {
				held = append(held, dialRawFrom(t, addr.String(), source))
			}
		}
		for range maxDoHConns/2 + 6 { // more than a share, every one turned away by the global budget
			requireTCPClosed(t, dialRawFrom(t, addr.String(), "127.0.0.7"))
		}
		for _, c := range held {
			_ = c.Close()
		}
		eventually(t, "the connections to drain", func() bool { return r.g.dohConns.n.Load() == 0 })
		third := newDoHClient(t, addr, m, dohOptions{source: "127.0.0.7"})
		if resp, _ := third.do(third.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
			t.Fatalf("the third address got status %d once the budget drained, want 200: its share leaked", resp.StatusCode)
		}
	})
	t.Run("doq", func(t *testing.T) {
		r, m, addr := newDoQRig(t, rigConfig{})
		r.autoAnswer(echoAnswer)
		var held []*doqClient
		for _, source := range []string{clientAllowed, otherClient} {
			for range maxDoQConns / 2 {
				held = append(held, dialDoQ(t, addr, m, source))
			}
		}
		for range maxDoQConns/2 + 2 {
			requireDoQRefusedBeforeTheHandshake(t, addr, m, "127.0.0.7")
		}
		for _, c := range held {
			_ = c.conn.CloseWithError(0, "")
		}
		eventually(t, "the connections to drain", func() bool { return r.g.doqConns.n.Load() == 0 })
		if got := dialDoQ(t, addr, m, "127.0.0.7").query(doqQuery(t, "example.")); len(got) < 2 {
			t.Fatalf("the third address got %x once the budget drained: its share leaked", got)
		}
	})
}
