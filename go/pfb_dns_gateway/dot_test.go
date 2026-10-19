package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// T1 (live): a DoT client is shown the chain exactly as the file holds it, leaf first.
func TestDoTServesTheConfiguredChainLeafFirst(t *testing.T) {
	store, leaf, mid, root := chainStore(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	m := tlsMaterial{certs: store, pool: root.pool()}
	addr := r.serveDoT(m)
	c := dialDoT(t, addr, m, "")
	peers := c.ConnectionState().PeerCertificates
	if len(peers) != 3 || !bytes.Equal(peers[0].Raw, leaf.der) || !bytes.Equal(peers[1].Raw, mid.der) || !bytes.Equal(peers[2].Raw, root.der) {
		t.Fatalf("the server presented %d certificates; want leaf, intermediate, root in that order", len(peers))
	}
}

// T4: a blocked name is answered by the decider over DoT.
func TestDoTQueryGetsTheDecidersAnswer(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(func(q decidedQuery) []byte { return append(echoAnswer(q), "block"...) })
	addr := r.serveDoT(m)
	c := dialDoT(t, addr, m, clientAllowed)
	query := buildQuery(t, 0x1111, "blocked.example.", true)
	tcpSend(t, c, query)
	got := tcpReply(t, c)
	q := r.nextQuery()
	if q.ip != clientAllowed || !bytes.Equal(q.wire, query) {
		t.Fatalf("QUERY: got client=%s wire=%x, want client=%s wire=%x", q.ip, q.wire, clientAllowed, query)
	}
	if want := append(echoAnswer(q), "block"...); !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want the decider's answer %x", got, want)
	}
}

// T4: an allowed name goes to Unbound over UDP (a stream client reaches Unbound as DoH and DoQ clients do) behind a
// PROXYv2 header naming the DoT client, and no upstream TCP connection is opened for it.
func TestDoTAllowedNameReachesUnboundAsTheClient(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoForward()
	addr := r.serveDoT(m)
	c := dialDoT(t, addr, m, "")
	for i, name := range []string{"allowed.example.", "second.example."} {
		query := buildQuery(t, uint16(i+1), name, true)
		tcpSend(t, c, query)
		got := tcpReply(t, c)
		seen := r.up.next()
		if seen.tcp || !bytes.Equal(seen.wire, query) {
			t.Fatalf("Unbound saw tcp=%v wire=%x, want UDP and %x", seen.tcp, seen.wire, query)
		}
		if want := wantHeader(t, transport{"udp", false}, c.LocalAddr(), addr); !bytes.Equal(seen.header, want) {
			t.Fatalf("PROXYv2 header:\n got  %x\n want %x", seen.header, want)
		}
		if want := echoWithQR(seen)[0]; !bytes.Equal(got, want) {
			t.Fatalf("reply: got %x, want Unbound's reply %x", got, want)
		}
	}
	if conns, _ := r.up.counts(); conns != 0 {
		t.Fatalf("an untruncated answer needs no upstream TCP connection, Unbound accepted %d", conns)
	}
}

// T4: TLS 1.1 is refused.
func TestDoTRefusesTLS11(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)
	conf := m.clientConfig()
	conf.MinVersion, conf.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	_, err := tls.Dial("tcp4", addr.String(), conf)
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("a TLS 1.1 client must be refused with a protocol version alert, got %v", err)
	}
	r.requireNoOtherQuery()

	conf.MinVersion, conf.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	c, err := tls.Dial("tcp4", addr.String(), conf)
	if err != nil {
		t.Fatalf("TLS 1.2 must be accepted: %v", err)
	}
	_ = c.Close()
}

// T5: the shared 128-connection cap is checked at accept, before any handshake byte; DoT and plain TCP count together.
func TestDoTConnectionsOverTheCapAreClosedBeforeTheHandshake(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)
	conns := make([]net.Conn, 0, maxTCPConns)
	for range maxTCPConns - 1 {
		c, err := net.DialTimeout("tcp4", addr.String(), watchdog)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns = append(conns, c)
	}
	plain := r.tcpClient("") // the 128th slot belongs to a plain TCP client: the cap is shared
	tcpSend(t, plain, buildQuery(t, 1, "example.", true))
	if got := tcpReply(t, plain); len(got) == 0 { // answered, so accepted: the two accept loops cannot race for the last slot
		t.Fatal("the plain TCP client inside the cap got an empty reply")
	}
	eventually(t, "all 128 slots to be taken", func() bool { return r.g.tcpConns.Load() == maxTCPConns })
	over, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = over.Close() })
	requireTCPClosed(t, over) // closed without a ClientHello from us: no handshake was waited for
	_ = conns[0].Close()
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == maxTCPConns-1 })
	c := dialDoT(t, addr, m, "")
	tcpSend(t, c, buildQuery(t, 2, "example.", true))
	if got := tcpReply(t, c); len(got) == 0 {
		t.Fatal("a DoT connection that arrives after a slot was freed must be served")
	}
}

// A connection that never starts a handshake is dropped after the handshake timeout and frees its slot.
func TestDoTClientThatNeverHandshakesIsDropped(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.handshake = 150 * time.Millisecond
	addr := r.serveDoT(m)
	c, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	requireTCPClosed(t, c)
	eventually(t, "the slot to be freed", func() bool { return r.g.tcpConns.Load() == 0 })
}

// A client that sends garbage instead of a ClientHello is dropped without reaching the decider.
func TestDoTClientThatSendsGarbageIsDropped(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)
	c, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write(bytes.Repeat([]byte("GET / HTTP/1.1\r\n"), 4)); err != nil {
		t.Fatal(err)
	}
	// the server may answer a TLS alert before it hangs up
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			if !isClosed(err) {
				t.Fatalf("want the connection closed, got %v", err)
			}
			break
		}
	}
	r.requireNoOtherQuery()
}

// ACL deny closes at accept (before the handshake), refuse answers over TLS, as for plain TCP.
func TestDoTACLDenyClosesAtAcceptAndRefuseAnswersRefused(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)

	denied, err := (&net.Dialer{Timeout: watchdog, LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientDenied)}}).Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = denied.Close() })
	requireTCPClosed(t, denied)

	refused := dialDoT(t, addr, m, clientRefused)
	query := buildQuery(t, 0x6666, "blocked.example.", true)
	tcpSend(t, refused, query)
	requireRefused(t, query, tcpReply(t, refused))

	allowed := dialDoT(t, addr, m, clientAllowed)
	tcpSend(t, allowed, buildQuery(t, 2, "allowed.example.", true))
	tcpReply(t, allowed)
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
	}
	r.requireNoOtherQuery()
}

// A deny that arrives while the TLS connection is open closes it, as for plain TCP.
func TestDoTDenyRuleArrivingOnAnOpenConnectionClosesIt(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: "access-control: 127.0.0.0/8 allow\n"})
	r.autoAnswer(echoAnswer)
	addr := r.serveDoT(m)
	c := dialDoT(t, addr, m, "")
	query := buildQuery(t, 1, "example.", true)
	tcpSend(t, c, query)
	tcpReply(t, c)
	rewriteACL(t, r, "access-control: 127.0.0.1/32 deny\n")
	tcpSend(t, c, query)
	requireTCPClosed(t, c)
}

// rewriteACL rewrites the ACL file in place and reloads it. Refresh keys on (inode, mtime, size) and an in-place
// rewrite of the same size can land in the same clock tick, so the new mtime is the old one plus a second.
func rewriteACL(t *testing.T, r *rig, content string) {
	t.Helper()
	fi, err := os.Stat(r.aclPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.aclPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(r.aclPath, time.Time{}, fi.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	r.g.acl.Refresh()
}
