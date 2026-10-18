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
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/quic-go/quic-go"
)

// Tests for the S4b gate findings (issue #3513). RFC 9000 20.1 names CONNECTION_REFUSED 0x2.
const rfcQUICConnectionRefused = 0x2

// F-1: a rewrite that keeps the size is seen by Refresh even inside one clock tick, so the helper must leave the
// file's (inode, mtime, size) different every time.
func TestRewriteACLIsSeenByRefreshWhateverTheSizeAndTheClock(t *testing.T) {
	r := newRig(t, rigConfig{acl: "access-control: 127.0.0.0/8 allow\n"})
	client := netip.MustParseAddr("127.0.0.1")
	for i := range 100 {
		content, want := "access-control: 127.0.0.1/32 deny\n", ACLDrop // both strings are 34 bytes
		if i%2 == 1 {
			content, want = "access-control: 127.0.0.0/8 allow\n", ACLForward
		}
		rewriteACL(t, r, content)
		if got := r.g.acl.Lookup(client); got != want {
			t.Fatalf("rewrite %d (%q): Lookup(%s) = %v, want %v: Refresh did not see the rewrite", i, content, client, got, want)
		}
	}
}

// F-2: the client dials from source and is refused by the server's first reply: CONNECTION_REFUSED, and its
// certificate check never ran, so no handshake message got through.
func requireDoQRefusedBeforeTheHandshake(t *testing.T, addr netip.AddrPort, m tlsMaterial, source string) {
	t.Helper()
	var verified atomic.Int32
	conf := doqConfig(m)
	conf.VerifyConnection = func(tls.ConnectionState) error { verified.Add(1); return nil }
	conn, err := tryDialDoQ(t, addr, conf, source)
	var te *quic.TransportError
	if !errors.As(err, &te) || !te.Remote || te.ErrorCode != rfcQUICConnectionRefused {
		t.Fatalf("dial from %q: got connection=%v err=%v, want the server's CONNECTION_REFUSED", source, conn != nil, err)
	}
	if n := verified.Load(); n != 0 {
		t.Fatalf("dial from %q: the client verified the server certificate %d times: the handshake ran before the refusal", source, n)
	}
}

// F-2: a connection whose handshake fails frees the slot it was given before the handshake.
func TestDoQFailedHandshakesDoNotHoldSlots(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	for range 2 * maxDoQConns {
		if _, err := tryDialDoQ(t, addr, m.clientConfig("h3"), ""); err == nil {
			t.Fatal("ALPN h3 must be refused")
		}
	}
	eventually(t, "the failed handshakes to free their slots", func() bool { return r.g.doqConns.n.Load() == 0 })
	dialDoQ(t, addr, m, "").query(doqQuery(t, "after.example."))
}

// F-2: a deny rule that arrives on an open connection cancels the next stream (the early refusal only sees the
// address at connect time).
func TestDoQDenyRuleArrivingOnAnOpenConnectionCancelsItsStreams(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)
	c.query(doqQuery(t, "before.example."))
	rewriteACL(t, r, aclMixed+"access-control: "+clientAllowed+"/32 deny\n")
	s := c.stream()
	sendDoQ(t, s, doqQuery(t, "after.example."))
	requireStreamReset(t, s, rfcDoQRequestCancelled)
}

// retryCounter counts the Retry packets a client receives (RFC 9000 17.2.5: long header, fixed bit, type 3).
type retryCounter struct {
	net.PacketConn
	retries atomic.Int32
}

func (c *retryCounter) ReadFrom(p []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(p)
	if n > 0 && p[0]&0xf0 == 0xf0 {
		c.retries.Add(1)
	}
	return n, from, err
}

// F-2: a slot taken at the first Initial packet is only safe when that packet's source address is real, so every
// new client first proves its address with a Retry. Otherwise 128 spoofed Initials would hold the cap.
func TestDoQNewClientsProveTheirAddressWithARetryBeforeTheyHoldASlot(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true") // the counting wrapper is not a *net.UDPConn
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	pc := &retryCounter{PacketConn: udp}
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), doqConfig(m), &quic.Config{})
	if err != nil {
		t.Fatalf("DoQ connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test over") })
	(&doqClient{t: t, conn: conn}).query(doqQuery(t, "retry.example."))
	if n := pc.retries.Load(); n < 1 { // a large ClientHello spans two Initial datagrams, each answered by a Retry
		t.Fatalf("the client received %d Retry packets, want at least 1: the server skipped address validation", n)
	}
}

// F-3: DoH trust follows the TCP peer's address, not the listener's. With only 127.0.0.9/32 trusted on a listener
// at 127.0.0.1, 127.0.0.9's PROXYv2 source and X-Forwarded-For are believed and 127.0.0.2's, on the same listener,
// are not.
func TestDoHTrustIsThePeerAddressNotTheListenerAddress(t *testing.T) {
	const frontEnd, stranger = "127.0.0.9", "127.0.0.2"
	r := newRig(t, rigConfig{acl: "access-control: 127.0.0.0/8 allow\n"}) // aclMixed would refuse 127.0.0.9 itself
	m := newTLSMaterial(t)
	addr := r.serveDoH(m, frontEnd+"/32")
	r.autoAnswer(echoAnswer)
	query := buildQuery(t, 0, "example.", true)
	asked := func(what string, c *dohClient, headers ...string) string {
		t.Helper()
		resp, err := c.http.Do(c.get(dnsParam(query), headers...))
		if err != nil {
			t.Fatalf("%s: the request failed: %v", what, err)
		}
		_ = resp.Body.Close()
		return r.nextQuery().ip
	}
	trustedProxy := newDoHClient(t, addr, m, dohOptions{source: frontEnd, prefix: pp2TCP("192.0.2.7:51000", "192.0.2.1:443")})
	if got := asked("trusted peer with a PROXYv2 header", trustedProxy); got != "192.0.2.7" {
		t.Fatalf("trusted peer %s with a PROXYv2 header: client %s, want its source 192.0.2.7", frontEnd, got)
	}
	trusted := newDoHClient(t, addr, m, dohOptions{source: frontEnd})
	if got := asked("trusted peer with X-Forwarded-For", trusted, "X-Forwarded-For", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("trusted peer %s with X-Forwarded-For: client %s, want 203.0.113.9", frontEnd, got)
	}
	untrusted := newDoHClient(t, addr, m, dohOptions{source: stranger})
	if got := asked("untrusted peer with X-Forwarded-For", untrusted, "X-Forwarded-For", "203.0.113.9"); got != stranger {
		t.Fatalf("untrusted peer %s with X-Forwarded-For: client %s, want the peer itself", stranger, got)
	}
	raw, err := (&net.Dialer{Timeout: watchdog, LocalAddr: &net.TCPAddr{IP: net.ParseIP(stranger)}}).Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Write(pp2TCP("192.0.2.7:51000", "192.0.2.1:443")); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(watchdog))
	if err := tlsClientHandshake(raw, m); err == nil {
		t.Fatalf("untrusted peer %s: PROXY bytes were parsed, the TLS handshake after them must fail", stranger)
	}
	r.requireNoOtherQuery()
}

// F-4: a stream of N bytes announced and N+1 sent is rejected also when the FIN arrives together with the extra byte
// (the read then returns n=1 and io.EOF at once, which a check that looks at the error alone would accept).
func TestReadDoQQueryRejectsOneExtraByteThatArrivesWithTheFIN(t *testing.T) {
	good := doqQuery(t, "example.")
	if wire, ok := readDoQQuery(iotest.DataErrReader(bytes.NewReader(framed(good)))); !ok || !bytes.Equal(wire, good) {
		t.Fatalf("control: the exact stream gave ok=%v wire=%x, want ok and %x", ok, wire, good)
	}
	extra := append(framed(good), 'x')
	if wire, ok := readDoQQuery(iotest.DataErrReader(bytes.NewReader(extra))); ok {
		t.Fatalf("a %d-byte message with one more byte and the FIN was accepted: %x", len(good), wire)
	}
}

// F-5: DoH and DoQ queries in flight share one cap of 512, apart from UDP's. Over it a DoH request gets 503 with
// Retry-After and a DoQ stream gets SERVFAIL; neither reaches the decider, the log says so once per flood, and the
// slots come back when the held queries are answered.
func TestDoHAndDoQQueriesOverTheSharedInflightCapAreAnsweredWithAnError(t *testing.T) {
	const wantCap, clients, perClient = 512, 4, 64 // 4 DoH + 4 DoQ clients x 64 queries = 512
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
	var dohClients []*dohClient
	var doqClients []*doqClient
	for range clients {
		c := newDoHClient(t, dohAddr, m, dohOptions{h2: true})
		if resp, _ := c.do(c.get(dnsParam(buildQuery(t, 0, "warm.example.", true)))); resp.StatusCode != 200 { // one HTTP/2 connection per client
			t.Fatalf("warm-up request: status %d", resp.StatusCode)
		}
		r.nextQuery()
		dohClients = append(dohClients, c)
		doqClients = append(doqClients, dialDoQ(t, doqAddr, m, ""))
	}

	var held sync.WaitGroup
	failures := make(chan string, 2*clients*perClient)
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
				body, _ := io.ReadAll(resp.Body)
				if want := echoWithQR(seenQuery{wire: query})[0]; resp.StatusCode != 200 || !bytes.Equal(body, want) {
					failures <- fmt.Sprintf("DoH held query %d-%d: status %d, body %x, want 200 and %x", i, j, resp.StatusCode, body, want)
				}
			}()
		}
	}
	for i, c := range doqClients {
		for j := range perClient {
			query := doqQuery(t, fmt.Sprintf("held%d-%d.example.", i, j))
			s := c.stream()
			sendDoQ(t, s, query)
			held.Add(1)
			go func() {
				defer held.Done()
				data, err := readDoQ(t, s)
				if want := withID0(echoWithQR(seenQuery{wire: query})[0]); !errors.Is(err, io.EOF) || len(data) < 2 || !bytes.Equal(data[2:], want) {
					failures <- fmt.Sprintf("DoQ held query %d-%d: err %v, data %x, want the echo %x", i, j, err, data, want)
				}
			}()
		}
	}
	for range wantCap {
		r.nextQuery() // every held query has reached the decider: all 512 slots are taken
	}
	if n := r.g.udpInflight.Load(); n != 0 {
		t.Fatalf("%d UDP queries in flight: DoH and DoQ must count against a cap of their own", n)
	}

	over := dohClients[0]
	resp, _ := over.do(over.get(dnsParam(buildQuery(t, 0, "over.example.", true))))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("DoH query over the cap: status %d, Retry-After %q, want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	reply := doqClients[0].query(doqQuery(t, "over.example."))
	servfailFor(t, reply)
	if id := binary.BigEndian.Uint16(reply); id != 0 {
		t.Fatalf("DoQ SERVFAIL has Message ID %d, want 0", id)
	}
	r.requireNoOtherQuery()
	if n := strings.Count(r.logs.joined(), "DoH and DoQ queries in flight"); n != 1 {
		t.Fatalf("a flood must log once, got %d lines: %s", n, r.logs.joined())
	}

	close(release)
	held.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
	if n := r.g.muxInflight.Load(); n != 0 { // each decrement runs before its reply is written, so this is exact
		t.Fatalf("%d DoH and DoQ queries still counted in flight after every one was answered or refused, want 0: a slot leaked", n)
	}
	again := buildQuery(t, 0, "again.example.", true)
	if resp, body := over.do(over.get(dnsParam(again))); resp.StatusCode != 200 || !bytes.Equal(body, echoWithQR(seenQuery{wire: again})[0]) {
		t.Fatalf("DoH query after the held ones were answered: status %d, body %x, want 200 and the echo", resp.StatusCode, body)
	}
	if got, want := doqClients[0].query(doqQuery(t, "again.example.")), withID0(echoWithQR(seenQuery{wire: again})[0]); !bytes.Equal(got[2:], want[2:]) {
		t.Fatalf("DoQ query after the held ones were answered: %x, want the echo %x", got, want)
	}
}

// F-5: a query the decider drops frees its shared slot too; if it did not, 512 drops would end DoH and DoQ until a
// restart. The abort or reset the client sees comes after the slot is released, so the count is exact.
func TestDoHAndDoQDroppedQueriesFreeTheirSharedSlot(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	m := newTLSMaterial(t)
	dohAddr, doqAddr := r.serveDoH(m), r.serveDoQ(m)
	r.autoAnswer(func(decidedQuery) []byte { return nil }) // DROP
	c := newDoHClient(t, dohAddr, m, dohOptions{h2: true})
	if resp, err := c.http.Do(c.get(dnsParam(buildQuery(t, 0, "drop.example.", true)))); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a DoH query the decider dropped got status %d, want the request aborted", resp.StatusCode)
	}
	r.nextQuery() // the decider saw it: the abort was its DROP, not a refusal
	if n := r.g.muxInflight.Load(); n != 0 {
		t.Fatalf("%d queries counted in flight after a dropped DoH query, want 0", n)
	}
	s := dialDoQ(t, doqAddr, m, "").stream()
	sendDoQ(t, s, doqQuery(t, "drop.example."))
	requireStreamReset(t, s, rfcDoQRequestCancelled)
	r.nextQuery()
	if n := r.g.muxInflight.Load(); n != 0 {
		t.Fatalf("%d queries counted in flight after a dropped DoQ query, want 0", n)
	}
}

// F-5: the overload latch re-arms once the shared counter drains, so each flood is logged once and a later flood is
// logged again. The queries go straight to resolveShared: no transport is needed to fill the cap.
func TestSharedInflightCapLogsEachFloodOnce(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	gates := map[byte]chan struct{}{'a': make(chan struct{}), 'b': make(chan struct{})} // first letter of a flood's names
	r.autoAnswer(func(q decidedQuery) []byte {
		if gate, ok := gates[q.wire[13]]; ok { // wire[12] is the first label's length
			<-gate
		}
		return echoAnswer(q)
	})
	client := netip.MustParseAddr(clientAllowed)
	noForward := func(context.Context, []byte) []byte {
		t.Error("the decider answered without a FORWARD, so nothing may be forwarded")
		return nil
	}
	logged := func() int { return strings.Count(r.logs.joined(), "DoH and DoQ queries in flight") }
	flood := func(tag string, wantLogged int) {
		t.Helper()
		var wg sync.WaitGroup
		for i := range maxMuxInflight {
			wire := buildQuery(t, uint16(i+1), fmt.Sprintf("%s%d.example.", tag, i), true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if reply, ok := r.g.resolveShared(r.g.ctx, client, wire, noForward); !ok || !bytes.Equal(reply, echoAnswer(decidedQuery{wire: wire})) {
					t.Errorf("flood %s, query %d: ok=%v reply=%x, want it admitted and echoed", tag, i, ok, reply)
				}
			}()
		}
		for range maxMuxInflight {
			r.nextQuery() // every query has reached the decider: the cap is full
		}
		for range 2 {
			over := buildQuery(t, 1, "over.example.", true)
			if reply, ok := r.g.resolveShared(r.g.ctx, client, over, noForward); ok || reply != nil {
				t.Fatalf("flood %s: a query over the cap got ok=%v reply=%x, want it refused", tag, ok, reply)
			}
		}
		if n := logged(); n != wantLogged {
			t.Fatalf("flood %s: %d log lines in all, want %d (one per flood): %s", tag, n, wantLogged, r.logs.joined())
		}
		close(gates[tag[0]])
		wg.Wait()
		if n := r.g.muxInflight.Load(); n != 0 || r.g.muxOverload.Load() {
			t.Fatalf("flood %s drained: inflight=%d overload latch=%v, want 0 and re-armed", tag, n, r.g.muxOverload.Load())
		}
	}
	flood("a", 1)
	flood("b", 2)
	r.requireNoOtherQuery()
}
