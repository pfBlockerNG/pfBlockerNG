package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func newDoQRig(t *testing.T, cfg rigConfig) (*rig, tlsMaterial, netip.AddrPort) {
	t.Helper()
	cfg.acl = aclMixed
	r := newRig(t, cfg)
	m := newTLSMaterial(t)
	return r, m, r.serveDoQ(m)
}

// zeroID is the query as RFC 9250 4.2.1 has it on the wire: Message ID 0.
func doqQuery(t *testing.T, name string) []byte { return buildQuery(t, 0, name, true) }

// withID0 is a reply with its Message ID set to 0, the form a DoQ client gets.
func withID0(reply []byte) []byte {
	out := bytes.Clone(reply)
	out[0], out[1] = 0, 0
	return out
}

// T14: blocked name over DoQ: the decider's answer, Message ID 0, a FIN after it. The decider is asked with a
// Message ID it chose (RFC 9250 4.2.1: "When forwarding a DNS message from DoQ over another transport, a DNS
// Message ID MUST be generated according to the rules of the protocol that is in use").
func TestDoQBlockedNameGetsTheDecidersAnswerWithMessageIDZero(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(func(q decidedQuery) []byte { return append(echoAnswer(q), "block"...) })
	c := dialDoQ(t, addr, m, clientAllowed)
	query := doqQuery(t, "blocked.example.")
	got := c.query(query)
	q := r.nextQuery()
	if q.ip != clientAllowed || !bytes.Equal(q.wire[2:], query[2:]) || q.wire[0] == 0 && q.wire[1] == 0 {
		t.Fatalf("the decider got client=%s wire=%x; want client %s, the client's query with a non-zero Message ID of the gateway's choosing", q.ip, q.wire, clientAllowed)
	}
	if want := withID0(append(echoAnswer(q), "block"...)); !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want the decider's answer with Message ID 0: %x", got, want)
	}
}

// T14: allowed name over DoQ: Unbound is asked over UDP behind a PROXYv2 header naming the client; the client gets
// Unbound's reply with Message ID 0.
func TestDoQAllowedNameReachesUnboundAsTheClient(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoForward()
	c := dialDoQ(t, addr, m, clientAllowed)
	query := doqQuery(t, "allowed.example.")
	got := c.query(query)
	seen := r.up.next()
	src, dst, tcp := parsePP2(t, seen.header)
	if tcp || src.Addr() != netip.MustParseAddr(clientAllowed) || dst != addr || !bytes.Equal(seen.wire[2:], query[2:]) {
		t.Fatalf("Unbound saw tcp=%v src=%s dst=%s wire=%x; want UDP, client %s -> %s, the query", tcp, src, dst, seen.wire, clientAllowed, addr)
	}
	if want := withID0(echoWithQR(seen)[0]); !bytes.Equal(got, want) {
		t.Fatalf("reply: got %x, want Unbound's reply with Message ID 0: %x", got, want)
	}
}

// RFC 9250 4.3.3 lists "a client or server receives a message with a non-zero Message ID" as a protocol error:
// "It SHOULD forcibly abort the connection using QUIC's CONNECTION_CLOSE mechanism and SHOULD use the DoQ error
// code DOQ_PROTOCOL_ERROR." T15.
func TestDoQNonZeroMessageIDClosesTheConnectionWithProtocolError(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)
	sendDoQ(t, c.stream(), buildQuery(t, 0x1234, "example.", true))
	requireConnClosed(t, c.conn, rfcDoQProtocolError)

	fresh := dialDoQ(t, addr, m, clientAllowed) // the server is fine: only that connection was condemned
	fresh.query(doqQuery(t, "barrier.example."))
	barrier := doqQuery(t, "barrier.example.")
	if q := r.nextQuery(); !bytes.Equal(q.wire[2:], barrier[2:]) {
		t.Fatalf("the decider's first query is %x: the non-zero-ID query reached it", q.wire)
	}
	r.requireNoOtherQuery()
}

// T16: ACL refuse answers REFUSED; ACL deny refuses the connection before its handshake; neither asks the decider.
func TestDoQACLRefuseAnswersRefusedAndDenyRefusesTheConnection(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	query := doqQuery(t, "blocked.example.")

	refused := dialDoQ(t, addr, m, clientRefused)
	requireRefused(t, query, refused.query(query))

	requireDoQRefusedBeforeTheHandshake(t, addr, m, clientDenied)

	allowed := dialDoQ(t, addr, m, clientAllowed)
	allowed.query(doqQuery(t, "allowed.example."))
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
	}
	r.requireNoOtherQuery()
}

// T17 + hostile rows: a malformed query stream is reset with DOQ_PROTOCOL_ERROR and the connection carries on:
// the next stream is answered. (RFC 9250 4.3.3 names these as protocol errors that SHOULD abort the connection;
// the gateway resets the stream only, so one bad stream cannot cancel the other queries on the connection.)
func TestDoQMalformedStreamIsResetAndTheConnectionSurvives(t *testing.T) {
	good := doqQuery(t, "example.")
	response := bytes.Clone(good)
	response[2] |= 0x80
	cases := []struct {
		name string
		send func(t *testing.T, s *quic.Stream)
	}{
		{"more bytes than the length says", func(t *testing.T, s *quic.Stream) {
			put(t, s, binary.BigEndian.AppendUint16(nil, 20))
			put(t, s, make([]byte, 40))
			_ = s.Close()
		}},
		{"a query followed by a second query", func(t *testing.T, s *quic.Stream) {
			put(t, s, append(framed(good), framed(good)...))
			_ = s.Close()
		}},
		{"length 65535 with 10 bytes then FIN", func(t *testing.T, s *quic.Stream) {
			put(t, s, append(binary.BigEndian.AppendUint16(nil, 65535), make([]byte, 10)...))
			_ = s.Close()
		}},
		{"FIN before the length is complete", func(t *testing.T, s *quic.Stream) {
			put(t, s, []byte{0})
			_ = s.Close()
		}},
		{"a 0-length message", func(t *testing.T, s *quic.Stream) {
			put(t, s, framed(nil))
			_ = s.Close()
		}},
		{"fewer bytes than a DNS header", func(t *testing.T, s *quic.Stream) {
			put(t, s, framed(good[:11]))
			_ = s.Close()
		}},
		{"a response instead of a query", func(t *testing.T, s *quic.Stream) {
			put(t, s, framed(response))
			_ = s.Close()
		}},
		{"one byte more than the length says, then FIN", func(t *testing.T, s *quic.Stream) {
			put(t, s, append(framed(good), 'x'))
			_ = s.Close()
		}},
		{"an empty stream", func(t *testing.T, s *quic.Stream) { _ = s.Close() }},
		{"a complete query that never gets its FIN", func(t *testing.T, s *quic.Stream) {
			put(t, s, framed(good))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{timeout: 300 * time.Millisecond}) // a stalled stream is cut at the query timeout
			r.autoAnswer(echoAnswer)
			c := dialDoQ(t, addr, m, clientAllowed)
			bad := c.stream()
			tc.send(t, bad)
			requireStreamReset(t, bad, rfcDoQProtocolError)

			barrier := doqQuery(t, "barrier.example.")
			if got := c.query(barrier); !bytes.Equal(got[2:], echoWithQR(seenQuery{wire: barrier})[0][2:]) {
				t.Fatalf("the next stream on the same connection was not answered correctly: %x", got)
			}
			if q := r.nextQuery(); !bytes.Equal(q.wire[2:], barrier[2:]) {
				t.Fatalf("the decider's first query is %x: the malformed stream reached it", q.wire)
			}
			r.requireNoOtherQuery()
		})
	}
}

func put(t *testing.T, s *quic.Stream, b []byte) {
	t.Helper()
	if _, err := s.Write(b); err != nil {
		t.Fatal(err)
	}
}

// T18: Unbound's reply to the UDP query has TC set: asked again over TCP, the full answer comes back.
func TestDoQTruncatedUDPReplyIsRetriedOverTCP(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{upstream: []upstreamOption{truncatedOverUDP()}})
	r.autoForward()
	c := dialDoQ(t, addr, m, clientAllowed)
	got := c.query(doqQuery(t, "big.example."))
	if !bytes.HasSuffix(got, []byte("full-answer")) {
		t.Fatalf("reply %x: want the full answer from the TCP retry", got)
	}
	first, second := r.up.next(), r.up.next()
	if first.tcp || !second.tcp || !bytes.Equal(first.wire, second.wire) {
		t.Fatalf("Unbound saw tcp=%v then tcp=%v, want UDP then TCP with the same query", first.tcp, second.tcp)
	}
}

// Queries on one connection run at once and each gets its own answer.
func TestDoQConcurrentStreamsEachGetTheirOwnAnswer(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := c.stream()
			query := doqQuery(t, strings.Repeat("a", i%50+1)+".example.")
			sendDoQ(t, s, query)
			data, err := readDoQ(t, s)
			if !errors.Is(err, io.EOF) || !bytes.Equal(data[2:], withID0(echoWithQR(seenQuery{wire: query})[0])) {
				errs <- "a stream got another query's answer or ended badly"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// Hostile: 100 streams in flight are served; the 101st is refused by the stream limit the server advertises.
func TestDoQStreamLimitIsHonoured(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)
	for range rfcMaxIncomingDoQStream {
		s, err := c.conn.OpenStream()
		if err != nil {
			t.Fatalf("stream within the limit: %v", err)
		}
		put(t, s, []byte{0, 32}) // the server now holds a stream waiting for 32 more bytes
	}
	_, err := c.conn.OpenStream()
	var limit *quic.StreamLimitReachedError
	if !errors.As(err, &limit) {
		t.Fatalf("the %dst stream: got %v, want the stream limit error", rfcMaxIncomingDoQStream+1, err)
	}
}

// RFC 9250 4.3.3: "a client or a server attempts to open a unidirectional QUIC stream" is a protocol error; the
// server grants none.
func TestDoQUnidirectionalStreamsAreNotAllowed(t *testing.T) {
	_, m, addr := newDoQRig(t, rigConfig{})
	c := dialDoQ(t, addr, m, clientAllowed)
	_, err := c.conn.OpenUniStream()
	var limit *quic.StreamLimitReachedError
	if !errors.As(err, &limit) {
		t.Fatalf("OpenUniStream: got %v, want the stream limit error (the server grants no unidirectional streams)", err)
	}
}

// Hostile: ALPN other than doq is refused in the handshake.
func TestDoQRefusesAnotherALPN(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	for _, protos := range [][]string{{"h3"}, {"dot"}} {
		_, err := tryDialDoQ(t, addr, m.clientConfig(protos...), "")
		if err == nil || !strings.Contains(err.Error(), "no application protocol") {
			t.Fatalf("ALPN %v: got %v, want the handshake refused with no application protocol", protos, err)
		}
	}
	r.requireNoOtherQuery()
}

// The 129th connection is refused before its handshake; the log says so once per burst; a slot freed is reusable.
func TestDoQConnectionsOverTheCapAreRefusedBeforeTheHandshake(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{perAddr: noAddrCap})
	r.autoAnswer(echoAnswer)
	conns := make([]*doqClient, 0, maxDoQConns)
	for range maxDoQConns {
		conns = append(conns, dialDoQ(t, addr, m, ""))
	}
	for range 2 {
		requireDoQRefusedBeforeTheHandshake(t, addr, m, "")
	}
	if n := strings.Count(r.logs.joined(), "DoQ client limit"); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}
	conns[3].query(doqQuery(t, "inside.example.")) // a connection inside the cap is untouched

	_ = conns[7].conn.CloseWithError(0, "")
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.doqConns.n.Load() == maxDoQConns-1 })
	dialDoQ(t, addr, m, "").query(doqQuery(t, "after.example."))
	for _, c := range conns {
		_ = c.conn.CloseWithError(0, "")
	}
	eventually(t, "every connection to drain", func() bool { return r.g.doqConns.n.Load() <= 1 })
}

// Stopping the gateway closes the DoQ connections.
func TestStopClosesDoQConnections(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	c := dialDoQ(t, addr, m, clientAllowed)
	r.g.stop()
	select {
	case <-c.conn.Context().Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK: the DoQ connection is still open after stop()")
	}
}
