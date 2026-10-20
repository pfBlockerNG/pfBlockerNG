package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func newDoHRig(t *testing.T, trusted ...string) (*rig, tlsMaterial, netip.AddrPort) {
	t.Helper()
	r := newRig(t, rigConfig{acl: aclMixed})
	m := newTLSMaterial(t)
	return r, m, r.serveDoH(m, trusted...)
}

func protoName(h2 bool) string {
	if h2 {
		return "h2"
	}
	return "http1"
}

func dnsParam(wire []byte) string {
	return "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(wire)
}

// parsePP2 reads the addresses of a PROXYv2 header the gateway sent to Unbound.
func parsePP2(t *testing.T, h []byte) (src, dst netip.AddrPort, tcp bool) {
	t.Helper()
	if len(h) < 16 || string(h[:12]) != pp2Signature {
		t.Fatalf("not a PROXYv2 header: %x", h)
	}
	tcp = h[13]&0x0f == 1
	switch h[13] >> 4 {
	case 1:
		a, b := netip.AddrFrom4([4]byte(h[16:20])), netip.AddrFrom4([4]byte(h[20:24]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(h[24:26])), netip.AddrPortFrom(b, binary.BigEndian.Uint16(h[26:28])), tcp
	case 2:
		a, b := netip.AddrFrom16([16]byte(h[16:32])), netip.AddrFrom16([16]byte(h[32:48]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(h[48:50])), netip.AddrPortFrom(b, binary.BigEndian.Uint16(h[50:52])), tcp
	}
	t.Fatalf("PROXYv2 header with address family %#x: %x", h[13]>>4, h)
	return
}

// T6: GET (no padding, with padding) and POST all get 200 application/dns-message with the decider's answer, over
// HTTP/1.1 and HTTP/2.
func TestDoHAnswersGETAndPOSTWithTheDecidersAnswer(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(protoName(h2), func(t *testing.T) {
			r, m, addr := newDoHRig(t)
			r.autoAnswer(func(q decidedQuery) []byte { return append(echoAnswer(q), "block"...) })
			c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, h2: h2})
			query := buildQuery(t, 0, "ab.example.", true) // 28 bytes: base64 needs padding
			padded := base64.URLEncoding.EncodeToString(query)
			if !strings.HasSuffix(padded, "=") {
				t.Fatalf("the test query must need base64 padding, got %q", padded)
			}
			forms := map[string]*http.Request{
				"GET without padding": c.get(dnsParam(query)),
				"GET with padding":    c.get("/dns-query?dns=" + padded),
				"POST":                c.post("/dns-query", "application/dns-message", query),
			}
			for name, req := range forms {
				resp, body := c.do(req)
				wantProto := 1
				if h2 {
					wantProto = 2
				}
				if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" || resp.ProtoMajor != wantProto {
					t.Fatalf("%s: got status %d, Content-Type %q, HTTP/%d; want 200, application/dns-message, HTTP/%d", name, resp.StatusCode, resp.Header.Get("Content-Type"), resp.ProtoMajor, wantProto)
				}
				q := r.nextQuery()
				if q.ip != clientAllowed || !bytes.Equal(q.wire, query) {
					t.Fatalf("%s: the decider got client=%s wire=%x, want client=%s wire=%x", name, q.ip, q.wire, clientAllowed, query)
				}
				if want := append(echoAnswer(q), "block"...); !bytes.Equal(body, want) {
					t.Fatalf("%s: body %x, want the decider's answer %x", name, body, want)
				}
				if got := resp.Header.Get("Cache-Control"); got != "max-age=0" { // RFC 8484 5.1: answers depend on the client's identity
					t.Fatalf("%s: Cache-Control %q, want max-age=0: the answer depends on who asks", name, got)
				}
			}
		})
	}
}

// An allowed name: Unbound is asked over UDP behind a PROXYv2 header naming the client; its reply is the answer.
func TestDoHAllowedNameReachesUnboundAsTheClient(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoForward()
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	query := buildQuery(t, 0, "allowed.example.", true)
	resp, body := c.do(c.get(dnsParam(query)))
	seen := r.up.next()
	src, dst, tcp := parsePP2(t, seen.header)
	if resp.StatusCode != 200 || tcp || !bytes.Equal(seen.wire, query) ||
		src.Addr() != netip.MustParseAddr(clientAllowed) || dst != addr {
		t.Fatalf("status=%d tcp=%v src=%s dst=%s wire=%x; want 200, UDP, client %s -> %s, wire %x", resp.StatusCode, tcp, src, dst, seen.wire, clientAllowed, addr, query)
	}
	if want := echoWithQR(seen)[0]; !bytes.Equal(body, want) {
		t.Fatalf("body %x, want Unbound's reply %x", body, want)
	}
}

// T7: every wrong request gets its status and never reaches the decider.
func TestDoHRejectsWhatIsNotADoHQuery(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(protoName(h2), func(t *testing.T) {
			r, m, addr := newDoHRig(t)
			r.autoAnswer(echoAnswer)
			c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, h2: h2})
			query := buildQuery(t, 0, "ab.example.", true)
			response := bytes.Clone(query)
			response[2] |= 0x80
			bare := func(method, path string) *http.Request {
				req, err := http.NewRequest(method, c.url(path), nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			}
			cases := []struct {
				name   string
				req    *http.Request
				status int
			}{
				{"wrong path", c.get("/other?dns=" + base64.RawURLEncoding.EncodeToString(query)), 404},
				{"path with a suffix", c.get("/dns-query/x?dns=" + base64.RawURLEncoding.EncodeToString(query)), 404},
				{"root", c.get("/"), 404},
				{"PUT", bare(http.MethodPut, dnsParam(query)), 405},
				{"DELETE", bare(http.MethodDelete, "/dns-query"), 405},
				{"HEAD", bare(http.MethodHead, dnsParam(query)), 405},
				{"OPTIONS", bare(http.MethodOptions, "/dns-query"), 405},
				{"POST with the wrong type", c.post("/dns-query", "text/plain", query), 415},
				{"POST with no type", c.post("/dns-query", "", query), 415},
				{"GET with bad base64", c.get("/dns-query?dns=!!!"), 400},
				{"GET in the standard alphabet", c.get("/dns-query?dns=AAAB++//AAAAAAAAAAAA"), 400},
				{"GET without dns", c.get("/dns-query"), 400},
				{"GET with another parameter", c.get("/dns-query?q=" + base64.RawURLEncoding.EncodeToString(query)), 400},
				{"GET with an empty dns", c.get("/dns-query?dns="), 400},
				{"GET with fewer bytes than a header", c.get(dnsParam(query[:11])), 400},
				{"GET with a response packet", c.get(dnsParam(response)), 400},
				{"POST with an empty body", c.post("/dns-query", "application/dns-message", nil), 400},
				{"POST with fewer bytes than a header", c.post("/dns-query", "application/dns-message", query[:11]), 400},
				{"GET over 65535 bytes", c.get(dnsParam(make([]byte, 65536))), 413},
				{"POST over 65535 bytes", c.post("/dns-query", "application/dns-message", make([]byte, 65536)), 413},
			}
			for _, tc := range cases {
				resp, _ := c.do(tc.req)
				if resp.StatusCode != tc.status {
					t.Fatalf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.status)
				}
				if tc.status == 405 && resp.Header.Get("Allow") != "GET, POST" {
					t.Fatalf("%s: Allow %q, want %q", tc.name, resp.Header.Get("Allow"), "GET, POST")
				}
			}
			// the barrier: the first query the decider ever sees is this one
			barrier := buildQuery(t, 0, "barrier.example.", true)
			if resp, _ := c.do(c.get(dnsParam(barrier))); resp.StatusCode != 200 {
				t.Fatalf("a valid query after the errors: status %d", resp.StatusCode)
			}
			if q := r.nextQuery(); !bytes.Equal(q.wire, barrier) {
				t.Fatalf("the decider's first query is %d bytes, want the barrier query: a rejected request reached it", len(q.wire))
			}
			r.requireNoOtherQuery()
		})
	}
}

// 65535 bytes is the largest DoH query and is accepted, in both forms.
func TestDoHLargestQueryIsAccepted(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	big := make([]byte, 65535)
	copy(big, buildQuery(t, 0, "big.example.", true))
	for name, req := range map[string]*http.Request{"GET": c.get(dnsParam(big)), "POST": c.post("/dns-query", "application/dns-message", big)} {
		resp, body := c.do(req)
		if resp.StatusCode != 200 || len(body) != len(big) {
			t.Fatalf("%s of 65535 bytes: status %d, body %d bytes, want 200 and %d bytes", name, resp.StatusCode, len(body), len(big))
		}
		if q := r.nextQuery(); !bytes.Equal(q.wire, big) {
			t.Fatalf("%s: the decider got %d bytes, want the %d-byte query intact", name, len(q.wire), len(big))
		}
	}
}

// T8: ACL refuse answers REFUSED; ACL deny aborts the request (the client sees a reset, never a reply).
func TestDoHACLRefuseAnswersRefusedAndDenyAbortsTheRequest(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(protoName(h2), func(t *testing.T) {
			r, m, addr := newDoHRig(t)
			r.autoAnswer(echoAnswer)
			query := buildQuery(t, 0x6666, "blocked.example.", true)

			refused := newDoHClient(t, addr, m, dohOptions{source: clientRefused, h2: h2})
			resp, body := refused.do(refused.get(dnsParam(query)))
			if resp.StatusCode != 200 {
				t.Fatalf("refused client: status %d, want 200 carrying REFUSED", resp.StatusCode)
			}
			requireRefused(t, query, body)

			denied := newDoHClient(t, addr, m, dohOptions{source: clientDenied, h2: h2})
			if resp, err := denied.http.Do(denied.get(dnsParam(query))); err == nil {
				resp.Body.Close()
				t.Fatalf("denied client got a response (status %d): the request must be aborted", resp.StatusCode)
			}

			allowed := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, h2: h2})
			allowed.do(allowed.get(dnsParam(buildQuery(t, 1, "allowed.example.", true))))
			if q := r.nextQuery(); q.ip != clientAllowed {
				t.Fatalf("the decider's first query came from %s, want %s", q.ip, clientAllowed)
			}
			r.requireNoOtherQuery()
		})
	}
}

// Queries on one HTTP/2 connection run at once and each gets its own answer.
func TestDoHConcurrentStreamsEachGetTheirOwnAnswer(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, h2: true})
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			query := buildQuery(t, 0, strings.Repeat("a", i%50+1)+".example.", true)
			resp, err := c.http.Do(c.get(dnsParam(query)))
			if err != nil {
				errs <- err.Error()
				return
			}
			defer resp.Body.Close()
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			if want := echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(buf.Bytes(), want) {
				errs <- "a stream got another query's answer"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// T9: a trusted peer's PROXYv2 header names the client, for IPv4 and IPv6 sources; Unbound sees the same client.
func TestDoHTrustedPeerProxyHeaderNamesTheClient(t *testing.T) {
	cases := []struct {
		name, header, client string
	}{
		{"IPv4", "192.0.2.7:51000>192.0.2.1:443", "192.0.2.7"},
		{"IPv6", "[2001:db8::7]:51000>[2001:db8::1]:443", "2001:db8::7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m, addr := newDoHRig(t, "127.0.0.0/8")
			r.autoForward()
			parts := strings.Split(tc.header, ">")
			c := newDoHClient(t, addr, m, dohOptions{prefix: pp2TCP(parts[0], parts[1])})
			query := buildQuery(t, 0, "allowed.example.", true)
			if resp, _ := c.do(c.get(dnsParam(query))); resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if q := r.nextQuery(); q.ip != tc.client {
				t.Fatalf("the decider's client: got %s, want the PROXY source %s", q.ip, tc.client)
			}
			src, dst, _ := parsePP2(t, r.up.next().header)
			if src.Addr() != netip.MustParseAddr(tc.client) || src.Port() != netip.MustParseAddrPort(parts[0]).Port() {
				t.Fatalf("Unbound was told the client is %s, want %s", src, parts[0])
			}
			if tc.client == "192.0.2.7" && dst != addr { // the local listener, not the front end's public address
				t.Fatalf("PROXYv2 destination %s, want the local listener %s", dst, addr)
			}
		})
	}
}

// Without a header a trusted peer is just the peer; the PROXY source of the header wins over the peer.
func TestDoHTrustedPeerWithoutAHeaderIsItsOwnClient(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("client %s, want the peer %s", q.ip, clientAllowed)
	}
}

// T10: the rightmost entry of the last X-Forwarded-For header, from a trusted peer; it refines the PROXY source.
func TestDoHTrustedPeerXForwardedForRightmostOfTheLastHeader(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		client  string
	}{
		{"one header, three entries", []string{"198.51.100.1, 198.51.100.2, 198.51.100.3"}, "198.51.100.3"},
		{"two headers: the last one counts", []string{"198.51.100.9", "198.51.100.1, 198.51.100.2"}, "198.51.100.2"},
		{"a single address", []string{"198.51.100.4"}, "198.51.100.4"},
		{"surrounding spaces", []string{"198.51.100.1,   198.51.100.5  "}, "198.51.100.5"},
		{"IPv6", []string{"198.51.100.1, 2001:db8::9"}, "2001:db8::9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m, addr := newDoHRig(t, "127.0.0.0/8")
			r.autoAnswer(echoAnswer)
			c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
			var headers []string
			for _, h := range tc.headers {
				headers = append(headers, "X-Forwarded-For", h)
			}
			c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), headers...))
			if q := r.nextQuery(); q.ip != tc.client {
				t.Fatalf("client %s, want %s (headers %q)", q.ip, tc.client, tc.headers)
			}
		})
	}
}

func TestDoHTrustedPeerXForwardedForOverridesTheProxySource(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{prefix: pp2TCP("192.0.2.7:51000", "192.0.2.1:443")})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", "203.0.113.9"))
	if q := r.nextQuery(); q.ip != "203.0.113.9" {
		t.Fatalf("client %s, want the X-Forwarded-For address 203.0.113.9", q.ip)
	}
}

// T11: an unusable X-Forwarded-For leaves the client as it was: the PROXY source, else the peer.
func TestDoHTrustedPeerBadXForwardedForLeavesTheClientAlone(t *testing.T) {
	bad := []string{"junk", "198.51.100.1, junk", "198.51.100.1,", "198.51.100.1:443", "", "[2001:db8::1]", "198.51.100.300"}
	for _, value := range bad {
		for _, withProxy := range []bool{false, true} {
			name := "peer"
			want := clientAllowed
			var prefix []byte
			if withProxy {
				name, want, prefix = "PROXY source", "192.0.2.7", pp2TCP("192.0.2.7:51000", "192.0.2.1:443")
			}
			t.Run(name+"/"+value, func(t *testing.T) {
				r, m, addr := newDoHRig(t, "127.0.0.0/8")
				r.autoAnswer(echoAnswer)
				c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, prefix: prefix})
				c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", value))
				if q := r.nextQuery(); q.ip != want {
					t.Fatalf("X-Forwarded-For %q: client %s, want %s", value, q.ip, want)
				}
			})
		}
	}
}

// T12: an untrusted peer's PROXY bytes are not parsed (the TLS handshake fails) and spoof nothing.
func TestDoHUntrustedPeerProxyBytesAreNotParsed(t *testing.T) {
	r, m, addr := newDoHRig(t, "192.0.2.0/24") // the loopback test clients are not trusted
	r.autoAnswer(echoAnswer)
	raw, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Write(pp2TCP("192.0.2.7:51000", "192.0.2.1:443")); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(watchdog))
	if err := tlsClientHandshake(raw, m); err == nil {
		t.Fatal("the TLS handshake after PROXY bytes from an untrusted peer must fail: the bytes are not a ClientHello")
	}
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("client %s, want the peer %s: a spoofed PROXY source must not be believed", q.ip, clientAllowed)
	}
	r.requireNoOtherQuery()
}

// T13: an untrusted peer's X-Forwarded-For is ignored.
func TestDoHUntrustedPeerXForwardedForIsIgnored(t *testing.T) {
	r, m, addr := newDoHRig(t, "192.0.2.0/24")
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", "203.0.113.9"))
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("client %s, want the peer %s", q.ip, clientAllowed)
	}
}

// No --doh-trusted at all: nobody is trusted.
func TestDoHWithoutTrustedPrefixesIgnoresProxyAndXForwardedFor(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", "203.0.113.9"))
	if q := r.nextQuery(); q.ip != clientAllowed {
		t.Fatalf("client %s, want the peer %s", q.ip, clientAllowed)
	}
}

// ACL decisions use the client the trusted front end names: a refused one is refused, a denied one gets a reset.
func TestDoHACLAppliesToTheClientTheTrustedFrontEndNames(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	query := buildQuery(t, 0x6666, "blocked.example.", true)

	viaProxy := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, prefix: pp2TCP(clientRefused+":51000", "192.0.2.1:443")})
	resp, body := viaProxy.do(viaProxy.get(dnsParam(query)))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	requireRefused(t, query, body)

	viaXFF := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	resp, body = viaXFF.do(viaXFF.get(dnsParam(query), "X-Forwarded-For", clientRefused))
	requireRefused(t, query, body)

	denied := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	if resp, err := denied.http.Do(denied.get(dnsParam(query), "X-Forwarded-For", clientDenied)); err == nil {
		resp.Body.Close()
		t.Fatalf("a client the front end names as denied got a response (status %d)", resp.StatusCode)
	}
	r.requireNoOtherQuery()
}

// T18: Unbound's reply to the UDP query has TC set: the query is asked again over TCP and the full answer returned.
func TestDoHTruncatedUDPReplyIsRetriedOverTCP(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{truncatedOverUDP()}})
	r.autoForward()
	m := newTLSMaterial(t)
	addr := r.serveDoH(m)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	resp, body := c.do(c.get(dnsParam(buildQuery(t, 0, "big.example.", true))))
	if resp.StatusCode != 200 || !bytes.HasSuffix(body, []byte("full-answer")) {
		t.Fatalf("status %d, body %x: want the full answer from the TCP retry", resp.StatusCode, body)
	}
	first, second := r.up.next(), r.up.next()
	if first.tcp || !second.tcp || !bytes.Equal(first.wire, second.wire) {
		t.Fatalf("Unbound saw tcp=%v then tcp=%v, want UDP then TCP with the same query", first.tcp, second.tcp)
	}
	s1, _, _ := parsePP2(t, first.header)
	s2, _, _ := parsePP2(t, second.header)
	if s1.Addr() != s2.Addr() || s1.Addr() != netip.MustParseAddr(clientAllowed) {
		t.Fatalf("both exchanges must carry the client %s, got %s and %s", clientAllowed, s1, s2)
	}
}

// truncatedOverUDP makes the fake Unbound answer UDP with a TC-flagged header and TCP with the full answer.
func truncatedOverUDP() upstreamOption {
	return answering(func(q seenQuery) [][]byte {
		reply := echoWithQR(q)[0]
		if !q.tcp {
			reply[2] |= 0x02
			return [][]byte{reply[:12]}
		}
		return [][]byte{append(reply, "full-answer"...)}
	})
}

// Hostile input -------------------------------------------------------------------------------------------------

// A 1 MiB POST is refused 413 from its Content-Length, long before the body has been sent.
func TestDoHOversizePostIsRefusedWithoutReadingTheBody(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	c := rawDoH(t, addr, m, nil)
	req := "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 1048576\r\n\r\n"
	if _, err := c.Write(append([]byte(req), make([]byte, 100)...)); err != nil { // 100 bytes of 1 MiB, then wait
		t.Fatal(err)
	}
	resp, _, err := readHTTPResponse(t, c)
	if err != nil || resp.StatusCode != 413 {
		t.Fatalf("got status %v err %v, want 413 before the body arrived", resp, err)
	}
	r.requireNoOtherQuery()
}

// An announced length that the body never reaches: the request ends (400 or a closed connection) once the read
// timeout passes, and the decider is never asked.
func TestDoHPostWithAShortBodyEndsAtTheReadTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: 300 * time.Millisecond})
	m := newTLSMaterial(t)
	addr := r.serveDoH(m)
	r.autoAnswer(echoAnswer)
	c := rawDoH(t, addr, m, nil)
	body := buildQuery(t, 0, "short.example.", true)
	req := "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 200\r\n\r\n"
	if _, err := c.Write(append([]byte(req), body...)); err != nil {
		t.Fatal(err)
	}
	resp, _, err := readHTTPResponse(t, c)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("STUCK/ENVIRONMENT: the server never ended the request whose body stops short of its Content-Length")
	}
	if err == nil && resp.StatusCode == 200 {
		t.Fatal("a body shorter than its Content-Length was answered")
	}
	r.requireNoOtherQuery()
}

// HTTP/1.0 is served: no keep-alive, same answer.
func TestDoHServesAnHTTP10Request(t *testing.T) {
	r, m, addr := newDoHRig(t)
	r.autoAnswer(echoAnswer)
	c := rawDoH(t, addr, m, nil)
	query := buildQuery(t, 0, "old.example.", true)
	if _, err := c.Write([]byte("GET " + dnsParam(query) + " HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, body, err := readHTTPResponse(t, c)
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(body, echoWithQR(seenQuery{wire: query})[0]) {
		t.Fatalf("HTTP/1.0 request: status %v err %v body %x, want 200 and the echoed answer", resp, err, body)
	}
}

// Headers that never end are cut at the read-header timeout; the connection's slot is freed.
func TestDoHRequestHeadersThatNeverEndAreCutAtTheReadHeaderTimeout(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.handshake = time.Second
	m := newTLSMaterial(t)
	addr := r.serveDoH(m)
	c := rawDoH(t, addr, m, nil)
	if _, err := c.Write([]byte("GET /dns-query HTTP/1.1\r\nHost: localhost\r\nX-Slow: 1\r\n")); err != nil { // no blank line
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		// a 408 response may precede the close; what matters is that the server ends the connection
		t.Log("the server answered before closing")
	}
	eventually(t, "the connection to be dropped", func() bool { return r.g.dohConns.n.Load() == 0 })
}

// A PROXYv2 header that arrives one byte at a time from a trusted peer is assembled.
func TestDoHProxyHeaderSplitAcrossSegmentsIsAssembled(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{prefix: pp2TCP("192.0.2.7:51000", "192.0.2.1:443"), split: true})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
	if q := r.nextQuery(); q.ip != "192.0.2.7" {
		t.Fatalf("client %s, want the PROXY source 192.0.2.7 from the split header", q.ip)
	}
}

// Library behaviour, pinned: go-proxyproto accepts a version 1 (text) header from a trusted peer. A change on a
// library upgrade fails here and must be decided on purpose.
func TestDoHTrustedPeerPROXYv1HeaderIsAcceptedByTheLibrary(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	c := newDoHClient(t, addr, m, dohOptions{prefix: pp1("192.0.2.8:51000", "192.0.2.1:443")})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
	if q := r.nextQuery(); q.ip != "192.0.2.8" {
		t.Fatalf("client %s, want the version 1 header's source 192.0.2.8", q.ip)
	}
}

// A LOCAL command (health check) or an AF_UNIX source carries no client address: the client is the TCP peer.
func TestDoHProxyHeaderWithoutAnIPSourceLeavesTheClientAsThePeer(t *testing.T) {
	cases := map[string][]byte{
		"LOCAL command":  pp2(0, 0x00, nil),
		"AF_UNIX stream": pp2(1, 0x31, make([]byte, 216)),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			r, m, addr := newDoHRig(t, "127.0.0.0/8")
			r.autoAnswer(echoAnswer)
			c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, prefix: header})
			c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
			if q := r.nextQuery(); q.ip != clientAllowed {
				t.Fatalf("%s: client %s, want the peer %s", name, q.ip, clientAllowed)
			}
		})
	}
}

// A malformed PROXY header from a trusted peer ends the connection; nothing reaches the decider. Library behaviour
// for a PROXY command with an unsupported (UNSPEC) address family is the same: the connection ends.
func TestDoHMalformedProxyHeaderFromATrustedPeerEndsTheConnection(t *testing.T) {
	cases := map[string][]byte{
		"an IPv4 block of 3 bytes": pp2(1, 0x11, []byte{1, 2, 3}),
		"PROXY with UNSPEC":        pp2(1, 0x00, nil),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			r, m, addr := newDoHRig(t, "127.0.0.0/8")
			r.autoAnswer(echoAnswer)
			raw, err := net.DialTimeout("tcp4", addr.String(), watchdog)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = raw.Close() })
			if _, err := raw.Write(bad); err != nil {
				t.Fatal(err)
			}
			_ = raw.SetDeadline(time.Now().Add(watchdog))
			if err := tlsClientHandshake(raw, m); err == nil {
				t.Fatal("a rejected PROXY header must not lead to a working TLS connection")
			}
			r.requireNoOtherQuery()
		})
	}
}

// T-cap: 128 connections to the DoH listener; the 129th is closed at accept, the log says so once.
func TestDoHConnectionsOverTheCapAreClosedAtAccept(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, perAddr: noAddrCap})
	m := newTLSMaterial(t)
	addr := r.serveDoH(m)
	r.autoAnswer(echoAnswer)
	conns := make([]net.Conn, 0, maxDoHConns)
	for range maxDoHConns {
		c, err := net.DialTimeout("tcp4", addr.String(), watchdog)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns = append(conns, c)
	}
	for range 2 {
		over, err := net.DialTimeout("tcp4", addr.String(), watchdog)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = over.Close() })
		requireTCPClosed(t, over) // accepted in order: once this one is shut, the first 128 hold their slots
	}
	if n := strings.Count(r.logs.joined(), "DoH client limit"); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}
	_ = conns[7].Close()
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.dohConns.n.Load() == maxDoHConns-1 })
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	if resp, _ := c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("a connection that arrives after a slot was freed got status %d", resp.StatusCode)
	}
	c.http.CloseIdleConnections()
	for _, c := range conns {
		_ = c.Close()
	}
	eventually(t, "every connection to drain", func() bool { return r.g.dohConns.n.Load() == 0 })
	if r.g.dohConns.over.Load() {
		t.Fatal("the over-limit log latch must reset once the clients have drained")
	}
}

// Stopping the gateway closes the DoT and DoH listeners.
func TestStopClosesTheTLSListeners(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	m := newTLSMaterial(t)
	dot, doh := r.serveDoT(m), r.serveDoH(m)
	r.g.stop()
	for name, addr := range map[string]netip.AddrPort{"DoT": dot, "DoH": doh} {
		if c, err := net.DialTimeout("tcp4", addr.String(), watchdog); err == nil {
			_ = c.Close()
			t.Fatalf("%s %s still accepts connections after stop()", name, addr)
		}
	}
}
