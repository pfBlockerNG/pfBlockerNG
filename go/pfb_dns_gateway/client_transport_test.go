package main

import (
	"bytes"
	"testing"
)

// issue #3517: the decider learns which kind of client asked (a datagram client has a UDP size limit, a stream
// client has none), and a plain-UDP client's chase is asked again over TCP when Unbound truncated it. The QUERY
// payload layout here is the one of docs/misc/dns-gateway-protocol.md: u8 transport, u8 n, n bytes of client IP
// text, then the DNS wire.

const (
	transportStream   byte = 0 // TCP, DoT, DoH, DoQ: no UDP size limit
	transportDatagram byte = 1 // plain UDP
)

type transportQuery struct {
	id        uint32
	transport byte
	ip        string
	wire      []byte
}

// recvTransportQuery reads the next frame, which must be a QUERY, and splits its payload by the documented layout.
func (r *rig) recvTransportQuery() transportQuery {
	r.t.Helper()
	typ, id, payload := r.p.recv()
	if typ != tQuery {
		r.t.Fatalf("frame from the gateway: type %d, want QUERY", typ)
	}
	if len(payload) < 2 || payload[0] > transportDatagram || len(payload) < 2+int(payload[1]) {
		r.t.Fatalf("QUERY payload %x does not start with a transport byte (0 stream, 1 datagram), the IP text length and the IP text", payload)
	}
	n := int(payload[1])
	return transportQuery{id: id, transport: payload[0], ip: string(payload[2 : 2+n]), wire: payload[2+n:]}
}

func (r *rig) requireNoUpstreamQuery(what string) {
	r.t.Helper()
	select {
	case q := <-r.up.queries:
		r.t.Fatalf("Unbound saw a query it must not have seen (%s): tcp=%v wire=%x", what, q.tcp, q.wire)
	default:
	}
}

// T1: every transport says what it is, and DoH and DoQ, which carry no UDP limit, are streams.
func TestQueryFrameNamesTheTransportOfTheClient(t *testing.T) {
	query := buildQuery(t, 0x0000, "allowed.example.", true)
	cases := []struct {
		name string
		want byte
		ask  func(t *testing.T) (r *rig, reply func() []byte)
	}{
		{"udp", transportDatagram, func(t *testing.T) (*rig, func() []byte) {
			r := newRig(t, rigConfig{acl: aclMixed})
			done := make(chan []byte, 1)
			go func() { done <- r.roundTrip(transport{"udp", false}, clientAllowed, query) }()
			return r, func() []byte { return awaitBytes(t, done) }
		}},
		{"tcp", transportStream, func(t *testing.T) (*rig, func() []byte) {
			r := newRig(t, rigConfig{acl: aclMixed})
			done := make(chan []byte, 1)
			go func() { done <- r.roundTrip(transport{"tcp", true}, clientAllowed, query) }()
			return r, func() []byte { return awaitBytes(t, done) }
		}},
		{"dot", transportStream, func(t *testing.T) (*rig, func() []byte) {
			r := newRig(t, rigConfig{acl: aclMixed})
			m := newTLSMaterial(t)
			c := dialDoT(t, r.serveDoT(m), m, clientAllowed)
			done := make(chan []byte, 1)
			go func() { tcpSend(t, c, query); done <- tcpReply(t, c) }()
			return r, func() []byte { return awaitBytes(t, done) }
		}},
		{"doh", transportStream, func(t *testing.T) (*rig, func() []byte) {
			r := newRig(t, rigConfig{acl: aclMixed})
			m := newTLSMaterial(t)
			c := newDoHClient(t, r.serveDoH(m), m, dohOptions{source: clientAllowed})
			done := make(chan []byte, 1)
			go func() { _, body := c.do(c.get(dnsParam(query))); done <- body }()
			return r, func() []byte { return awaitBytes(t, done) }
		}},
		{"doq", transportStream, func(t *testing.T) (*rig, func() []byte) {
			r, m, addr := newDoQRig(t, rigConfig{})
			c := dialDoQ(t, addr, m, clientAllowed)
			done := make(chan []byte, 1)
			go func() { done <- c.query(doqQuery(t, "allowed.example.")) }()
			return r, func() []byte { return awaitBytes(t, done) }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, reply := c.ask(t)
			q := r.recvTransportQuery()
			if q.transport != c.want || q.ip != clientAllowed {
				t.Fatalf("QUERY: transport=%d client=%q, want transport=%d client=%q", q.transport, q.ip, c.want, clientAllowed)
			}
			r.p.send(tAnswer, q.id, echoAnswer(decidedQuery{wire: q.wire}))
			if got := reply(); len(got) == 0 {
				t.Fatal("the client got no reply to the decider's answer")
			}
		})
	}
}

// T2: a plain-UDP client's first FORWARD is UDP only and its reply, truncated or not, is the decider's as it is;
// every FORWARD after it (the SafeSearch chase) is asked again over TCP when Unbound truncated it, behind a
// stream PROXYv2 header for the same client.
func TestPlainUDPFirstForwardIsRelayedAsIsAndTheChaseIsRetriedOverTCPWhenTruncated(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{truncatedOverUDP()}})
	c := r.udpClient("")
	query, chase := buildQuery(t, 0x3333, "duck.example.", true), buildQuery(t, 0x4444, "safe.duck.example.", true)
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	q := r.recvTransportQuery()
	if q.transport != transportDatagram {
		t.Fatalf("QUERY transport %d, want datagram", q.transport)
	}

	r.p.send(tForward, q.id, q.wire)
	first := r.up.next()
	truncated := echoWithQR(first)[0]
	truncated[2] |= 0x02
	r.p.expect(tReply, q.id, truncated[:12])
	r.requireNoUpstreamQuery("the first FORWARD is UDP only: its truncated reply goes to the decider as it is")
	if first.tcp {
		t.Fatal("the first FORWARD went to Unbound over TCP")
	}

	r.p.send(tForward, q.id, chase)
	viaUDP, viaTCP := r.up.next(), r.up.next()
	if viaUDP.tcp || !viaTCP.tcp || !bytes.Equal(viaUDP.wire, chase) || !bytes.Equal(viaTCP.wire, chase) {
		t.Fatalf("Unbound saw tcp=%v wire=%x then tcp=%v wire=%x, want the chase over UDP, then the same chase over TCP", viaUDP.tcp, viaUDP.wire, viaTCP.tcp, viaTCP.wire)
	}
	if want := wantHeader(t, transport{"udp", false}, c.LocalAddr(), r.addr); !bytes.Equal(viaUDP.header, want) {
		t.Fatalf("UDP header:\n got  %x\n want %x", viaUDP.header, want)
	}
	if want := wantHeader(t, transport{"tcp", true}, c.LocalAddr(), r.addr); !bytes.Equal(viaTCP.header, want) {
		t.Fatalf("TCP retry header:\n got  %x\n want %x (a stream header naming the same client)", viaTCP.header, want)
	}
	full := append(echoWithQR(viaTCP)[0], "full-answer"...)
	r.p.expect(tReply, q.id, full)
	r.p.send(tAnswer, q.id, []byte("cname+target"))
	if got := udpReply(t, c); string(got) != "cname+target" {
		t.Fatalf("client reply: got %q", got)
	}
}

// T3: Unbound's untruncated reply to the chase is taken as it is: no second exchange over TCP.
func TestPlainUDPChaseIsNotRetriedWhenUnboundDidNotTruncateIt(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	c := r.udpClient("")
	if _, err := c.Write(buildQuery(t, 0x3333, "duck.example.", true)); err != nil {
		t.Fatal(err)
	}
	q := r.recvTransportQuery()
	r.p.send(tForward, q.id, q.wire)
	r.p.expect(tReply, q.id, echoWithQR(r.up.next())[0])
	chase := buildQuery(t, 0x4444, "safe.duck.example.", true)
	r.p.send(tForward, q.id, chase)
	seen := r.up.next()
	r.p.expect(tReply, q.id, echoWithQR(seen)[0])
	r.requireNoUpstreamQuery("the chase was answered whole over UDP")
	if seen.tcp {
		t.Fatal("the chase went to Unbound over TCP although UDP was not truncated")
	}
	r.p.send(tAnswer, q.id, []byte("done"))
	if got := udpReply(t, c); string(got) != "done" {
		t.Fatalf("client reply: got %q", got)
	}
}

// T4: a stream client's FORWARDs all use its one upstream TCP connection; nothing is asked over UDP.
func TestStreamClientForwardsStayOnItsOneUpstreamTCPConnection(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{truncatedOverUDP()}})
	c := r.tcpClient("")
	tcpSend(t, c, buildQuery(t, 0x3333, "duck.example.", true))
	q := r.recvTransportQuery()
	if q.transport != transportStream {
		t.Fatalf("QUERY transport %d, want stream", q.transport)
	}
	for _, name := range []string{"duck.example.", "safe.duck.example."} {
		wire := buildQuery(t, 0x5555, name, true)
		r.p.send(tForward, q.id, wire)
		seen := r.up.next()
		if !seen.tcp || !bytes.Equal(seen.wire, wire) {
			t.Fatalf("Unbound saw tcp=%v wire=%x for %s, want TCP with the FORWARD's wire", seen.tcp, seen.wire, name)
		}
		r.p.expect(tReply, q.id, append(echoWithQR(seen)[0], "full-answer"...))
	}
	r.requireNoUpstreamQuery("a stream client's query never goes out as a datagram")
	if conns, _ := r.up.counts(); conns != 1 {
		t.Fatalf("Unbound accepted %d TCP connections, want the client's one", conns)
	}
	r.p.send(tAnswer, q.id, []byte("done"))
	if got := tcpReply(t, c); string(got) != "done" {
		t.Fatalf("client reply: got %q", got)
	}
}
