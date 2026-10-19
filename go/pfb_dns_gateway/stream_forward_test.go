package main

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

// dialStreamClients connects n clients of one stream transport (streamKinds' name) to one listener and returns the
// listener's address as the clients see it.
func dialStreamClients(t *testing.T, r *rig, kind string, n int) (clients []net.Conn, gw netip.AddrPort) {
	t.Helper()
	if kind == "dot" {
		m := newTLSMaterial(t)
		gw = r.serveDoT(m)
		for range n {
			clients = append(clients, dialDoT(t, gw, m, ""))
		}
		return clients, gw
	}
	for range n {
		clients = append(clients, r.tcpClient(""))
	}
	return clients, r.addr
}

// A TCP or DoT client reaches Unbound the way a DoH or DoQ client does: over UDP, behind a UDP PROXYv2 header naming
// the client. Unbound counts a TCP connection against its few TCP slots (incoming-num-tcp, 10 per thread by default),
// so clients that ask small names must not open any.
func TestStreamClientsAskUnboundOverUDPAndOpenNoTCPConnections(t *testing.T) {
	const clients = 8
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			r.autoForward()
			conns, gw := dialStreamClients(t, r, k.name, clients)
			queries := make([][]byte, clients)
			for i, c := range conns {
				queries[i] = buildQuery(t, uint16(i+1), "allowed.example.", true)
				tcpSend(t, c, queries[i])
			}
			for i, c := range conns {
				if got, want := tcpReply(t, c), echoWithQR(seenQuery{wire: queries[i]})[0]; !bytes.Equal(got, want) {
					t.Fatalf("client %d got %x, want Unbound's reply %x", i, got, want)
				}
			}
			ports := map[uint16]bool{}
			for range clients {
				seen := r.up.next()
				src, dst, tcp := parsePP2(t, seen.header)
				if seen.tcp || tcp {
					t.Fatalf("Unbound saw a TCP query (header says tcp=%v): a small answer must be asked over UDP", tcp)
				}
				if dst != gw {
					t.Fatalf("the header's destination is %s, want the listener %s", dst, gw)
				}
				ports[src.Port()] = true
			}
			for i, c := range conns {
				if port := uint16(c.LocalAddr().(*net.TCPAddr).Port); !ports[port] {
					t.Fatalf("no header names client %d (port %d); the headers named ports %v", i, port, ports)
				}
			}
			if upConns, _ := r.up.counts(); upConns != 0 {
				t.Fatalf("Unbound accepted %d TCP connections for %d clients asking small names, want none", upConns, clients)
			}
		})
	}
}

// A reply Unbound truncated over UDP reaches a stream client whole, from the TCP retry; both legs carry a PROXYv2
// header naming the client (UDP header, then TCP header), and the retries of one client connection share one
// upstream TCP connection.
func TestTruncatedAnswerReachesAStreamClientWholeAndBothLegsNameTheClient(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{truncatedOverUDP()}})
			r.autoForward()
			c := k.dial(t, r)
			gw := netip.MustParseAddrPort(c.RemoteAddr().String())
			for i, name := range []string{"big.example.", "bigger.example."} {
				query := buildQuery(t, uint16(i+1), name, true)
				tcpSend(t, c, query)
				reply := tcpReply(t, c)
				viaUDP, viaTCP := r.up.next(), r.up.next()
				if viaUDP.tcp || !viaTCP.tcp || !bytes.Equal(viaUDP.wire, query) || !bytes.Equal(viaTCP.wire, query) {
					t.Fatalf("Unbound saw tcp=%v wire=%x then tcp=%v wire=%x, want the query over UDP, then the same query over TCP", viaUDP.tcp, viaUDP.wire, viaTCP.tcp, viaTCP.wire)
				}
				if want := wantHeader(t, transport{"udp", false}, c.LocalAddr(), gw); !bytes.Equal(viaUDP.header, want) {
					t.Fatalf("UDP leg header:\n got  %x\n want %x", viaUDP.header, want)
				}
				if want := wantHeader(t, transport{"tcp", true}, c.LocalAddr(), gw); !bytes.Equal(viaTCP.header, want) {
					t.Fatalf("TCP leg header:\n got  %x\n want %x", viaTCP.header, want)
				}
				if want := append(echoWithQR(viaTCP)[0], "full-answer"...); !bytes.Equal(reply, want) {
					t.Fatalf("client got %x, want the whole answer from the TCP retry %x", reply, want)
				}
			}
			if upConns, headers := r.up.counts(); upConns != 1 || headers != 1 {
				t.Fatalf("two truncated answers on one client connection used %d upstream TCP connections and %d headers, want 1 and 1", upConns, headers)
			}
		})
	}
}
