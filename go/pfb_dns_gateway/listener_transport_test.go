package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestListenerTransportAndClientFamilies(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, tc := range []struct {
			name      string
			transport byte
		}{{"tcp", 0}, {"udp", 1}, {"dot", 2}, {"doh", 3}, {"doq", 4}} {
			t.Run(host+"/"+tc.name, func(t *testing.T) {
				r := newRig(t, rigConfig{upstream: []upstreamOption{truncatedOverUDP()}})
				m := newTLSMaterial(t)
				query := buildQuery(t, 0, "allowed.example.", true)
				done := make(chan clientResult, 1)
				var ask func() []byte
				switch tc.name {
				case "udp":
					l, err := bindPlain(host, 0)
					if err != nil {
						t.Fatal(err)
					}
					r.g.serve(l)
					c, err := net.DialUDP(ipFamily("udp", l.addr()), nil, net.UDPAddrFromAddrPort(l.addr()))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = c.Close() })
					if _, err := c.Write(query); err != nil {
						t.Fatal(err)
					}
					ask = func() []byte { return udpReply(t, c) }
				case "tcp", "dot", "doh":
					ln, err := bindTCP(host, 0)
					if err != nil {
						t.Fatal(err)
					}
					addr := ln.Addr().(*net.TCPAddr).AddrPort()
					switch tc.name {
					case "tcp":
						r.g.wg.Add(1)
						go r.g.serveTCP(ln, nil)
						r.g.closeOnStop(func() { _ = ln.Close() })
						c, err := net.DialTCP(ipFamily("tcp", addr), nil, net.TCPAddrFromAddrPort(addr))
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = c.Close() })
						tcpSend(t, c, query)
						ask = func() []byte { return tcpReply(t, c) }
					case "dot":
						r.g.serveDoT(ln, m.certs.dot())
						c := dialDoT(t, addr, m, "")
						tcpSend(t, c, query)
						ask = func() []byte { return tcpReply(t, c) }
					case "doh":
						r.g.serveDoH(ln, m.certs.doh(), nil)
						c := newDoHClient(t, addr, m, dohOptions{})
						go func() {
							resp, err := c.http.Do(c.post(dohPath, dohMediaType, query))
							if err != nil {
								done <- clientResult{err: err}
								return
							}
							defer resp.Body.Close()
							body, err := io.ReadAll(resp.Body)
							done <- clientResult{body: body, err: err}
						}()
						ask = func() []byte { return awaitClient(t, done) }
					}
				case "doq":
					udp, err := bindUDP(host, 0)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = r.g.serveDoQ(udp, m.certs.doq()); err != nil {
						t.Fatal(err)
					}
					c := dialDoQ(t, udp.LocalAddr().(*net.UDPAddr).AddrPort(), m, "")
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), watchdog)
						defer cancel()
						s, err := c.conn.OpenStreamSync(ctx)
						if err != nil {
							done <- clientResult{err: err}
							return
						}
						_ = s.SetDeadline(time.Now().Add(watchdog))
						_, err = s.Write(framed(query))
						if err == nil {
							err = s.Close()
						}
						if err != nil {
							done <- clientResult{err: err}
							return
						}
						body, err := io.ReadAll(s)
						done <- clientResult{body: body, err: err}
					}()
					ask = func() []byte { return unframe(t, awaitClient(t, done)) }
				}
				q := r.recvTransportQuery()
				if q.transport != tc.transport || netip.MustParseAddr(q.ip) != netip.MustParseAddr(host) {
					t.Fatalf("QUERY transport=%d client=%s, want %d %s", q.transport, q.ip, tc.transport, host)
				}
				r.p.send(tForward, q.id, q.wire)
				seen := r.up.next()
				if seen.tcp {
					t.Fatal("first forward used TCP, want UDP")
				}
				want := echoWithQR(seen)[0]
				if tc.transport == 1 {
					want[2] |= 0x02
					want = want[:12]
				} else {
					seen = r.up.next()
					src, _, tcp := parsePP2(t, seen.header)
					if !seen.tcp || !tcp || src.Addr().String() != host {
						t.Fatalf("fallback tcp=%v source=%s, want TCP source %s", seen.tcp, src, host)
					}
					want = append(echoWithQR(seen)[0], "full-answer"...)
				}
				r.p.expect(tReply, q.id, want)
				answer := echoAnswer(decidedQuery{wire: q.wire})
				if tc.transport != 1 {
					answer = append(answer, make([]byte, 2048)...)
				}
				r.p.send(tAnswer, q.id, answer)
				if tc.transport == 4 {
					answer[0], answer[1] = 0, 0
				}
				if got := ask(); !bytes.Equal(got, answer) {
					t.Fatalf("client received %d bytes, want unchanged %d-byte answer", len(got), len(answer))
				}
			})
		}
	}
}

func TestDoHAttributionKeepsListenerTransport(t *testing.T) {
	for _, tc := range []struct {
		name, header, value, want string
		trusted                   bool
		prefix                    []byte
	}{
		{"trusted XFF", "X-Forwarded-For", "2001:db8::7", "2001:db8::7", true, nil},
		{"trusted Forwarded remains ignored", "Forwarded", "for=192.0.2.7", clientAllowed, true, nil},
		{"trusted PROXY", "", "", "192.0.2.7", true, pp2TCP("192.0.2.7:51000", "192.0.2.1:443")},
		{"untrusted XFF", "X-Forwarded-For", "192.0.2.7", clientAllowed, false, nil},
		{"untrusted Forwarded", "Forwarded", "for=192.0.2.7", clientAllowed, false, nil},
		{"malformed XFF", "X-Forwarded-For", "not-an-address", clientAllowed, true, nil},
		{"malformed Forwarded", "Forwarded", "for=unknown", clientAllowed, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed})
			m := newTLSMaterial(t)
			var trusted []string
			if tc.trusted {
				trusted = []string{"127.0.0.0/8"}
			}
			c := newDoHClient(t, r.serveDoH(m, trusted...), m, dohOptions{source: clientAllowed, prefix: tc.prefix})
			query := buildQuery(t, 0, "allowed.example.", true)
			req := c.get(dnsParam(query))
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			done := make(chan clientResult, 1)
			go func() {
				resp, err := c.http.Do(req)
				if err != nil {
					done <- clientResult{err: err}
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				done <- clientResult{body: body, err: err}
			}()
			q := r.recvTransportQuery()
			if q.transport != 3 || q.ip != tc.want {
				t.Fatalf("QUERY transport=%d client=%s, want 3 %s", q.transport, q.ip, tc.want)
			}
			r.p.send(tAnswer, q.id, echoAnswer(decidedQuery{wire: q.wire}))
			if len(awaitClient(t, done)) == 0 {
				t.Fatal("empty answer")
			}
		})
	}
}
