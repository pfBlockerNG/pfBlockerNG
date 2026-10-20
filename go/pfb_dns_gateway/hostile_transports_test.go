package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The same hostile messages on every listener. The gateway judges nothing but a runt and a message that is already a
// response (never answered); anything else, malformed or not, goes to the decider and from there to Unbound, which
// owns the answer (NOTIMP for another opcode, FORMERR for a bad count or OPT). So on UDP, TCP, DoT, DoH and DoQ a message
// of the first kind gets no answer and never reaches Unbound, and one of the second kind reaches Unbound as the client
// sent it (a DoQ message but for the Message ID, which RFC 9250 4.2.1 has the gateway pick) and the client gets
// Unbound's answer back byte for byte. Unbound is a fake that answers each row with the rcode the row names.

const hostileSentinelName = "sentinel.example." // a query sent after one that gets no answer: the barrier that says nothing is coming

// hostileRow is a message and what the gateway must do with it: rcode is Unbound's answer to it, dropped means that the
// gateway itself never answers it and never asks Unbound.
type hostileRow struct {
	name    string
	wire    []byte
	rcode   byte
	dropped bool
}

func hostileHeader(flags, qd, an, ns, ar uint16) []byte {
	h := make([]byte, 12) // Message ID 0: DoQ requires it, and the other transports do not care
	binary.BigEndian.PutUint16(h[2:], flags)
	for i, n := range []uint16{qd, an, ns, ar} {
		binary.BigEndian.PutUint16(h[4+2*i:], n)
	}
	return h
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	hostileQuestion = mustHexString("076578616d706c650000010001") // example. A IN
	rdFlag          = uint16(0x0100)
)

func mustHexString(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return out
}

// opt is an OPT record: owner name, type 41, UDP payload size, the TTL field (extended rcode, version, flags), RDLENGTH.
func opt(owner []byte, ttl uint32, rdlen uint16, rdata ...byte) []byte {
	r := append([]byte{}, owner...)
	r = binary.BigEndian.AppendUint16(r, 41)
	r = binary.BigEndian.AppendUint16(r, 1232)
	r = binary.BigEndian.AppendUint32(r, ttl)
	r = binary.BigEndian.AppendUint16(r, rdlen)
	return append(r, rdata...)
}

func hostileRows() []hostileRow {
	q := func(flags, qd, an, ns, ar uint16, rest ...[]byte) []byte {
		return cat(append([][]byte{hostileHeader(flags, qd, an, ns, ar)}, rest...)...)
	}
	root := []byte{0}
	return []hostileRow{
		{name: "control: an ordinary query", wire: q(rdFlag, 1, 0, 0, 0, hostileQuestion), rcode: 0},
		{name: "opcode IQUERY", wire: q(1<<11|rdFlag, 1, 0, 0, 0, hostileQuestion), rcode: 4},
		{name: "opcode STATUS", wire: q(2<<11|rdFlag, 1, 0, 0, 0, hostileQuestion), rcode: 4},
		{name: "opcode NOTIFY", wire: q(4<<11, 1, 0, 0, 0, hostileQuestion), rcode: 4},
		{name: "opcode UPDATE", wire: q(5<<11, 1, 0, 0, 0, hostileQuestion), rcode: 4},
		{name: "opcode 15", wire: q(15<<11, 1, 0, 0, 0, hostileQuestion), rcode: 4},
		{name: "QDCOUNT 0", wire: q(rdFlag, 0, 0, 0, 0), rcode: 1},
		{name: "QDCOUNT 2", wire: q(rdFlag, 2, 0, 0, 0, hostileQuestion, hostileQuestion), rcode: 1},
		{name: "QDCOUNT 65535 over one question", wire: q(rdFlag, 0xffff, 0, 0, 0, hostileQuestion), rcode: 1},
		{name: "ANCOUNT 1 and no record", wire: q(rdFlag, 1, 1, 0, 0, hostileQuestion), rcode: 1},
		{name: "ANCOUNT 65535", wire: q(rdFlag, 1, 0xffff, 0, 0, hostileQuestion), rcode: 1},
		{name: "NSCOUNT 65535", wire: q(rdFlag, 1, 0, 0xffff, 0, hostileQuestion), rcode: 1},
		{name: "ARCOUNT 65535", wire: q(rdFlag, 1, 0, 0, 0xffff, hostileQuestion), rcode: 1},
		{name: "TC set on a query", wire: q(0x0200|rdFlag, 1, 0, 0, 0, hostileQuestion), rcode: 1},
		{name: "question cut short", wire: q(rdFlag, 1, 0, 0, 0, hostileQuestion[:5]), rcode: 1},
		{name: "name that is a compression pointer to itself", wire: q(rdFlag, 1, 0, 0, 0, []byte{0xc0, 12, 0, 1, 0, 1}), rcode: 1},
		{name: "label of 64 bytes", wire: q(rdFlag, 1, 0, 0, 0, []byte{0x40}, bytes.Repeat([]byte{'a'}, 64), []byte{0, 0, 1, 0, 1}), rcode: 1},
		{name: "OPT whose RDLENGTH runs past the message", wire: q(rdFlag, 1, 0, 0, 1, hostileQuestion, opt(root, 0, 0xffff)), rcode: 1},
		{name: "OPT with an option that runs past its RDATA", wire: q(rdFlag, 1, 0, 0, 1, hostileQuestion, opt(root, 0, 4, 0, 10, 0, 9)), rcode: 1},
		{name: "OPT that is not at the root", wire: q(rdFlag, 1, 0, 0, 1, hostileQuestion, opt([]byte{1, 'a', 0}, 0, 0)), rcode: 1},
		{name: "OPT of version 1", wire: q(rdFlag, 1, 0, 0, 1, hostileQuestion, opt(root, 1<<16, 0)), rcode: 1},
		{name: "two OPT records", wire: q(rdFlag, 1, 0, 0, 2, hostileQuestion, opt(root, 0, 0), opt(root, 0, 0)), rcode: 1},
		{name: "a message that is already a response", wire: q(0x8000|rdFlag, 1, 0, 0, 0, hostileQuestion), dropped: true},
		{name: "a runt of 11 bytes", wire: hostileHeader(rdFlag, 1, 0, 0, 0)[:11], dropped: true},
		{name: "an empty message", wire: []byte{}, dropped: true},
	}
}

// hostileAsker sends a message from one client address over one transport and returns the answer, nil when the
// transport gave none. For a message that gets none it sends a sentinel query after it, so that "nothing came" is
// known and not waited for.
type hostileAsker func(t *testing.T, wire []byte, dropped bool) []byte

func requireSentinel(t *testing.T, reply []byte) {
	t.Helper()
	if len(reply) < 2 || binary.BigEndian.Uint16(reply) != 0xBEEF {
		t.Fatalf("the reply after a message that gets no answer is %x, want the sentinel's (id 0xbeef)", reply)
	}
}

func TestTheSameHostileMessagesGetTheSameResultOnEveryTransport(t *testing.T) {
	rows := hostileRows()
	byBody := map[string]hostileRow{}
	for _, row := range rows {
		if len(row.wire) >= 2 {
			byBody[string(row.wire[2:])] = row
		}
	}
	sentinel := buildQuery(t, 0xBEEF, hostileSentinelName, true)
	answerLikeUnbound := answering(func(q seenQuery) [][]byte {
		reply := bytes.Clone(q.wire)
		reply[2] = reply[2]&^0x02 | 0x80 // Unbound's answer never carries TC: a truncated one is asked again over TCP by every transport but UDP
		if row, ok := byBody[string(q.wire[2:])]; ok {
			reply[3] = reply[3]&0xf0 | row.rcode
		}
		return [][]byte{reply}
	})
	expected := func(row hostileRow) []byte {
		reply := bytes.Clone(row.wire)
		reply[2] = reply[2]&^0x02 | 0x80
		reply[3] = reply[3]&0xf0 | row.rcode
		return reply
	}

	for _, tr := range []string{"udp", "tcp", "dot", "doh", "doq"} {
		t.Run(tr, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, perAddr: noAddrCap, upstream: []upstreamOption{answerLikeUnbound}})
			r.autoForward()
			m := newTLSMaterial(t)
			var ask hostileAsker
			switch tr {
			case "udp":
				ask = func(t *testing.T, wire []byte, dropped bool) []byte {
					c := r.udpClient(clientAllowed)
					if _, err := c.Write(wire); err != nil {
						t.Fatal(err)
					}
					if !dropped {
						return udpReply(t, c)
					}
					if _, err := c.Write(sentinel); err != nil {
						t.Fatal(err)
					}
					requireSentinel(t, udpReply(t, c))
					requireNoUDPReply(t, c)
					return nil
				}
			case "tcp", "dot":
				dial := func() net.Conn { return r.tcpClient(clientAllowed) }
				if tr == "dot" {
					addr := r.serveDoT(m)
					dial = func() net.Conn { return dialDoT(t, addr, m, clientAllowed) }
				}
				ask = func(t *testing.T, wire []byte, dropped bool) []byte {
					c := dial()
					tcpSend(t, c, wire)
					if !dropped {
						return tcpReply(t, c)
					}
					tcpSend(t, c, sentinel)
					requireSentinel(t, tcpReply(t, c))
					_ = c.SetReadDeadline(time.Now()) // the sentinel was answered after the message: nothing else is coming
					if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatalf("the connection delivered %d more bytes (err %v) after a message that gets no answer", n, err)
					}
					return nil
				}
			case "doh":
				addr := r.serveDoH(m)
				ask = func(t *testing.T, wire []byte, dropped bool) []byte {
					c := newDoHClient(t, addr, m, dohOptions{h2: true, source: clientAllowed})
					resp, body := c.do(c.post(dohPath, dohMediaType, wire))
					if dropped {
						if resp.StatusCode != http.StatusBadRequest {
							t.Fatalf("DoH answered a message the gateway drops with status %d, want 400", resp.StatusCode)
						}
						return nil
					}
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("DoH answered with status %d, want 200 and Unbound's answer", resp.StatusCode)
					}
					return body
				}
			case "doq":
				addr := r.serveDoQ(m)
				ask = func(t *testing.T, wire []byte, dropped bool) []byte {
					s := dialDoQ(t, addr, m, clientAllowed).stream()
					sendDoQ(t, s, wire)
					data, err := readDoQ(t, s)
					if dropped {
						var se *quic.StreamError
						if !errors.As(err, &se) || !se.Remote {
							t.Fatalf("a message the gateway drops ended its DoQ stream with %v, want a reset by the server", err)
						}
						return nil
					}
					if !errors.Is(err, io.EOF) {
						t.Fatalf("DoQ stream ended with %v, want Unbound's answer and a FIN", err)
					}
					return unframe(t, data)
				}
			}

			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					for len(r.up.queries) > 0 {
						<-r.up.queries
					}
					got := ask(t, row.wire, row.dropped)
					var reachedUnbound [][]byte
					for len(r.up.queries) > 0 {
						if q := <-r.up.queries; !bytes.Contains(q.wire, []byte("sentinel")) {
							reachedUnbound = append(reachedUnbound, q.wire)
						}
					}
					if row.dropped {
						if got != nil || len(reachedUnbound) != 0 {
							t.Fatalf("answer %x, and %d queries reached Unbound: a dropped message gets no answer and is never asked", got, len(reachedUnbound))
						}
						return
					}
					if len(reachedUnbound) != 1 || !bytes.Equal(reachedUnbound[0][2:], row.wire[2:]) {
						t.Fatalf("Unbound was asked %x, want exactly the client's message %x (its Message ID aside)", reachedUnbound, row.wire)
					}
					if want := expected(row); !bytes.Equal(got, want) {
						t.Fatalf("the client got %x, want Unbound's answer %x (rcode %d)", got, want, row.rcode)
					}
				})
			}
		})
	}
}
