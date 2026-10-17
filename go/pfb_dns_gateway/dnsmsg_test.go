package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// buildQuery packs a one-question query the way a stub resolver would (no EDNS).
func buildQuery(t testing.TB, id uint16, name string, rd bool) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: rd},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func parseReply(t *testing.T, wire []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("reply does not parse: %v (wire %x)", err, wire)
	}
	return m
}

var builders = map[string]struct {
	build func([]byte) []byte
	rcode dnsmessage.RCode
}{
	"REFUSED":  {buildRefused, dnsmessage.RCodeRefused},
	"SERVFAIL": {buildServfail, dnsmessage.RCodeServerFailure},
}

// G10: the gateway's own error replies keep the id, set QR, copy RD and echo the question byte for byte.
func TestErrorRepliesKeepIDRDAndEchoTheQuestion(t *testing.T) {
	for name, b := range builders {
		for _, rd := range []bool{true, false} {
			t.Run(name, func(t *testing.T) {
				query := buildQuery(t, 0xBEEF, "BlOcKeD.ExAmPlE.", rd)
				reply := b.build(query)
				m := parseReply(t, reply)
				if m.ID != 0xBEEF || !m.Response || m.RecursionDesired != rd || m.RCode != b.rcode {
					t.Fatalf("header: got id=%#x qr=%v rd=%v rcode=%v, want id=0xbeef qr=true rd=%v rcode=%v", m.ID, m.Response, m.RecursionDesired, m.RCode, rd, b.rcode)
				}
				if len(m.Answers)+len(m.Authorities)+len(m.Additionals) != 0 {
					t.Fatalf("an error reply carries no records, got %+v", m)
				}
				if !bytes.Equal(reply[12:], query[12:]) { // 0x20-style mixed case must come back unchanged
					t.Fatalf("question section:\n got  %x\n want %x", reply[12:], query[12:])
				}
			})
		}
	}
}

func TestErrorRepliesKeepTheOpcode(t *testing.T) {
	for name, b := range builders {
		t.Run(name, func(t *testing.T) {
			query := buildQuery(t, 5, "example.", true)
			query[2] |= 4 << 3 // opcode NOTIFY
			if got := parseReply(t, b.build(query)).OpCode; got != 4 {
				t.Fatalf("opcode: got %d, want 4", got)
			}
		})
	}
}

// G11: when the question cannot be echoed the reply is header-only, never a malformed question.
func TestErrorRepliesWithoutAParseableQuestionAreHeaderOnly(t *testing.T) {
	good := buildQuery(t, 0x1234, "example.", true)
	cases := map[string][]byte{
		"question cut inside the name":       good[:15],
		"question cut before type and class": good[:len(good)-3],
		"qdcount 0":                          append(append([]byte{}, good[:4]...), make([]byte, 8)...),
		"qdcount 1 and no bytes after":       good[:12],
		"label length runs past the packet":  append(append([]byte{}, good[:12]...), 0x3f, 'a'),
		"compression pointer to itself":      append(append([]byte{}, good[:12]...), 0xc0, 0x0c, 0, 1, 0, 1),
	}
	for name, b := range builders {
		for label, query := range cases {
			t.Run(name+"/"+label, func(t *testing.T) {
				reply := b.build(query)
				if len(reply) != 12 {
					t.Fatalf("want a 12-byte header-only reply, got %d bytes: %x", len(reply), reply)
				}
				flags := binary.BigEndian.Uint16(reply[2:4])
				if binary.BigEndian.Uint16(reply[:2]) != 0x1234 || flags&0x8000 == 0 || flags&0x100 == 0 || flags&0xf != uint16(b.rcode) {
					t.Fatalf("header: id/flags %x %04x, want id 0x1234, QR+RD set, rcode %d", reply[:2], flags, b.rcode)
				}
				for i := 4; i < 12; i++ {
					if reply[i] != 0 {
						t.Fatalf("all four counts must be zero, got %x", reply[4:12])
					}
				}
			})
		}
	}
}

func TestErrorRepliesToAPacketTooShortForAHeaderAreNil(t *testing.T) {
	for name, b := range builders {
		for _, n := range []int{0, 1, 11} {
			if got := b.build(make([]byte, n)); got != nil {
				t.Errorf("%s of a %d-byte packet: got %x, want nil (nothing to answer)", name, n, got)
			}
		}
	}
}

func TestErrorRepliesIgnoreEverythingAfterTheFirstQuestion(t *testing.T) {
	query := buildQuery(t, 9, "example.", true)
	query = append(query, 0xde, 0xad, 0xbe, 0xef) // trailing bytes, e.g. an OPT record of a client
	binary.BigEndian.PutUint16(query[10:], 1)     // arcount 1
	for name, b := range builders {
		t.Run(name, func(t *testing.T) {
			m := parseReply(t, b.build(query))
			if len(m.Questions) != 1 || m.Questions[0].Name.String() != "example." || len(m.Additionals) != 0 {
				t.Fatalf("got %+v, want only the question", m)
			}
		})
	}
}
