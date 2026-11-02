package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
)

// Question names are DNS labels, not dotted text. RFC 2181 section 11 permits every octet in a label, including a dot.
// These fixtures stay on the wire so neither a text parser nor a text encoder can change the label boundaries.
func labelWire(labels ...[]byte) []byte {
	var name []byte
	for _, label := range labels {
		name = append(name, byte(len(label)))
		name = append(name, label...)
	}
	return append(name, 0)
}

func questionWire(name []byte, typ, class uint16) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(bytes.Clone(name), typ), class)
}

func queryWire(section []byte, edns bool) []byte {
	ar := uint16(0)
	if edns {
		ar = 1
	}
	wire := withID(cat(hostileHeader(rdFlag, 1, 0, 0, ar), section), replyID)
	if edns {
		wire = append(wire, opt([]byte{0}, 0, 0)...)
	}
	return wire
}

func replyRR(owner []byte, typ uint16, data []byte) []byte {
	wire := append(bytes.Clone(owner), 0, 0, 0, 1, 0, 0, 1, 44)
	binary.BigEndian.PutUint16(wire[len(owner):], typ)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(data)))
	return append(wire, data...)
}

// wireAnswer is an answer, not an echo: the record after the question must not make an otherwise matching reply fail.
func wireAnswer(section []byte, typ uint16, edns, nx bool) []byte {
	flags, an, ns, ar := uint16(0x8180), uint16(1), uint16(0), uint16(0)
	if nx {
		flags, an, ns = flags|3, 0, 1
	}
	if edns {
		ar = 1
	}
	wire := withID(cat(hostileHeader(flags, 1, an, ns, ar), section), replyID)
	if nx {
		soa := cat(labelWire([]byte("ns"), []byte("example")), labelWire([]byte("hostmaster"), []byte("example")))
		for _, n := range []uint32{1, 2, 3, 4, 5} {
			soa = binary.BigEndian.AppendUint32(soa, n)
		}
		wire = append(wire, replyRR(labelWire([]byte("example")), 6, soa)...)
	} else if typ == 16 {
		wire = append(wire, replyRR([]byte{0xc0, 12}, typ, []byte{2, 'o', 'k'})...)
	} else {
		wire = append(wire, replyRR([]byte{0xc0, 12}, typ, []byte{192, 0, 2, 11})...)
	}
	if edns {
		wire = append(wire, opt([]byte{0}, 0, 0)...)
	}
	return wire
}

func TestExchangeUDPKeepsAnswersToEveryLegalLabelOctet(t *testing.T) {
	for _, c := range []struct {
		name  string
		label []byte
	}{
		{"dot in a label", []byte("a.b")},
		{"several dots in a label", []byte("a.b.c")},
		{"dot-only label", []byte(".")},
		{"high byte", []byte{'x', 0xff, 'y'}},
		{"NUL", []byte{'u', 0, 'v'}},
		{"backslash", []byte(`a\b`)},
		{"space", []byte("a b")},
		{"UTF-8", []byte("é")},
		{"mixed ASCII case", []byte("MiXeD")},
		{"63-octet label", bytes.Repeat([]byte{'a'}, 63)},
	} {
		for _, shape := range []struct {
			name string
			typ  uint16
			edns bool
			nx   bool
		}{
			{"A answer", 1, false, false},
			{"A answer with EDNS", 1, true, false},
			{"TXT answer", 16, false, false},
			{"NXDOMAIN with SOA", 1, false, true},
		} {
			t.Run(c.name+"/"+shape.name, func(t *testing.T) {
				t.Parallel()
				q := questionWire(labelWire(c.label, []byte("example")), shape.typ, 1)
				answer := wireAnswer(q, shape.typ, shape.edns, shape.nx)
				requireKept(t, exchangeUDPAgainst(t, queryWire(q, shape.edns), answer), answer)
			})
		}
	}
	for _, name := range [][]byte{
		{0}, // root
		labelWire(bytes.Repeat([]byte{'a'}, 63), bytes.Repeat([]byte{'b'}, 63), bytes.Repeat([]byte{'c'}, 63), bytes.Repeat([]byte{'d'}, 61)), // 255 octets
	} {
		t.Run(fmt.Sprintf("%d-octet name", len(name)), func(t *testing.T) {
			t.Parallel()
			q := questionWire(name, 1, 1)
			answer := wireAnswer(q, 1, false, true)
			requireKept(t, exchangeUDPAgainst(t, queryWire(q, false), answer), answer)
		})
	}
}

func TestExchangeUDPCaseFoldsOnlyASCIINameOctets(t *testing.T) {
	q := questionWire(labelWire([]byte("A.B"), []byte("ExAmPlE")), 65, 65)
	replyQuestion := questionWire(labelWire([]byte("a.b"), []byte("eXaMpLe")), 65, 65)
	answer := wireAnswer(replyQuestion, 65, false, false)
	requireKept(t, exchangeUDPAgainst(t, queryWire(q, false), answer), answer)
}

func TestExchangeUDPDoesNotConfuseDifferentWireQuestions(t *testing.T) {
	ordinary := labelWire([]byte("www"), []byte("example"))
	for _, c := range []struct {
		name      string
		want, got []byte
	}{
		{"same text but different labels", questionWire(labelWire([]byte("a.b"), []byte("c")), 1, 1), questionWire(labelWire([]byte("a"), []byte("b.c")), 1, 1)},
		{"same text split at the dot", questionWire(labelWire([]byte("a.b"), []byte("example")), 1, 1), questionWire(labelWire([]byte("a"), []byte("b"), []byte("example")), 1, 1)},
		{"name prefix", questionWire(ordinary, 1, 1), questionWire(labelWire([]byte("www")), 1, 1)},
		{"name suffix", questionWire(ordinary, 1, 1), questionWire(labelWire([]byte("example")), 1, 1)},
		{"longer name", questionWire(ordinary, 1, 1), questionWire(labelWire([]byte("www"), []byte("example"), []byte("net")), 1, 1)},
		{"high bytes are not case folded", questionWire(labelWire([]byte{0xc9}), 1, 1), questionWire(labelWire([]byte{0xe9}), 1, 1)},
		{"UTF-8 is not case folded", questionWire(labelWire([]byte("É")), 1, 1), questionWire(labelWire([]byte("é")), 1, 1)},
		{"before ASCII A", questionWire(labelWire([]byte("@")), 1, 1), questionWire(labelWire([]byte("`")), 1, 1)},
		{"after ASCII Z", questionWire(labelWire([]byte("[")), 1, 1), questionWire(labelWire([]byte("{")), 1, 1)},
		{"type is not case folded", questionWire(ordinary, 65, 1), questionWire(ordinary, 97, 1)},
		{"class is not case folded", questionWire(ordinary, 1, 65), questionWire(ordinary, 1, 97)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			answer := wireAnswer(c.want, 1, false, false)
			bad := wireAnswer(c.got, 1, false, false)
			requireKept(t, exchangeUDPAgainst(t, queryWire(c.want, false), bad, answer), answer)
		})
	}
}

// The label content contains an earlier root followed by n-1 pointers to it, and the name ends in a pointer to that
// chain. The uncompressed name has identical labels (not text): the binary label content followed by the root.
func chainedQuestion(n int) (compressed, plain []byte) {
	content := []byte{0}
	for i := 1; i < n; i++ {
		target := 13
		if i > 1 {
			target = 13 + 1 + 2*(i-2)
		}
		content = append(content, 0xc0, byte(target))
	}
	target := 13
	if n > 1 {
		target = 13 + 1 + 2*(n-2)
	}
	name := append([]byte{byte(len(content))}, content...)
	compressed = questionWire(append(bytes.Clone(name), 0xc0, byte(target)), 1, 1)
	plain = questionWire(append(name, 0), 1, 1)
	return
}

func TestExchangeUDPExpandsTheQuestionNameBeforeComparing(t *testing.T) {
	for _, n := range []int{1, 3, 30} {
		compressed, plain := chainedQuestion(n)
		for _, pair := range []struct {
			name      string
			want, got []byte
		}{{"reply compressed", plain, compressed}, {"query compressed", compressed, plain}} {
			t.Run(fmt.Sprintf("%s %d pointers", pair.name, n), func(t *testing.T) {
				t.Parallel()
				answer := wireAnswer(pair.got, 1, false, false)
				requireKept(t, exchangeUDPAgainst(t, queryWire(pair.want, false), answer), answer)
			})
		}
	}
}

func unreadableQuestions() []struct {
	name    string
	section []byte
} {
	longName := labelWire(bytes.Repeat([]byte{'a'}, 63), bytes.Repeat([]byte{'b'}, 63), bytes.Repeat([]byte{'c'}, 63), bytes.Repeat([]byte{'d'}, 62)) // 256 octets
	return []struct {
		name    string
		section []byte
	}{
		{"self pointer", []byte{0xc0, 12, 0, 1, 0, 1}},
		{"pointer into the header", []byte{0xc0, 0, 0, 1, 0, 1}},
		{"forward pointer", []byte{0xc0, 18, 0, 1, 0, 1, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}},
		{"out of bounds pointer", []byte{0xff, 0xff, 0, 1, 0, 1}},
		{"label pointer loop", []byte{1, 'x', 0xc0, 12, 0, 1, 0, 1}},
		{"reserved label 01", []byte{0x40, 0, 0, 1, 0, 1}},
		{"reserved label 10", []byte{0x80, 0, 0, 1, 0, 1}},
		{"label cut short", []byte{7, 'e', 'x'}},
		{"no root", []byte{1, 'x'}},
		{"type missing", labelWire([]byte("www"))},
		{"class cut short", append(labelWire([]byte("www")), 0, 1, 0)},
		{"256-octet name", questionWire(longName, 1, 1)},
	}
}

func TestExchangeUDPDoesNotMistakeAnUnreadableQuestionForAnError(t *testing.T) {
	ordinary := questionWire(labelWire([]byte("www"), []byte("example")), 1, 1)
	answer := wireAnswer(ordinary, 1, false, false)
	for _, c := range unreadableQuestions() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			bad := withID(cat(hostileHeader(0x8101, 1, 0, 0, 0), c.section), replyID) // FORMERR with a question that does not match
			requireKept(t, exchangeUDPAgainst(t, queryWire(ordinary, false), bad, answer), answer)
		})
	}
}

func TestExchangeUDPKeepsOnlyTheSameUnreadableQuestionOrABareError(t *testing.T) {
	other := wireAnswer(questionWire(labelWire([]byte("www"), []byte("example")), 1, 1), 1, false, false)
	for _, c := range unreadableQuestions() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			query := queryWire(c.section, false)
			echo := echoError(query, 1)
			bare := bareReply(query, 1, false)
			requireKept(t, exchangeUDPAgainst(t, query, other, echo), echo)
			requireKept(t, exchangeUDPAgainst(t, query, append(bytes.Clone(echo), 0), bare), bare)
		})
	}
}

func TestExchangeUDPRequiresAWholeHeaderOnBothSides(t *testing.T) {
	query := queryWire(questionWire(labelWire([]byte("example")), 1, 1), false)
	answer := wireAnswer(query[12:], 1, false, false)
	for n := range 12 {
		t.Run(fmt.Sprintf("%d-byte reply", n), func(t *testing.T) {
			t.Parallel()
			requireKept(t, exchangeUDPAgainst(t, query, bareReply(query, 1, true)[:n], answer), answer)
		})
		t.Run(fmt.Sprintf("%d-byte query", n), func(t *testing.T) {
			t.Parallel()
			f := newFakeUpstream(t, answering(func(seenQuery) [][]byte { return [][]byte{bareReply(query, 1, false)} }))
			got := newUpstream(f.addr, watchdog).exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), query[:n])
			if got != nil || len(f.queries) != 0 {
				t.Fatalf("runt query yielded reply %x and reached Unbound %d times; want neither", got, len(f.queries))
			}
		})
	}
}

func TestAnswersWithDotsInsideALabelReachEveryClientTransport(t *testing.T) {
	name := labelWire([]byte("a.b"), []byte("example"))
	section := questionWire(name, 1, 1)
	rows := []hostileRow{
		{name: "positive answer", wire: withID(queryWire(section, false), 0), rcode: 0},
		{name: "positive answer with EDNS", wire: withID(queryWire(section, true), 0), rcode: 0},
		{name: "NXDOMAIN and SOA", wire: withID(queryWire(questionWire(labelWire([]byte("q.r"), []byte("example")), 1, 1), false), 0), rcode: 3},
	}
	runHostileMessages(t, rows, func(row hostileRow, query []byte) []byte {
		end := len(query)
		if row.name == "positive answer with EDNS" {
			end -= 11
		}
		answer := wireAnswer(query[12:end], 1, row.name == "positive answer with EDNS", row.rcode == 3)
		copy(answer[:2], query[:2])
		return answer
	})
}
