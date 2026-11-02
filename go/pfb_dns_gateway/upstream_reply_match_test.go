package main

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A UDP exchange returns the first datagram that is Unbound's answer to its query and ignores the others. Unbound
// answers a message it refuses before it reads the question (TC set, an opcode it does not implement, a bad count, a
// question that does not parse) with a bare 12-byte header: QDCOUNT 0 and an error rcode (probed against Unbound
// 1.26.1 over UDP and TCP). That error is the answer. So is a truncated reply, whatever it kept of the question: the
// client asks again over TCP. Nothing else without a question that matches is.

const replyID = 0x4242

// bareReply is that 12-byte message: the query's id, QR, the query's RD, the rcode, TC when asked, and nothing else.
func bareReply(query []byte, rcode byte, tc bool) []byte {
	reply := make([]byte, 12)
	copy(reply, query[:2])
	reply[2] = 0x80 | query[2]&0x01
	if tc {
		reply[2] |= 0x02
	}
	reply[3] = rcode
	return reply
}

// echoError is the reply of an upstream that sends the message back with QR and an error rcode, question included.
func echoError(query []byte, rcode byte) []byte {
	reply := bytes.Clone(query)
	reply[2] |= 0x80
	reply[3] = reply[3]&0xf0 | rcode
	return reply
}

// replyCutInItsQuestion says it has one question and carries only the start of it.
func replyCutInItsQuestion(flags uint16) []byte {
	return withID(cat(hostileHeader(flags, 1, 0, 0, 0), hostileQuestion[:5]), replyID)
}

type malformedQuery struct {
	name string
	wire []byte
}

// malformedQueries are queries whose first question cannot be read, under the id the exchange checks.
func malformedQueries() []malformedQuery {
	header := func(qd uint16) []byte { return hostileHeader(rdFlag, qd, 0, 0, 0) }
	return []malformedQuery{
		{"QDCOUNT 0", withID(header(0), replyID)},
		{"question cut short", withID(cat(header(1), hostileQuestion[:5]), replyID)},
		{"name that is a compression pointer to itself", withID(cat(header(1), []byte{0xc0, 12, 0, 1, 0, 1}), replyID)},
		{"label of 64 bytes", withID(cat(header(1), []byte{0x40}, bytes.Repeat([]byte{'a'}, 64), []byte{0, 0, 1, 0, 1}), replyID)},
	}
}

// exchangeUDPAgainst sends query to a fake Unbound that answers with datagrams, in order, and returns what the exchange kept.
func exchangeUDPAgainst(t *testing.T, query []byte, datagrams ...[]byte) []byte {
	t.Helper()
	f := newFakeUpstream(t, answering(func(seenQuery) [][]byte { return datagrams }))
	return newUpstream(f.addr, watchdog).exchangeUDP(context.Background(), headerFor(t, "ipv4 udp"), query)
}

func requireKept(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("the exchange kept %x, want %x", got, want)
	}
}

func TestExchangeUDPKeepsUnboundsHeaderOnlyAnswers(t *testing.T) {
	query := dnsMessage(t, replyID, "example.", dnsmessage.TypeA, dnsmessage.ClassINET, false)
	answer := dnsMessage(t, replyID, "example.", dnsmessage.TypeA, dnsmessage.ClassINET, true)
	lostQuestion := echoWithQR(seenQuery{wire: query})[0][:12] // the header of a truncated reply that still counts its question
	lostQuestion[2] |= 0x02
	cases := []struct {
		name  string
		reply []byte
	}{
		{"FORMERR", bareReply(query, 1, false)},
		{"NOTIMP", bareReply(query, 4, false)},
		{"a truncated reply with no question", bareReply(query, 0, true)},
		{"a truncated reply that lost its question", lostQuestion},
		{"a truncated reply cut inside its question", replyCutInItsQuestion(0x8300)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			requireKept(t, exchangeUDPAgainst(t, query, c.reply, answer), c.reply)
		})
	}
}

func TestExchangeUDPKeepsUnboundsErrorForAQueryWhoseQuestionDoesNotParse(t *testing.T) {
	for _, q := range malformedQueries() {
		for _, shape := range []struct {
			name  string
			reply []byte
		}{
			{"bare header", bareReply(q.wire, 1, false)},
			{"the query sent back with FORMERR", echoError(q.wire, 1)},
		} {
			t.Run(q.name+"/"+shape.name, func(t *testing.T) {
				t.Parallel()
				requireKept(t, exchangeUDPAgainst(t, q.wire, shape.reply), shape.reply)
			})
		}
	}
}

func TestExchangeUDPKeepsAMatchingAnswerWhateverTheCaseOfTheName(t *testing.T) {
	query := dnsMessage(t, replyID, "Example.", dnsmessage.TypeA, dnsmessage.ClassINET, false)
	answer := dnsMessage(t, replyID, "eXAMPLE.", dnsmessage.TypeA, dnsmessage.ClassINET, true)
	requireKept(t, exchangeUDPAgainst(t, query, answer), answer)
}

// A datagram that is not the answer is skipped, and the one after it is kept.
func TestExchangeUDPIgnoresADatagramThatCannotBeTheAnswer(t *testing.T) {
	query := dnsMessage(t, replyID, "example.", dnsmessage.TypeA, dnsmessage.ClassINET, false)
	answer := dnsMessage(t, replyID, "example.", dnsmessage.TypeA, dnsmessage.ClassINET, true)
	clearQR := bareReply(query, 1, false)
	clearQR[2] &^= 0x80
	bareTC := bareReply(query, 0, true)
	cases := []struct {
		name string
		bad  []byte
	}{
		{"another id", bareReply(withID(query, replyID+1), 1, false)},
		{"QR clear", clearQR},
		{"no question and no error", bareReply(query, 0, false)},
		{"a 3-byte message with TC", []byte{query[0], query[1], 0x82}},
		{"a truncated header of 11 bytes", bareTC[:11]},
		{"a cut-short question with FORMERR", replyCutInItsQuestion(0x8101)},
		{"another question", dnsMessage(t, replyID, "previous.example.", dnsmessage.TypeA, dnsmessage.ClassINET, true)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			requireKept(t, exchangeUDPAgainst(t, query, c.bad, answer), answer)
		})
	}

	// With no question to compare, only the same bytes or no question at all can be the answer.
	malformed := malformedQueries()[1] // question cut short
	other := malformedQueries()[2]     // a different question that does not parse
	good := bareReply(malformed.wire, 1, false)
	for _, c := range []struct {
		name string
		bad  []byte
	}{
		{"a question that parses", dnsMessage(t, replyID, "example.", dnsmessage.TypeA, dnsmessage.ClassINET, true)},
		{"another question that does not parse", echoError(other.wire, 1)},
		{"no question and no error", bareReply(malformed.wire, 0, false)},
	} {
		t.Run("to a question that does not parse: "+c.name, func(t *testing.T) {
			t.Parallel()
			requireKept(t, exchangeUDPAgainst(t, malformed.wire, c.bad, good), good)
		})
	}
}

// A bare truncated reply is asked again over TCP, as a truncated reply with its question always was.
func TestABareTruncatedReplyIsAskedAgainOverTCP(t *testing.T) {
	newRetrying := func(t *testing.T) (*fakeUpstream, *upstream) {
		f := newFakeUpstream(t, answering(func(q seenQuery) [][]byte {
			if q.tcp {
				return replyMarked(q)
			}
			return [][]byte{bareReply(q.wire, 0, true)}
		}))
		return f, newUpstream(f.addr, watchdog)
	}
	query := buildQuery(t, replyID, "example.", true)
	src, dst := "203.0.113.5:40000", "198.51.100.1:53"
	t.Run("new connection", func(t *testing.T) {
		f, u := newRetrying(t)
		requireKept(t, u.exchangeUDPThenTCP(context.Background(), ap(src), ap(dst), query), markedReply(query, true))
		if conns, _ := f.counts(); conns != 1 {
			t.Fatalf("%d TCP connections, want 1", conns)
		}
	})
	t.Run("pool", func(t *testing.T) {
		f, u := newRetrying(t)
		p := u.newPool(headerFor(t, "ipv4 tcp"))
		t.Cleanup(p.close)
		requireKept(t, u.exchangeUDPThenPool(context.Background(), headerFor(t, "ipv4 udp"), p, query), markedReply(query, true))
		if conns, _ := f.counts(); conns != 1 {
			t.Fatalf("%d TCP connections, want 1", conns)
		}
	})
}
