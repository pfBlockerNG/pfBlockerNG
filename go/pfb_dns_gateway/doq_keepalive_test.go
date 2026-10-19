package main

import (
	"bytes"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Option codes from the IANA "DNS EDNS0 Option Codes" registry, written out so no test trusts the code under test.
const (
	ednsTCPKeepalive = 11 // RFC 7828
	ednsPadding      = 12 // RFC 7830
)

// ednsQuery is a DoQ query (Message ID 0) with an OPT record carrying one option of the given code.
func ednsQuery(t *testing.T, name string, code uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	opt := dnsmessage.Resource{Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: code, Data: []byte{0, 0}}}}}
	if err := opt.Header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	wire, err := (&dnsmessage.Message{
		Header:      dnsmessage.Header{RecursionDesired: true},
		Questions:   []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{opt},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// RFC 9250 5.5.2: DoQ clients and servers MUST NOT send edns-tcp-keepalive (option 11), and a message that carries it
// is a protocol error, which 4.3.3 has answered with CONNECTION_CLOSE and DOQ_PROTOCOL_ERROR like a non-zero Message
// ID. Another option, padding, is fine.
func TestDoQQueryWithTCPKeepaliveClosesTheConnectionWithProtocolError(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{})
	r.autoAnswer(echoAnswer)
	c := dialDoQ(t, addr, m, clientAllowed)
	sendDoQ(t, c.stream(), ednsQuery(t, "keepalive.example.", ednsTCPKeepalive))
	requireConnClosed(t, c.conn, rfcDoQProtocolError)

	padded := dialDoQ(t, addr, m, clientAllowed) // the server is fine, and another option is not the keepalive
	paddedQuery := ednsQuery(t, "padded.example.", ednsPadding)
	if got, want := padded.query(paddedQuery), withID0(echoAnswer(decidedQuery{wire: paddedQuery})); len(got) == 0 || !bytes.Equal(got[2:], want[2:]) {
		t.Fatalf("a query with a padding option got %x, want the decider's answer %x", got, want)
	}
	if q := r.nextQuery(); !bytes.Equal(q.wire[2:], paddedQuery[2:]) {
		t.Fatalf("the decider's first query is %x: the keepalive query reached it", q.wire)
	}
	r.requireNoOtherQuery()
}
