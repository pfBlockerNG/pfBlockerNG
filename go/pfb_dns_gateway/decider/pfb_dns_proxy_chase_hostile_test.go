package decider

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
)

// Frontend._chase_cname takes whatever the forward returns: only a reply that does not parse is an error. Its TC bit
// and its question are never read, so a truncated or off-question reply still lends the chase its answer records.
func TestAChaseReplyIsParsedNotTrusted(t *testing.T) {
	address := func([]byte) []byte {
		wire, err := dnswire.Encode(&dnswire.Message{
			ID: 7, Flags: dnswire.QR | dnswire.RD | dnswire.RA | dnswire.TC,
			Questions: []dnswire.Question{{Name: "other.example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}},
			Answers:   []dnswire.RR{aRecord(ssTarget, 300, 88)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, row := range []struct {
		name     string
		reply    func([]byte) []byte
		servfail bool
	}{
		{"0 bytes", func([]byte) []byte { return []byte{} }, true},
		{"1 byte", func([]byte) []byte { return []byte{0x42} }, true},
		{"a truncated header", func([]byte) []byte { return make([]byte, 11) }, true},
		{"TC set and another question", address, false},
	} {
		out := captureLog(t)
		u := paritycorpus.NewFakeUnbound(ssZone())
		reply := ssResolve(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, u, map[string]func([]byte) []byte{ssTarget: row.reply}), "Unknown")
		if row.servfail {
			if reply.Rcode() != RCODE_SERVFAIL || len(reply.Answers) != 0 {
				t.Errorf("%s: (rcode, answers) = (%d, %d), want a bare SERVFAIL", row.name, reply.Rcode(), len(reply.Answers))
			}
			if lines := logLines(out); len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy error: ") {
				t.Errorf("%s: log = %q, want the one error line", row.name, lines)
			}
			continue
		}
		if reply.Rcode() != RCODE_NOERROR || reply.Flags&dnswire.TC != 0 || len(reply.Answers) != 2 ||
			reply.Answers[0].Rtype != dnswire.TYPE_CNAME || reply.Answers[1].Rtype != dnswire.TYPE_A {
			t.Errorf("%s: reply = %+v, want the CNAME and the A, TC clear", row.name, reply)
		}
	}
}

// A target name of 255 octets (the most a name holds) with the client's EDNS padding up to MAX_DNS_MESSAGE makes the
// chase longer than the query it answers: over 65535 bytes it is never sent.
func TestAMaxLengthTargetThatPushesTheChaseOverOneMessageIsAnErrorWithoutAChase(t *testing.T) {
	label := func(n int) string { return strings.Repeat("a", n) + "." }
	name := label(63) + label(63) + label(63) + label(61) // 64*3 + 62 + root = 255 octets
	rdata, err := dnswire.EncodeName(name)
	if err != nil || len(rdata) != 255 {
		t.Fatalf("EncodeName: %d octets, %v, want 255", len(rdata), err)
	}
	padding := MAX_DNS_MESSAGE - 45
	options := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, 12), uint16(padding))
	query := ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true, options: append(options, make([]byte, padding)...)})
	if len(query) != MAX_DNS_MESSAGE {
		t.Fatalf("the client's query is %d bytes, want %d", len(query), MAX_DNS_MESSAGE)
	}
	f := newTestFrontend(t)
	out := captureLog(t)
	qstate := newModuleQstate(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, ssClient, 0, dnswire.RD, "UDP", "", "")
	qstate.returnMsg = newDnsMsg(qstate.qinfo, dnswire.QR,
		[]dnswire.RR{{Name: ssDuck, Rtype: dnswire.TYPE_CNAME, Rclass: dnswire.CLASS_IN, TTL: 3600, Rdata: rdata}}, nil, nil)
	r := &recorder{}
	if got := f.chaseCname(parse(t, query), qstate, r.forward); got != MODULE_ERROR {
		t.Errorf("state = %d, want MODULE_ERROR (%d)", got, MODULE_ERROR)
	}
	if lines := logLines(out); len(r.wires) != 0 || len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy error: ") {
		t.Errorf("forwarded %d wires, log = %q, want no chase and one error line", len(r.wires), lines)
	}
}
