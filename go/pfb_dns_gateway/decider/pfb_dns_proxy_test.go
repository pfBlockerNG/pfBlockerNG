// Tests of pfb_dns_proxy.go: the Frontend that decides one client query, and the replies it builds itself, as
// tests/dns_proxy/test_hostile.py, test_frontend_e2e.py and test_no_module.py check them for the Python Frontend.
package decider

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const (
	testClient = "192.0.2.10"
	allowed    = "allowed.example."
	// A reply that is no DNS message: it comes back exactly as forwarded, so a test sees who answered.
	unboundSaid = "Unbound's reply, not a DNS message"
)

var qtc = []byte{0, 1, 0, 1} // qtype A, qclass IN

// --- helpers -------------------------------------------------------------------------------------

func bootModule(t *testing.T) *pfbUnbound {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	module, err := boot(dir)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	stopModule(t, module)
	return module
}

func newTestFrontend(t *testing.T) *Frontend { return newFrontend(bootModule(t)) }

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	previous := logOutput
	logOutput = &out
	t.Cleanup(func() { logOutput = previous })
	return &out
}

// logLines is what was logged, one entry per line.
func logLines(out *bytes.Buffer) []string {
	if out.Len() == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
}

// recorder is the gateway's forward: it keeps every wire it is handed and answers with `answer` (nil: silence).
type recorder struct {
	wires  [][]byte
	answer func(wire []byte) []byte
}

func (r *recorder) forward(wire []byte) []byte {
	r.wires = append(r.wires, bytes.Clone(wire))
	if r.answer == nil {
		return nil
	}
	return r.answer(wire)
}

func answering(reply []byte) *recorder {
	return &recorder{answer: func([]byte) []byte { return reply }}
}

func header(id, flags, qd, an, ns, ar uint16) []byte {
	out := make([]byte, 12)
	for i, field := range []uint16{id, flags, qd, an, ns, ar} {
		binary.BigEndian.PutUint16(out[2*i:], field)
	}
	return out
}

func encode(t *testing.T, m *dnswire.Message) []byte {
	t.Helper()
	wire, err := dnswire.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func parse(t *testing.T, wire []byte) *dnswire.Message {
	t.Helper()
	m, err := dnswire.Parse(wire)
	if err != nil {
		t.Fatalf("parse %x: %v", wire, err)
	}
	return m
}

func question(name string, qclass uint16) []dnswire.Question {
	return []dnswire.Question{{Name: name, Qtype: dnswire.TYPE_A, Qclass: qclass}}
}

func queryWire(t *testing.T, name string, flags uint16, additional ...dnswire.RR) []byte {
	t.Helper()
	return encode(t, &dnswire.Message{ID: 0x4242, Flags: flags, Questions: question(name, dnswire.CLASS_IN), Additional: additional})
}

// replyTo is Unbound's answer to `wire`: the question echoed, RD copied, RA set.
func replyTo(t *testing.T, wire []byte, rcode uint16, answers ...dnswire.RR) []byte {
	t.Helper()
	q := parse(t, wire)
	return encode(t, &dnswire.Message{ID: q.ID, Flags: dnswire.QR | dnswire.RA | (q.Flags & dnswire.RD) | rcode, Questions: q.Questions, Answers: answers})
}

func opt(version uint32, owner string) dnswire.RR {
	return dnswire.RR{Name: owner, Rtype: dnswire.TYPE_OPT, Rclass: 1232, TTL: version << 16}
}

func sameRRs(a, b []dnswire.RR) bool {
	return slices.EqualFunc(a, b, func(x, y dnswire.RR) bool {
		return x.Name == y.Name && x.Rtype == y.Rtype && x.Rclass == y.Rclass && x.TTL == y.TTL && bytes.Equal(x.Rdata, y.Rdata)
	})
}

// wantOnlyOpt fails unless `additional` is exactly one root OPT of the proxy's UDP size with the DO bit as given.
func wantOnlyOpt(t *testing.T, what string, additional []dnswire.RR, do bool) {
	t.Helper()
	want := dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, do, nil)
	if !sameRRs(additional, []dnswire.RR{want}) {
		t.Errorf("%s: additional = %+v, want the one OPT %+v", what, additional, want)
	}
}

// wantBare fails unless `wire` is a reply with exactly the given id, flags, rcode and question section, and no records.
func wantBare(t *testing.T, what string, wire []byte, id, flags uint16, rcode int, questions []dnswire.Question) {
	t.Helper()
	if wire == nil {
		t.Fatalf("%s: the decider dropped the query, want a reply", what)
	}
	m := parse(t, wire)
	if m.ID != id || m.Flags != flags || m.Rcode() != rcode || !slices.Equal(m.Questions, questions) {
		t.Errorf("%s: (id, flags, rcode, questions) = (%#x, %#x, %d, %v), want (%#x, %#x, %d, %v)",
			what, m.ID, m.Flags, m.Rcode(), m.Questions, id, flags, rcode, questions)
	}
	if len(m.Answers)+len(m.Authority) != 0 {
		t.Errorf("%s: a bare reply carries %d answers and %d authority records", what, len(m.Answers), len(m.Authority))
	}
}

// --- boot ----------------------------------------------------------------------------------------

func TestBootLoadsTheModuleFromItsDirectory(t *testing.T) {
	if module := bootModule(t); module == nil {
		t.Fatal("boot returned no module")
	}
}

func TestBootReportsAModuleThatCannotInitialise(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = banana\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	module, err := boot(dir)
	if err == nil || module != nil || !strings.Contains(err.Error(), "python_enable") {
		t.Errorf("boot of a non-boolean python_enable = (%v, %v), want (nil, an error naming python_enable)", module, err)
	}
}

// --- the replies the proxy builds itself -----------------------------------------------------------

func TestEdnsForEchoesTheClientsDoBitAtTheProxysSize(t *testing.T) {
	options := []byte{0, 8, 0, 4, 0, 1, 24, 0}
	for _, do := range []bool{false, true} {
		query := &dnswire.Message{Additional: []dnswire.RR{dnswire.MakeOpt(4096, do, options)}}
		wantOnlyOpt(t, "options=false", ednsFor(query, false), do)
		with := ednsFor(query, true)
		if want := dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, do, options); !sameRRs(with, []dnswire.RR{want}) {
			t.Errorf("do=%v options=true: %+v, want the client's options carried: %+v", do, with, want)
		}
	}
	if got := ednsFor(&dnswire.Message{Additional: []dnswire.RR{aRecord(allowed, 1, 1)}}, true); len(got) != 0 {
		t.Errorf("a client without EDNS got %+v, want no OPT", got)
	}
}

func TestOptOfFindsTheFirstOptRecord(t *testing.T) {
	first, second := dnswire.MakeOpt(1111, false, nil), dnswire.MakeOpt(2222, true, nil)
	query := &dnswire.Message{Additional: []dnswire.RR{aRecord(allowed, 1, 1), first, second}}
	if got := optOf(query); got == nil || got.Rclass != 1111 {
		t.Errorf("optOf = %+v, want the first OPT (size 1111)", got)
	}
	if got := optOf(&dnswire.Message{Additional: []dnswire.RR{aRecord(allowed, 1, 1)}}); got != nil {
		t.Errorf("optOf of a message without OPT = %+v, want nil", got)
	}
}

func TestUdpLimit(t *testing.T) {
	for _, row := range []struct {
		name       string
		additional []dnswire.RR
		want       int
	}{
		{"no EDNS", nil, 512},
		{"a size under 512", []dnswire.RR{dnswire.MakeOpt(100, false, nil)}, 512},
		{"exactly 512", []dnswire.RR{dnswire.MakeOpt(512, false, nil)}, 512},
		{"a size in between", []dnswire.RR{dnswire.MakeOpt(1000, false, nil)}, 1000},
		{"exactly the proxy's size", []dnswire.RR{dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, false, nil)}, int(dnswire.EDNS_UDP_SIZE)},
		{"a size over the proxy's", []dnswire.RR{dnswire.MakeOpt(4096, false, nil)}, int(dnswire.EDNS_UDP_SIZE)},
		{"the largest size", []dnswire.RR{dnswire.MakeOpt(65535, false, nil)}, int(dnswire.EDNS_UDP_SIZE)},
	} {
		if got := udpLimit(&dnswire.Message{Additional: row.additional}); got != row.want {
			t.Errorf("%s: udpLimit = %d, want %d", row.name, got, row.want)
		}
	}
}

func TestErrorReplyIsABareErrorLikeUnboundsErrorEncode(t *testing.T) {
	query := &dnswire.Message{
		ID:         0x0B0B,
		Flags:      dnswire.RD | dnswire.CD | 0x0020 | 5<<11, // RD, CD, AD and opcode UPDATE
		Questions:  question(allowed, dnswire.CLASS_IN),
		Additional: []dnswire.RR{dnswire.MakeOpt(4096, true, []byte{0, 8, 0, 4, 0, 1, 24, 0})},
	}
	wire := errorReply(query, RCODE_SERVFAIL)
	// Id, RD, CD and the opcode copied; AD is not; the question echoed.
	wantBare(t, "servfail", wire, 0x0B0B, dnswire.QR|dnswire.RA|dnswire.RD|dnswire.CD|5<<11|RCODE_SERVFAIL, RCODE_SERVFAIL, query.Questions)
	wantOnlyOpt(t, "servfail", parse(t, wire).Additional, true) // the client's DO echoed, its options not

	headerOnly := errorReply(&dnswire.Message{ID: 7, Flags: dnswire.RD}, RCODE_FORMERR)
	if len(headerOnly) != 12 {
		t.Errorf("an error for a message without questions is %d bytes, want the 12 of the header alone", len(headerOnly))
	}
	wantBare(t, "formerr", headerOnly, 7, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_FORMERR, RCODE_FORMERR, nil)
}

func TestModuleDecides(t *testing.T) {
	for _, row := range []struct {
		name       string
		qclass     uint16
		additional []dnswire.RR
		want       bool
	}{
		{"a plain query", dnswire.CLASS_IN, nil, true},
		{"class ANY", dnswire.CLASS_ANY, nil, true},
		{"an OPT of the root, EDNS version 0", dnswire.CLASS_IN, []dnswire.RR{opt(0, ".")}, true},
		{"class CH", 3, nil, false},
		{"class HS", 4, nil, false},
		{"an OPT of EDNS version 1", dnswire.CLASS_IN, []dnswire.RR{opt(1, ".")}, false},
		{"an OPT not owned by the root", dnswire.CLASS_IN, []dnswire.RR{opt(0, "example.")}, false},
		{"an additional record that is not an OPT", dnswire.CLASS_IN, []dnswire.RR{aRecord(allowed, 1, 1)}, false},
	} {
		query := &dnswire.Message{Questions: question(allowed, row.qclass), Additional: row.additional}
		if got := moduleDecides(query); got != row.want {
			t.Errorf("%s: moduleDecides = %v, want %v", row.name, got, row.want)
		}
	}
}

// --- rendered and send ---------------------------------------------------------------------------

func manyAnswers(n int) []dnswire.RR {
	var out []dnswire.RR
	for i := range n {
		out = append(out, aRecord(fmt.Sprintf("host%d.example.", i), 300, byte(i)))
	}
	return out
}

func rdataOf(n int) []dnswire.RR {
	return []dnswire.RR{{Name: allowed, Rtype: dnswire.TYPE_A, Rclass: dnswire.CLASS_IN, TTL: 300, Rdata: make([]byte, n)}}
}

func moduleMessage(answers []dnswire.RR, flags uint16) *dnsMsg {
	return newDnsMsg(queryInfo{qnameStr: allowed, qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}, flags, answers, nil, nil)
}

func TestRenderedFullMessageCarriesTheModulesSectionsAndTheClientsEdns(t *testing.T) {
	answers := manyAnswers(2)
	authority := []dnswire.RR{aRecord("auth.example.", 30, 8)}
	glue := aRecord("ns.example.", 60, 9)
	msg := newDnsMsg(queryInfo{qnameStr: allowed, qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN},
		dnswire.QR|dnswire.AA|0x0020|3, answers, authority, []dnswire.RR{glue})
	query := &dnswire.Message{
		ID:         0x4242,
		Flags:      dnswire.RD | dnswire.CD | 0x0020,
		Questions:  question(allowed, dnswire.CLASS_IN),
		Additional: []dnswire.RR{dnswire.MakeOpt(4096, true, []byte{0, 8, 0, 4, 0, 1, 24, 0})},
	}
	wire, replaced, err := rendered(query, msg, new(1232))
	if err != nil || replaced {
		t.Fatalf("rendered = (replaced %v, %v), want the message whole", replaced, err)
	}
	m := parse(t, wire)
	// QR and RA set, AA and the rcode (NXDOMAIN) from the module, RD and CD from the client, AD from nobody.
	if want := dnswire.QR | dnswire.RA | dnswire.AA | 3 | dnswire.RD | dnswire.CD; m.ID != 0x4242 || m.Flags != want {
		t.Errorf("(id, flags) = (%#x, %#x), want (0x4242, %#x)", m.ID, m.Flags, want)
	}
	if !slices.Equal(m.Questions, query.Questions) || !sameRRs(m.Answers, answers) || !sameRRs(m.Authority, authority) {
		t.Errorf("sections differ from the module's message: %+v", m)
	}
	if len(m.Additional) != 2 || !sameRRs(m.Additional[:1], []dnswire.RR{glue}) {
		t.Fatalf("additional = %+v, want the module's glue, then the OPT", m.Additional)
	}
	wantOnlyOpt(t, "EDNS", m.Additional[1:], true)
}

func TestRenderedHasNoOptForAClientWithoutEdns(t *testing.T) {
	query := &dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	wire, _, err := rendered(query, moduleMessage(manyAnswers(1), dnswire.QR), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := parse(t, wire).Additional; len(got) != 0 {
		t.Errorf("additional = %+v, want none", got)
	}
}

func TestRenderedOverTheUdpLimitIsTheQuestionAloneWithTC(t *testing.T) {
	query := &dnswire.Message{
		ID:         0x4242,
		Flags:      dnswire.RD,
		Questions:  question(allowed, dnswire.CLASS_IN),
		Additional: []dnswire.RR{dnswire.MakeOpt(512, false, nil)},
	}
	msg := moduleMessage(manyAnswers(60), dnswire.QR|dnswire.AA|3)
	whole, _, err := rendered(query, msg, nil)
	if err != nil || len(whole) <= 512 {
		t.Fatalf("the test message is %d bytes (%v), want more than the 512 it is limited to", len(whole), err)
	}
	wire, replaced, err := rendered(query, msg, new(512))
	if err != nil || replaced {
		t.Fatalf("rendered = (replaced %v, %v), want a truncated reply, not a SERVFAIL", replaced, err)
	}
	// It keeps the module's rcode and AA, so the reply callback stays "reply".
	wantBare(t, "truncated", wire, 0x4242, dnswire.QR|dnswire.RA|dnswire.AA|3|dnswire.RD|dnswire.TC, 3, query.Questions)
	wantOnlyOpt(t, "truncated", parse(t, wire).Additional, false)
	if len(wire) > 512 {
		t.Errorf("the truncated reply is %d bytes, want at most 512", len(wire))
	}
}

func TestRenderedLimitBoundary(t *testing.T) {
	query := &dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	msg := moduleMessage(manyAnswers(30), dnswire.QR)
	whole, _, err := rendered(query, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	at, _, _ := rendered(query, msg, new(len(whole)))
	below, _, _ := rendered(query, msg, new(len(whole)-1))
	if !bytes.Equal(at, whole) {
		t.Errorf("a limit of exactly %d bytes truncated the %d-byte reply", len(whole), len(at))
	}
	if parse(t, below).Flags&dnswire.TC == 0 {
		t.Errorf("a limit of %d bytes did not truncate the %d-byte reply", len(whole)-1, len(whole))
	}
}

func TestRenderedOverOneDnsMessageIsServfailForAStreamAndTruncatedForADatagram(t *testing.T) {
	query := &dnswire.Message{ID: 0x4242, Flags: dnswire.RD | dnswire.CD, Questions: question(allowed, dnswire.CLASS_IN)}
	msg := moduleMessage(rdataOf(65535), dnswire.QR|dnswire.RA)

	wire, replaced, err := rendered(query, msg, nil)
	if err != nil || !replaced {
		t.Fatalf("stream: rendered = (replaced %v, %v), want the bare SERVFAIL, replaced", replaced, err)
	}
	wantBare(t, "stream", wire, 0x4242, dnswire.QR|dnswire.RA|dnswire.RD|dnswire.CD|RCODE_SERVFAIL, RCODE_SERVFAIL, query.Questions)

	wire, replaced, err = rendered(query, msg, new(512))
	if err != nil || replaced {
		t.Fatalf("datagram: rendered = (replaced %v, %v), want a truncated reply, not replaced", replaced, err)
	}
	wantBare(t, "datagram", wire, 0x4242, dnswire.QR|dnswire.RA|dnswire.RD|dnswire.CD|dnswire.TC, 0, query.Questions)
}

func TestRenderedStreamUnderOneDnsMessageIsNotTruncated(t *testing.T) {
	query := &dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	answers := rdataOf(3000)
	wire, replaced, err := rendered(query, moduleMessage(answers, dnswire.QR), nil)
	if err != nil || replaced {
		t.Fatalf("rendered = (replaced %v, %v), want the message whole", replaced, err)
	}
	if m := parse(t, wire); m.Flags&dnswire.TC != 0 || !sameRRs(m.Answers, answers) {
		t.Errorf("a stream reply over 512 bytes was cut: flags %#x, %d answers", m.Flags, len(m.Answers))
	}
}

func TestRenderedFailsForAnRRTheWireCannotCarry(t *testing.T) {
	query := &dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	wire, replaced, err := rendered(query, moduleMessage(rdataOf(65536), dnswire.QR), nil)
	if err == nil || wire != nil || replaced {
		t.Errorf("rendered = (%d bytes, replaced %v, %v), want an error and nothing sent", len(wire), replaced, err)
	}
}

func sendState(query *dnswire.Message, msg *dnsMsg, rcode int) *moduleQstate {
	qstate := newModuleQstate(queryInfo{qnameStr: allowed, qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}, testClient, 0, query.Flags, "UDP", "", "")
	qstate.returnMsg, qstate.returnRcode = msg, rcode
	return qstate
}

func TestSendRepliesTheWayMeshSendReplyDoes(t *testing.T) {
	f := newTestFrontend(t)
	query := &dnswire.Message{ID: 0x4242, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	msg := moduleMessage(manyAnswers(2), dnswire.QR|dnswire.RA)
	oversized := moduleMessage(rdataOf(65535), dnswire.QR|dnswire.RA)
	relay := []byte("Unbound's own bytes")
	bare := func(rcode int) uint16 { return dnswire.QR | dnswire.RA | dnswire.RD | uint16(rcode) }

	for _, row := range []struct {
		name  string
		state *moduleQstate
		relay []byte
		limit *int
		check func(t *testing.T, wire []byte)
	}{
		{name: "no message and no rcode is a SERVFAIL", state: sendState(query, nil, RCODE_NOERROR), check: func(t *testing.T, wire []byte) {
			wantBare(t, "no message", wire, 0x4242, bare(RCODE_SERVFAIL), RCODE_SERVFAIL, query.Questions)
		}},
		{name: "no message and a REFUSED rcode is a bare REFUSED", state: sendState(query, nil, 5), check: func(t *testing.T, wire []byte) {
			wantBare(t, "refused", wire, 0x4242, bare(5), 5, query.Questions)
		}},
		{name: "an NXDOMAIN rcode is a bare NXDOMAIN even though the module left records", state: sendState(query, msg, RCODE_NXDOMAIN), check: func(t *testing.T, wire []byte) {
			wantBare(t, "nxdomain", wire, 0x4242, bare(RCODE_NXDOMAIN), RCODE_NXDOMAIN, query.Questions)
		}},
		{name: "a message with no error is rendered", state: sendState(query, msg, RCODE_NOERROR), check: func(t *testing.T, wire []byte) {
			if m := parse(t, wire); m.Flags != bare(0) || !sameRRs(m.Answers, msg.answer) {
				t.Errorf("rendered reply: flags %#x, answers %+v", m.Flags, m.Answers)
			}
		}},
		{name: "a relay is sent as it is, whatever the module's message", state: sendState(query, msg, RCODE_NOERROR), relay: relay, check: func(t *testing.T, wire []byte) {
			if !bytes.Equal(wire, relay) {
				t.Errorf("reply = %q, want the relayed bytes %q", wire, relay)
			}
		}},
		{name: "a datagram answer over its limit is truncated and keeps the module's rcode", state: sendState(query, oversized, RCODE_NOERROR), limit: new(512), check: func(t *testing.T, wire []byte) {
			wantBare(t, "datagram", wire, 0x4242, bare(0)|dnswire.TC, 0, query.Questions)
		}},
		{name: "a stream answer over one DNS message is a bare SERVFAIL", state: sendState(query, oversized, RCODE_NOERROR), check: func(t *testing.T, wire []byte) {
			wantBare(t, "stream", wire, 0x4242, bare(RCODE_SERVFAIL), RCODE_SERVFAIL, query.Questions)
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := f.send(query, row.state, row.relay, row.limit)
			if err != nil {
				t.Fatal(err)
			}
			row.check(t, wire)
		})
	}
}

func TestSendFailsForAMessageTheWireCannotCarry(t *testing.T) {
	f := newTestFrontend(t)
	query := &dnswire.Message{ID: 1, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN)}
	wire, err := f.send(query, sendState(query, moduleMessage(rdataOf(65536), dnswire.QR), RCODE_NOERROR), nil, nil)
	if err == nil || wire != nil {
		t.Errorf("send = (%d bytes, %v), want an error and nothing sent", len(wire), err)
	}
}

// --- Frontend.operate ----------------------------------------------------------------------------

func TestFrontendOperateReturnsTheStateTheModuleLeftInItsSlot(t *testing.T) {
	f := newTestFrontend(t)
	qstate := newModuleQstate(queryInfo{qnameStr: allowed, qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}, testClient, 0, dnswire.RD, "UDP", "", "")
	if got := f.operate(qstate, MODULE_EVENT_NEW); got != MODULE_WAIT_MODULE {
		t.Errorf("state after NEW = %d, want MODULE_WAIT_MODULE (%d)", got, MODULE_WAIT_MODULE)
	}
	if got := f.operate(qstate, MODULE_EVENT_MODDONE); got != MODULE_FINISHED {
		t.Errorf("state after MODDONE = %d, want MODULE_FINISHED (%d)", got, MODULE_FINISHED)
	}
}

// --- resolve: what is never answered, what Unbound answers itself ----------------------------------

func TestResolveNeverAnswersWhatIsNotAQuery(t *testing.T) {
	f := newTestFrontend(t)
	for name, wire := range map[string][]byte{
		"no packet at all":                   nil,
		"a packet shorter than a header":     {0x12, 0x34, 0x01},
		"eleven bytes":                       make([]byte, 11),
		"a response":                         replyTo(t, queryWire(t, allowed, dnswire.RD), 0),
		"a truncated response with QR set":   append(header(7, 0x8100, 1, 0, 0, 0), 0xC0),
		"a header-only response with QR set": header(7, dnswire.QR, 0, 0, 0, 0),
		"a response claiming two questions":  append(header(7, dnswire.QR|dnswire.RD, 2, 0, 0, 0), bytes.Repeat([]byte{0xC0, 0x0C}, 50)...),
	} {
		r := answering([]byte(unboundSaid))
		if reply := f.resolve(wire, testClient, r.forward, "UDP", "", ""); reply != nil || len(r.wires) != 0 {
			t.Errorf("%s: reply %q, forwarded %d wires, want a drop and nothing forwarded", name, reply, len(r.wires))
		}
	}
}

func TestResolveAnswersAQueryWithoutExactlyOneQuestionWithAHeaderOnlyFormerr(t *testing.T) {
	f := newTestFrontend(t)
	oneLabel := []byte{1, 'a', 0}
	for _, row := range []struct {
		name  string
		flags uint16 // the flags the client sent, of which RD and CD come back
		wire  []byte
	}{
		{"no question", dnswire.RD, header(0xABCD, dnswire.RD, 0, 0, 0, 0)},
		{"two questions", dnswire.RD, slices.Concat(header(0xABCD, dnswire.RD, 2, 0, 0, 0), oneLabel, qtc, []byte{0xC0, 0x0C}, qtc)},
		{"four thousand questions", dnswire.RD, slices.Concat(header(0xABCD, dnswire.RD, 4000, 0, 0, 0), bytes.Repeat([]byte{0xC0, 0x0C, 0, 1, 0, 1}, 4000))},
		{"CD is copied", dnswire.RD | dnswire.CD, header(0xABCD, dnswire.RD|dnswire.CD, 0, 0, 0, 0)},
		{"RD that is not set is not made up", 0, header(0xABCD, 0, 3, 0, 0, 0)},
	} {
		r := answering([]byte(unboundSaid))
		reply := f.resolve(row.wire, testClient, r.forward, "UDP", "", "")
		if len(reply) != 12 {
			t.Errorf("%s: reply is %d bytes, want the 12 of the header alone: no question echoed, nothing to amplify", row.name, len(reply))
		}
		wantBare(t, row.name, reply, 0xABCD, dnswire.QR|dnswire.RA|row.flags|RCODE_FORMERR, RCODE_FORMERR, nil)
		if len(r.wires) != 0 {
			t.Errorf("%s: forwarded %d wires, want none: a FORMERR never reaches Unbound", row.name, len(r.wires))
		}
	}
}

func TestResolveAnswersAnUnparseableBodyWithAHeaderOnlyFormerr(t *testing.T) {
	f := newTestFrontend(t)
	r := answering([]byte(unboundSaid))
	wire := append(header(0xABCD, dnswire.RD, 1, 0, 0, 0), 5, 'a', 'b') // a 5-octet label with 2 octets present
	reply := f.resolve(wire, testClient, r.forward, "UDP", "", "")
	if len(reply) != 12 {
		t.Errorf("reply is %d bytes, want the 12 of a header-only FORMERR", len(reply))
	}
	wantBare(t, "unparseable", reply, 0xABCD, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_FORMERR, RCODE_FORMERR, nil)
	if len(r.wires) != 0 {
		t.Errorf("forwarded %d wires, want none", len(r.wires))
	}
}

// forwardedCase is a query Unbound rejects or answers before it resolves a name: its reply is the answer, the module
// is not asked. `parsed` says whether the decider read the packet, so that its SERVFAIL echoes the question.
type forwardedCase struct {
	name   string
	wire   []byte
	parsed bool
}

func forwardedCases(t *testing.T) []forwardedCase {
	nullRR := dnswire.RR{Name: ".", Rtype: 10, Rclass: dnswire.CLASS_IN}
	blocked := aRecord(allowed, 60, 1)
	build := func(flags, qclass uint16, answers, authority, additional []dnswire.RR) []byte {
		return encode(t, &dnswire.Message{ID: 0x4242, Flags: flags, Questions: question(allowed, qclass), Answers: answers, Authority: authority, Additional: additional})
	}
	name, err := dnswire.EncodeName(allowed)
	if err != nil {
		t.Fatal(err)
	}
	return []forwardedCase{
		{"TC set", build(dnswire.RD|dnswire.TC, dnswire.CLASS_IN, nil, nil, nil), false},
		{"an answer record", build(dnswire.RD, dnswire.CLASS_IN, []dnswire.RR{blocked}, nil, nil), false},
		{"an authority record", build(dnswire.RD, dnswire.CLASS_IN, nil, []dnswire.RR{blocked}, nil), false},
		{"two additional records", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, []dnswire.RR{opt(0, "."), nullRR}), false},
		{"two OPT records", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, []dnswire.RR{opt(0, "."), opt(0, ".")}), false},
		{"nine additional records", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, slices.Repeat([]dnswire.RR{nullRR}, 9)), false},
		{"one additional record that is not an OPT", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, []dnswire.RR{nullRR}), true},
		{"an OPT of EDNS version 1", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, []dnswire.RR{opt(1, ".")}), true},
		{"an OPT not owned by the root", build(dnswire.RD, dnswire.CLASS_IN, nil, nil, []dnswire.RR{opt(0, "example.")}), true},
		{"class CH", build(dnswire.RD, 3, nil, nil, nil), true},
		{"class HS", build(dnswire.RD, 4, nil, nil, nil), true},
		{"opcode UPDATE", build(dnswire.RD|5<<11, dnswire.CLASS_IN, nil, nil, nil), false},
		{"opcode IQUERY", build(dnswire.RD|1<<11, dnswire.CLASS_IN, nil, nil, nil), false},
		{"opcode STATUS", build(dnswire.RD|2<<11, dnswire.CLASS_IN, nil, nil, nil), false},
		{"an answer section the parser cannot read", slices.Concat(header(0x4242, dnswire.RD, 1, 1, 0, 0), name, qtc, []byte{0xFF}), false},
	}
}

func TestResolveForwardsWhatUnboundAnswersItselfUnchanged(t *testing.T) {
	f := newTestFrontend(t)
	for _, c := range forwardedCases(t) {
		for _, transport := range []string{"UDP", "TCP"} {
			r := answering([]byte(unboundSaid))
			reply := f.resolve(c.wire, testClient, r.forward, transport, "", "")
			if string(reply) != unboundSaid || len(r.wires) != 1 || !bytes.Equal(r.wires[0], c.wire) {
				t.Errorf("%s over %s: reply %q, forwarded %x, want Unbound's reply and the client's own bytes %x", c.name, transport, reply, r.wires, c.wire)
			}
		}
	}
}

func TestResolveServfailsAForwardedQueryUnboundDoesNotAnswerWithoutLoggingIt(t *testing.T) {
	f := newTestFrontend(t)
	out := captureLog(t)
	for _, c := range forwardedCases(t) {
		var questions []dnswire.Question
		if c.parsed {
			questions = parse(t, c.wire).Questions
		}
		flags := binary.BigEndian.Uint16(c.wire[2:])
		reply := f.resolve(c.wire, testClient, (&recorder{}).forward, "UDP", "", "")
		// As the SERVFAIL of a module-decided query: id, RD, CD and the opcode kept.
		want := dnswire.QR | dnswire.RA | (flags & (dnswire.RD | dnswire.CD | dnswire.OPCODE_MASK)) | RCODE_SERVFAIL
		wantBare(t, c.name, reply, 0x4242, want, RCODE_SERVFAIL, questions)
	}
	if lines := logLines(out); len(lines) != 0 {
		t.Errorf("forwarded queries logged %q, want nothing: silence is logged on the module's path only", lines)
	}
}

// --- resolve: the module decides, Unbound answers -------------------------------------------------

func TestResolveRelaysUnboundsReplyByteForByte(t *testing.T) {
	f := newTestFrontend(t)
	out := captureLog(t)
	for _, transport := range []string{"UDP", "TCP", "Unknown", ""} {
		wire := queryWire(t, allowed, dnswire.RD, dnswire.MakeOpt(4096, true, nil))
		// Trailing bytes after the last record: the parser ignores them, a re-encoding would lose them.
		upstream := append(replyTo(t, wire, 0, aRecord(allowed, 300, 1)), 0xDE, 0xAD)
		r := answering(upstream)
		reply := f.resolve(wire, testClient, r.forward, transport, "", "")
		if !bytes.Equal(reply, upstream) || len(r.wires) != 1 || !bytes.Equal(r.wires[0], wire) {
			t.Errorf("transport %q: reply %x, forwarded %x, want Unbound's exact bytes %x for the client's exact query %x", transport, reply, r.wires, upstream, wire)
		}
	}
	if lines := logLines(out); len(lines) != 0 {
		t.Errorf("a relayed answer logged %q", lines)
	}
}

func TestResolveRelaysUnboundErrorRepliesUnchanged(t *testing.T) {
	f := newTestFrontend(t)
	out := captureLog(t)
	for name, rcode := range map[string]uint16{"SERVFAIL": 2, "NXDOMAIN": 3, "REFUSED": 5} {
		wire := queryWire(t, allowed, dnswire.RD)
		upstream := replyTo(t, wire, rcode)
		reply := f.resolve(wire, testClient, answering(upstream).forward, "UDP", "", "")
		if !bytes.Equal(reply, upstream) {
			t.Errorf("%s: reply %x, want Unbound's reply %x untouched (the module left it alone)", name, reply, upstream)
		}
	}
	if lines := logLines(out); len(lines) != 0 {
		t.Errorf("relayed errors logged %q", lines)
	}
}

func TestResolveRelaysAReplyThatCarriesNoQuestion(t *testing.T) {
	f := newTestFrontend(t)
	// Unbound's access-control REFUSED has no question section at all.
	refused := header(0x1234, dnswire.QR|dnswire.RD|dnswire.RA|5, 0, 0, 0, 0)
	reply := f.resolve(queryWire(t, allowed, dnswire.RD), testClient, answering(refused).forward, "UDP", "", "")
	if !bytes.Equal(reply, refused) {
		t.Errorf("reply %x, want the 12-byte REFUSED %x relayed as it is", reply, refused)
	}
}

func TestResolveServfailsWhenUnboundGivesNoReply(t *testing.T) {
	for _, do := range []bool{false, true} {
		f := newTestFrontend(t)
		out := captureLog(t)
		wire := encode(t, &dnswire.Message{ID: 0x0B0B, Flags: dnswire.RD, Questions: question(allowed, dnswire.CLASS_IN), Additional: []dnswire.RR{dnswire.MakeOpt(4096, do, nil)}})
		r := &recorder{}
		reply := f.resolve(wire, testClient, r.forward, "UDP", "", "")
		wantBare(t, "silent", reply, 0x0B0B, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_SERVFAIL, RCODE_SERVFAIL, question(allowed, dnswire.CLASS_IN))
		wantOnlyOpt(t, "silent", parse(t, reply).Additional, do)
		if len(r.wires) != 1 || !bytes.Equal(r.wires[0], wire) {
			t.Errorf("do=%v: forwarded %x, want the client's query once", do, r.wires)
		}
		if lines := logLines(out); !slices.Equal(lines, []string{"pfb_dns_proxy warning: no reply from Unbound for allowed.example. A"}) {
			t.Errorf("do=%v: log = %q, want the one silence warning naming the query", do, lines)
		}
	}
}

func TestResolveTakesAReplyTooShortForAHeaderForNoReply(t *testing.T) {
	for name, short := range map[string][]byte{"zero-length": {}, "the id alone": {0x0B, 0x0B}, "eleven bytes": make([]byte, 11)} {
		f := newTestFrontend(t)
		out := captureLog(t)
		wire := queryWire(t, allowed, dnswire.RD)
		reply := f.resolve(wire, testClient, answering(short).forward, "UDP", "", "")
		wantBare(t, name, reply, 0x4242, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_SERVFAIL, RCODE_SERVFAIL, question(allowed, dnswire.CLASS_IN))
		if lines := logLines(out); len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy warning: no reply from Unbound for ") {
			t.Errorf("%s: log = %q, want one silence warning", name, lines)
		}
	}
}

func TestResolveServfailsAMalformedReplyAndLogsItOnce(t *testing.T) {
	f := newTestFrontend(t)
	out := captureLog(t)
	garbage := append(header(0x4242, dnswire.QR|dnswire.RD|dnswire.RA, 1, 0, 0, 0), 5, 'a', 'b') // a 5-octet label, 2 present
	reply := f.resolve(queryWire(t, allowed, dnswire.RD), testClient, answering(garbage).forward, "UDP", "", "")
	wantBare(t, "malformed", reply, 0x4242, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_SERVFAIL, RCODE_SERVFAIL, question(allowed, dnswire.CLASS_IN))
	if lines := logLines(out); len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy error: ") {
		t.Errorf("log = %q, want exactly one error line (Unbound did answer, so no silence warning)", lines)
	}
}

// --- resolve: Unbound's silence is logged once per window -----------------------------------------

type silenceStep struct {
	pause time.Duration
	name  string
	qtype uint16
}

// silenceLog resolves the steps in order on a manual clock and returns the silence warnings logged. Unbound answers
// every name that does not start with "silent".
func silenceLog(t *testing.T, f *Frontend, steps []silenceStep) []string {
	t.Helper()
	out := captureLog(t)
	var now time.Duration
	f.monotonic = func() time.Duration { return now }
	for _, step := range steps {
		now += step.pause
		wire := encode(t, &dnswire.Message{ID: 0x4242, Flags: dnswire.RD, Questions: []dnswire.Question{{Name: step.name, Qtype: step.qtype, Qclass: dnswire.CLASS_IN}}})
		r := &recorder{answer: func(wire []byte) []byte {
			if strings.HasPrefix(parse(t, wire).Questions[0].Name, "silent") {
				return nil
			}
			return replyTo(t, wire, 0)
		}}
		f.resolve(wire, testClient, r.forward, "UDP", "", "")
	}
	var warnings []string
	for _, line := range logLines(out) {
		if strings.Contains(line, "no reply from Unbound") {
			warnings = append(warnings, line)
		}
	}
	return warnings
}

func TestResolveLogsUnboundsSilenceOncePerInterval(t *testing.T) {
	const prefix = "pfb_dns_proxy warning: no reply from Unbound for "
	got := silenceLog(t, newTestFrontend(t), []silenceStep{
		{0, "silent0.example.", dnswire.TYPE_A}, // the first one is logged, though the clock reads 0
		{0, allowed, dnswire.TYPE_A},            // an answer in between does not re-arm the line
		{0, "silent1.example.", dnswire.TYPE_A},
		{29500 * time.Millisecond, "silent2.example.", dnswire.TYPE_A},  // 29.5 s into the window
		{500 * time.Millisecond, "silent3.example.", dnswire.TYPE_AAAA}, // exactly 30 s: the next window
		{0, "silent4.example.", dnswire.TYPE_A},
	})
	if want := []string{prefix + "silent0.example. A", prefix + "silent3.example. AAAA"}; !slices.Equal(got, want) {
		t.Errorf("silence log = %q, want %q", got, want)
	}
}

func TestResolveLogsOneSilenceLinePerIntervalWhateverIsAnsweredInBetween(t *testing.T) {
	var steps []silenceStep
	for second := range 60 {
		pause := time.Second
		if second == 0 {
			pause = 0
		}
		steps = append(steps,
			silenceStep{pause, fmt.Sprintf("silent%da.example.", second), dnswire.TYPE_A},
			silenceStep{0, fmt.Sprintf("silent%db.example.", second), dnswire.TYPE_A},
			silenceStep{0, allowed, dnswire.TYPE_A})
	}
	got := silenceLog(t, newTestFrontend(t), steps)
	// Sixty seconds of two silent queries per answered one are two windows: the answer each second never re-arms it.
	if len(got) != 2 || !strings.HasSuffix(got[0], "silent0a.example. A") || !strings.HasSuffix(got[1], "silent30a.example. A") {
		t.Errorf("silence log = %q, want two lines: the first query and the one 30 s later", got)
	}
}

func TestEachFrontendKeepsItsOwnSilenceWindow(t *testing.T) {
	module := bootModule(t)
	steps := []silenceStep{{0, "silent0.example.", dnswire.TYPE_A}}
	first := silenceLog(t, newFrontend(module), steps)
	second := silenceLog(t, newFrontend(module), steps)
	if len(first) != 1 || len(second) != 1 {
		t.Errorf("(first, second) silence lines = (%q, %q), want one each: a window belongs to its Frontend", first, second)
	}
}
