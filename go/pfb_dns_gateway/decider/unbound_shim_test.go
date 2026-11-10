// Tests of unbound_shim.go: what the module reads of Unbound's reply and query objects, as
// tests/dns_proxy/test_unbound_shim.py checks them for the Python shim.
package decider

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

func aRecord(name string, ttl uint32, last byte) dnswire.RR {
	return dnswire.RR{Name: name, Rtype: dnswire.TYPE_A, Rclass: dnswire.CLASS_IN, TTL: ttl, Rdata: []byte{192, 0, 2, last}}
}

// rrsigOf is an RRSIG over `covered` with a 20-octet body, the first two octets being the covered type.
func rrsigOf(name string, covered uint16, class uint16, ttl uint32) dnswire.RR {
	rdata := append([]byte{byte(covered >> 8), byte(covered)}, make([]byte, 18)...)
	return dnswire.RR{Name: name, Rtype: dnswire.TYPE_RRSIG, Rclass: class, TTL: ttl, Rdata: rdata}
}

// rrData is Unbound's rr_data layout: a 2-octet rdlength, then the rdata.
func rrData(rdata []byte) []byte {
	return append([]byte{byte(len(rdata) >> 8), byte(len(rdata))}, rdata...)
}

func typeStrings(sets []*rrSet) []string {
	var out []string
	for _, set := range sets {
		out = append(out, set.rk.typeStr)
	}
	return out
}

func checkRrset(t *testing.T, what string, set *rrSet, count, rrsigCount int, data [][]byte, ttls []uint32) {
	t.Helper()
	got := set.entry.data
	if got.count != count || got.rrsigCount != rrsigCount {
		t.Errorf("%s: (count, rrsigCount) = (%d, %d), want (%d, %d)", what, got.count, got.rrsigCount, count, rrsigCount)
	}
	if !slices.EqualFunc(got.rrData, data, bytes.Equal) {
		t.Errorf("%s: rrData = %x, want %x", what, got.rrData, data)
	}
	if !slices.Equal(got.rrTTL, ttls) {
		t.Errorf("%s: rrTTL = %v, want %v", what, got.rrTTL, ttls)
	}
}

func TestBuildRrsetsGroupsPerOwnerTypeAndClassWithinASection(t *testing.T) {
	anyClassA := dnswire.RR{Name: "a.example.", Rtype: dnswire.TYPE_A, Rclass: dnswire.CLASS_ANY, TTL: 5, Rdata: []byte{192, 0, 2, 3}}
	aaaa := dnswire.RR{Name: "a.example.", Rtype: dnswire.TYPE_AAAA, Rclass: dnswire.CLASS_IN, TTL: 90, Rdata: make([]byte, 16)}
	sections := [3][]dnswire.RR{
		{aRecord("a.example.", 60, 1), aRecord("A.Example.", 30, 2), anyClassA, aaaa},
		{aRecord("a.example.", 20, 4)},                                    // the same key as the first answer RR, in another section: its own rrset
		{dnswire.MakeOpt(4096, false, nil), aRecord("b.example.", 90, 5)}, // EDNS is dropped, its TTL 0 never the minimum
	}
	sets, counts, ttl := buildRrsets(sections)
	if counts != [3]int{3, 1, 1} {
		t.Errorf("per-section rrset counts = %v, want [3 1 1]", counts)
	}
	if ttl != 5 {
		t.Errorf("minimum TTL = %d, want 5", ttl)
	}
	if want := []string{"A", "A", "AAAA", "A", "A"}; !slices.Equal(typeStrings(sets), want) {
		t.Fatalf("rrset types = %v, want %v", typeStrings(sets), want)
	}
	// Owner case folds into one set; the RRs keep the order they came in.
	checkRrset(t, "A/IN a.example.", sets[0], 2, 0, [][]byte{rrData([]byte{192, 0, 2, 1}), rrData([]byte{192, 0, 2, 2})}, []uint32{60, 30})
	checkRrset(t, "A/ANY a.example.", sets[1], 1, 0, [][]byte{rrData([]byte{192, 0, 2, 3})}, []uint32{5})
	checkRrset(t, "authority A", sets[3], 1, 0, [][]byte{rrData([]byte{192, 0, 2, 4})}, []uint32{20})
}

func TestBuildRrsetsWithNothingToGroup(t *testing.T) {
	sets, counts, ttl := buildRrsets([3][]dnswire.RR{})
	if len(sets) != 0 || counts != [3]int{} || ttl != 0 {
		t.Errorf("empty sections gave (%d sets, %v, ttl %d), want (0 sets, [0 0 0], ttl 0)", len(sets), counts, ttl)
	}
}

func TestBuildRrsetsAttachesAnRrsigToTheSetItCovers(t *testing.T) {
	first, second, other := aRecord("a.example.", 60, 1), aRecord("a.example.", 61, 3), aRecord("b.example.", 60, 2)
	sig := rrsigOf("a.example.", dnswire.TYPE_A, dnswire.CLASS_IN, 99)
	sets, counts, _ := buildRrsets([3][]dnswire.RR{{first, sig, other, second}, nil, nil})
	if counts[0] != 2 {
		t.Fatalf("answer rrset count = %d, want 2: the RRSIG is no rrset of its own", counts[0])
	}
	// RRs come first, then the RRSIGs, whatever the order on the wire.
	checkRrset(t, "covered set", sets[0], 2, 1,
		[][]byte{rrData(first.Rdata), rrData(second.Rdata), rrData(sig.Rdata)}, []uint32{60, 61, 99})
	checkRrset(t, "other owner", sets[1], 1, 0, [][]byte{rrData(other.Rdata)}, []uint32{60})
}

func TestBuildRrsetsKeepsAnRrsigThatCoversNothingAsItsOwnSet(t *testing.T) {
	record := aRecord("a.example.", 60, 1)
	for _, row := range []struct {
		name    string
		section []dnswire.RR
	}{
		{"it comes before the RR it covers", []dnswire.RR{rrsigOf("a.example.", dnswire.TYPE_A, dnswire.CLASS_IN, 99), record}},
		{"another class", []dnswire.RR{record, rrsigOf("a.example.", dnswire.TYPE_A, dnswire.CLASS_ANY, 99)}},
		{"another type", []dnswire.RR{record, rrsigOf("a.example.", dnswire.TYPE_AAAA, dnswire.CLASS_IN, 99)}},
		{"rdata too short to name the covered type", []dnswire.RR{record, {Name: "a.example.", Rtype: dnswire.TYPE_RRSIG, Rclass: dnswire.CLASS_IN, TTL: 99, Rdata: []byte{0}}}},
	} {
		sets, counts, _ := buildRrsets([3][]dnswire.RR{row.section, nil, nil})
		if counts[0] != 2 || len(sets) != 2 {
			t.Errorf("%s: %d rrsets (counts %v), want 2", row.name, len(sets), counts)
			continue
		}
		for _, set := range sets {
			if set.entry.data.rrsigCount != 0 {
				t.Errorf("%s: an RRSIG was attached to %s", row.name, set.rk.typeStr)
			}
		}
		if got := typeStrings(sets); !slices.Contains(got, "RRSIG") {
			t.Errorf("%s: rrset types = %v, want one of them RRSIG", row.name, got)
		}
	}
}

func TestNewDnsMsgFlagsAndAuthoritativeBit(t *testing.T) {
	qinfo := queryInfo{qnameStr: "a.example.", qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}
	msg := newDnsMsg(qinfo, dnswire.QR|dnswire.AA|3, []dnswire.RR{aRecord("a.example.", 60, 1)}, nil, nil)
	if msg.rep.flags != dnswire.QR|dnswire.AA|3 || msg.rep.authoritative != 1 {
		t.Errorf("flags %#x authoritative %d, want %#x and 1", msg.rep.flags, msg.rep.authoritative, dnswire.QR|dnswire.AA|3)
	}
	if msg.rep.security != secStatusUnchecked || msg.rep.anNumrrsets != 1 || msg.rep.ttl != 60 {
		t.Errorf("(security, an, ttl) = (%d, %d, %d), want (%d, 1, 60)", msg.rep.security, msg.rep.anNumrrsets, msg.rep.ttl, secStatusUnchecked)
	}
	if msg.qinfo != qinfo {
		t.Errorf("qinfo = %+v, want %+v", msg.qinfo, qinfo)
	}
	plain := newDnsMsg(qinfo, dnswire.QR, nil, nil, nil)
	if plain.rep.authoritative != 0 {
		t.Errorf("authoritative without AA = %d, want 0", plain.rep.authoritative)
	}
}

func TestDnsMsgFromMessageDropsEdnsAndClearsCD(t *testing.T) {
	cname, err := dnswire.RRFromText("alias.example. 300 IN CNAME blocked.example.")
	if err != nil {
		t.Fatal(err)
	}
	address, err := dnswire.RRFromText("blocked.example. 300 IN A 192.0.2.99")
	if err != nil {
		t.Fatal(err)
	}
	glue := aRecord("ns.example.", 300, 7)
	wire, err := dnswire.Encode(&dnswire.Message{
		ID:         7,
		Flags:      dnswire.QR | dnswire.RD | dnswire.RA | dnswire.CD,
		Questions:  []dnswire.Question{{Name: "Alias.Example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}},
		Answers:    []dnswire.RR{cname, address},
		Additional: []dnswire.RR{dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, false, nil), glue},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := dnswire.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := dnsMsgFromMessage(message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := dnswire.QR | dnswire.RD | dnswire.RA; msg.rep.flags != want {
		t.Errorf("flags = %#x, want %#x (CD cleared, the rest kept)", msg.rep.flags, want)
	}
	if len(msg.additional) != 1 || msg.additional[0].Rtype != dnswire.TYPE_A {
		t.Errorf("additional = %+v, want the glue A alone: EDNS is removed", msg.additional)
	}
	if got := [3]int{msg.rep.anNumrrsets, msg.rep.nsNumrrsets, msg.rep.arNumrrsets}; got != [3]int{2, 0, 1} {
		t.Errorf("rrset counts = %v, want [2 0 1]", got)
	}
	if got, want := typeStrings(msg.rep.rrsets), []string{"CNAME", "A", "A"}; !slices.Equal(got, want) {
		t.Fatalf("rrset types = %v, want %v", got, want)
	}
	// The parsed CNAME rdata is uncompressed: rdlength 17, then 7"blocked"7"example"0.
	if want := []byte("\x00\x11\x07blocked\x07example\x00"); !bytes.Equal(msg.rep.rrsets[0].entry.data.rrData[0], want) {
		t.Errorf("CNAME rr_data = %q, want %q", msg.rep.rrsets[0].entry.data.rrData[0], want)
	}
	if want := (queryInfo{qnameStr: "Alias.Example.", qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}); msg.qinfo != want {
		t.Errorf("qinfo = %+v, want %+v (the client's case kept)", msg.qinfo, want)
	}
}

func TestDnsMsgFromMessageQuestionSources(t *testing.T) {
	fallback := &dnswire.Question{Name: "fallback.example.", Qtype: dnswire.TYPE_AAAA, Qclass: dnswire.CLASS_ANY}
	own := dnswire.Question{Name: "own.example.", Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}

	withQuestion := &dnswire.Message{Flags: dnswire.QR, Questions: []dnswire.Question{own}}
	msg, err := dnsMsgFromMessage(withQuestion, fallback)
	if err != nil || msg.qinfo.qnameStr != "own.example." || msg.qinfo.qtype != dnswire.TYPE_A || msg.qinfo.qclass != dnswire.CLASS_IN {
		t.Errorf("reply with a question and a fallback: (%+v, %v), want the reply's own question", msg, err)
	}

	noQuestion := &dnswire.Message{Flags: dnswire.QR | 5}
	msg, err = dnsMsgFromMessage(noQuestion, fallback)
	if err != nil || msg.qinfo != (queryInfo{qnameStr: "fallback.example.", qtype: dnswire.TYPE_AAAA, qclass: dnswire.CLASS_ANY}) {
		t.Errorf("reply without a question, with a fallback: (%+v, %v), want the fallback question", msg, err)
	}

	if msg, err = dnsMsgFromMessage(noQuestion, nil); err == nil || msg != nil {
		t.Errorf("reply without a question or a fallback: (%+v, %v), want an error and no message", msg, err)
	}
}

func TestSetReturnMsgMapsEachPktFlagToItsWireBit(t *testing.T) {
	for _, row := range []struct {
		name string
		pkt  int
		wire uint16
	}{
		{"PKT_QR", PKT_QR, 0x8000}, {"PKT_AA", PKT_AA, 0x0400}, {"PKT_TC", PKT_TC, 0x0200}, {"PKT_RD", PKT_RD, 0x0100},
		{"PKT_CD", PKT_CD, 0x0010}, {"PKT_RA", PKT_RA, 0x0080}, {"PKT_AD", PKT_AD, 0x0020},
		{"all seven", PKT_QR | PKT_AA | PKT_TC | PKT_RD | PKT_CD | PKT_RA | PKT_AD, 0x87B0},
		{"none", 0, 0},
	} {
		qstate := newModuleQstate(queryInfo{qnameStr: "blocked.example.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, "192.0.2.10", 40000, 0x0100, "UDP", "", "")
		if !newDNSMessage("blocked.example.", RR_TYPE_A, RR_CLASS_IN, row.pkt).setReturnMsg(qstate) {
			t.Errorf("%s: setReturnMsg reported failure", row.name)
			continue
		}
		if qstate.returnMsg.rep.flags != row.wire {
			t.Errorf("%s: wire flags = %#04x, want %#04x", row.name, qstate.returnMsg.rep.flags, row.wire)
		}
	}
}

func TestSetReturnMsgBuildsTheSectionsFromTextRRs(t *testing.T) {
	qstate := newModuleQstate(queryInfo{qnameStr: "blocked.example.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, "192.0.2.10", 40000, 0x0100, "UDP", "", "")
	old := &dnsMsg{}
	qstate.returnMsg = old
	m := newDNSMessage("Blocked.Example.", RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR|PKT_AA|PKT_RA)
	m.answer = []string{"blocked.example. 3600 IN A 10.10.10.1"}
	m.authority = []string{"blocked.example. 3600 IN SOA pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600"}
	m.additional = []string{"ns.example. 60 IN A 10.10.10.2"}
	if !m.setReturnMsg(qstate) {
		t.Fatal("setReturnMsg reported failure")
	}
	msg := qstate.returnMsg
	if msg == old {
		t.Fatal("returnMsg was not replaced")
	}
	if want := (queryInfo{qnameStr: "Blocked.Example.", qtype: RR_TYPE_AAAA, qclass: RR_CLASS_IN}); msg.qinfo != want {
		t.Errorf("qinfo = %+v, want %+v", msg.qinfo, want)
	}
	if want := uint16(0x8000 | 0x0400 | 0x0080); msg.rep.flags != want || msg.rep.authoritative != 1 {
		t.Errorf("(flags, authoritative) = (%#x, %d), want (%#x, 1)", msg.rep.flags, msg.rep.authoritative, want)
	}
	if got := [3]int{msg.rep.anNumrrsets, msg.rep.nsNumrrsets, msg.rep.arNumrrsets}; got != [3]int{1, 1, 1} {
		t.Errorf("rrset counts = %v, want [1 1 1]", got)
	}
	if msg.rep.ttl != 60 || msg.rep.security != secStatusUnchecked {
		t.Errorf("(ttl, security) = (%d, %d), want (60, %d)", msg.rep.ttl, msg.rep.security, secStatusUnchecked)
	}
	if got, want := typeStrings(msg.rep.rrsets), []string{"A", "SOA", "A"}; !slices.Equal(got, want) {
		t.Fatalf("rrset types = %v, want %v", got, want)
	}
	checkRrset(t, "answer A", msg.rep.rrsets[0], 1, 0, [][]byte{{0, 4, 10, 10, 10, 1}}, []uint32{3600})
	if len(msg.answer) != 1 || len(msg.authority) != 1 || len(msg.additional) != 1 {
		t.Fatalf("section sizes = (%d, %d, %d), want one RR each", len(msg.answer), len(msg.authority), len(msg.additional))
	}
	if want := []byte{10, 10, 10, 1}; !bytes.Equal(msg.answer[0].Rdata, want) {
		t.Errorf("answer rdata = %x, want %x", msg.answer[0].Rdata, want)
	}
}

func TestSetReturnMsgFailsWithoutTouchingReturnMsg(t *testing.T) {
	for _, row := range []struct {
		name  string
		build func(m *DNSMessage)
	}{
		{"an answer RR with an unparseable address", func(m *DNSMessage) { m.answer = []string{"blocked.example. 3600 IN A not-an-address"} }},
		{"an authority RR of an unsupported type", func(m *DNSMessage) { m.authority = []string{"blocked.example. 3600 IN MX 10 mail.example."} }},
		{"an additional RR that is no record", func(m *DNSMessage) { m.additional = []string{"nonsense"} }},
		{"an empty owner name", func(m *DNSMessage) { m.rrName = "" }},
		{"a label over 63 octets", func(m *DNSMessage) { m.rrName = strings.Repeat("a", 64) + ".example." }},
	} {
		qstate := newModuleQstate(queryInfo{qnameStr: "blocked.example.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, "192.0.2.10", 40000, 0x0100, "UDP", "", "")
		kept := &dnsMsg{}
		qstate.returnMsg = kept
		m := newDNSMessage("blocked.example.", RR_TYPE_A, RR_CLASS_IN, PKT_QR)
		m.answer = []string{"blocked.example. 3600 IN A 10.10.10.1"}
		row.build(m)
		if m.setReturnMsg(qstate) {
			t.Errorf("%s: setReturnMsg reported success", row.name)
		}
		if qstate.returnMsg != kept {
			t.Errorf("%s: returnMsg was replaced", row.name)
		}
	}
}

func TestQueryInfoExposesWhatTheModuleReads(t *testing.T) {
	qinfo := queryInfo{qnameStr: "Sub.Blocked.Example.", qtype: RR_TYPE_AAAA, qclass: RR_CLASS_IN}
	labels, err := qinfo.qnameList()
	if want := []string{"Sub", "Blocked", "Example", ""}; err != nil || !slices.Equal(labels, want) {
		t.Errorf("qnameList = (%q, %v), want (%q, nil): client case kept, root label included so the TLD is [-2]", labels, err, want)
	}
	if got := qinfo.qtypeStr(); got != "AAAA" {
		t.Errorf("qtypeStr = %q, want AAAA", got)
	}
	if got := (&queryInfo{qnameStr: "x.", qtype: 65280}).qtypeStr(); got != "TYPE65280" {
		t.Errorf("qtypeStr of an unnamed type = %q, want TYPE65280", got)
	}
	root := queryInfo{qnameStr: "."}
	if labels, err := root.qnameList(); err != nil || !slices.Equal(labels, []string{""}) {
		t.Errorf("qnameList of the root = (%q, %v), want ([\"\"], nil)", labels, err)
	}
}

func TestQnameListFailsWhereTheRealPropertyRaises(t *testing.T) {
	for name, qname := range map[string]string{
		"a label that is not UTF-8": "\\255.example.",
		"a name that is no name":    "",
	} {
		q := queryInfo{qnameStr: qname}
		if labels, err := q.qnameList(); err == nil {
			t.Errorf("%s: qnameList = %q, want an error", name, labels)
		}
	}
}

func TestNewModuleQstateStartsUnfinished(t *testing.T) {
	qinfo := queryInfo{qnameStr: "blocked.example.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}
	qstate := newModuleQstate(qinfo, "2001:db8::7", 40000, 0x0100, "TCP", "2001:db8::53", "vlan10")
	if qstate.qinfo != qinfo || qstate.queryFlags != 0x0100 || qstate.clientIP != "2001:db8::7" || qstate.clientPort != 40000 {
		t.Errorf("identity fields = %+v", qstate)
	}
	if qstate.pfbTransport != "TCP" || qstate.pfbListenerIP != "2001:db8::53" || qstate.pfbListenerInterface != "vlan10" {
		t.Errorf("endpoint fields = (%q, %q, %q), want (TCP, 2001:db8::53, vlan10)", qstate.pfbTransport, qstate.pfbListenerIP, qstate.pfbListenerInterface)
	}
	if qstate.returnMsg != nil || qstate.returnRcode != RCODE_NOERROR || qstate.noCacheStore != 0 {
		t.Errorf("(returnMsg, returnRcode, noCacheStore) = (%v, %d, %d), want (nil, %d, 0)", qstate.returnMsg, qstate.returnRcode, qstate.noCacheStore, RCODE_NOERROR)
	}
	if qstate.extState != [16]int{} {
		t.Errorf("extState = %v, want sixteen zeros: one per module", qstate.extState)
	}
	qstate.extState[MODULE_ID] = MODULE_WAIT_MODULE
	if qstate.extState[0] != MODULE_WAIT_MODULE || qstate.extState[1] != 0 {
		t.Errorf("extState after setting the module's slot = %v", qstate.extState[:2])
	}
}

func TestLogFunctionsWriteTheLevelAndTheMessage(t *testing.T) {
	var out bytes.Buffer
	previous := logOutput
	logOutput = &out
	t.Cleanup(func() { logOutput = previous })
	logInfo("alpha")
	logWarn("beta")
	logErr("gamma")
	want := "pfb_dns_proxy info: alpha\npfb_dns_proxy warning: beta\npfb_dns_proxy error: gamma\n"
	if out.String() != want {
		t.Errorf("log output = %q, want %q", out.String(), want)
	}
}

// The SafeSearch pass calls both for every query and the proxy runs for weeks: neither keeps anything or touches the query.
func TestTheCacheCallsAreNoOpsThatRememberNothing(t *testing.T) {
	qstate := newModuleQstate(queryInfo{qnameStr: "duck.example.", qtype: dnswire.TYPE_A, qclass: dnswire.CLASS_IN}, "192.0.2.10", 0, 0, "UDP", "", "")
	before := *qstate
	for range 1000 {
		if !storeQueryInCache(qstate, qstate.qinfo, nil, 1) {
			t.Fatal("storeQueryInCache = false, want true: the shim's store always succeeds")
		}
		invalidateQueryInCache(qstate, qstate.qinfo)
	}
	if !reflect.DeepEqual(*qstate, before) {
		t.Errorf("the cache calls changed the query state to %+v, was %+v", *qstate, before)
	}
}

// The values come from pythonmod's interface.i and util/module.h, typed here independently of unbound_shim.go.
func TestShimConstantsCarryUnboundsValues(t *testing.T) {
	for name, pair := range map[string][2]int{
		"MODULE_ID":              {MODULE_ID, 0},
		"RR_TYPE_SIG":            {int(RR_TYPE_SIG), 24},
		"RR_TYPE_SRV":            {int(RR_TYPE_SRV), 33},
		"RR_TYPE_DNAME":          {int(RR_TYPE_DNAME), 39},
		"RR_TYPE_ANY":            {int(RR_TYPE_ANY), 255},
		"RCODE_NXDOMAIN":         {RCODE_NXDOMAIN, 3},
		"MODULE_EVENT_NEW":       {MODULE_EVENT_NEW, 0},
		"MODULE_EVENT_PASS":      {MODULE_EVENT_PASS, 1},
		"MODULE_EVENT_MODDONE":   {MODULE_EVENT_MODDONE, 5},
		"MODULE_WAIT_MODULE":     {MODULE_WAIT_MODULE, 2},
		"MODULE_RESTART_NEXT":    {MODULE_RESTART_NEXT, 3},
		"MODULE_WAIT_SUBQUERY":   {MODULE_WAIT_SUBQUERY, 4},
		"MODULE_ERROR":           {MODULE_ERROR, 5},
		"MODULE_FINISHED":        {MODULE_FINISHED, 6},
		"secStatusIndeterminate": {secStatusIndeterminate, 2},
		"secStatusInsecure":      {secStatusInsecure, 3},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %d, want %d", name, pair[0], pair[1])
		}
	}
}
