// Tests of pfb_dns_proxy.go's SafeSearch chase (Frontend._chase_cname and the MODULE_RESTART_NEXT dispatch in resolve),
// as tests/dns_proxy/test_safesearch.py checks them for the Python Frontend with the real module. The rows that need a
// real Unbound (test_gateway_e2e.py, test_gateway_safesearch.py, test_gateway_chase.py, test_integration_unbound.py)
// run in-process here: the gateway's TCP retry of a truncated chase is the gateway's, so the decider sees the target's
// whole answer, which is what the UDP-size and stream rows feed it.
package decider

import (
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
)

const (
	ssClient = testClient
	ssDuck   = "duck.example."
	ssTarget = "safe.duck.example."
	adBit    = 0x0020 // DNSSEC authenticated data: dnswire does not name it, and the proxy never sets it on its own answers
)

var (
	ssVIP4       = []byte{10, 10, 10, 1}
	ssTargetA    = []byte{192, 0, 2, 88}
	ssTargetAAAA = netip.MustParseAddr("2001:db8::88").AsSlice()
	// EDNS Client Subnet: 192.0.2.0/24
	ssECS = []byte{0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2}
)

// ssCsv is pfb_py_ss.txt as pfb_ss_csv_rows() writes a CNAME redirect: domain,cname,target,baked_v4,baked_v6, as
// tests/dns_proxy/frontend_constants.py SAFESEARCH_CSV does. The baked addresses differ from every address the fake
// authoritative serves, so an answer shows whether the target was chased or the module's baked fallback ran. odd.example
// has a target whose planted CNAME the module cannot read back as its own (the label holds a dot).
var ssCsv = []string{
	"duck.example,cname,safe.duck.example,198.51.100.7,2001:db8::7",
	"www.duck.example,cname,safe.duck.example,198.51.100.7,2001:db8::7",
	"nodata.example,cname,nodata-target.example,198.51.100.8,2001:db8::8",
	"nx.example,cname,nx-target.example,198.51.100.10,2001:db8::10",
	"servfail.example,cname,servfail-target.example,198.51.100.11,2001:db8::11",
	"silent.example,cname,silent-target.example,198.51.100.12,2001:db8::12",
	"nobaked.example,cname,nodata-target.example,,",
	"trap.example,cname,blocked.example,198.51.100.9,2001:db8::9",
	"big.example,cname,big-target.example,198.51.100.13,2001:db8::13",
	`odd.example,cname,safe\.duck.example,198.51.100.14,2001:db8::14`,
}

// ssBoot is a module dir shaped like /var/unbound, as write_module_dir shapes it: python_blocking and python_cname on,
// blocked.example on a feed, and ssCsv as the SafeSearch list.
func ssBoot(t *testing.T) *pfbUnbound {
	t.Helper()
	dir := t.TempDir()
	err := paritycorpus.WriteModule(dir, paritycorpus.Module{
		Ini: []paritycorpus.IniSection{{Name: "MAIN", Keys: [][2]string{
			{"python_enable", "true"}, {"python_blocking", "true"}, {"python_cname", "true"},
			{"dnsbl_ipv4", "10.10.10.1"}, {"dnsbl_ipv6", "fd00::1"},
		}}},
		Manifest: []byte(`{"version":1,"config":{},"feeds":[{"raw":"pfb_py_raw/feed.txt","feed":"TestFeed","group":"TestGroup","log_flag":"1"}]}`),
		Files: []paritycorpus.ModuleFile{
			{Path: "pfb_py_raw/feed.txt", Lines: []string{"blocked.example"}},
			{Path: "pfb_py_ss.txt", Lines: ssCsv},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	module, err := boot(dir)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	stopModule(t, module)
	return module
}

func ssKey(name string, qtype uint16) paritycorpus.UpstreamKey {
	return paritycorpus.UpstreamKey{Name: name, Qtype: qtype}
}

// ssZone is what Unbound's upstream serves: tests/dns_proxy/test_safesearch.py ZONE. An empty list is a NOERROR answer
// without records; nil, no reply at all.
func ssZone() map[paritycorpus.UpstreamKey][]string {
	const a, aaaa, txt = dnswire.TYPE_A, dnswire.TYPE_AAAA, dnswire.TYPE_TXT
	return map[paritycorpus.UpstreamKey][]string{
		ssKey(ssDuck, a):                      {ssDuck + " 300 IN A 192.0.2.50"},
		ssKey(ssDuck, aaaa):                   {ssDuck + " 300 IN AAAA 2001:db8::50"},
		ssKey("www.duck.example.", a):         {"www.duck.example. 300 IN A 192.0.2.50"},
		ssKey(ssTarget, a):                    {ssTarget + " 300 IN A 192.0.2.88"},
		ssKey(ssTarget, aaaa):                 {ssTarget + " 300 IN AAAA 2001:db8::88"},
		ssKey("nodata.example.", a):           {"nodata.example. 300 IN A 192.0.2.51"},
		ssKey("nodata.example.", aaaa):        {"nodata.example. 300 IN AAAA 2001:db8::51"},
		ssKey("nodata-target.example.", a):    {},
		ssKey("nodata-target.example.", aaaa): {},
		ssKey("nx.example.", a):               {"nx.example. 300 IN A 192.0.2.52"},
		ssKey("nx.example.", aaaa):            {"nx.example. 300 IN AAAA 2001:db8::52"},
		ssKey("servfail.example.", a):         {"servfail.example. 300 IN A 192.0.2.53"},
		ssKey("silent.example.", a):           {"silent.example. 300 IN A 192.0.2.54"},
		ssKey("silent-target.example.", a):    nil,
		ssKey("nobaked.example.", a):          {"nobaked.example. 300 IN A 192.0.2.55"},
		ssKey("trap.example.", a):             {"trap.example. 300 IN A 192.0.2.56"},
		ssKey("blocked.example.", a):          {"blocked.example. 300 IN A 192.0.2.99"},
		ssKey("odd.example.", a):              {"odd.example. 300 IN A 192.0.2.57"},
		ssKey(ssDuck, txt):                    {},
		ssKey("chain.example.", a): {
			"chain.example. 300 IN CNAME other.example.",
			"other.example. 300 IN A 192.0.2.60",
		},
	}
}

// ssTargetZone is ssZone with `count` addresses for the SafeSearch target, each an A record of its own.
func ssTargetZone(count int) map[paritycorpus.UpstreamKey][]string {
	zone := ssZone()
	var addresses []string
	for n := range count {
		addresses = append(addresses, fmt.Sprintf("%s 300 IN A 10.0.%d.%d", ssTarget, n/250, n%250+1))
	}
	zone[ssKey(ssTarget, dnswire.TYPE_A)] = addresses
	return zone
}

// ssForward is the gateway's forward over a FakeUnbound; a name in `override` is answered by its function instead (nil
// is silence), the query recorded either way.
func ssForward(t *testing.T, u *paritycorpus.FakeUnbound, override map[string]func(wire []byte) []byte) forward {
	return func(wire []byte) []byte {
		reply, err := u.Answer(wire)
		if err != nil {
			t.Errorf("FakeUnbound: %v", err)
		}
		if answer, ok := override[strings.ToLower(parse(t, wire).Questions[0].Name)]; ok {
			return answer(wire)
		}
		return reply
	}
}

// ssQ are the options of ssQuery, tests/dns_proxy/frontend_helpers.py build_query's keyword arguments: a zero qid is
// 0x1234 and a zero udpSize 1232; edns, do or options add an OPT, do sets its DNSSEC-OK bit and options (already
// encoded EDNS options) are its rdata.
type ssQ struct {
	qid          uint16
	cd, edns, do bool
	udpSize      uint16
	options      []byte
}

func ssQuery(t *testing.T, name string, qtype uint16, o ssQ) []byte {
	t.Helper()
	if o.qid == 0 {
		o.qid = 0x1234
	}
	if o.udpSize == 0 {
		o.udpSize = 1232
	}
	flags := dnswire.RD
	if o.cd {
		flags |= dnswire.CD
	}
	m := &dnswire.Message{ID: o.qid, Flags: flags, Questions: []dnswire.Question{{Name: name, Qtype: qtype, Qclass: dnswire.CLASS_IN}}}
	if o.edns || o.do || len(o.options) > 0 {
		var ttl uint32
		if o.do {
			ttl = 0x8000
		}
		m.Additional = []dnswire.RR{{Name: ".", Rtype: dnswire.TYPE_OPT, Rclass: o.udpSize, TTL: ttl, Rdata: o.options}}
	}
	return encode(t, m)
}

// ssResolveWire is what the client is sent; a fresh Frontend decides, as each Python test makes one.
func ssResolveWire(t *testing.T, module *pfbUnbound, wire []byte, fwd forward, transport string) []byte {
	t.Helper()
	return newFrontend(module).resolve(wire, ssClient, fwd, transport, "", "")
}

func ssResolve(t *testing.T, module *pfbUnbound, wire []byte, fwd forward, transport string) *dnswire.Message {
	t.Helper()
	return parse(t, ssResolveWire(t, module, wire, fwd, transport))
}

type ssRR struct {
	name  string
	rtype uint16
	rdata string
}

func ssAnswers(m *dnswire.Message) []ssRR {
	var out []ssRR
	for _, rr := range m.Answers {
		out = append(out, ssRR{rr.Name, rr.Rtype, string(rr.Rdata)})
	}
	return out
}

func ssCname(t *testing.T, owner, target string) ssRR {
	t.Helper()
	rdata, err := dnswire.EncodeName(target)
	if err != nil {
		t.Fatal(err)
	}
	return ssRR{owner, dnswire.TYPE_CNAME, string(rdata)}
}

func ssWantAnswers(t *testing.T, what string, m *dnswire.Message, want ...ssRR) {
	t.Helper()
	if got := ssAnswers(m); !reflect.DeepEqual(got, append([]ssRR(nil), want...)) {
		t.Errorf("%s: answers = %+v, want %+v", what, got, want)
	}
}

// ssAsked is the questions Unbound was sent, in order, as "name TYPE".
func ssAsked(t *testing.T, u *paritycorpus.FakeUnbound) []string {
	t.Helper()
	var out []string
	for _, wire := range u.Queries {
		for _, q := range parse(t, wire).Questions {
			out = append(out, q.Name+" "+dnswire.TypeStr(q.Qtype))
		}
	}
	return out
}

// ssTrace is the cache calls in order as text; a store of no reply is marked, so the module cannot ask to cache nothing.
func ssTrace(calls *[]cacheCall) []string {
	var out []string
	for _, call := range *calls {
		switch {
		case call.op == "invalidate":
			out = append(out, "invalidate "+call.qname)
		case call.rep == nil:
			out = append(out, fmt.Sprintf("store %s referral=%d, NO REPLY", call.qname, call.isReferral))
		default:
			out = append(out, fmt.Sprintf("store %s referral=%d", call.qname, call.isReferral))
		}
	}
	return out
}

func ssDoBits(t *testing.T, wire []byte) []bool {
	t.Helper()
	bits := []bool{}
	for _, rr := range parse(t, wire).Additional {
		if rr.Rtype == dnswire.TYPE_OPT {
			bits = append(bits, rr.TTL&0x8000 != 0)
		}
	}
	return bits
}

// --- the chase ---

func TestChaseGivesTheClientTheCnameAndTheTargetsAddress(t *testing.T) {
	module := ssBoot(t)
	for _, row := range []struct {
		name    string
		qtype   uint16
		address []byte
	}{{"A", dnswire.TYPE_A, ssTargetA}, {"AAAA", dnswire.TYPE_AAAA, ssTargetAAAA}} {
		t.Run(row.name, func(t *testing.T) {
			calls := recordCache(t, false)
			out := captureLog(t)
			u := paritycorpus.NewFakeUnbound(ssZone())
			reply := ssResolve(t, module, ssQuery(t, ssDuck, row.qtype, ssQ{qid: 0xBEEF}), ssForward(t, u, nil), "Unknown")
			if want := dnswire.QR | dnswire.RA | dnswire.RD; reply.ID != 0xBEEF || reply.Rcode() != 0 || reply.Flags&want != want {
				t.Errorf("(id, rcode, flags) = (%#x, %d, %#x), want (0xbeef, 0, QR|RA|RD)", reply.ID, reply.Rcode(), reply.Flags)
			}
			if want := []dnswire.Question{{Name: ssDuck, Qtype: row.qtype, Qclass: dnswire.CLASS_IN}}; !slices.Equal(reply.Questions, want) {
				t.Errorf("questions = %v, want %v", reply.Questions, want)
			}
			ssWantAnswers(t, row.name, reply, ssCname(t, ssDuck, ssTarget), ssRR{ssTarget, row.qtype, string(row.address)})
			ty := dnswire.TypeStr(row.qtype)
			if want := []string{ssDuck + " " + ty, ssTarget + " " + ty}; !slices.Equal(ssAsked(t, u), want) { // the name first, then the chase
				t.Errorf("Unbound was asked %q, want %q", ssAsked(t, u), want)
			}
			// The module itself ran both passes: plant and restart, then the post-chase re-cache.
			if want := []string{"invalidate " + ssDuck, "store " + ssDuck + " referral=1", "invalidate " + ssDuck, "store " + ssDuck + " referral=0"}; !slices.Equal(ssTrace(calls), want) {
				t.Errorf("cache calls = %q, want %q", ssTrace(calls), want)
			}
			if lines := logLines(out); len(lines) != 0 {
				t.Errorf("a plain chase logged %q", lines)
			}
		})
	}
}

func TestASafeSearchAnswerNeverClaimsDnssecAuthenticationWhateverTheClientAsks(t *testing.T) {
	module := ssBoot(t)
	for name, o := range map[string]ssQ{"do": {do: true, edns: true}, "cd": {cd: true, edns: true}, "do and cd": {do: true, cd: true, edns: true}} {
		reply := ssResolve(t, module, ssQuery(t, ssDuck, dnswire.TYPE_A, o), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
		ssWantAnswers(t, name, reply, ssCname(t, ssDuck, ssTarget), ssRR{ssTarget, dnswire.TYPE_A, string(ssTargetA)})
		if reply.Flags&adBit != 0 { // the proxy synthesised this answer, so it cannot vouch for it
			t.Errorf("%s: the reply claims authenticated data (flags %#x)", name, reply.Flags)
		}
	}
}

func TestTheWwwVariantOfASafeSearchNameIsRedirectedToo(t *testing.T) {
	reply := ssResolve(t, ssBoot(t), ssQuery(t, "www.duck.example.", dnswire.TYPE_A, ssQ{}), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	ssWantAnswers(t, "www", reply, ssCname(t, "www.duck.example.", ssTarget), ssRR{ssTarget, dnswire.TYPE_A, string(ssTargetA)})
}

// chaseWire is the second upstream query, the chase: a missing one fails the test rather than panicking the package.
func chaseWire(t *testing.T, u *paritycorpus.FakeUnbound) []byte {
	t.Helper()
	if len(u.Queries) < 2 {
		t.Fatalf("Unbound was sent %d queries, want the client's and one chase", len(u.Queries))
	}
	return u.Queries[1]
}

func TestTheFirstUpstreamQueryIsTheClientsOwnBytesAndTheChaseIsAFreshRecursiveOne(t *testing.T) {
	u := paritycorpus.NewFakeUnbound(ssZone())
	clientWire := ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{qid: 0x4242, edns: true})
	ssResolveWire(t, ssBoot(t), clientWire, ssForward(t, u, nil), "Unknown")
	if len(u.Queries) != 2 {
		t.Fatalf("Unbound was sent %d queries, want the client's and one chase", len(u.Queries))
	}
	chase := parse(t, u.Queries[1])
	if string(u.Queries[0]) != string(clientWire) {
		t.Errorf("first upstream query = %x, want the client's own bytes %x", u.Queries[0], clientWire)
	}
	if chase.Flags != dnswire.RD {
		t.Errorf("chase flags = %#x, want RD alone: a fresh recursive query", chase.Flags)
	}
	if want := []dnswire.Question{{Name: ssTarget, Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}}; !slices.Equal(chase.Questions, want) {
		t.Errorf("chase question = %v, want %v", chase.Questions, want)
	}
	if len(chase.Additional) != 1 || chase.Additional[0].Rtype != dnswire.TYPE_OPT { // the client speaks EDNS, so the chase does
		t.Errorf("chase additional = %+v, want one OPT", chase.Additional)
	}
}

func TestTheChaseIdIsRandom(t *testing.T) {
	module := ssBoot(t)
	ids := map[uint16]bool{}
	for range 64 {
		u := paritycorpus.NewFakeUnbound(ssZone())
		ssResolveWire(t, module, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, u, nil), "Unknown")
		ids[parse(t, chaseWire(t, u)).ID] = true
	}
	if len(ids) < 2 { // 64 draws of 16 bits all equal is a 2^-1008 chance
		t.Errorf("64 chases carried %d distinct ids, want a random one each", len(ids))
	}
	// The id is all an off-path forger has to guess: all 16 bits are drawn, so 64 draws all below 256 is a 2^-512 chance.
	if !slices.ContainsFunc(slices.Collect(maps.Keys(ids)), func(id uint16) bool { return id > 0xFF }) {
		t.Errorf("64 chase ids %v all fit in 8 bits, want 16 random bits", slices.Collect(maps.Keys(ids)))
	}
}

func TestTheChaseHasNoEdnsWhenTheClientHasNone(t *testing.T) {
	u := paritycorpus.NewFakeUnbound(ssZone())
	ssResolveWire(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, u, nil), "Unknown")
	if got := parse(t, chaseWire(t, u)).Additional; len(got) != 0 {
		t.Errorf("chase additional = %+v, want none", got)
	}
}

func TestTheChaseCarriesTheClientsDnssecOkBitOrNoOptAtAll(t *testing.T) {
	module := ssBoot(t)
	for _, row := range []struct {
		name       string
		edns, do   bool
		client, up []bool
	}{
		{"do-1", true, true, []bool{true}, []bool{true}},
		{"do-0", true, false, []bool{false}, []bool{false}},
		{"no-opt", false, false, []bool{}, []bool{}},
	} {
		u := paritycorpus.NewFakeUnbound(ssZone())
		ssResolveWire(t, module, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: row.edns, do: row.do}), ssForward(t, u, nil), "Unknown")
		if got := ssDoBits(t, u.Queries[0]); !slices.Equal(got, row.client) { // what the client sent
			t.Errorf("%s: client DO bits = %v, want %v", row.name, got, row.client)
		}
		if got := ssDoBits(t, chaseWire(t, u)); !slices.Equal(got, row.up) { // what the chase sends Unbound for the target
			t.Errorf("%s: chase DO bits = %v, want %v", row.name, got, row.up)
		}
	}
}

func TestOtherQueryTypesForASafeSearchNameAreRelayedUntouched(t *testing.T) {
	u := paritycorpus.NewFakeUnbound(ssZone())
	wire := ssQuery(t, ssDuck, dnswire.TYPE_TXT, ssQ{})
	reply := ssResolveWire(t, ssBoot(t), wire, ssForward(t, u, nil), "Unknown")
	want, err := paritycorpus.NewFakeUnbound(ssZone()).Answer(wire)
	if err != nil || string(reply) != string(want) {
		t.Errorf("reply = %x (%v), want Unbound's own %x", reply, err, want)
	}
	if got := ssAsked(t, u); !slices.Equal(got, []string{ssDuck + " TXT"}) {
		t.Errorf("Unbound was asked %q, want the one TXT query", got)
	}
}

// The module's CNAME validation runs on the chased message, as it does behind the real iterator.
func TestATargetTheDnsblBlocksGetsTheBlockAnswerForTheSafeSearchName(t *testing.T) {
	reply := ssResolve(t, ssBoot(t), ssQuery(t, "trap.example.", dnswire.TYPE_A, ssQ{}), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	ssWantAnswers(t, "trap", reply, ssRR{"trap.example.", dnswire.TYPE_A, string(ssVIP4)})
}

// Only the target's answer records reach the module: not its flags, authority or additional section.
func TestTheChaseGivesTheModuleOnlyTheTargetsAnswerRecords(t *testing.T) {
	chased := func(wire []byte) []byte {
		q := parse(t, wire)
		return encode(t, &dnswire.Message{
			ID: q.ID, Flags: dnswire.QR | dnswire.RA | dnswire.AA | dnswire.RD, Questions: q.Questions,
			Answers:    []dnswire.RR{{Name: ssTarget, Rtype: dnswire.TYPE_A, Rclass: dnswire.CLASS_IN, TTL: 300, Rdata: ssTargetA}},
			Authority:  []dnswire.RR{aRecord("auth.example.", 30, 8)},
			Additional: []dnswire.RR{aRecord("glue.example.", 60, 9)},
		})
	}
	u := paritycorpus.NewFakeUnbound(ssZone())
	reply := ssResolve(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, u, map[string]func([]byte) []byte{ssTarget: chased}), "Unknown")
	ssWantAnswers(t, "chased", reply, ssCname(t, ssDuck, ssTarget), ssRR{ssTarget, dnswire.TYPE_A, string(ssTargetA)})
	if reply.Flags&dnswire.AA != 0 || len(reply.Authority) != 0 || len(reply.Additional) != 0 {
		t.Errorf("the target's AA, authority or additional reached the client: flags %#x, authority %+v, additional %+v", reply.Flags, reply.Authority, reply.Additional)
	}
}

// --- the client's UDP size is kept ---

// (client's EDNS size or 0, target addresses, whether the reply has to be truncated). The reply holds the CNAME and
// every address: 92 + 16 per further address bytes without an OPT, 11 more with the proxy's own OPT.
var ssUdpSizes = []struct {
	name      string
	size      uint16 // 0: the client has no EDNS
	count     int
	truncated bool
}{
	{"no-edns-limit-512", 0, 40, true},
	{"edns-512", 512, 40, true},
	{"edns-below-512-counts-as-512", 100, 26, false},
	{"edns-1232-fits", 1232, 60, false},
	{"edns-4096-is-held-to-the-1232-the-proxy-advertises", 4096, 94, true},
	{"edns-65535-is-held-to-1232-too", 65535, 94, true},
}

func ssUdpQuery(t *testing.T, size uint16) []byte {
	t.Helper()
	if size == 0 {
		return ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{})
	}
	return ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true, udpSize: size})
}

// Issue #3517 review: a no-EDNS client was sent 530 bytes and one advertising 512 was sent 796, TC clear.
func TestAReplyTheProxyBuildsIsCutToTheUdpSizeTheClientAdvertised(t *testing.T) {
	module := ssBoot(t)
	for _, row := range ssUdpSizes {
		t.Run(row.name, func(t *testing.T) {
			wire := ssResolveWire(t, module, ssUdpQuery(t, row.size), ssForward(t, paritycorpus.NewFakeUnbound(ssTargetZone(row.count)), nil), "UDP")
			if wire == nil {
				t.Fatal("the decider dropped the query")
			}
			reply := parse(t, wire)
			limit := min(max(int(row.size), 512), 1232)
			if wantQ := []dnswire.Question{{Name: ssDuck, Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}}; reply.ID != 0x1234 || reply.Rcode() != 0 || reply.Flags&dnswire.RD != dnswire.RD || !slices.Equal(reply.Questions, wantQ) {
				t.Errorf("(id, rcode, flags, questions) = (%#x, %d, %#x, %v), want the client's question answered NOERROR with RD", reply.ID, reply.Rcode(), reply.Flags, reply.Questions)
			}
			if row.truncated {
				if reply.Flags&dnswire.TC == 0 || len(reply.Answers) != 0 || len(reply.Authority) != 0 {
					t.Errorf("TC = %v, answers = %d, authority = %d, want the question alone with TC set", reply.Flags&dnswire.TC != 0, len(reply.Answers), len(reply.Authority))
				}
			} else if reply.Flags&dnswire.TC != 0 || len(reply.Answers) != 1+row.count {
				t.Errorf("TC = %v, answers = %d, want %d whole", reply.Flags&dnswire.TC != 0, len(reply.Answers), 1+row.count)
			}
			if len(wire) > limit {
				t.Errorf("the reply is %d bytes, want at most the %d the client can take", len(wire), limit)
			}
			var wantOpt []dnswire.RR
			if row.size != 0 {
				wantOpt = []dnswire.RR{dnswire.MakeOpt(dnswire.EDNS_UDP_SIZE, false, nil)}
			}
			if !sameRRs(reply.Additional, wantOpt) {
				t.Errorf("additional = %+v, want %+v", reply.Additional, wantOpt)
			}
		})
	}
}

func TestAReplyExactlyAsBigAsTheClientsUdpSizeIsNotTruncated(t *testing.T) {
	module := ssBoot(t)
	zone := ssTargetZone(45)
	full := ssResolveWire(t, module, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true, udpSize: 4096}), ssForward(t, paritycorpus.NewFakeUnbound(zone), nil), "TCP") // a stream client: no limit
	if len(full) <= 512 || len(full) >= 1232 {
		t.Fatalf("the whole reply is %d bytes, want one between the two limits", len(full))
	}
	for _, row := range []struct {
		size      int
		truncated bool
	}{{len(full), false}, {len(full) - 1, true}} {
		reply := ssResolve(t, module, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true, udpSize: uint16(row.size)}), ssForward(t, paritycorpus.NewFakeUnbound(zone), nil), "UDP")
		if got := reply.Flags&dnswire.TC != 0; got != row.truncated {
			t.Errorf("a client taking %d bytes: TC = %v, want %v", row.size, got, row.truncated)
		}
	}
}

func TestToAStreamClientAReplyLargerThanAnyUdpSizeIsSentWhole(t *testing.T) {
	wire := ssResolveWire(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, paritycorpus.NewFakeUnbound(ssTargetZone(94)), nil), "TCP")
	if len(wire) <= 1232 {
		t.Fatalf("the stream reply is %d bytes, want more than any UDP size", len(wire))
	}
	if reply := parse(t, wire); reply.Flags&dnswire.TC != 0 || len(reply.Answers) != 95 {
		t.Errorf("TC = %v, answers = %d, want the CNAME and the 94 addresses whole", reply.Flags&dnswire.TC != 0, len(reply.Answers))
	}
}

// Characterization (rendered is PR1's): Python plants the flags through a swapped module.operate, which Go has no
// seam for; the flags of the sent message are rendered's.
func TestARenderedMessageTheModuleFlagsTruncatedOrAuthoritativeKeepsBothFlags(t *testing.T) {
	query := &dnswire.Message{ID: 0x1234, Flags: dnswire.RD, Questions: question(ssDuck, dnswire.CLASS_IN)}
	wire, replaced, err := rendered(query, moduleMessage(manyAnswers(1), dnswire.QR|dnswire.RA|dnswire.AA|dnswire.TC), nil)
	if err != nil || replaced {
		t.Fatalf("rendered = (replaced %v, %v), want the message whole", replaced, err)
	}
	if got := parse(t, wire).Flags & (dnswire.AA | dnswire.TC); got != dnswire.AA|dnswire.TC {
		t.Errorf("AA|TC kept = %#x, want both", got)
	}
}

// --- the chase carries the client's context ---

// Issue #3517 review: the chase dropped CD and ECS, so a CD client's bogus target was a SERVFAIL, not an answer.
func TestTheChaseCarriesTheClientsCdBitAndEdnsOptionsAndAdvertises1232(t *testing.T) {
	u := paritycorpus.NewFakeUnbound(ssZone())
	ssResolveWire(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{cd: true, do: true, udpSize: 4096, options: ssECS}), ssForward(t, u, nil), "Unknown")
	chase := parse(t, chaseWire(t, u))
	if chase.Flags&(dnswire.RD|dnswire.CD) != dnswire.RD|dnswire.CD {
		t.Errorf("chase flags = %#x, want RD and CD", chase.Flags)
	}
	if len(chase.Additional) != 1 {
		t.Fatalf("chase additional = %+v, want one OPT", chase.Additional)
	}
	if opt := chase.Additional[0]; opt.Rtype != dnswire.TYPE_OPT || opt.Rclass != 1232 || opt.TTL&0x8000 == 0 || string(opt.Rdata) != string(ssECS) {
		t.Errorf("chase OPT = %+v, want size 1232, DO set, the client's ECS option", opt)
	}
}

func TestTheChaseHasNoCdBitWhenTheClientSentNone(t *testing.T) {
	u := paritycorpus.NewFakeUnbound(ssZone())
	ssResolveWire(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true}), ssForward(t, u, nil), "Unknown")
	if flags := parse(t, chaseWire(t, u)).Flags; flags&dnswire.CD != 0 {
		t.Errorf("chase flags = %#x, want no CD", flags)
	}
}

// The chased answer is the module's message, rendered with its own flags: a client's AA bit is never echoed into it.
func TestTheChasedAnswerIsNotAuthoritativeWhenTheClientSetAA(t *testing.T) {
	query := ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{})
	query[2] |= 0x04 // AA
	reply := ssResolve(t, ssBoot(t), query, ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	if reply.Flags&dnswire.AA != 0 || len(reply.Answers) == 0 {
		t.Errorf("reply flags %#x with %d answers, want the chased answer without AA", reply.Flags, len(reply.Answers))
	}
}

func TestTheReplyAdvertises1232AndEchoesNoneOfTheClientsEdnsOptions(t *testing.T) {
	reply := ssResolve(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{do: true, udpSize: 4096, options: ssECS}), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	wantOnlyOpt(t, "reply", reply.Additional, true)
}

// --- the chase yields no address: the module's own baked fallback ---

func TestAChaseWithoutAnAddressGetsTheBakedAddress(t *testing.T) {
	module := ssBoot(t)
	servfail := func(wire []byte) []byte { return replyTo(t, wire, 2) }
	for _, row := range []struct {
		name  string
		baked netip.Addr
		over  map[string]func([]byte) []byte
	}{
		{"nodata.example.", netip.MustParseAddr("198.51.100.8"), nil},
		{"nx.example.", netip.MustParseAddr("198.51.100.10"), nil},
		{"servfail.example.", netip.MustParseAddr("198.51.100.11"), map[string]func([]byte) []byte{"servfail-target.example.": servfail}},
		{"silent.example.", netip.MustParseAddr("198.51.100.12"), nil}, // the zone lists its target as never answering
	} {
		// The gateway's two transports give the same answer (test_gateway_safesearch.py runs both).
		for _, transport := range []string{"UDP", "TCP"} {
			out := captureLog(t)
			u := paritycorpus.NewFakeUnbound(ssZone())
			reply := ssResolve(t, module, ssQuery(t, row.name, dnswire.TYPE_A, ssQ{}), ssForward(t, u, row.over), transport)
			if reply.Rcode() != 0 {
				t.Errorf("%s over %s: rcode %d, want NOERROR", row.name, transport, reply.Rcode())
			}
			ssWantAnswers(t, row.name+" over "+transport, reply, ssRR{row.name, dnswire.TYPE_A, string(row.baked.AsSlice())})
			if got := ssAsked(t, u); len(got) != 2 { // the original name and exactly one chase
				t.Errorf("%s over %s: Unbound was asked %q, want the name and one chase", row.name, transport, got)
			}
			if lines := logLines(out); len(lines) != 0 { // a chase that finds nothing is not Unbound's silence
				t.Errorf("%s over %s: logged %q, want nothing", row.name, transport, lines)
			}
		}
	}
}

func TestAaaaWithoutAnAddressGetsTheBakedV6(t *testing.T) {
	reply := ssResolve(t, ssBoot(t), ssQuery(t, "nodata.example.", dnswire.TYPE_AAAA, ssQ{}), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	ssWantAnswers(t, "nodata", reply, ssRR{"nodata.example.", dnswire.TYPE_AAAA, string(netip.MustParseAddr("2001:db8::8").AsSlice())})
}

// The module declines (no baked address for the type) and finishes with what the chase gave it: the CNAME.
func TestNoChasedAddressAndNoBakedAddressLeavesTheClientTheLoneCname(t *testing.T) {
	reply := ssResolve(t, ssBoot(t), ssQuery(t, "nobaked.example.", dnswire.TYPE_A, ssQ{}), ssForward(t, paritycorpus.NewFakeUnbound(ssZone()), nil), "Unknown")
	if reply.Rcode() != 0 {
		t.Errorf("rcode %d, want NOERROR", reply.Rcode())
	}
	ssWantAnswers(t, "nobaked", reply, ssCname(t, "nobaked.example.", "nodata-target.example."))
}

// --- guards ---

// The one way the real module asks for a second restart: the chased message has our CNAME, but its target does not read
// back as the entry's text (the label holds a dot), so the pass after the chase is a first pass again.
func TestAModuleThatKeepsAskingForRestartsGetsOneChaseThenServfail(t *testing.T) {
	calls := recordCache(t, false)
	u := paritycorpus.NewFakeUnbound(ssZone())
	reply := ssResolve(t, ssBoot(t), ssQuery(t, "odd.example.", dnswire.TYPE_A, ssQ{}), ssForward(t, u, nil), "Unknown")
	if reply.Rcode() != 2 || len(reply.Answers) != 0 {
		t.Errorf("(rcode, answers) = (%d, %d), want a bare SERVFAIL", reply.Rcode(), len(reply.Answers))
	}
	if want := []string{"odd.example. A", `safe\.duck.example. A`}; !slices.Equal(ssAsked(t, u), want) {
		t.Errorf("Unbound was asked %q, want the name and exactly one chase %q", ssAsked(t, u), want)
	}
	if got := ssTrace(calls); len(got) != 4 { // the first pass, then the second asking again
		t.Errorf("cache calls = %q, want the plant twice", got)
	}
}

func TestARestartWithNothingPlantedIsAnErrorWithoutAChase(t *testing.T) {
	const logged = "pfb_dns_proxy error: MODULE_RESTART_NEXT without a planted CNAME referral"
	address := newDnsMsg(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, dnswire.QR, []dnswire.RR{aRecord(ssDuck, 300, 50)}, nil, nil)
	chain := newDnsMsg(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, dnswire.QR,
		[]dnswire.RR{opRR(t, "duck.example. 300 IN CNAME other.example."), opRR(t, "other.example. 300 IN A 192.0.2.60")}, nil, nil)
	for _, row := range []struct {
		name string
		msg  *dnsMsg
	}{
		{"no message", nil},
		{"an empty answer", newDnsMsg(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, dnswire.QR, nil, nil, nil)},
		{"an address answer", address},
		{"an unrelated CNAME chain", chain},
	} {
		f := newTestFrontend(t)
		out := captureLog(t)
		qstate := newModuleQstate(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, ssClient, 0, dnswire.RD, "UDP", "", "")
		qstate.returnMsg = row.msg
		r := &recorder{}
		query := parse(t, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}))
		if got := f.chaseCname(query, qstate, r.forward); got != MODULE_ERROR {
			t.Errorf("%s: state = %d, want MODULE_ERROR (%d)", row.name, got, MODULE_ERROR)
		}
		if len(r.wires) != 0 {
			t.Errorf("%s: forwarded %d wires, want no chase", row.name, len(r.wires))
		}
		if lines := logLines(out); !slices.Equal(lines, []string{logged}) {
			t.Errorf("%s: log = %q, want %q", row.name, lines, logged)
		}
	}
}

func TestAPlantedCnameTheChaseCannotReadIsAnErrorWithoutAChase(t *testing.T) {
	f := newTestFrontend(t)
	out := captureLog(t)
	planted := dnswire.RR{Name: ssDuck, Rtype: dnswire.TYPE_CNAME, Rclass: dnswire.CLASS_IN, TTL: 3600, Rdata: []byte{0xFF}} // a pointer with no second octet
	qstate := newModuleQstate(queryInfo{ssDuck, dnswire.TYPE_A, dnswire.CLASS_IN}, ssClient, 0, dnswire.RD, "UDP", "", "")
	qstate.returnMsg = newDnsMsg(qstate.qinfo, dnswire.QR, []dnswire.RR{planted}, nil, nil)
	r := &recorder{}
	if got := f.chaseCname(parse(t, ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{})), qstate, r.forward); got != MODULE_ERROR {
		t.Errorf("state = %d, want MODULE_ERROR (%d)", got, MODULE_ERROR)
	}
	if lines := logLines(out); len(r.wires) != 0 || len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy error: ") {
		t.Errorf("forwarded %d wires, log = %q, want no chase and one error line", len(r.wires), lines)
	}
}

func TestAChaseReplyThatIsNotADnsMessageIsAServfailAndLoggedOnce(t *testing.T) {
	out := captureLog(t)
	garbage := func([]byte) []byte {
		return append(header(0x4242, dnswire.QR|dnswire.RD|dnswire.RA, 1, 0, 0, 0), 5, 'a', 'b')
	} // a 5-octet label, 2 present
	u := paritycorpus.NewFakeUnbound(ssZone())
	reply := ssResolve(t, ssBoot(t), ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{}), ssForward(t, u, map[string]func([]byte) []byte{ssTarget: garbage}), "Unknown")
	if reply.Rcode() != 2 || len(reply.Answers) != 0 {
		t.Errorf("(rcode, answers) = (%d, %d), want a bare SERVFAIL", reply.Rcode(), len(reply.Answers))
	}
	if lines := logLines(out); len(lines) != 1 || !strings.HasPrefix(lines[0], "pfb_dns_proxy error: ") {
		t.Errorf("log = %q, want the one error line", lines)
	}
}

// Issue #3641: a chase over one DNS message is never sent. Each client gets the SERVFAIL, and a client repeating the
// query costs one log line per SILENCE_LOG_INTERVAL, not one per query: the log is not rotated.
func TestAnOversizedChaseIsAServfailAndOneLogLineHoweverOftenItIsAsked(t *testing.T) {
	padding := MAX_DNS_MESSAGE - 45 // header 12, question 18, OPT 11 and the option's 4-byte header
	options := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, 12), uint16(padding))
	query := ssQuery(t, ssDuck, dnswire.TYPE_A, ssQ{edns: true, options: append(options, make([]byte, padding)...)})
	if len(query) != MAX_DNS_MESSAGE {
		t.Fatalf("the client's query is %d bytes, want exactly %d", len(query), MAX_DNS_MESSAGE)
	}
	// The chase asks for the 19-byte name of the target instead of the client's 14: 5 bytes over.
	const logged = "pfb_dns_proxy error: SafeSearch chase for safe.duck.example. is 65540 bytes, over one DNS message; SERVFAIL"
	out := captureLog(t)
	f := newFrontend(ssBoot(t))
	var now time.Duration
	f.monotonic = func() time.Duration { return now }
	u := paritycorpus.NewFakeUnbound(ssZone())
	ask := func() *dnswire.Message {
		reply := f.resolve(query, ssClient, ssForward(t, u, nil), "Unknown", "", "")
		wantBare(t, "oversized", reply, 0x1234, dnswire.QR|dnswire.RA|dnswire.RD|RCODE_SERVFAIL, RCODE_SERVFAIL, question(ssDuck, dnswire.CLASS_IN))
		return parse(t, reply)
	}
	ask()
	ask()
	now = SILENCE_LOG_INTERVAL - 500*time.Millisecond
	ask()
	if lines := logLines(out); !slices.Equal(lines, []string{logged}) { // still inside the interval
		t.Errorf("log after three asks = %q, want the one line %q", lines, logged)
	}
	now = SILENCE_LOG_INTERVAL // the interval ends exactly here
	ask()
	if lines := logLines(out); !slices.Equal(lines, []string{logged, logged}) {
		t.Errorf("log after the interval = %q, want the line twice", lines)
	}
	// The interval restarts at the second line: two intervals later one ask logs, and an ask at that same instant does not.
	now = 3 * SILENCE_LOG_INTERVAL
	ask()
	ask()
	if lines := logLines(out); !slices.Equal(lines, []string{logged, logged, logged}) {
		t.Errorf("log after a later interval = %q, want the line three times", lines)
	}
	want := slices.Repeat([]string{ssDuck + " A"}, 6) // the client's own queries; no chase
	if got := ssAsked(t, u); !slices.Equal(got, want) {
		t.Errorf("Unbound was asked %q, want %q", got, want)
	}
}
