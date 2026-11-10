// Tests of pfb_unbound.go's SafeSearch CNAME redirect (pfb_unbound.py _ss_answer_has_cname_to, _ss_answer_has_address,
// _safesearch_baked_fallback, safesearch_cname_redirect) and the call to it in operate()'s MODDONE pass. They mirror
// tests/test_pfb_unbound.py TestSafeSearchAnswerHelpers and TestSafeSearchCnameRedirect; the expectations are the
// Python source's. Python swaps `convert_other` and the cache builtins; these tests build real CNAME rdata for the
// first and swap the package's cache calls (recordCache) for the second.
package decider

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const (
	ssQname      = "duckduckgo.com."
	ssTargetText = "safe.duckduckgo.com" // the entry's AAAA column: the CNAME target, written without a root dot
	ssPlanted    = "duckduckgo.com. 3600 IN CNAME safe.duckduckgo.com"
	ssChasedCN   = "duckduckgo.com. 3600 IN CNAME safe.duckduckgo.com."
	ssChasedA    = "safe.duckduckgo.com. 300 IN A 192.0.2.88"
	ssChasedAAAA = "safe.duckduckgo.com. 300 IN AAAA 2001:db8::88"
)

// cacheCall is one call the module made to Unbound's message cache.
type cacheCall struct {
	op         string // "store" or "invalidate"
	qname      string
	isReferral int        // stores only
	rep        *replyInfo // stores only: the reply the module asked to cache
}

// recordCache swaps the shim's cache calls for recorders, as the Python tests swap the builtins; the originals come
// back at cleanup. With storeFails every store reports failure, as real Unbound's silent falsy failure does (#749).
func recordCache(t *testing.T, storeFails bool) *[]cacheCall {
	t.Helper()
	var calls []cacheCall
	previousStore, previousInvalidate := storeQueryInCache, invalidateQueryInCache
	storeQueryInCache = func(qstate *moduleQstate, qinfo queryInfo, msgrep *replyInfo, isReferral int) bool {
		calls = append(calls, cacheCall{op: "store", qname: qinfo.qnameStr, isReferral: isReferral, rep: msgrep})
		return !storeFails
	}
	invalidateQueryInCache = func(qstate *moduleQstate, qinfo queryInfo) {
		calls = append(calls, cacheCall{op: "invalidate", qname: qinfo.qnameStr})
	}
	t.Cleanup(func() { storeQueryInCache, invalidateQueryInCache = previousStore, previousInvalidate })
	return &calls
}

func ssEntry(v4, v6 string) safeSearchEntry {
	return safeSearchEntry{a: "cname", aaaa: ssTargetText, v4: v4, v6: v6}
}

// ssModule is a module whose snapshot holds one CNAME SafeSearch entry for duckduckgo.com and, when clients are given,
// a Group Policy bypass list of them.
func ssModule(t *testing.T, entry safeSearchEntry, bypassed ...string) *pfbUnbound {
	t.Helper()
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { s.safeSearchDB, s.gpListDB = true, len(bypassed) > 0 }, func(s *snapshot) {
		s.safeSearchDB["duckduckgo.com"] = entry
		for _, client := range bypassed {
			s.gpListDB[client] = 0
		}
	})
	return m
}

// ssMsg is a message as the iterator hands it back: the given answer and authority RR texts, flags QR|RD|RA.
func ssMsg(t *testing.T, qtype uint16, answer, authority []string) *dnsMsg {
	t.Helper()
	rrs := func(texts []string) []dnswire.RR {
		var out []dnswire.RR
		for _, text := range texts {
			out = append(out, opRR(t, text))
		}
		return out
	}
	return newDnsMsg(queryInfo{qnameStr: ssQname, qtype: qtype, qclass: RR_CLASS_IN}, dnswire.QR|dnswire.RD|dnswire.RA, rrs(answer), rrs(authority), nil)
}

func ssQstate(t *testing.T, qtype uint16, client string, answer ...string) *moduleQstate {
	t.Helper()
	q := opQstate(ssQname, qtype, client)
	if answer != nil {
		q.returnMsg = ssMsg(t, qtype, answer, nil)
	}
	return q
}

func ssWantCalls(t *testing.T, what string, got *[]cacheCall, want ...cacheCall) {
	t.Helper()
	if !reflect.DeepEqual(*got, append([]cacheCall(nil), want...)) {
		t.Errorf("%s: cache calls = %+v, want %+v", what, *got, want)
	}
}

func ssInvalidate() cacheCall { return cacheCall{op: "invalidate", qname: ssQname} }

func ssStore(isReferral int, rep *replyInfo) cacheCall {
	return cacheCall{op: "store", qname: ssQname, isReferral: isReferral, rep: rep}
}

// ssNeedMsg ends the test when the module left no reply message, so a regression fails the test and does not panic the
// package.
func ssNeedMsg(t *testing.T, what string, q *moduleQstate) {
	t.Helper()
	if q.returnMsg == nil || q.returnMsg.rep == nil {
		t.Fatalf("%s: the module left no reply message", what)
	}
}

// ssWantFinishedAs fails unless the module finished the query with a NOERROR reply stamped insecure whose records are
// exactly `answer`, and wrote nothing to the log.
func ssWantFinishedAs(t *testing.T, what string, q *moduleQstate, answer string, flags uint16) {
	t.Helper()
	opSections(t, what, q, []string{answer}, nil)
	ssNeedMsg(t, what, q)
	if q.returnRcode != RCODE_NOERROR || q.returnMsg.rep.security != secStatusInsecure || q.returnMsg.rep.flags != flags {
		t.Errorf("%s: (rcode, security, flags) = (%d, %d, %#x), want (NOERROR, insecure %d, %#x)",
			what, q.returnRcode, q.returnMsg.rep.security, q.returnMsg.rep.flags, secStatusInsecure, flags)
	}
}

// --- _ss_answer_has_cname_to and _ss_answer_has_address ---

func TestSsAnswerHasCnameTo(t *testing.T) {
	cnameTo := func(owner, target string) string { return owner + " 3600 IN CNAME " + target }
	withAuthority := newDnsMsg(queryInfo{qnameStr: ssQname, qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR,
		[]dnswire.RR{opRR(t, ssChasedA)}, []dnswire.RR{opRR(t, ssChasedCN)}, nil)
	ns := opRR(t, ssChasedCN) // an NS record's rdata is a name too: the same bytes, typed NS
	ns.Rtype = dnswire.TYPE_NS
	nsToTarget := newDnsMsg(queryInfo{qnameStr: ssQname, qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR, []dnswire.RR{ns}, nil, nil)
	for _, row := range []struct {
		name   string
		msg    *dnsMsg
		target string
		want   bool
	}{
		{"the planted CNAME", ssMsg(t, RR_TYPE_A, []string{ssChasedCN, ssChasedA}, nil), ssTargetText, true},
		{"the CNAME alone", ssMsg(t, RR_TYPE_A, []string{ssChasedCN}, nil), ssTargetText, true},
		{"case and trailing dots on either side do not matter", ssMsg(t, RR_TYPE_A, []string{cnameTo("duckduckgo.com.", "SAFE.DuckDuckGo.com.")}, nil), "Safe.duckDUCKgo.com..", true},
		{"an NS record pointing at the target is no CNAME", nsToTarget, ssTargetText, false},
		{"a genuine CNAME to another name is not ours", ssMsg(t, RR_TYPE_A, []string{cnameTo("duckduckgo.com.", "cdn.example.net."), "cdn.example.net. 60 IN A 192.0.2.9"}, nil), ssTargetText, false},
		{"our target as the second CNAME of a chain", ssMsg(t, RR_TYPE_A, []string{cnameTo("duckduckgo.com.", "mid.example."), cnameTo("mid.example.", "safe.duckduckgo.com."), ssChasedA}, nil), ssTargetText, true},
		{"our target as the second CNAME of one owner", ssMsg(t, RR_TYPE_A, []string{cnameTo("duckduckgo.com.", "mid.example."), cnameTo("duckduckgo.com.", "safe.duckduckgo.com.")}, nil), ssTargetText, true},
		{"an address answer without a CNAME", ssMsg(t, RR_TYPE_A, []string{ssChasedA}, nil), ssTargetText, false},
		{"a CNAME to the target in the authority section only", withAuthority, ssTargetText, false},
		{"no message", nil, ssTargetText, false},
		{"a message without a reply", &dnsMsg{}, ssTargetText, false},
	} {
		q := opQstate(ssQname, RR_TYPE_A, "192.0.2.1")
		q.returnMsg = row.msg
		if got := ssAnswerHasCnameTo(q, row.target); got != row.want {
			t.Errorf("%s: ssAnswerHasCnameTo(%q) = %v, want %v", row.name, row.target, got, row.want)
		}
	}
}

func TestSsAnswerHasAddress(t *testing.T) {
	withAuthority := newDnsMsg(queryInfo{qnameStr: ssQname, qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR,
		[]dnswire.RR{opRR(t, ssChasedCN)}, []dnswire.RR{opRR(t, ssChasedA)}, nil)
	for _, row := range []struct {
		name string
		msg  *dnsMsg
		want bool
	}{
		{"CNAME and A", ssMsg(t, RR_TYPE_A, []string{ssChasedCN, ssChasedA}, nil), true},
		{"CNAME and AAAA", ssMsg(t, RR_TYPE_AAAA, []string{ssChasedCN, ssChasedAAAA}, nil), true},
		{"a bare CNAME", ssMsg(t, RR_TYPE_A, []string{ssChasedCN}, nil), false},
		{"a TXT is not an address", ssMsg(t, RR_TYPE_A, []string{ssChasedCN, "safe.duckduckgo.com. 300 IN TXT hello"}, nil), false},
		{"an A in the authority section only", withAuthority, false},
		{"no message", nil, false},
		{"a message without a reply", &dnsMsg{}, false},
	} {
		q := opQstate(ssQname, RR_TYPE_A, "192.0.2.1")
		q.returnMsg = row.msg
		if got := ssAnswerHasAddress(q); got != row.want {
			t.Errorf("%s: ssAnswerHasAddress = %v, want %v", row.name, got, row.want)
		}
	}
}

// --- safesearch_cname_redirect: the first pass ---

func TestSafesearchCnameRedirectPlantsTheReferralAndRestarts(t *testing.T) {
	for _, row := range []struct {
		name   string
		qtype  uint16
		answer []string // what Unbound resolved: nil is no message
	}{
		{"A, nothing resolved yet", RR_TYPE_A, nil},
		{"AAAA, nothing resolved yet", RR_TYPE_AAAA, nil},
		{"Unbound's own address answer", RR_TYPE_A, []string{"duckduckgo.com. 300 IN A 192.0.2.50"}},
		{"a genuine CNAME chain is not read as the chased answer", RR_TYPE_A, []string{"duckduckgo.com. 300 IN CNAME other.example.", "other.example. 300 IN A 192.0.2.60"}},
	} {
		calls := recordCache(t, false)
		m := ssModule(t, ssEntry("203.0.113.7", "2001:db8::7"))
		out := captureLog(t) // after the boot, which logs its missing ini
		q := ssQstate(t, row.qtype, "192.0.2.1", row.answer...)
		opWantState(t, row.name, opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_RESTART_NEXT)
		opSections(t, row.name, q, []string{ssPlanted}, nil)
		ssNeedMsg(t, row.name, q)
		if q.noCacheStore != 1 || q.returnMsg.qinfo.qtype != row.qtype || q.returnMsg.rep.flags != dnswire.QR|dnswire.RD|dnswire.RA {
			t.Errorf("%s: (noCacheStore, qtype, flags) = (%d, %d, %#x), want (1, %d, %#x): a referral for this very question",
				row.name, q.noCacheStore, q.returnMsg.qinfo.qtype, q.returnMsg.rep.flags, row.qtype, dnswire.QR|dnswire.RD|dnswire.RA)
		}
		// The referral is dropped, then stored as one (is_referral 1): the iterator reads it back and chases the target.
		ssWantCalls(t, row.name, calls, ssInvalidate(), ssStore(1, q.returnMsg.rep))
		if lines := logLines(out); len(lines) != 0 {
			t.Errorf("%s: logged %q, want nothing", row.name, lines)
		}
	}
}

func TestSafesearchCnameRedirectAnswersFromTheBakedAddressWhenTheReferralCannotBeStored(t *testing.T) {
	const failed = "pfb_dns_proxy info: [pfBlockerNG]: SafeSearch: failed to store planted CNAME referral for duckduckgo.com."
	for _, row := range []struct {
		name     string
		qtype    uint16
		v4, v6   string
		wantAns  string // "" = the query ends in MODULE_ERROR
		wantFlag uint16
	}{
		{"A with a baked v4", RR_TYPE_A, "203.0.113.7", "2001:db8::7", "duckduckgo.com. 300 IN A 203.0.113.7", dnswire.QR | dnswire.RA},
		{"AAAA with a baked v6", RR_TYPE_AAAA, "203.0.113.7", "2001:db8::7", "duckduckgo.com. 300 IN AAAA 2001:db8::7", dnswire.QR | dnswire.RA},
		{"A without baked addresses", RR_TYPE_A, "", "", "", 0},
		// SafeSearch never resolves unsafely because the other family has an address: it fails closed.
		{"AAAA with only a baked v4", RR_TYPE_AAAA, "203.0.113.7", "", "", 0},
		{"A with only a baked v6", RR_TYPE_A, "", "2001:db8::7", "", 0},
	} {
		calls := recordCache(t, true)
		m := ssModule(t, ssEntry(row.v4, row.v6))
		out := captureLog(t) // after the boot, which logs its missing ini
		q := ssQstate(t, row.qtype, "192.0.2.1")
		q.returnRcode = RCODE_NXDOMAIN // a stale rcode: the baked answer is a NOERROR one
		got := opOperate(m, MODULE_EVENT_MODDONE, q)
		if row.wantAns == "" {
			opWantState(t, row.name, got, MODULE_ERROR)
		} else {
			opWantState(t, row.name, got, MODULE_FINISHED)
			ssWantFinishedAs(t, row.name, q, row.wantAns, row.wantFlag)
		}
		if q.noCacheStore != 0 {
			t.Errorf("%s: noCacheStore = %d, want 0: the restart that sets it never happened", row.name, q.noCacheStore)
		}
		rep := ssPlantedRep(calls)
		if rep == nil {
			t.Errorf("%s: the store was not asked to cache the planted CNAME referral: %+v", row.name, *calls)
		}
		ssWantCalls(t, row.name, calls, ssInvalidate(), ssStore(1, rep))
		if lines := logLines(out); len(lines) != 1 || lines[0] != failed {
			t.Errorf("%s: log = %q, want the one line %q", row.name, lines, failed)
		}
	}
}

// A SafeSearch row is loaded as PHP wrote it, so a target or a baked address that is no record's text reaches the
// module; set_return_msg then fails and the query ends in MODULE_ERROR, a SERVFAIL, as in Python.
func TestSafesearchCnameRedirectIsAnErrorWhenItsRecordCannotBeBuilt(t *testing.T) {
	const failed = "pfb_dns_proxy info: [pfBlockerNG]: SafeSearch: failed to store planted CNAME referral for duckduckgo.com."
	for _, row := range []struct {
		name       string
		entry      safeSearchEntry
		chased     []string // the answer the chase brought back: nil is the first pass
		storeFails bool
		wantCalls  int    // cache calls made before the failure
		wantLog    string // "" = nothing logged
	}{
		{"a target with a space", safeSearchEntry{a: "cname", aaaa: "safe duck.example", v4: "203.0.113.7"}, nil, false, 0, ""},
		{"a target with a label over 63 octets", safeSearchEntry{a: "cname", aaaa: strings.Repeat("a", 64) + ".example", v4: "203.0.113.7"}, nil, false, 0, ""},
		{"a baked v4 that is no address, after a failed store", ssEntry("not-an-address", ""), nil, true, 2, failed},
		// The fallback's own MODULE_ERROR: a false return here would let operate go on with the bare chased CNAME.
		{"a baked v4 that is no address, after a chase without one", ssEntry("not-an-address", ""), []string{ssChasedCN}, false, 0, ""},
	} {
		calls := recordCache(t, row.storeFails)
		m := ssModule(t, row.entry)
		out := captureLog(t) // after the boot, which logs its missing ini
		q := ssQstate(t, RR_TYPE_A, "192.0.2.1", row.chased...)
		opWantState(t, row.name, opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_ERROR)
		if len(*calls) != row.wantCalls || q.noCacheStore != 0 {
			t.Errorf("%s: (cache calls, noCacheStore) = (%+v, %d), want %d calls and 0", row.name, *calls, q.noCacheStore, row.wantCalls)
		}
		if row.chased == nil && row.wantCalls == 0 && q.returnMsg != nil {
			t.Errorf("%s: returnMsg = %v, want none: no record was built", row.name, q.returnMsg)
		}
		if lines := logLines(out); (row.wantLog == "" && len(lines) != 0) || (row.wantLog != "" && (len(lines) != 1 || lines[0] != row.wantLog)) {
			t.Errorf("%s: log = %q, want %q", row.name, lines, row.wantLog)
		}
	}
}

// ssPlantedRep is the reply the second cache call asked to store when that is a lone-CNAME referral, else nil.
func ssPlantedRep(calls *[]cacheCall) *replyInfo {
	if len(*calls) < 2 || (*calls)[1].rep == nil {
		return nil
	}
	rep := (*calls)[1].rep
	if rep.anNumrrsets != 1 || len(rep.rrsets) != 1 || rep.rrsets[0].rk.typeStr != "CNAME" {
		return nil
	}
	return rep
}

// --- safesearch_cname_redirect: the pass after the chase ---

func TestSafesearchCnameRedirectFinishesTheChasedAnswer(t *testing.T) {
	for _, row := range []struct {
		name       string
		qtype      uint16
		answer     []string
		bypassed   bool
		storeFails bool
		wantCalls  func(rep *replyInfo) []cacheCall
		wantLog    string
		noStore    int // noCacheStore after the pass, from 1 as the first pass left it
	}{
		{"A", RR_TYPE_A, []string{ssChasedCN, ssChasedA}, false, false,
			func(rep *replyInfo) []cacheCall { return []cacheCall{ssInvalidate(), ssStore(0, rep)} }, "", 0},
		{"AAAA", RR_TYPE_AAAA, []string{ssChasedCN, ssChasedAAAA}, false, false,
			func(rep *replyInfo) []cacheCall { return []cacheCall{ssInvalidate(), ssStore(0, rep)} }, "", 0},
		// issue #3508: a bypassed client's answer stays out of the shared cache, and no_cache_store stays as it was.
		{"a Group Policy bypassed client", RR_TYPE_A, []string{ssChasedCN, ssChasedA}, true, false,
			func(*replyInfo) []cacheCall { return []cacheCall{ssInvalidate()} }, "", 1},
		// issue #749: a failed re-cache must not SERVFAIL an answer that is already built and validated.
		{"a re-cache that fails", RR_TYPE_A, []string{ssChasedCN, ssChasedA}, false, true,
			func(rep *replyInfo) []cacheCall { return []cacheCall{ssInvalidate(), ssStore(0, rep)} },
			"pfb_dns_proxy info: [pfBlockerNG]: SafeSearch: failed to re-cache chased answer for duckduckgo.com.", 0},
	} {
		calls := recordCache(t, row.storeFails)
		client := "192.0.2.1"
		var bypassed []string
		if row.bypassed {
			client, bypassed = "10.0.0.77", []string{"10.0.0.77"}
		}
		m := ssModule(t, ssEntry("203.0.113.7", "2001:db8::7"), bypassed...)
		out := captureLog(t) // after the boot, which logs its missing ini
		q := ssQstate(t, row.qtype, client, row.answer...)
		chased := q.returnMsg
		q.noCacheStore = 1             // as the first pass (plant and restart) leaves it
		q.returnRcode = RCODE_NXDOMAIN // a stale rcode: the finished answer is NOERROR
		opWantState(t, row.name, opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_FINISHED)
		if q.returnMsg != chased || len(q.returnMsg.answer) != 2 {
			t.Errorf("%s: the chased message was replaced or cut: %+v", row.name, q.returnMsg)
		}
		// The planted hop is unsigned: without the insecure stamp a signed original zone goes bogus (issue #149).
		if q.returnRcode != RCODE_NOERROR || q.returnMsg.rep.security != secStatusInsecure || q.noCacheStore != row.noStore {
			t.Errorf("%s: (rcode, security, noCacheStore) = (%d, %d, %d), want (NOERROR, insecure %d, %d)",
				row.name, q.returnRcode, q.returnMsg.rep.security, q.noCacheStore, secStatusInsecure, row.noStore)
		}
		ssWantCalls(t, row.name, calls, row.wantCalls(chased.rep)...)
		wantLines := []string(nil)
		if row.wantLog != "" {
			wantLines = []string{row.wantLog}
		}
		if lines := logLines(out); !reflect.DeepEqual(lines, wantLines) {
			t.Errorf("%s: log = %q, want %q", row.name, lines, wantLines)
		}
	}
}

func TestSafesearchCnameRedirectAnswersFromTheBakedAddressWhenTheChaseFindsNoAddress(t *testing.T) {
	for _, row := range []struct {
		name    string
		qtype   uint16
		v4, v6  string
		want    string // "" = the redirect declines and the query finishes with the chased message untouched
		wantMsg uint16
	}{
		{"A", RR_TYPE_A, "203.0.113.7", "2001:db8::7", "duckduckgo.com. 300 IN A 203.0.113.7", dnswire.QR | dnswire.RA},
		{"AAAA", RR_TYPE_AAAA, "203.0.113.7", "2001:db8::7", "duckduckgo.com. 300 IN AAAA 2001:db8::7", dnswire.QR | dnswire.RA},
		// Proves the baked branch is real, not an always-answer path.
		{"A without baked addresses", RR_TYPE_A, "", "", "", 0},
		{"AAAA with only a baked v4", RR_TYPE_AAAA, "203.0.113.7", "", "", 0},
	} {
		calls := recordCache(t, false)
		m := ssModule(t, ssEntry(row.v4, row.v6))
		q := ssQstate(t, row.qtype, "192.0.2.1", ssChasedCN)
		chased := q.returnMsg
		q.returnRcode = RCODE_NXDOMAIN
		opWantState(t, row.name, opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_FINISHED)
		if row.want == "" {
			if q.returnMsg != chased || len(chased.answer) != 1 || q.returnRcode != RCODE_NXDOMAIN || chased.rep.security != secStatusUnchecked {
				t.Errorf("%s: the declined redirect touched the message: %+v, rcode %d", row.name, q.returnMsg, q.returnRcode)
			}
		} else {
			ssWantFinishedAs(t, row.name, q, row.want, row.wantMsg)
		}
		ssWantCalls(t, row.name, calls) // the baked answer is never cached either
	}
}

// --- safesearch_cname_redirect: what it leaves alone ---

func TestSafesearchCnameRedirectLeavesWhatItDoesNotHandle(t *testing.T) {
	entry := ssEntry("203.0.113.7", "2001:db8::7")
	m := ssModule(t, entry)
	snap := m.snapshot.Load()
	for _, row := range []struct {
		name  string
		qtype uint16
		entry safeSearchEntry
	}{
		{"a TXT query", RR_TYPE_TXT, entry},
		{"an MX query", RR_TYPE_MX, entry},
		{"an ANY query", RR_TYPE_ANY, entry},
		{"an entry without a target", RR_TYPE_A, safeSearchEntry{a: "cname", v4: "203.0.113.7", v6: "2001:db8::7"}},
	} {
		calls := recordCache(t, false)
		q := ssQstate(t, row.qtype, "192.0.2.1")
		if got := safesearchCnameRedirect(snap, MODULE_ID, q, row.qtype, row.entry); got {
			t.Errorf("%s: safesearchCnameRedirect = true, want false: let normal processing go on", row.name)
		}
		if q.returnMsg != nil || q.extState[MODULE_ID] != 0 || q.noCacheStore != 0 {
			t.Errorf("%s: the query was touched: %+v", row.name, q)
		}
		ssWantCalls(t, row.name, calls)
	}
}

func TestOperateModdoneLeavesTheReplyOfAnythingButACnameSafeSearchEntry(t *testing.T) {
	plain := func(s *snapshot) { s.safeSearchDB["duckduckgo.com"] = safeSearchEntry{a: "1.2.3.4"} }
	for _, row := range []struct {
		name  string
		set   func(*pfbSettings)
		fill  func(*snapshot)
		qname string
		qtype uint16
	}{
		{"a name with no entry", func(s *pfbSettings) { s.safeSearchDB = true }, nil, "normal.com.", RR_TYPE_A},
		{"a plain A-rewrite entry", func(s *pfbSettings) { s.safeSearchDB = true }, plain, ssQname, RR_TYPE_A},
		{"the SafeSearch flag off", nil, func(s *snapshot) { s.safeSearchDB["duckduckgo.com"] = ssEntry("203.0.113.7", "2001:db8::7") }, ssQname, RR_TYPE_A},
		{"a TXT query for a CNAME entry", func(s *pfbSettings) { s.safeSearchDB = true }, func(s *snapshot) { s.safeSearchDB["duckduckgo.com"] = ssEntry("203.0.113.7", "2001:db8::7") }, ssQname, RR_TYPE_TXT},
	} {
		calls := recordCache(t, false)
		m := modMust(t, t.TempDir())
		opInstall(t, m, row.set, row.fill)
		q := opQstate(row.qname, row.qtype, "192.0.2.1")
		reply := ssMsg(t, row.qtype, []string{"duckduckgo.com. 300 IN A 192.0.2.50"}, nil)
		q.returnMsg = reply
		opWantState(t, row.name, opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_FINISHED)
		if q.returnMsg != reply || len(reply.answer) != 1 || reply.rep.security != secStatusUnchecked || q.noCacheStore != 0 {
			t.Errorf("%s: Unbound's reply was touched: %+v", row.name, q.returnMsg)
		}
		ssWantCalls(t, row.name, calls)
	}
}

// --- the owner's snapshot rule: one query, one generation, the CNAME pass included ---

func TestSafesearchCnameRedirectReadsTheQuerysOwnSnapshot(t *testing.T) {
	entry := ssEntry("203.0.113.7", "2001:db8::7")
	swap := func(t *testing.T, m *pfbUnbound, bypassed bool) {
		t.Helper()
		opInstall(t, m, func(s *pfbSettings) { s.gpListDB = bypassed }, func(s *snapshot) {
			if bypassed {
				s.gpListDB["10.0.0.77"] = 0
			}
		})
	}
	for _, row := range []struct {
		name       string
		bypassedAt bool // the client is on the bypass list when the query arrives
		bypassedTo bool // and in the snapshot a reload publishes before the chased answer comes back
		wantCalls  func(rep *replyInfo) []cacheCall
	}{
		{"bypassed on arrival, listed no more", true, false, func(*replyInfo) []cacheCall { return []cacheCall{ssInvalidate()} }},
		{"not bypassed on arrival, listed since", false, true, func(rep *replyInfo) []cacheCall { return []cacheCall{ssInvalidate(), ssStore(0, rep)} }},
	} {
		calls := recordCache(t, false)
		var listed []string
		if row.bypassedAt {
			listed = []string{"10.0.0.77"}
		}
		m := ssModule(t, entry, listed...)
		q := opQstate(ssQname, RR_TYPE_A, "10.0.0.77")
		opWantState(t, row.name+": NEW", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
		swap(t, m, row.bypassedTo)
		q.returnMsg = ssMsg(t, RR_TYPE_A, []string{ssChasedCN, ssChasedA}, nil)
		opWantState(t, row.name+": MODDONE", opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_FINISHED)
		ssWantCalls(t, row.name, calls, row.wantCalls(q.returnMsg.rep)...)
	}

	// The entry is the arrival snapshot's too: a reload that drops it does not turn the first pass into a pass-through.
	calls := recordCache(t, false)
	m := ssModule(t, entry)
	q := opQstate(ssQname, RR_TYPE_A, "192.0.2.1")
	opWantState(t, "entry dropped: NEW", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	opInstall(t, m, nil, nil)
	opWantState(t, "entry dropped: MODDONE", opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_RESTART_NEXT)
	opSections(t, "entry dropped", q, []string{ssPlanted}, nil)
	ssNeedMsg(t, "entry dropped", q)
	ssWantCalls(t, "entry dropped", calls, ssInvalidate(), ssStore(1, q.returnMsg.rep))
}
