// Tests for the Go translation of pfb_unbound.py's loaders and decisions: _load_hsts_db, _load_gp_bypass_list,
// _gp_net_match, _gp_bypassed, convert_other, _load_safesearch_db, safesearch_entry, rebuild_and_swap, init_standard's
// noAAAA / Group Policy / SafeSearch / HSTS sections and operate()'s noAAAA, SafeSearch and DNSBL branches. They
// mirror tests/test_pfb_unbound.py (TestConvertOther, TestOperateNoAAAA, TestOperateDnsbl, TestGroupPolicyBypassCidr,
// TestLoadSafeSearchDb, TestSafeSearchEntry, TestStage2UnifiedDecision), tests/test_adr10_swap.py,
// tests/test_adr61_py_status.py (the loader wiring) and tests/test_adr06_init_from_raw.py (noAAAA); the expectations
// are the Python source's. The Group Policy rows replay testdata/pfb_unbound_gp_oracle.json, which
// testdata/gen_pfb_unbound_gp_oracle.py records from pfb_unbound.py on CPython 3.11.
package decider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const opSOA = "pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600"

// opInstall publishes a fresh snapshot the way a reload does: through rebuildAndSwap, with the live settings as the
// base (set edits a copy) and fill populating the new snapshot's dicts.
func opInstall(t *testing.T, m *pfbUnbound, set func(*pfbSettings), fill func(*snapshot)) {
	t.Helper()
	settings := *m.snapshot.Load().settings
	if set != nil {
		set(&settings)
	}
	ok := m.rebuildAndSwap(func() (*snapshot, error) {
		s := newSnapshot()
		s.settings = &settings
		if fill != nil {
			fill(s)
		}
		return s, nil
	}, false)
	if !ok {
		t.Fatalf("rebuildAndSwap = false, want the snapshot installed")
	}
}

// opEnable is the Python tests' _enable: the DNSBL gate on, Python blocking on, the VIP addresses set.
func opEnable(s *pfbSettings) {
	s.pythonBlacklist = true
	s.pythonBlocking = true
	s.dnsblIpv4 = "10.10.10.1"
	s.dnsblIpv6 = "2001:db8::10"
}

func opBlockData(s *snapshot, name, log string, index int) {
	s.dataDB[name] = &blockEntry{log: log, index: index, band: 1}
}

func opFeed(s *snapshot, index int, feed, group string) {
	s.feedGroupIndexDB[index] = feedGroup{feed, group}
}

func opQstate(qname string, qtype uint16, clientIP string) *moduleQstate {
	return newModuleQstate(queryInfo{qnameStr: qname, qtype: qtype, qclass: RR_CLASS_IN}, clientIP, 5353, 0, "UDP", "192.0.2.2", "em0")
}

func opRR(t *testing.T, text string) dnswire.RR {
	t.Helper()
	rr, err := dnswire.RRFromText(text)
	if err != nil {
		t.Fatalf("RRFromText(%q): %v", text, err)
	}
	return rr
}

// opSections fails the test unless the query's reply carries exactly the given answer and authority RR texts.
func opSections(t *testing.T, what string, q *moduleQstate, answer, authority []string) {
	t.Helper()
	if q.returnMsg == nil {
		t.Errorf("%s: returnMsg = nil, want a reply with answer %v authority %v", what, answer, authority)
		return
	}
	for _, section := range []struct {
		name string
		got  []dnswire.RR
		want []string
	}{{"answer", q.returnMsg.answer, answer}, {"authority", q.returnMsg.authority, authority}} {
		var want []dnswire.RR
		for _, text := range section.want {
			want = append(want, opRR(t, text))
		}
		if len(section.got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(section.got, want)) {
			t.Errorf("%s: %s = %v, want %v", what, section.name, section.got, section.want)
		}
	}
}

func opOperate(m *pfbUnbound, event int, q *moduleQstate) int {
	m.operate(MODULE_ID, event, q, nil)
	return q.extState[MODULE_ID]
}

func opWantState(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: extState = %d, want %d", what, got, want)
	}
}

// opSeed puts a verdict on the name's Decision, stamped with the live snapshot generation (a seeded memo plays a
// verdict the live snapshot produced; an unstamped one reads as stale, issue #1074).
func opSeed(m *pfbUnbound, name string, d *dnsblDecision) {
	decisionFor(m.decisionDB, name, m.snapshot.Load().gen).setDnsbl(d)
}

func opBlockVerdict(extra func(*dnsblDecision)) *dnsblDecision {
	d := &dnsblDecision{isFound: true, logType: "1", bType: "DNSBL", pType: "Python", feed: "F", group: "G", groupOwner: "G", groupOrigin: "custom"}
	if extra != nil {
		extra(d)
	}
	return d
}

func opMemo(t *testing.T, m *pfbUnbound, name string) *dnsblDecision {
	t.Helper()
	dec, ok := m.decisionDB.get(name)
	if !ok {
		return nil
	}
	d, _ := dec.getDnsbl().(*dnsblDecision)
	return d
}

func opIsBlock(d *dnsblDecision) bool { return d != nil && d.isFound && !d.inWhitelist }

// opCnameReply is a resolved answer carrying `orig -> CNAME -> target`, then the target's A record: the shape
// operate()'s CNAME walk reads (an_numrrsets 2, the CNAME rrset first).
func opCnameReply(t *testing.T, orig, target string) *dnsMsg {
	t.Helper()
	return newDnsMsg(queryInfo{qnameStr: orig + ".", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR|dnswire.RA, []dnswire.RR{
		opRR(t, orig+". 300 IN CNAME "+target+"."),
		opRR(t, target+". 300 IN A 192.0.2.50"),
	}, nil, nil)
}

// --- convert_other ---

// rr_data for a CNAME/NS/PTR-class record: a 2-byte RDATA length prefix, then an uncompressed wire-format name.
func opDname(name string) []byte {
	var wire []byte
	for label := range strings.SplitSeq(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	return append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...)
}

func TestConvertOther(t *testing.T) {
	longLabel := strings.Repeat("a", 40)
	overrun := []byte{0, 3, 10, 'a', 'b'}
	var drop64 []byte
	drop64 = append(drop64, 3, 'w', 'w', 'w', 64)
	drop64 = append(drop64, strings.Repeat("a", 64)...)
	drop64 = append(drop64, 3, 'c', 'o', 'm', 0)
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"an interior 16-char label decodes whole", opDname("www.googleadservices.com"), "www.googleadservices.com"},
		{"an interior 13-char label decodes whole", opDname("www.thirteenchars.com"), "www.thirteenchars.com"},
		{"an interior 40-char label decodes whole", opDname("www." + longLabel + ".com"), "www." + longLabel + ".com"},
		{"a label byte above 126 is kept, as the Latin-1 character", append([]byte{0, 15}, 3, 'w', 'w', 'w', 3, 'a', 0xE9, 'b', 3, 'c', 'o', 'm', 0), "www.a\u00e9b.com"},
		{"a plain two-label name", opDname("example.com"), "example.com"},
		{"a bare root label is the empty name", []byte{0, 1, 0}, "Unknown"},
		{"a compression pointer (length over 63) is malformed", []byte{0, 2, 0xC0, 0x2A}, "Unknown"},
		{"a label overrunning the buffer is malformed", overrun, "Unknown"},
		{"empty input", []byte{}, "Unknown"},
		{"nil input", nil, "Unknown"},
		{"a 63-char label is the valid maximum", opDname("www." + strings.Repeat("a", 63) + ".com"), "www." + strings.Repeat("a", 63) + ".com"},
		{"a 64-char label is malformed without any overrun", append([]byte{0, byte(len(drop64))}, drop64...), "Unknown"},
		{"only a length prefix", []byte{0, 5}, "Unknown"},
		{"a TXT character-string with no root terminator decodes", []byte("\x00\x06\x05hello"), "hello"},
		{"MX rdata reads its preference's zero as a root label", append([]byte{0, 11, 0, 0x0a}, 3, 'f', 'o', 'o', 3, 'c', 'o', 'm', 0), "Unknown"},
		{"a single byte (no room for the prefix body)", []byte{0}, "Unknown"},
		{"labels then the buffer ends mid-label", []byte{0, 4, 3, 'a', 'b'}, "Unknown"},
	} {
		if got := convertOther(tc.in); got != tc.want {
			t.Errorf("%s: convertOther(% x) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// --- _load_hsts_db ---

func opHstsModule(t *testing.T, python bool, content *string) (*pfbUnbound, string) {
	t.Helper()
	dir := t.TempDir()
	m := modMust(t, dir)
	m.pfb.pythonHsts = python
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	if content != nil {
		if err := os.WriteFile(m.pfb.pfbPyHsts, []byte(*content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return m, m.pfb.pfbPyStatus
}

func opLedgerItems(t *testing.T, path string) []string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	var items []string
	for _, entry := range statusRead(t, path) {
		items = append(items, fmt.Sprint(entry["item"]))
	}
	return items
}

func TestLoadHstsDbReadsKeysAndSkipsCommentsAndBlanks(t *testing.T) {
	content := "# comment\n\n  bank.example  \r\n0\r#another comment\rgle\n   # indented comment\nmeet\n"
	m, _ := opHstsModule(t, true, &content)
	db := map[string]struct{}{}

	m.loadHstsDb(db)

	want := []string{"bank.example", "0", "gle", "meet"}
	var got []string
	for key := range db {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("hstsDB keys = %q, want %q (stripped; '#'-lines and blank lines skipped; '0' is a valid key; a lone CR ends a line)", got, want)
	}
}

func TestLoadHstsDbIsGatedOnPythonHstsAndTheFile(t *testing.T) {
	content := "bad.example\n"
	for _, tc := range []struct {
		name    string
		python  bool
		content *string
	}{{"python_hsts off", false, &content}, {"no file", true, nil}} {
		m, ledger := opHstsModule(t, tc.python, tc.content)
		m.pfbPyStatusOpen("dnsbl", m.pfb.pfbPyHsts, "parse", "left open by an earlier failure")
		db := map[string]struct{}{}

		m.loadHstsDb(db)

		if len(db) != 0 {
			t.Errorf("%s: hstsDB = %v, want nothing loaded", tc.name, db)
		}
		if items := opLedgerItems(t, ledger); len(items) != 0 {
			t.Errorf("%s: ledger = %v, want the orphaned entry closed", tc.name, items)
		}
	}
}

func TestLoadHstsDbNeverOpensAnEntryWhenDisabled(t *testing.T) {
	content := "bad.example\n"
	m, ledger := opHstsModule(t, false, &content)

	m.loadHstsDb(map[string]struct{}{})

	if _, err := os.Stat(ledger); err == nil {
		t.Errorf("%s exists, want no ledger write when python_hsts is off", ledger)
	}
}

// Python's tests fail a real open(); the module reads through m.readFile so a test can fail the read the same way.
func TestLoadHstsDbFailureOpensAnEntryAndSuccessClearsIt(t *testing.T) {
	content := "bad.example\n"
	m, ledger := opHstsModule(t, true, &content)
	logs := modCaptureLog(t)
	real := m.readFile
	m.readFile = func(name string) ([]byte, error) { return nil, errors.New("simulated read failure") }
	db := map[string]struct{}{}

	m.loadHstsDb(db)

	want := "pfb_dns_proxy error: [pfBlockerNG]: Failed to load: " + m.pfb.pfbPyHsts + ": simulated read failure\n"
	if logs.String() != want {
		t.Errorf("log = %q, want %q", logs.String(), want)
	}
	if items := opLedgerItems(t, ledger); !slices.Equal(items, []string{m.pfb.pfbPyHsts}) {
		t.Errorf("ledger after a failed load = %v, want one entry for %s", items, m.pfb.pfbPyHsts)
	}
	entries := statusRead(t, ledger)
	if entries[0]["stage"] != "parse" || entries[0]["facility"] != "dnsbl" || entries[0]["message"] != "Failed to load: "+m.pfb.pfbPyHsts+": simulated read failure" {
		t.Errorf("ledger entry = %v, want facility dnsbl, stage parse and the failure text", entries[0])
	}

	m.readFile = real
	m.loadHstsDb(db)
	if items := opLedgerItems(t, ledger); len(items) != 0 {
		t.Errorf("ledger after a good load = %v, want the entry cleared", items)
	}
	if _, ok := db["bad.example"]; !ok {
		t.Errorf("hstsDB = %v, want bad.example loaded on the retry", db)
	}
}

// --- _load_safesearch_db and safesearch_entry ---

func opSafeSearchModule(t *testing.T, content *string) (*pfbUnbound, string) {
	t.Helper()
	dir := t.TempDir()
	m := modMust(t, dir)
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	if content != nil {
		if err := os.WriteFile(m.pfb.pfbPySs, []byte(*content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return m, m.pfb.pfbPyStatus
}

func TestLoadSafeSearchDbParsesThreeAndFiveColumnRows(t *testing.T) {
	content := "forcesafe.com,1.2.3.4,::1\ncname.com,cname,target.com,5.6.7.8,::2\n"
	m, _ := opSafeSearchModule(t, &content)
	db := map[string]safeSearchEntry{}

	m.loadSafesearchDb(db)

	want := map[string]safeSearchEntry{
		"forcesafe.com": {a: "1.2.3.4", aaaa: "::1"},
		"cname.com":     {a: "cname", aaaa: "target.com", v4: "5.6.7.8", v6: "::2"},
	}
	if !reflect.DeepEqual(db, want) {
		t.Errorf("safeSearchDB = %v, want %v", db, want)
	}
	if !m.pfb.safeSearchDB {
		t.Errorf("pfb.safeSearchDB = false, want true")
	}
}

func TestLoadSafeSearchDbReportsOtherRowShapesAndKeepsGoing(t *testing.T) {
	content := "a.com,1.2.3.4\nb.com,1.2.3.4,::1,x\nok.com,5.6.7.8,\nc.com,1,2,3,4,5\n"
	m, _ := opSafeSearchModule(t, &content)
	logs := modCaptureLog(t)
	db := map[string]safeSearchEntry{}

	m.loadSafesearchDb(db)

	if !reflect.DeepEqual(db, map[string]safeSearchEntry{"ok.com": {a: "5.6.7.8"}}) {
		t.Errorf("safeSearchDB = %v, want only the 3-column row", db)
	}
	for _, row := range []string{"['a.com', '1.2.3.4']", "['b.com', '1.2.3.4', '::1', 'x']", "['c.com', '1', '2', '3', '4', '5']"} {
		want := "pfb_dns_proxy error: [pfBlockerNG]: Failed to parse: " + m.pfb.pfbPySs + ": " + row + "\n"
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log = %q, want it to contain %q", logs.String(), want)
		}
	}
}

func TestLoadSafeSearchDbFailureNamesTheSafeSearchFileAndLedgers(t *testing.T) {
	content := "forcesafe.com,1.2.3.4,::1\n"
	m, ledger := opSafeSearchModule(t, &content)
	logs := modCaptureLog(t)
	m.pfb.pfbPyZone = filepath.Join(t.TempDir(), "pfb_py_zone.txt") // the wrong-file trap of #714 FIX #6
	real := m.readFile
	m.readFile = func(string) ([]byte, error) { return nil, errors.New("simulated read failure") }
	db := map[string]safeSearchEntry{}

	m.loadSafesearchDb(db)

	if !strings.Contains(logs.String(), m.pfb.pfbPySs) || strings.Contains(logs.String(), m.pfb.pfbPyZone) {
		t.Errorf("log = %q, want it to name %s and not %s", logs.String(), m.pfb.pfbPySs, m.pfb.pfbPyZone)
	}
	if items := opLedgerItems(t, ledger); !slices.Equal(items, []string{m.pfb.pfbPySs}) {
		t.Errorf("ledger after a failed load = %v, want one entry for %s", items, m.pfb.pfbPySs)
	}
	if m.pfb.safeSearchDB {
		t.Errorf("pfb.safeSearchDB = true after a failed load, want false")
	}

	m.readFile = real
	m.loadSafesearchDb(db)
	if items := opLedgerItems(t, ledger); len(items) != 0 {
		t.Errorf("ledger after a good load = %v, want the entry cleared", items)
	}
	if db["forcesafe.com"] != (safeSearchEntry{a: "1.2.3.4", aaaa: "::1"}) {
		t.Errorf("safeSearchDB = %v, want forcesafe.com loaded on the retry", db)
	}
}

func TestLoadSafeSearchDbAbsentFileClosesAnOrphanedEntryAndTouchesNothingElse(t *testing.T) {
	m, ledger := opSafeSearchModule(t, nil)
	m.pfbPyStatusOpen("dnsbl", m.pfb.pfbPySs, "parse", "left open")

	m.loadSafesearchDb(map[string]safeSearchEntry{})

	if items := opLedgerItems(t, ledger); len(items) != 0 {
		t.Errorf("ledger = %v, want the orphaned entry closed when the file is gone", items)
	}
	m2, ledger2 := opSafeSearchModule(t, nil)
	m2.loadSafesearchDb(map[string]safeSearchEntry{})
	if _, err := os.Stat(ledger2); err == nil {
		t.Errorf("a ledger was written for a module that never had a failure")
	}
}

func TestSafesearchEntry(t *testing.T) {
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { s.safeSearchDB = true }, func(s *snapshot) {
		s.safeSearchDB["forcesafe.com"] = safeSearchEntry{a: "1.2.3.4"}
		s.safeSearchDB["www.x.com"] = safeSearchEntry{a: "5.6.7.8"}
		s.safeSearchDB["www.www.y.com"] = safeSearchEntry{a: "9.9.9.9"}
	})
	snap := m.snapshot.Load()

	for _, tc := range []struct {
		name, query string
		want        safeSearchEntry
		found       bool
	}{
		{"an exact match", "forcesafe.com", safeSearchEntry{a: "1.2.3.4"}, true},
		{"the www. form of a bare query", "x.com", safeSearchEntry{a: "5.6.7.8"}, true},
		{"a miss", "nomatch.com", safeSearchEntry{}, false},
		{"a www. query tries no second www.", "www.y.com", safeSearchEntry{}, false},
	} {
		got, found := m.safesearchEntry(snap, tc.query)
		if found != tc.found || got != tc.want {
			t.Errorf("%s: safesearchEntry(%q) = (%v, %v), want (%v, %v)", tc.name, tc.query, got, found, tc.want, tc.found)
		}
	}

	// A miss is memoized on the Decision as None, so it is decided once.
	dec, ok := m.decisionDB.get("nomatch.com")
	if !ok || dec.getSafesearch() != nil {
		t.Errorf("decision for a miss = (%v, %v), want a Decision whose safesearch axis is nil (None)", dec, ok)
	}
	dec, ok = m.decisionDB.get("x.com")
	if !ok || dec.getSafesearch() != (safeSearchEntry{a: "5.6.7.8"}) {
		t.Errorf("decision for a hit = (%v, %v), want the entry memoized", dec, ok)
	}
}

// --- _load_gp_bypass_list, _gp_net_match, _gp_bypassed ---

type gpOracle struct {
	Probes []string `json:"probes"`
	Rows   []struct {
		Value    string   `json:"value"`
		Gate     bool     `json:"gate"`
		Exact    []string `json:"exact"`
		Nets     []string `json:"nets"`
		Bypassed []string `json:"bypassed"`
	} `json:"rows"`
}

var zoneSuffix = regexp.MustCompile(`%[^/]*`)

// opGpConfig is a [GP_Bypass_List] section with one row per value, read by the module's own ini parser.
func opGpConfig(t *testing.T, rows ...string) *configParser {
	t.Helper()
	var text strings.Builder
	text.WriteString("[GP_Bypass_List]\n")
	for i, row := range rows {
		fmt.Fprintf(&text, "%d = %s\n", i, row)
	}
	return cfgParse(t, text.String())
}

func opGpLoad(t *testing.T, rows ...string) (*pfbUnbound, *snapshot) {
	t.Helper()
	m := modMust(t, t.TempDir())
	snap := newSnapshot()
	m.loadGpBypassList(opGpConfig(t, rows...), snap)
	return m, snap
}

// opGpBypassed is _gp_bypassed for a client address, against a snapshot the loader filled.
func opGpBypassed(m *pfbUnbound, snap *snapshot, qIP string) bool {
	snap.settings = &pfbSettings{gpListDB: m.pfb.gpListDB}
	return gpBypassed(snap, opQstate("evil.com.", RR_TYPE_A, qIP))
}

func TestGroupPolicyRowsMatchPython(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_gp_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle gpOracle
	if err := json.Unmarshal(data, &oracle); err != nil {
		t.Fatal(err)
	}
	logs := modCaptureLog(t)
	for _, row := range oracle.Rows {
		logs.Reset()
		m, snap := opGpLoad(t, row.Value)
		if m.pfb.gpListDB != row.Gate {
			t.Errorf("row %q: gate = %v, want %v", row.Value, m.pfb.gpListDB, row.Gate)
		}
		var exact []string
		for key := range snap.gpListDB {
			exact = append(exact, key)
		}
		if !slices.Equal(exact, row.Exact) {
			t.Errorf("row %q: exact keys = %q, want %q", row.Value, exact, row.Exact)
		}
		var nets []string
		for _, prefix := range snap.gpNetDB {
			nets = append(nets, prefix.String())
		}
		var wantNets []string
		for _, net := range row.Nets {
			wantNets = append(wantNets, zoneSuffix.ReplaceAllString(net, ""))
		}
		if !slices.Equal(nets, wantNets) {
			t.Errorf("row %q: networks = %q, want %q", row.Value, nets, wantNets)
		}
		var bypassed []string
		for _, probe := range oracle.Probes {
			if opGpBypassed(m, snap, probe) {
				bypassed = append(bypassed, probe)
			}
		}
		if !slices.Equal(bypassed, row.Bypassed) {
			t.Errorf("row %q: bypassed clients = %q, want %q", row.Value, bypassed, row.Bypassed)
		}
		failed := strings.Contains(logs.String(), "Failed to parse: GP_Bypass_List: row:0 line:"+row.Value)
		if failed != (!row.Gate) {
			t.Errorf("row %q: parse failure logged = %v (log %q), want %v", row.Value, failed, logs.String(), !row.Gate)
		}
	}
}

func TestGroupPolicyUnparseableRowIsSkippedReportedAndNeverAbortsTheLoad(t *testing.T) {
	for _, bad := range []string{"example.com", "10.0.0.0/33", "2001:db8:9::/129", "xn--abc", "10.0.0.0/", "/24", "10.0.0.0/-1", "10.0.0.0/24 extra", "# comment", ""} {
		logs := modCaptureLog(t)
		m, snap := opGpLoad(t, "192.0.2.0/24", bad, "2001:db8:5::/48")
		if !strings.Contains(logs.String(), "[pfBlockerNG]: Failed to parse: GP_Bypass_List: row:1 line:"+bad+"\n") {
			t.Errorf("row %q: log = %q, want the row-1 parse failure", bad, logs.String())
		}
		for ip, want := range map[string]bool{"192.0.2.9": true, "2001:db8:5::1": true, "203.0.113.50": false, "10.0.0.5": false} {
			if got := opGpBypassed(m, snap, ip); got != want {
				t.Errorf("after bad row %q: bypassed(%s) = %v, want %v (the rows around it still load, it widens nothing)", bad, ip, got, want)
			}
		}
	}
}

func TestGroupPolicyGateStaysOffWhenNoRowParses(t *testing.T) {
	logs := modCaptureLog(t)
	m, snap := opGpLoad(t, "example.com")
	if m.pfb.gpListDB || len(snap.gpListDB) != 0 || len(snap.gpNetDB) != 0 {
		t.Errorf("gate, exact, networks = (%v, %v, %v), want an off gate and nothing loaded", m.pfb.gpListDB, snap.gpListDB, snap.gpNetDB)
	}
	if logs.Len() == 0 {
		t.Errorf("log is empty, want the parse failure")
	}
	m = modMust(t, t.TempDir())
	snap = newSnapshot()
	m.loadGpBypassList(cfgParse(t, "[MAIN]\nk = v\n"), snap)
	if m.pfb.gpListDB {
		t.Errorf("a config without the section turned the gate on")
	}
}

func TestGroupPolicyBypassedIsFalseWithoutAUsableAddress(t *testing.T) {
	m, snap := opGpLoad(t, "0.0.0.0/0", "::/0")
	for _, ip := range []string{"", "not-an-address", "Unknown"} {
		if opGpBypassed(m, snap, ip) {
			t.Errorf("bypassed(%q) = true, want false even with the widest networks", ip)
		}
	}
	snap.settings = &pfbSettings{gpListDB: false}
	if gpBypassed(snap, opQstate("evil.com.", RR_TYPE_A, "203.0.113.9")) {
		t.Errorf("bypassed with the gate off = true, want false")
	}
}

func TestGpNetMatch(t *testing.T) {
	_, snap := opGpLoad(t, "10.0.0.0/24", "2001:db8:1::/64")
	for ip, want := range map[string]bool{
		"10.0.0.77": true, "10.0.1.1": false, "2001:db8:1::abcd": true, "2001:db8:2::1": false,
		"fe80::1%em0": false, "::ffff:10.0.0.77": false, "garbage": false, "": false,
	} {
		if got := gpNetMatch(snap.gpNetDB, ip); got != want {
			t.Errorf("gpNetMatch(%q) = %v, want %v", ip, got, want)
		}
	}
}

// Both of Python's per-IP rules at once, through operate(): a bypassed client resolves and is kept out of the shared
// cache (issue #3508), any other client is blocked.
func TestOperateGroupPolicyBypass(t *testing.T) {
	m := modMust(t, t.TempDir())
	probe := newSnapshot()
	m.loadGpBypassList(opGpConfig(t, "10.0.0.0/24", "192.0.2.7", "fe80::1%em0", "2001:db8:1::/64"), probe)
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.gpListDB = true }, func(s *snapshot) {
		opBlockData(s, "evil.com", "1", 0)
		opFeed(s, 0, "TestFeed", "TestGroup")
		s.gpListDB, s.gpNetDB = probe.gpListDB, probe.gpNetDB
	})
	for _, tc := range []struct {
		qname, ip string
		bypassed  bool
	}{
		{"evil.com.", "9.255.255.255", false}, {"evil.com.", "10.0.1.0", false}, {"evil.com.", "10.0.0.77", true},
		{"evil.com.", "10.0.0.255", true}, {"evil.com.", "192.0.2.7", true}, {"evil.com.", "192.0.2.8", false},
		{"evil.com.", "fe80::1", false}, {"evil.com.", "fe80::1%em0", true}, {"evil.com.", "2001:db8:1::abcd", true},
		{"evil.com.", "2001:db8:2::1", false}, {"good.com.", "10.0.0.77", true},
	} {
		m.decisionDB.clear()
		q := opQstate(tc.qname, RR_TYPE_A, tc.ip)
		state := opOperate(m, MODULE_EVENT_NEW, q)
		switch {
		case tc.bypassed:
			opWantState(t, tc.ip+" "+tc.qname, state, MODULE_WAIT_MODULE)
			if q.noCacheStore != 1 {
				t.Errorf("%s %s: noCacheStore = %d, want 1: a bypassed answer must not reach the shared cache", tc.ip, tc.qname, q.noCacheStore)
			}
		case tc.qname == "evil.com.":
			opWantState(t, tc.ip+" "+tc.qname, state, MODULE_FINISHED)
		}
	}
	q := opQstate("good.com.", RR_TYPE_A, "10.0.1.1")
	opWantState(t, "an unbypassed client, an unlisted name", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if q.noCacheStore != 0 {
		t.Errorf("noCacheStore = %d for a client outside the list, want 0: only bypassed answers stay out of the cache", q.noCacheStore)
	}
}

// --- init_standard: the noAAAA, Group Policy, SafeSearch and HSTS sections ---

func TestInitStandardLoadsNoAAAARows(t *testing.T) {
	logs := modCaptureLog(t)
	// Rows follow the file order; a later row for the same domain wins, whatever its option name.
	ini := "[MAIN]\npython_enable = true\n[noAAAA]\n1 = noaaaa.com,0\n2 = noaaawild.net,1\n3 = bad row\n4 = a,b,c\n5 = dup.com,0\n6 = dup.com,1\n7 = x.com,2\n"
	m := modMust(t, modIniDir(t, ini))
	snap := m.snapshot.Load()

	want := map[string]bool{"noaaaa.com": false, "noaaawild.net": true, "dup.com": true, "x.com": false}
	if !reflect.DeepEqual(snap.noAAAADB, want) {
		t.Errorf("noAAAADB = %v, want %v", snap.noAAAADB, want)
	}
	if !snap.settings.noAAAADB || !m.pfb.noAAAADB {
		t.Errorf("noAAAADB flag = (snapshot %v, pfb %v), want true", snap.settings.noAAAADB, m.pfb.noAAAADB)
	}
	for _, row := range []string{"row:3 line:bad row", "row:4 line:a,b,c"} {
		if !strings.Contains(logs.String(), "[pfBlockerNG]: Failed to parse: noAAAA: "+row+"\n") {
			t.Errorf("log = %q, want the parse failure %q", logs.String(), row)
		}
	}
	for domain, wantBlock := range map[string]bool{"noaaaa.com": true, "sub.noaaaa.com": false, "host.noaaawild.net": true, "noaaawild.net": true, "unrelated.com": false} {
		if got := evaluateNoaaaa(domain, snap.noAAAADB); got != wantBlock {
			t.Errorf("evaluateNoaaaa(%q) = %v, want %v", domain, got, wantBlock)
		}
	}
}

func TestInitStandardNoAAAAFlagFollowsTheSectionAndPythonEnable(t *testing.T) {
	for _, tc := range []struct {
		name, ini string
		wantFlag  bool
		wantRows  int
	}{
		{"an empty section", "[MAIN]\npython_enable = true\n[noAAAA]\n", false, 0},
		{"no section", "[MAIN]\npython_enable = true\n", false, 0},
		{"only malformed rows still turn the flag on", "[MAIN]\npython_enable = true\n[noAAAA]\n1 = nocomma\n", true, 0},
		{"python_enable off loads nothing", "[MAIN]\npython_enable = false\n[noAAAA]\n1 = a.com,1\n", false, 0},
		{"CRLF line endings", "[MAIN]\npython_enable = true\n[noAAAA]\r\n1 = a.com,1\r\n", true, 1},
	} {
		modCaptureLog(t)
		m := modMust(t, modIniDir(t, tc.ini))
		snap := m.snapshot.Load()
		if snap.settings.noAAAADB != tc.wantFlag || len(snap.noAAAADB) != tc.wantRows {
			t.Errorf("%s: (flag, rows) = (%v, %d), want (%v, %d)", tc.name, snap.settings.noAAAADB, len(snap.noAAAADB), tc.wantFlag, tc.wantRows)
		}
	}
}

func TestInitStandardRaisesWhereNoAAAAItemsRaisesInPython(t *testing.T) {
	// config.items("noAAAA") interpolates every value outside the try block, so a bad '%' escapes init_standard.
	m, err := initStandard(MODULE_ID, modIniDir(t, "[MAIN]\npython_enable = true\n[noAAAA]\n1 = a.com%(nope)s,1\n"))
	if m != nil || err == nil || !strings.Contains(err.Error(), "noAAAA") || !strings.Contains(err.Error(), "Bad value substitution") {
		t.Errorf("initStandard = (%v, %v), want (nil, an error naming noAAAA and the bad substitution)", m, err)
	}
	// [GP_Bypass_List] is read raw, so the same text is no error there.
	zoned, err := initStandard(MODULE_ID, modIniDir(t, "[MAIN]\npython_enable = true\n[GP_Bypass_List]\n1 = fe80::1%em0\n"))
	if err != nil {
		t.Fatalf("initStandard with a zone-id Group Policy row: %v, want nil", err)
	}
	stopModule(t, zoned)
}

func TestInitStandardLoadsGroupPolicyAndSafeSearchAndHsts(t *testing.T) {
	dir := t.TempDir()
	ini := "[MAIN]\r\npython_enable = true\r\npython_hsts = true\r\n[GP_Bypass_List]\r\n0 = 10.0.0.0/24\r\n1 = 2001:db8:1::/64\r\n2 = 192.0.2.7\r\n3 = fe80::1%em0\r\n"
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"pfb_py_ss.txt": "forcesafe.com,1.2.3.4,::1\n", "pfb_py_hsts.txt": "# header\nbank.example\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := modMust(t, dir)
	snap := m.snapshot.Load()

	if !snap.settings.gpListDB || !snap.settings.safeSearchDB {
		t.Errorf("flags (gpListDB, safeSearchDB) = (%v, %v), want true", snap.settings.gpListDB, snap.settings.safeSearchDB)
	}
	for ip, want := range map[string]bool{"10.0.1.1": false, "10.0.0.77": true, "2001:db8:1::abcd": true, "192.0.2.7": true, "fe80::1": false, "fe80::1%em0": true} {
		if got := gpBypassed(snap, opQstate("x.", RR_TYPE_A, ip)); got != want {
			t.Errorf("after a CRLF ini boot: gpBypassed(%q) = %v, want %v", ip, got, want)
		}
	}
	if got := snap.safeSearchDB["forcesafe.com"]; got != (safeSearchEntry{a: "1.2.3.4", aaaa: "::1"}) {
		t.Errorf("safeSearchDB[forcesafe.com] = %v, want the row", got)
	}
	if _, ok := snap.hstsDB["bank.example"]; !ok || len(snap.hstsDB) != 1 {
		t.Errorf("hstsDB = %v, want exactly bank.example", snap.hstsDB)
	}
}

func TestInitStandardGroupPolicyReloadDropsEntriesRemovedFromTheIni(t *testing.T) {
	dir := t.TempDir()
	boot := func(row string) *pfbUnbound {
		if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\n[GP_Bypass_List]\n0 = "+row+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return modMust(t, dir)
	}
	first := boot("10.0.0.0/24")
	if !gpBypassed(first.snapshot.Load(), opQstate("x.", RR_TYPE_A, "10.0.0.77")) {
		t.Fatalf("before the reload: 10.0.0.77 is not bypassed, want bypassed")
	}
	second := boot("192.0.2.0/24")
	snap := second.snapshot.Load()
	if gpBypassed(snap, opQstate("x.", RR_TYPE_A, "10.0.0.77")) || !gpBypassed(snap, opQstate("x.", RR_TYPE_A, "192.0.2.9")) {
		t.Errorf("after the reload: want 10.0.0.77 blocked and 192.0.2.9 bypassed; a reload must not inherit the old network")
	}
}

func TestInitStandardInstallsOneSnapshotOnEveryPath(t *testing.T) {
	modCaptureLog(t)
	for name, dir := range map[string]string{
		"no ini":         t.TempDir(),
		"python_enable":  modIniDir(t, "[MAIN]\npython_enable = true\n"),
		"disabled":       modIniDir(t, "[MAIN]\npython_enable = false\n"),
		"without a MAIN": modIniDir(t, "[X]\nk = v\n"),
	} {
		m := modMust(t, dir)
		snap := m.snapshot.Load()
		if snap == nil || snap.settings == nil || snap.gen == 0 {
			t.Errorf("%s: snapshot = %+v, want one with settings and a generation", name, snap)
			continue
		}
		if !reflect.DeepEqual(*snap.settings, m.pfb) {
			t.Errorf("%s: snapshot settings differ from the module's settings:\n got %+v\nwant %+v", name, *snap.settings, m.pfb)
		}
		if m.decisionDB == nil || m.regexRuntime == nil {
			t.Errorf("%s: (decisionDB, regexRuntime) = (%v, %v), want both created", name, m.decisionDB, m.regexRuntime)
		}
		if snap.counts != 0 || snap.regexCount != 0 || snap.hasTldAllowRoots != true {
			t.Errorf("%s: (counts, regexCount, hasTldAllowRoots) = (%d, %d, %v), want (0, 0, true): init freezes the TLD roots", name, snap.counts, snap.regexCount, snap.hasTldAllowRoots)
		}
	}
	m := modMain(t, "decisiondb_max = 3")
	if m.decisionDB == nil {
		t.Fatalf("decisionDB is nil")
	}
	for i := range 5 {
		m.decisionDB.set(fmt.Sprint(i), newDecision(1))
	}
	if got := m.decisionDB.len(); got != 3 {
		t.Errorf("decisionDB holds %d entries after 5 sets with decisiondb_max = 3, want 3", got)
	}
}

// --- rebuild_and_swap ---

func opSwapSnapshot(counts, regexCount int, fill func(*snapshot)) func() (*snapshot, error) {
	return func() (*snapshot, error) {
		s := newSnapshot()
		s.counts, s.regexCount = counts, regexCount
		if fill != nil {
			fill(s)
		}
		return s, nil
	}
}

func opReadCount(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return "<absent>"
	}
	return string(data)
}

func TestRebuildAndSwapSuccess(t *testing.T) {
	dir := t.TempDir()
	m := modMust(t, dir)
	old := m.snapshot.Load()
	opSeed(m, "stale.example.com", opBlockVerdict(nil))
	if m.snapshot.Load() != old || !m.decisionDB.contains("stale.example.com") { // before-state
		t.Fatalf("before the swap: the old snapshot is not live or the stale memo is missing")
	}
	var next *snapshot

	ok := m.rebuildAndSwap(func() (*snapshot, error) {
		next, _ = opSwapSnapshot(42, 7, func(s *snapshot) { s.dataDB["new.example.com"] = &blockEntry{log: "1", band: 1} })()
		return next, nil
	}, true)

	if !ok {
		t.Fatalf("rebuildAndSwap = false, want true")
	}
	if m.snapshot.Load() != next || m.snapshot.Load() == old {
		t.Errorf("live snapshot = %p, want the new one %p (not the old %p)", m.snapshot.Load(), next, old)
	}
	if m.decisionDB.contains("stale.example.com") || m.decisionDB.len() != 0 {
		t.Errorf("decisionDB holds %d entries after the swap, want it cleared", m.decisionDB.len())
	}
	if got := opReadCount(t, m.pfb.pfbPyCount); got != "42\n" {
		t.Errorf("pfb_py_count = %q, want %q", got, "42\n")
	}
	if got := opReadCount(t, m.pfb.pfbPyRegexCount); got != "7\n" {
		t.Errorf("pfb_py_regex_count = %q, want %q", got, "7\n")
	}
}

// A swap installs the snapshot, and the settings the snapshot carries, as one value: the old snapshot's settings are
// never written (copy-on-write), so a query still reading it sees the config it started with.
func TestRebuildAndSwapEnablesTheMasterGateInTheNewSnapshotOnly(t *testing.T) {
	m := modMust(t, t.TempDir())
	old := m.snapshot.Load()
	if old.settings.pythonBlacklist {
		t.Fatalf("before: pythonBlacklist = true, want false (the last init had no lists)")
	}
	regexOnly := func(s *snapshot) {
		s.regexDB.set("feed#0", &regexEntry{re: regexp.MustCompile("badword"), band: 1})
		s.importantRules, s.regexCount = true, 1
	}

	if !m.rebuildAndSwap(opSwapSnapshot(0, 1, regexOnly), false) {
		t.Fatalf("rebuildAndSwap = false")
	}
	live := m.snapshot.Load()
	if !live.settings.pythonBlacklist {
		t.Errorf("after a regex-only swap: pythonBlacklist = false, want true: the newly swapped lists must block")
	}
	if old.settings.pythonBlacklist {
		t.Errorf("the OLD snapshot's settings changed: a published snapshot is immutable")
	}
	if live.settings == old.settings {
		t.Errorf("new and old snapshots share one settings value, want a copy")
	}

	// The other branch: an EMPTY swap must not enable a gate that is off, and keeps one that is on.
	if !m.rebuildAndSwap(opSwapSnapshot(0, 0, nil), false) {
		t.Fatalf("rebuildAndSwap (empty) = false")
	}
	if !m.snapshot.Load().settings.pythonBlacklist {
		t.Errorf("an empty swap turned the master gate off, want it kept: only python_control clears it")
	}
	fresh := modMust(t, t.TempDir())
	if !fresh.rebuildAndSwap(opSwapSnapshot(0, 0, nil), false) || fresh.snapshot.Load().settings.pythonBlacklist {
		t.Errorf("an empty swap over a module with the gate off enabled it, want it left off")
	}
	for name, fill := range map[string]func(*snapshot){
		"data":       func(s *snapshot) { opBlockData(s, "a.com", "1", 0) },
		"zone":       func(s *snapshot) { s.zoneDB["a.com"] = &blockEntry{log: "1", band: 1} },
		"allowRegex": func(s *snapshot) { s.allowRegexDB.set("r", &regexEntry{re: regexp.MustCompile("x")}) },
		"userRegex":  func(s *snapshot) { s.userRegexDB.set("r", &regexEntry{re: regexp.MustCompile("x")}) },
		"userAllow":  func(s *snapshot) { s.userAllowRegexDB.set("r", &regexEntry{re: regexp.MustCompile("x")}) },
	} {
		m := modMust(t, t.TempDir())
		if !m.rebuildAndSwap(opSwapSnapshot(0, 0, fill), false) || !m.snapshot.Load().settings.pythonBlacklist {
			t.Errorf("a swap carrying only %s entries left the master gate off, want it on", name)
		}
	}
	// Whitelist-only and HSTS-only snapshots block nothing, so they do not turn the gate on.
	for name, fill := range map[string]func(*snapshot){
		"white": func(s *snapshot) { s.whiteDB["a.com"] = whiteEntry{legacy: true} },
		"hsts":  func(s *snapshot) { s.hstsDB["a.com"] = struct{}{} },
	} {
		m := modMust(t, t.TempDir())
		if !m.rebuildAndSwap(opSwapSnapshot(0, 0, fill), false) || m.snapshot.Load().settings.pythonBlacklist {
			t.Errorf("a swap carrying only %s entries turned the master gate on, want it left off", name)
		}
	}
}

func TestRebuildAndSwapFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		builder func() (*snapshot, error)
		wantLog string
	}{
		{"the builder returns nothing", func() (*snapshot, error) { return nil, nil }, ""},
		{"the builder fails", func() (*snapshot, error) { return nil, errors.New("build blew up") },
			"pfb_dns_proxy error: [pfBlockerNG]: DNSBL rebuild failed, keeping current snapshot: build blew up\n"},
	} {
		logs := modCaptureLog(t)
		m := modMust(t, t.TempDir())
		old := m.snapshot.Load()
		opSeed(m, "stale.example.com", opBlockVerdict(nil))
		logs.Reset()

		for _, emit := range []bool{true, false} {
			if m.rebuildAndSwap(tc.builder, emit) {
				t.Errorf("%s (emit %v): rebuildAndSwap = true, want false", tc.name, emit)
			}
			if m.snapshot.Load() != old {
				t.Errorf("%s (emit %v): the live snapshot changed, want the old one kept", tc.name, emit)
			}
			if !m.decisionDB.contains("stale.example.com") {
				t.Errorf("%s (emit %v): the memo was cleared, want it to survive a failed build", tc.name, emit)
			}
			if _, err := os.Stat(m.pfb.pfbPyCount); err == nil {
				t.Errorf("%s (emit %v): pfb_py_count was written, want no recount on failure", tc.name, emit)
			}
		}
		if want := strings.Repeat(tc.wantLog, 2); logs.String() != want {
			t.Errorf("%s: log = %q, want %q (the failure is logged once per call)", tc.name, logs.String(), want)
		}
	}
}

func TestRebuildAndSwapEmitCountsToggle(t *testing.T) {
	m := modMust(t, t.TempDir())
	if !m.rebuildAndSwap(opSwapSnapshot(99, 5, nil), false) {
		t.Fatalf("rebuildAndSwap = false")
	}
	for _, path := range []string{m.pfb.pfbPyCount, m.pfb.pfbPyRegexCount, m.pfb.pfbPyRejectStats} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("emit_counts=false wrote %s, want init's own inline emits to be the only ones", path)
		}
	}

	if !m.rebuildAndSwap(opSwapSnapshot(99, 5, func(s *snapshot) {
		s.rejects[[2]string{"F", "G"}] = map[string]int{"shape": 1, "wire_cap": 2}
	}), true) {
		t.Fatalf("rebuildAndSwap = false")
	}
	if got := opReadCount(t, m.pfb.pfbPyCount); got != "99\n" {
		t.Errorf("pfb_py_count = %q, want 99", got)
	}
	data, err := os.ReadFile(m.pfb.pfbPyRejectStats)
	if err != nil {
		t.Fatalf("reject stats not written: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 1 || rows[0]["feed"] != "F" || rows[0]["group"] != "G" || rows[0]["shape"] != float64(1) || rows[0]["wire_cap"] != float64(2) {
		t.Errorf("reject stats = %q (%v), want one row for (F, G) shape 1 wire_cap 2", data, err)
	}

	// A module built without the reject-stats path (the Python tests' bare pfb dict) emits no stats and does not fail.
	bare := modMust(t, t.TempDir())
	bare.pfb.pfbPyRejectStats = ""
	if !bare.rebuildAndSwap(opSwapSnapshot(1, 1, func(s *snapshot) {
		s.rejects[[2]string{"F", "G"}] = map[string]int{"shape": 1, "wire_cap": 0}
	}), true) {
		t.Errorf("rebuildAndSwap without a reject-stats path = false, want true")
	}
}

// pfb_unbound.py's TestSingleRebindPoint: the live snapshot is bound in exactly two places, each under publishMu:
// rebuildAndSwap, which installs a rebuilt snapshot, and publishControl, which publishes the copy a control command
// edited. Python's control commands write the module globals in place; the snapshot rule (a published snapshot is never
// written) makes them a second publisher here.
func TestSnapshotIsStoredOnlyByRebuildAndSwapAndThePublishControlStep(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	stores := map[string]int{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(data), ".snapshot.Store(") + strings.Count(string(data), ".snapshot.Swap(") + strings.Count(string(data), ".snapshot.CompareAndSwap("); n > 0 {
			stores[file] = n
		}
	}
	want := map[string]int{"pfb_unbound.go": 1, "pfb_unbound_control.go": 1}
	if !reflect.DeepEqual(stores, want) {
		t.Errorf("production code binds the snapshot at %v, want %v (rebuildAndSwap and publishControl)", stores, want)
	}
}

// --- operate(): noAAAA ---

func opNoAAAAModule(t *testing.T, domains map[string]bool) *pfbUnbound {
	t.Helper()
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { s.noAAAADB = true }, func(s *snapshot) {
		for domain, wildcard := range domains {
			s.noAAAADB[domain] = wildcard
		}
	})
	return m
}

func TestOperateNoAAAA(t *testing.T) {
	m := opNoAAAAModule(t, map[string]bool{"example.com": false})
	q := opQstate("example.com.", RR_TYPE_AAAA, "192.0.2.1")
	if !m.operate(0, MODULE_EVENT_NEW, q, nil) {
		t.Errorf("operate = false, want true")
	}
	opWantState(t, "an exact entry", q.extState[0], MODULE_FINISHED)
	if q.returnRcode != RCODE_NOERROR || q.returnMsg == nil || q.returnMsg.rep.security != 2 {
		t.Errorf("(rcode, returnMsg) = (%d, %v), want NOERROR and a reply stamped non-bogus (security 2, issue #149)", q.returnRcode, q.returnMsg)
	}
	// issue #3224: an empty answer is the RFC 2308 Type-2 NODATA, the SOA in AUTHORITY.
	opSections(t, "exact entry", q, nil, []string{"example.com. 3600 IN SOA " + opSOA})
	if q.returnMsg.qinfo.qtype != RR_TYPE_A {
		t.Errorf("reply qtype = %d, want %d: the AAAA is answered as a NODATA A reply", q.returnMsg.qinfo.qtype, RR_TYPE_A)
	}

	m = opNoAAAAModule(t, map[string]bool{"example.com": true})
	q = opQstate("sub.example.com.", RR_TYPE_AAAA, "192.0.2.1")
	m.operate(0, MODULE_EVENT_NEW, q, nil)
	opWantState(t, "a wildcard parent", q.extState[0], MODULE_FINISHED)
	opSections(t, "wildcard parent", q, nil, []string{"sub.example.com. 3600 IN SOA " + opSOA})
	if dec, ok := m.decisionDB.get("sub.example.com"); !ok || dec.getNoaaaa() != true {
		t.Errorf("memo for sub.example.com = (%v, %v), want the child's noaaaa axis true", dec, ok)
	}
	again := opQstate("sub.example.com.", RR_TYPE_AAAA, "192.0.2.1")
	m.operate(0, MODULE_EVENT_NEW, again, nil)
	opWantState(t, "the memoized repeat", again.extState[0], MODULE_FINISHED)
	opSections(t, "memoized repeat", again, nil, []string{"sub.example.com. 3600 IN SOA " + opSOA})
	if again.returnMsg.rep.security != 2 {
		t.Errorf("memoized reply security = %d, want 2", again.returnMsg.rep.security)
	}
}

func TestOperateNoAAAAPassesWhatItDoesNotBlock(t *testing.T) {
	m := opNoAAAAModule(t, map[string]bool{"example.com": false})
	m.decisionDB.set("example.com", func() *decision {
		d := newDecision(m.snapshot.Load().gen)
		d.setNoaaaa(false) // a cached allow short-circuits
		return d
	}())
	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
	}{{"a cached allow verdict", "example.com.", RR_TYPE_AAAA}, {"a non-AAAA query", "example.com.", RR_TYPE_A}} {
		q := opQstate(tc.qname, tc.qtype, "192.0.2.1")
		opWantState(t, tc.name, opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	}

	m = opNoAAAAModule(t, map[string]bool{"other.com": true})
	q := opQstate("example.com.", RR_TYPE_AAAA, "192.0.2.1")
	opWantState(t, "an unlisted name", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if dec, ok := m.decisionDB.get("example.com"); !ok || dec.getNoaaaa() != false {
		t.Errorf("memo for example.com = (%v, %v), want the noaaaa axis cached as false", dec, ok)
	}

	// The gate is the settings flag, not the dict: with the flag off a listed name resolves.
	m = modMust(t, t.TempDir())
	opInstall(t, m, nil, func(s *snapshot) { s.noAAAADB["example.com"] = false })
	q = opQstate("example.com.", RR_TYPE_AAAA, "192.0.2.1")
	opWantState(t, "noAAAADB flag off", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if m.decisionDB.len() != 0 {
		t.Errorf("decisionDB holds %d entries, want none: the noAAAA axis is not evaluated with the flag off", m.decisionDB.len())
	}
}

// --- operate(): SafeSearch (the NEW/PASS branch) ---

func opSafeSearchOperate(t *testing.T, entries map[string]safeSearchEntry) *pfbUnbound {
	t.Helper()
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { s.safeSearchDB = true }, func(s *snapshot) {
		for name, entry := range entries {
			s.safeSearchDB[name] = entry
		}
	})
	return m
}

func TestOperateSafeSearchRewrites(t *testing.T) {
	entries := map[string]safeSearchEntry{
		"forcesafe.com": {a: "1.2.3.4", aaaa: ""},
		"both.com":      {a: "1.2.3.4", aaaa: "2001:db8::4"},
		"nx.com":        {a: "nxdomain"},
		"www.www2.com":  {a: "5.6.7.8"},
	}
	for _, tc := range []struct {
		name, qname string
		qtype       uint16
		answer      []string
	}{
		{"A", "forcesafe.com.", RR_TYPE_A, []string{"forcesafe.com. 300 IN A 1.2.3.4"}},
		// Python answers an AAAA query with the A record when the entry's AAAA is empty.
		{"AAAA with an empty AAAA column", "forcesafe.com.", RR_TYPE_AAAA, []string{"forcesafe.com. 300 IN A 1.2.3.4"}},
		{"AAAA with an AAAA column", "both.com.", RR_TYPE_AAAA, []string{"both.com. 300 IN AAAA 2001:db8::4"}},
		{"A with both columns", "both.com.", RR_TYPE_A, []string{"both.com. 300 IN A 1.2.3.4"}},
		{"the www. fallback", "www2.com.", RR_TYPE_A, []string{"www2.com. 300 IN A 5.6.7.8"}},
	} {
		m := opSafeSearchOperate(t, entries)
		q := opQstate(tc.qname, tc.qtype, "192.0.2.1")
		opWantState(t, tc.name, opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
		opSections(t, tc.name, q, tc.answer, nil)
		if q.returnRcode != RCODE_NOERROR || q.returnMsg.rep.security != 2 {
			t.Errorf("%s: (rcode, security) = (%d, %d), want (NOERROR, 2)", tc.name, q.returnRcode, q.returnMsg.rep.security)
		}
	}

	m := opSafeSearchOperate(t, entries)
	q := opQstate("nx.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "nxdomain", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	if q.returnRcode != RCODE_NXDOMAIN || q.returnMsg != nil {
		t.Errorf("nxdomain: (rcode, returnMsg) = (%d, %v), want (NXDOMAIN, nil)", q.returnRcode, q.returnMsg)
	}

	// A type the entry does not rewrite goes on to the resolver, as does a name the table lacks.
	for _, tc := range []struct {
		qname string
		qtype uint16
	}{{"forcesafe.com.", RR_TYPE_TXT}, {"other.com.", RR_TYPE_A}} {
		q := opQstate(tc.qname, tc.qtype, "192.0.2.1")
		opWantState(t, tc.qname, opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	}
}

func TestOperateSafeSearchCnameEntryIsRedirectedAfterResolution(t *testing.T) {
	m := opSafeSearchOperate(t, map[string]safeSearchEntry{"cname.com": {a: "cname", aaaa: "target.com", v4: "5.6.7.8", v6: "::2"}})
	q := opQstate("cname.com.", RR_TYPE_A, "192.0.2.1")
	// The pre-resolution pass leaves a CNAME entry to the post-resolution one (issue #149 / unbound #976).
	opWantState(t, "NEW", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if q.returnMsg != nil || q.returnRcode != RCODE_NOERROR {
		t.Errorf("NEW: (returnMsg, rcode) = (%v, %d), want the query untouched", q.returnMsg, q.returnRcode)
	}
	// The post-resolution pass plants the CNAME referral and asks for the restart that has the iterator chase it
	// (safesearch_cname_redirect, tested in pfb_unbound_safesearch_cname_test.go).
	opWantState(t, "MODDONE", opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_RESTART_NEXT)
	opSections(t, "MODDONE", q, []string{"cname.com. 3600 IN CNAME target.com"}, nil)
}

func TestOperateSafeSearchMemoIsReusedAndGenerationGated(t *testing.T) {
	m := opSafeSearchOperate(t, map[string]safeSearchEntry{"other.com": {a: "9.9.9.9"}})
	gen := m.snapshot.Load().gen
	live := newDecision(gen)
	live.setSafesearch(safeSearchEntry{a: "1.2.3.4"})
	m.decisionDB.set("x.com", live)
	// The name is not in the table: only the memo can rewrite it.
	q := opQstate("x.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "live memo", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	opSections(t, "live memo", q, []string{"x.com. 300 IN A 1.2.3.4"}, nil)

	// issue #1074, the sibling axis: a foreign-generation memo is recomputed, not served.
	stale := newDecision(gen - 1) // an older generation: a newer resident would not be replaced (#1074)
	stale.setSafesearch(safeSearchEntry{a: "1.2.3.4"})
	m.decisionDB.set("x.com", stale)
	q = opQstate("x.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "stale memo", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if dec, _ := m.decisionDB.get("x.com"); dec == nil || dec.snapGen != gen || dec.getSafesearch() != nil {
		t.Errorf("memo after the stale one = %+v, want a live-generation Decision with the safesearch axis nil", dec)
	}
}

// --- operate(): the DNSBL branch ---

func opDnsblModule(t *testing.T, fill func(*snapshot), set func(*pfbSettings)) *pfbUnbound {
	t.Helper()
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) {
		opEnable(s)
		if set != nil {
			set(s)
		}
	}, fill)
	return m
}

func opEvil(s *snapshot) {
	opBlockData(s, "evil.com", "1", 0)
	opFeed(s, 0, "TestFeed", "TestGroup")
}

func TestOperateDnsblDataBlockAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		qtype  uint16
		answer []string
		soa    bool
	}{
		{"A", RR_TYPE_A, []string{"evil.com. 3600 IN A 10.10.10.1"}, false},
		{"AAAA", RR_TYPE_AAAA, []string{"evil.com. 3600 IN AAAA 2001:db8::10"}, false},
		{"ANY", RR_TYPE_ANY, []string{"evil.com. 3600 IN A 10.10.10.1", "evil.com. 3600 IN AAAA 2001:db8::10"}, false},
		// issue #3222: a non-address type of a VIP hit is NODATA with the SOA, never an empty NOERROR.
		{"SVCB", 64, nil, true}, {"HTTPS", 65, nil, true}, {"MX", RR_TYPE_MX, nil, true}, {"TXT", RR_TYPE_TXT, nil, true}, {"SRV", RR_TYPE_SRV, nil, true},
	} {
		m := opDnsblModule(t, opEvil, nil)
		q := opQstate("evil.com.", tc.qtype, "192.0.2.1")
		if q.noCacheStore != 0 { // before-state: cacheable by default
			t.Fatalf("noCacheStore = %d before operate, want 0", q.noCacheStore)
		}
		if !m.operate(0, MODULE_EVENT_NEW, q, nil) {
			t.Errorf("%s: operate = false, want true", tc.name)
		}
		opWantState(t, tc.name, q.extState[0], MODULE_FINISHED)
		var authority []string
		if tc.soa {
			authority = []string{"evil.com. 3600 IN SOA " + opSOA}
		}
		opSections(t, tc.name, q, tc.answer, authority)
		if q.returnRcode != RCODE_NOERROR || q.returnMsg.rep.security != 2 || q.noCacheStore != 1 {
			t.Errorf("%s: (rcode, security, noCacheStore) = (%d, %d, %d), want (0, 2, 1): the synthetic block is not cached (#43)", tc.name, q.returnRcode, q.returnMsg.rep.security, q.noCacheStore)
		}
		if got := q.returnMsg.qinfo.qtype; got != tc.qtype {
			t.Errorf("%s: reply qtype = %d, want the query's %d", tc.name, got, tc.qtype)
		}
		if d := opMemo(t, m, "evil.com"); !opIsBlock(d) {
			t.Errorf("%s: memo = %+v, want a block verdict", tc.name, d)
		}
	}
}

func TestOperateDnsblVerdictShapesFromTheMemo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		d      *dnsblDecision
		qtype  uint16
		answer []string
		soa    bool
	}{
		{"null block A", opBlockVerdict(func(d *dnsblDecision) { d.nullBlocking = true; d.logType = "0" }), RR_TYPE_A, []string{"evil.com. 3600 IN A 0.0.0.0"}, false},
		{"null block AAAA", opBlockVerdict(func(d *dnsblDecision) { d.nullBlocking = true; d.logType = "0" }), RR_TYPE_AAAA, []string{"evil.com. 3600 IN AAAA ::"}, false},
		{"null block ANY", opBlockVerdict(func(d *dnsblDecision) { d.nullBlocking = true; d.logType = "0" }), RR_TYPE_ANY, []string{"evil.com. 3600 IN A 0.0.0.0", "evil.com. 3600 IN AAAA ::"}, false},
		{"null block HTTPS", opBlockVerdict(func(d *dnsblDecision) { d.nullBlocking = true; d.logType = "0" }), 65, nil, true},
		{"NODATA 5 A", opBlockVerdict(func(d *dnsblDecision) { d.logType = "5" }), RR_TYPE_A, nil, true},
		{"NODATA 5 AAAA", opBlockVerdict(func(d *dnsblDecision) { d.logType = "5" }), RR_TYPE_AAAA, nil, true},
		{"NODATA 5 ANY", opBlockVerdict(func(d *dnsblDecision) { d.logType = "5" }), RR_TYPE_ANY, nil, true},
		{"NODATA 6 A", opBlockVerdict(func(d *dnsblDecision) { d.logType = "6" }), RR_TYPE_A, nil, true},
		{"NODATA 6 MX", opBlockVerdict(func(d *dnsblDecision) { d.logType = "6" }), RR_TYPE_MX, nil, true},
	} {
		m := opDnsblModule(t, nil, nil)
		opSeed(m, "evil.com", tc.d)
		// A repeat query is served from the memo and must carry the same shape and re-set noCacheStore.
		for pass := range 2 {
			q := opQstate("evil.com.", tc.qtype, "192.0.2.1")
			opWantState(t, fmt.Sprintf("%s pass %d", tc.name, pass), opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
			var authority []string
			if tc.soa {
				authority = []string{"evil.com. 3600 IN SOA " + opSOA}
			}
			opSections(t, fmt.Sprintf("%s pass %d", tc.name, pass), q, tc.answer, authority)
			if q.noCacheStore != 1 {
				t.Errorf("%s pass %d: noCacheStore = %d, want 1", tc.name, pass, q.noCacheStore)
			}
		}
	}
}

func TestOperateDnsblNxdomainMode(t *testing.T) {
	for _, log := range []string{"3", "4"} {
		m := opDnsblModule(t, func(s *snapshot) { opBlockData(s, "evil.com", log, 0); opFeed(s, 0, "TestFeed", "TestGroup") }, nil)
		q := opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
		opWantState(t, "log "+log, opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
		if q.returnRcode != RCODE_NXDOMAIN || q.returnMsg != nil || q.noCacheStore != 1 {
			t.Errorf("log %s: (rcode, returnMsg, noCacheStore) = (%d, %v, %d), want a bare NXDOMAIN, no message, uncached (issue #31)", log, q.returnRcode, q.returnMsg, q.noCacheStore)
		}
		if d := opMemo(t, m, "evil.com"); d == nil || !d.nxdomain {
			t.Errorf("log %s: memo = %+v, want nxdomain true", log, d)
		}
	}
}

func TestOperateDnsblAllowsWhatIsNotBlocked(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fill  func(*snapshot)
		set   func(*pfbSettings)
		seed  *dnsblDecision // a block verdict already memoized for evil.com
		qname string
		qtype uint16
	}{
		{"an unlisted name", opEvil, nil, nil, "good.com.", RR_TYPE_A},
		{"a whitelisted listed name", func(s *snapshot) { opEvil(s); s.whiteDB["evil.com"] = whiteEntry{legacy: true} }, nil, nil, "evil.com.", RR_TYPE_A},
		{"a q_type outside rr_types", opEvil, nil, nil, "evil.com.", 6},
		// Only the gate keeps the memoized block from being served.
		{"the master gate off", nil, func(s *pfbSettings) { s.pythonBlacklist = false }, opBlockVerdict(nil), "evil.com.", RR_TYPE_A},
		{"an in-addr.arpa name", func(s *snapshot) { opBlockData(s, "1.0.0.10.in-addr.arpa", "1", 0) }, nil, nil, "1.0.0.10.in-addr.arpa.", RR_TYPE_PTR},
	} {
		m := opDnsblModule(t, tc.fill, tc.set)
		if tc.seed != nil {
			opSeed(m, "evil.com", tc.seed)
		}
		q := opQstate(tc.qname, tc.qtype, "192.0.2.1")
		opWantState(t, tc.name, opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
		if q.noCacheStore != 0 || q.returnMsg != nil {
			t.Errorf("%s: (noCacheStore, returnMsg) = (%d, %v), want the cacheable pass-through", tc.name, q.noCacheStore, q.returnMsg)
		}
	}
	// A whitelisted verdict is memoized as an allow.
	m := opDnsblModule(t, func(s *snapshot) { opEvil(s); s.whiteDB["evil.com"] = whiteEntry{legacy: true} }, nil)
	opOperate(m, MODULE_EVENT_NEW, opQstate("evil.com.", RR_TYPE_A, "192.0.2.1"))
	if d := opMemo(t, m, "evil.com"); d == nil || opIsBlock(d) || !d.inWhitelist {
		t.Errorf("memo = %+v, want a whitelisted allow", d)
	}
}

func TestOperateDnsblZoneEntryBlocksASubdomain(t *testing.T) {
	m := opDnsblModule(t, func(s *snapshot) {
		s.zoneDB["example.com"] = &blockEntry{log: "1", index: 0, band: 1}
		opFeed(s, 0, "TestFeed", "TestGroup")
	}, nil)
	q := opQstate("sub.example.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "zone", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
}

func TestOperateDnsblMemo(t *testing.T) {
	// A cached allow short-circuits the matcher.
	m := opDnsblModule(t, opEvil, nil)
	opSeed(m, "evil.com", &dnsblDecision{})
	opWantState(t, "cached allow", opOperate(m, MODULE_EVENT_NEW, opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")), MODULE_WAIT_MODULE)

	// A cached BLOCK blocks the unlisted name straight from decisionDB.
	m = opDnsblModule(t, nil, nil)
	opSeed(m, "cached-block.com", opBlockVerdict(func(d *dnsblDecision) { d.bEval = "cached-block.com" }))
	q := opQstate("cached-block.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "cached block", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	opSections(t, "cached block", q, []string{"cached-block.com. 3600 IN A 10.10.10.1"}, nil)

	// issue #1074: a foreign-generation memo is recomputed against the live snapshot, not served.
	m = opDnsblModule(t, nil, nil)
	stale := newDecision(m.snapshot.Load().gen - 1) // an older generation: a newer resident would not be replaced (#1074)
	stale.setDnsbl(opBlockVerdict(func(d *dnsblDecision) { d.bEval = "evil.com" }))
	m.decisionDB.set("evil.com", stale)
	q = opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "stale memo", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	dec, _ := m.decisionDB.get("evil.com")
	if dec == nil || dec.snapGen != m.snapshot.Load().gen {
		t.Fatalf("memo after the stale one = %+v, want one stamped with the live generation %d", dec, m.snapshot.Load().gen)
	}
	if d, _ := dec.getDnsbl().(*dnsblDecision); d == nil || d.isFound {
		t.Errorf("memo verdict = %+v, want the live snapshot's not-found allow", dec.getDnsbl())
	}
}

func TestOperateOneDecisionAccumulatesEveryAxis(t *testing.T) {
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.noAAAADB = true; s.safeSearchDB = true }, func(s *snapshot) {
		opBlockData(s, "multi.com", "1", 0)
		opFeed(s, 0, "F", "G")
		s.noAAAADB["unrelated.com"] = false                         // enables the noAAAA path; multi.com is unlisted
		s.safeSearchDB["other.com"] = safeSearchEntry{a: "9.9.9.9"} // enables SafeSearch; multi.com is unlisted
	})
	if m.decisionDB.contains("multi.com") {
		t.Fatalf("a Decision exists before the query")
	}
	q := opQstate("multi.com.", RR_TYPE_AAAA, "192.0.2.1")
	opWantState(t, "AAAA of a listed name", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	dec, ok := m.decisionDB.get("multi.com")
	if !ok {
		t.Fatalf("no Decision for multi.com")
	}
	if dec.getNoaaaa() != false || dec.getSafesearch() != nil || !opIsBlock(opMemo(t, m, "multi.com")) {
		t.Errorf("axes (noaaaa, safesearch, dnsbl) = (%v, %v, %+v), want (false evaluated, nil evaluated, a block)", dec.getNoaaaa(), dec.getSafesearch(), dec.getDnsbl())
	}
	if m.decisionDB.len() != 1 {
		t.Errorf("decisionDB holds %d entries, want ONE carrying all three axes", m.decisionDB.len())
	}
}

func TestOperateNoAAAAMemoIsReusedAndGenerationGated(t *testing.T) {
	m := opNoAAAAModule(t, map[string]bool{"unrelated.com": false})
	live := newDecision(m.snapshot.Load().gen)
	live.setNoaaaa(true)
	m.decisionDB.set("x.com", live) // x.com is not in the source: only the memo can block it
	opWantState(t, "live memo", opOperate(m, MODULE_EVENT_NEW, opQstate("x.com.", RR_TYPE_AAAA, "192.0.2.1")), MODULE_FINISHED)

	stale := newDecision(m.snapshot.Load().gen - 1) // an older generation: a newer resident would not be replaced (#1074)
	stale.setNoaaaa(true)
	m.decisionDB.set("x.com", stale)
	opWantState(t, "stale memo", opOperate(m, MODULE_EVENT_NEW, opQstate("x.com.", RR_TYPE_AAAA, "192.0.2.1")), MODULE_WAIT_MODULE)
}

func TestOperateRespectsTheDecisionDbCap(t *testing.T) {
	m := opDnsblModule(t, func(s *snapshot) {
		opBlockData(s, "one.com", "1", 0)
		opBlockData(s, "two.com", "1", 1)
		opFeed(s, 0, "F1", "G1")
		opFeed(s, 1, "F2", "G2")
	}, nil)
	m.decisionDB = newLruCache[*decision](1)
	opOperate(m, MODULE_EVENT_NEW, opQstate("one.com.", RR_TYPE_A, "192.0.2.1"))
	if m.decisionDB.len() != 1 {
		t.Fatalf("decisionDB holds %d entries, want 1", m.decisionDB.len())
	}
	opOperate(m, MODULE_EVENT_NEW, opQstate("two.com.", RR_TYPE_A, "192.0.2.1"))
	if m.decisionDB.len() != 1 || !m.decisionDB.contains("two.com") || m.decisionDB.contains("one.com") {
		t.Errorf("decisionDB after the second name: len %d, two.com %v, one.com %v; want the LRU one.com evicted", m.decisionDB.len(), m.decisionDB.contains("two.com"), m.decisionDB.contains("one.com"))
	}
}

// --- operate(): the CNAME walk ---

func opCnameModule(t *testing.T, fill func(*snapshot), cname bool) *pfbUnbound {
	t.Helper()
	return opDnsblModule(t, fill, func(s *pfbSettings) { s.pythonCname = cname })
}

func opEvilCname(s *snapshot) {
	opBlockData(s, "evil-cname.com", "1", 0)
	opFeed(s, 0, "F", "G")
}

func TestOperateCnameTargetBlocksAndMarksTheOriginal(t *testing.T) {
	m := opCnameModule(t, opEvilCname, true)
	q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	q.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")

	opWantState(t, "cname chain", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)

	// The block is recorded against the ORIGINAL name and the reply is built for it.
	if d := opMemo(t, m, "orig.com"); !opIsBlock(d) {
		t.Errorf("memo for orig.com = %+v, want the block recorded against the original name", d)
	}
	if opIsBlock(opMemo(t, m, "evil-cname.com")) {
		t.Errorf("memo for evil-cname.com is a block, want it keyed on the original only")
	}
	opSections(t, "cname block", q, []string{"orig.com. 3600 IN A 10.10.10.1"}, nil)
}

func TestOperateCnameValidationIsOffByDefault(t *testing.T) {
	m := opCnameModule(t, opEvilCname, false)
	q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	q.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
	opWantState(t, "python_cname off", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
}

// The walk feeds the real convert_other decoder: a 16-char interior label (the googleadservices cloak) must still
// resolve to the exact blocked name (#717).
func TestOperateCnameWalkDecodesTheRealRdata(t *testing.T) {
	m := opCnameModule(t, func(s *snapshot) { opBlockData(s, "www.googleadservices.com", "1", 0); opFeed(s, 0, "F", "G") }, true)
	q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	q.returnMsg = opCnameReply(t, "orig.com", "www.googleadservices.com")
	opWantState(t, "long label", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	if d := opMemo(t, m, "orig.com"); !opIsBlock(d) {
		t.Errorf("memo for orig.com = %+v, want a block", d)
	}
}

func TestOperateCnameWalkSkipsAMalformedTargetAndNeedsTwoRrsets(t *testing.T) {
	m := opCnameModule(t, func(s *snapshot) { opBlockData(s, "unknown", "1", 0); opEvilCname(s) }, true)
	// A target that decodes to "Unknown" (a compression pointer) is skipped, never evaluated: the capital-U sentinel
	// compared before lower-casing (#714 FIX #3).
	bad := newDnsMsg(queryInfo{qnameStr: "orig.com.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR|dnswire.RA,
		[]dnswire.RR{opRR(t, "orig.com. 300 IN A 192.0.2.1"), opRR(t, "orig.com. 300 IN CNAME evil-cname.com.")}, nil, nil)
	bad.rep.rrsets[1].entry.data.rrData[0] = []byte{0, 2, 0xC0, 0x2A}
	q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	q.returnMsg = bad
	opWantState(t, "malformed target", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if m.decisionDB.contains("unknown") {
		t.Errorf("the 'Unknown' sentinel was evaluated as a name")
	}

	// a single answer rrset (an_numrrsets 1) is no chain
	single := newDnsMsg(queryInfo{qnameStr: "orig.com.", qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, dnswire.QR|dnswire.RA,
		[]dnswire.RR{opRR(t, "orig.com. 300 IN CNAME evil-cname.com.")}, nil, nil)
	q = opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	q.returnMsg = single
	opWantState(t, "one rrset", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
}

func TestOperateCnameMemoizedTargetAnswersInTheOriginalsBailiwick(t *testing.T) {
	for _, log := range []string{"1", "5", "6"} {
		m := opCnameModule(t, func(s *snapshot) { opBlockData(s, "evil-cname.com", log, 0); opFeed(s, 0, "F", "G") }, true)
		// Query the target first (memoizing it), then the original: the answer owner must be the ORIGINAL (#3222).
		opOperate(m, MODULE_EVENT_NEW, opQstate("evil-cname.com.", RR_TYPE_A, "192.0.2.1"))
		if !opIsBlock(opMemo(t, m, "evil-cname.com")) {
			t.Fatalf("log %s: the direct query did not memoize the target as a block", log)
		}
		q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
		q.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
		opWantState(t, "log "+log, opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
		if log == "1" {
			opSections(t, "log 1", q, []string{"orig.com. 3600 IN A 10.10.10.1"}, nil)
		} else {
			opSections(t, "log "+log, q, nil, []string{"orig.com. 3600 IN SOA " + opSOA})
		}
		if d := opMemo(t, m, "orig.com"); !opIsBlock(d) {
			t.Errorf("log %s: orig.com memo = %+v, want it memoized as a block", log, d)
		}
		https := opQstate("orig.com.", 65, "192.0.2.1")
		https.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
		opOperate(m, MODULE_EVENT_NEW, https)
		opSections(t, "HTTPS", https, nil, []string{"orig.com. 3600 IN SOA " + opSOA})
	}
}

// The memoized target is re-evaluated in the CNAME context, so the original's whitelist still applies (#3222).
func TestOperateCnameMemoizedTargetRespectsTheOriginalsWhitelist(t *testing.T) {
	m := opCnameModule(t, func(s *snapshot) { opEvilCname(s); s.whiteDB["orig.com"] = whiteEntry{legacy: true} }, true)
	opOperate(m, MODULE_EVENT_NEW, opQstate("evil-cname.com.", RR_TYPE_A, "192.0.2.1"))
	for _, qtype := range []uint16{65, RR_TYPE_A} {
		q := opQstate("orig.com.", qtype, "192.0.2.1")
		q.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
		opWantState(t, fmt.Sprintf("whitelisted original, type %d", qtype), opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	}
	follow := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "a follow-up without the chain", opOperate(m, MODULE_EVENT_NEW, follow), MODULE_WAIT_MODULE)
	if d := opMemo(t, m, "orig.com"); opIsBlock(d) {
		t.Errorf("orig.com is memoized as a block (%+v), want it not to inherit the target's memo", d)
	}
}

// Bug #3775 must not be reproduced: a whitelisted alias's CNAME-context allow is not the blocked target's own
// verdict, so a direct query for the target is still blocked. The corpus never queries in this order.
func TestOperateCnameContextAllowIsNotMemoizedAsTheTargetsVerdict(t *testing.T) {
	m := opCnameModule(t, func(s *snapshot) { opEvilCname(s); s.whiteDB["trusted.example"] = whiteEntry{legacy: true} }, true)
	alias := opQstate("trusted.example.", RR_TYPE_A, "192.0.2.10")
	alias.returnMsg = opCnameReply(t, "trusted.example", "evil-cname.com")
	opWantState(t, "the whitelisted alias", opOperate(m, MODULE_EVENT_NEW, alias), MODULE_WAIT_MODULE)

	direct := opQstate("evil-cname.com.", RR_TYPE_A, "192.0.2.10")
	opWantState(t, "the target, queried directly after the alias", opOperate(m, MODULE_EVENT_NEW, direct), MODULE_FINISHED)
	opSections(t, "direct target", direct, []string{"evil-cname.com. 3600 IN A 10.10.10.1"}, nil)
}

// --- operate(): one snapshot per query ---

// The owner's rule of 2026-11-09: a query Loads the snapshot once, on its first event, and every later event reuses
// it, so a swap between NEW and MODDONE never tears the query across two generations.
func TestOperateKeepsOneSnapshotForAllEventsOfAQuery(t *testing.T) {
	m := opCnameModule(t, opEvilCname, true)
	first := m.snapshot.Load()
	q := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "NEW", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	if q.snap != first {
		t.Fatalf("the query's snapshot = %p after NEW, want the one live then (%p)", q.snap, first)
	}

	// The swap lands between the events: the new lists no longer block the target, and the new settings carry another
	// sinkhole address, so a reply that mixed generations would show it.
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.pythonCname = true; s.dnsblIpv4 = "10.10.10.99" }, nil)
	if m.snapshot.Load() == first {
		t.Fatalf("the swap did not install a new snapshot")
	}
	q.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
	opWantState(t, "MODDONE", opOperate(m, MODULE_EVENT_MODDONE, q), MODULE_FINISHED)
	if q.snap != first {
		t.Errorf("the query's snapshot = %p after MODDONE, want the first one %p", q.snap, first)
	}
	opSections(t, "MODDONE on the first generation", q, []string{"orig.com. 3600 IN A 10.10.10.1"}, nil)
	if dec, ok := m.decisionDB.get("orig.com"); ok && dec.snapGen == m.snapshot.Load().gen {
		t.Errorf("the first generation's verdict was memoized under the new generation %d", dec.snapGen)
	}

	// A new query sees the new generation.
	fresh := opQstate("orig.com.", RR_TYPE_A, "192.0.2.1")
	fresh.returnMsg = opCnameReply(t, "orig.com", "evil-cname.com")
	opWantState(t, "a query after the swap", opOperate(m, MODULE_EVENT_MODDONE, fresh), MODULE_FINISHED)
	if fresh.snap != m.snapshot.Load() || fresh.returnMsg == nil || len(fresh.returnMsg.answer) != 2 {
		t.Errorf("a query after the swap = (%p, %v), want the new snapshot and Unbound's reply untouched", fresh.snap, fresh.returnMsg)
	}
}

// A query that loaded generation A at NEW reads A's noAAAA, SafeSearch and Group Policy data at its later events, though
// a swap installed B in between: each would decide differently on B.
func TestOperateReadsNoaaaaFromTheQuerysOwnSnapshot(t *testing.T) {
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.noAAAADB = true }, nil)
	q := opQstate("n.example.", RR_TYPE_AAAA, "192.0.2.1")
	opWantState(t, "NEW on A", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.noAAAADB = true }, func(s *snapshot) { s.noAAAADB["n.example"] = false })
	opWantState(t, "PASS after the swap to B, which lists the name", opOperate(m, MODULE_EVENT_PASS, q), MODULE_WAIT_MODULE)
}

func TestOperateReadsSafeSearchFromTheQuerysOwnSnapshot(t *testing.T) {
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.safeSearchDB = true }, nil)
	q := opQstate("ss.example.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "NEW on A", opOperate(m, MODULE_EVENT_NEW, q), MODULE_WAIT_MODULE)
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.safeSearchDB = true }, func(s *snapshot) {
		s.safeSearchDB["ss.example"] = safeSearchEntry{a: "1.2.3.4"}
	})
	opWantState(t, "PASS after the swap to B, which rewrites the name", opOperate(m, MODULE_EVENT_PASS, q), MODULE_WAIT_MODULE)
}

func TestOperateReadsGroupPolicyFromTheQuerysOwnSnapshot(t *testing.T) {
	m := modMust(t, t.TempDir())
	settings := func(s *pfbSettings) { opEnable(s); s.gpListDB = true; s.rrTypes = []uint16{RR_TYPE_A} }
	opInstall(t, m, settings, func(s *snapshot) { opBlockData(s, "b.example", "1", 0); opFeed(s, 0, "F", "G") })
	q := opQstate("b.example.", RR_TYPE_A, "192.0.2.77")
	opWantState(t, "NEW on A, client not bypassed: blocked", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	opInstall(t, m, settings, func(s *snapshot) {
		opBlockData(s, "b.example", "1", 0)
		opFeed(s, 0, "F", "G")
		s.gpListDB["192.0.2.77"] = 0
	})
	opWantState(t, "PASS after the swap to B, which bypasses the client: still blocked", opOperate(m, MODULE_EVENT_PASS, q), MODULE_FINISHED)
}

// --- the swap race ---

type raceSide struct {
	name     string
	sinkhole string
}

var (
	raceA = raceSide{"A", "192.0.2.1"}
	raceB = raceSide{"B", "192.0.2.2"}
)

// raceSnapshot is one generation: the two generations block different names and answer with different sinkholes, so
// a torn mix (A's list with B's address, or a memo of one served under the other) matches neither.
func raceSnapshot(t *testing.T, side raceSide) func() (*snapshot, error) {
	return func() (*snapshot, error) {
		s := newSnapshot()
		settings := raceSettings(t, side)
		s.settings = &settings
		if side == raceA {
			opBlockData(s, "n.example", "1", 0)
			opBlockData(s, "t.example", "1", 0)
		} else {
			opBlockData(s, "m.example", "1", 0)
		}
		opFeed(s, 0, "F", "G")
		return s, nil
	}
}

func raceSettings(t *testing.T, side raceSide) pfbSettings {
	var s pfbSettings
	opEnable(&s)
	s.pythonCname = true
	s.dnsblIpv4 = side.sinkhole
	s.rrTypes = []uint16{RR_TYPE_A, RR_TYPE_AAAA}
	return s
}

func raceQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	wire, err := dnswire.Encode(&dnswire.Message{ID: id, Flags: dnswire.RD, Questions: []dnswire.Question{{Name: name, Qtype: dnswire.TYPE_A, Qclass: dnswire.CLASS_IN}}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// raceUpstream plays Unbound: c.example is an alias of t.example, every other name resolves to 192.0.2.99.
func raceUpstream(t *testing.T) forward {
	return func(wire []byte) []byte {
		query, err := dnswire.Parse(wire)
		if err != nil {
			t.Errorf("upstream: %v", err)
			return nil
		}
		name := query.Questions[0].Name
		answers := []dnswire.RR{opRR(t, name+" 300 IN A 192.0.2.99")}
		if name == "c.example." {
			answers = []dnswire.RR{opRR(t, "c.example. 300 IN CNAME t.example."), opRR(t, "t.example. 300 IN A 192.0.2.99")}
		}
		reply, err := dnswire.Encode(&dnswire.Message{ID: query.ID, Flags: dnswire.QR | dnswire.RA | dnswire.RD, Questions: query.Questions, Answers: answers})
		if err != nil {
			t.Errorf("upstream: %v", err)
			return nil
		}
		return reply
	}
}

// raceAddresses is the A rdata of a reply, as text.
func raceAddresses(t *testing.T, reply []byte) string {
	t.Helper()
	message, err := dnswire.Parse(reply)
	if err != nil {
		t.Errorf("reply %x: %v", reply, err)
		return "<unparseable>"
	}
	var out []string
	for _, rr := range message.Answers {
		if rr.Rtype == dnswire.TYPE_A && len(rr.Rdata) == 4 {
			out = append(out, fmt.Sprintf("%d.%d.%d.%d", rr.Rdata[0], rr.Rdata[1], rr.Rdata[2], rr.Rdata[3]))
		} else {
			out = append(out, dnswire.TypeStr(rr.Rtype))
		}
	}
	return strings.Join(out, ",")
}

// Queries run through Frontend.Resolve in several goroutines (one Frontend each, one module between them) while
// another goroutine swaps between two snapshots that block different names. Each answer must be exactly one
// generation's verdict for that name. Run it with -race: the memo, the snapshot pointer and the settings are shared.
func TestSwapRaceEveryAnswerIsOneGenerationsVerdict(t *testing.T) {
	m := modMust(t, t.TempDir())
	swap := func(side raceSide) {
		if !m.rebuildAndSwap(raceSnapshot(t, side), false) {
			t.Error("rebuildAndSwap = false")
		}
	}
	// name -> the addresses its answer carries on each generation
	want := map[string]map[string]string{
		"n.example.": {"A": "192.0.2.1", "B": "192.0.2.99"},
		"m.example.": {"A": "192.0.2.99", "B": "192.0.2.2"},
		"c.example.": {"A": "192.0.2.1", "B": "CNAME,192.0.2.99"},
		"u.example.": {"A": "192.0.2.99", "B": "192.0.2.99"},
	}
	names := []string{"n.example.", "m.example.", "c.example.", "u.example."}
	upstream := raceUpstream(t)

	// Settled generations first: each side answers as its own list says.
	for _, side := range []raceSide{raceA, raceB} {
		swap(side)
		f := newFrontend(m)
		for i, name := range names {
			got := raceAddresses(t, f.Resolve(raceQuery(t, uint16(i+1), name), "192.0.2.10", upstream, "UDP", "", ""))
			if got != want[name][side.name] {
				t.Errorf("settled generation %s: %s answered %q, want %q", side.name, name, got, want[name][side.name])
			}
		}
	}

	const queriers, rounds = 6, 400
	var wg, swapper sync.WaitGroup
	stop := make(chan struct{})
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			swap([]raceSide{raceA, raceB}[i%2])
		}
	}()
	for g := range queriers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := newFrontend(m)
			for i := range rounds {
				name := names[(g+i)%len(names)]
				got := raceAddresses(t, f.Resolve(raceQuery(t, uint16(g*rounds+i), name), "192.0.2.10", upstream, "UDP", "", ""))
				if got != want[name]["A"] && got != want[name]["B"] {
					t.Errorf("%s answered %q, want one generation's verdict: %q (A) or %q (B)", name, got, want[name]["A"], want[name]["B"])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	swapper.Wait()
}

// #714 FIX #2: a swap installs brand-new regex DBs, so the slow-match warn suppression keyed on a rule name must not
// survive it. init_standard clears it on a restart; rebuildAndSwap must clear it for a no-restart swap.
func TestRebuildAndSwapClearsTheRegexWarnState(t *testing.T) {
	m := modMust(t, t.TempDir())
	if !m.regexRuntime.firstWarning("stale-pattern") || m.regexRuntime.firstWarning("stale-pattern") { // before-state
		t.Fatalf("firstWarning is not warn-once before the swap")
	}

	if !m.rebuildAndSwap(opSwapSnapshot(1, 0, nil), false) {
		t.Fatalf("rebuildAndSwap = false")
	}

	if !m.regexRuntime.firstWarning("stale-pattern") {
		t.Errorf("a rule warned before the swap is still suppressed after it, want the warn state cleared")
	}
	failed := modMust(t, t.TempDir())
	failed.regexRuntime.firstWarning("kept")
	failed.rebuildAndSwap(func() (*snapshot, error) { return nil, errors.New("boom") }, false)
	if failed.regexRuntime.firstWarning("kept") {
		t.Errorf("a failed swap cleared the warn state, want it kept like the rest of the live state")
	}
}

// --- init_standard: the user regex list and the manifest build ---

// opManifestModule writes a module directory: the ini's MAIN lines, a manifest of the given feeds (name -> lines, all
// "feed" provenance, log flag 1) and their raw files. A nil feeds map writes no manifest.
func opManifestModule(t *testing.T, main []string, feeds map[string][]string) string {
	t.Helper()
	dir := t.TempDir()
	if feeds != nil {
		rows := []map[string]string{}
		for name, lines := range feeds {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, map[string]string{"raw": name, "feed": name, "group": name, "log_flag": "1", "provenance": "feed"})
		}
		manifest, err := json.Marshal(map[string]any{"version": 1, "config": map[string]any{}, "feeds": rows})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ini := "[MAIN]\npython_enable = true\n" + strings.Join(main, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func opRegexList(rows ...string) string {
	return "regex_list = " + base64.StdEncoding.EncodeToString([]byte(strings.Join(rows, "\n")))
}

func TestInitStandardLoadsTheMainRegexList(t *testing.T) {
	modCaptureLog(t)
	// Without a manifest, init keeps what the user-regex load set: the master gate is on, but important_rules (set only
	// by a manifest build) stays off, and pfb_py_count is not written; pfb_py_regex_count always is.
	m := modMust(t, opManifestModule(t, []string{opRegexList(`^user[0-9]+\.example$`)}, nil))
	snap := m.snapshot.Load()
	if snap.userRegexDB.len() != 1 || snap.regexCount != 1 || !snap.settings.pythonBlacklist || snap.importantRules {
		t.Errorf("without a manifest: (userRegexDB, regexCount, pythonBlacklist, importantRules) = (%d, %d, %v, %v), want (1, 1, true, false)",
			snap.userRegexDB.len(), snap.regexCount, snap.settings.pythonBlacklist, snap.importantRules)
	}
	if got := opReadCount(t, m.pfb.pfbPyRegexCount); got != "1\n" {
		t.Errorf("pfb_py_regex_count = %q, want 1", got)
	}
	if got := opReadCount(t, m.pfb.pfbPyCount); got != "<absent>" {
		t.Errorf("pfb_py_count = %q, want none: it is the manifest build's", got)
	}

	// With a (feedless) manifest the build succeeds: the user regex make the fast path off, pfb_py_count is 0.
	m = modMust(t, opManifestModule(t, []string{opRegexList(`^user[0-9]+\.example$`)}, map[string][]string{}))
	snap = m.snapshot.Load()
	if !snap.importantRules || snap.userRegexDB.len() != 1 || !snap.settings.pythonBlacklist {
		t.Errorf("with a manifest: (importantRules, userRegexDB, pythonBlacklist) = (%v, %d, %v), want (true, 1, true)", snap.importantRules, snap.userRegexDB.len(), snap.settings.pythonBlacklist)
	}
	for path, want := range map[string]string{m.pfb.pfbPyCount: "0\n", m.pfb.pfbPyRegexCount: "1\n"} {
		if got := opReadCount(t, path); got != want {
			t.Errorf("%s = %q, want %q", filepath.Base(path), got, want)
		}
	}
	if got := opReadCount(t, m.pfb.pfbPyRejectStats); got != "[]" {
		t.Errorf("pfb_py_reject_stats.json = %q, want an empty array: ran, zero rejects", got)
	}
}

func TestInitStandardInstallsTheManifestBuildAndBlocksFromIt(t *testing.T) {
	modCaptureLog(t)
	m := modMust(t, opManifestModule(t, []string{"python_blocking = true", "dnsbl_ipv4 = 10.10.10.1"},
		map[string][]string{"feed.txt": {"evil.example", `/^bad[0-9]+\.example$/`}}))
	snap := m.snapshot.Load()
	if snap.counts != 1 || snap.regexDB.len() != 1 || snap.regexCount != 1 || !snap.settings.pythonBlacklist || !snap.importantRules {
		t.Errorf("(counts, regexDB, regexCount, pythonBlacklist, importantRules) = (%d, %d, %d, %v, %v), want (1, 1, 1, true, true)",
			snap.counts, snap.regexDB.len(), snap.regexCount, snap.settings.pythonBlacklist, snap.importantRules)
	}
	if got := opReadCount(t, m.pfb.pfbPyCount); got != "1\n" {
		t.Errorf("pfb_py_count = %q, want 1", got)
	}
	// A feed line blocks with the VIP; a regex rule is a built-in block, which the build logs as a null block (the
	// fail-safe flag of issue #3539 when no mechanism is configured).
	for _, tc := range []struct{ name, answer string }{
		{"evil.example.", "10.10.10.1"}, {"bad42.example.", "0.0.0.0"}, {"good.example.", ""},
	} {
		q := opQstate(tc.name, RR_TYPE_A, "192.0.2.1")
		want := MODULE_WAIT_MODULE
		if tc.answer != "" {
			want = MODULE_FINISHED
		}
		opWantState(t, tc.name, opOperate(m, MODULE_EVENT_NEW, q), want)
		if tc.answer != "" {
			opSections(t, tc.name, q, []string{tc.name + " 3600 IN A " + tc.answer}, nil)
		}
	}

	// A reload swaps in the new list, clears the memo and re-emits the counts from the new snapshot.
	m.decisionDB.set("stale.example", newDecision(m.snapshot.Load().gen))
	ok := m.rebuildAndSwap(func() (*snapshot, error) {
		next := newSnapshot()
		build := m.dnsblBuildFromManifest(m.pfb.pfbPySources)
		if build == nil {
			return nil, errors.New("manifest build failed")
		}
		next.dataDB, next.counts = build.dataDB, build.counts
		return next, nil
	}, true)
	if !ok || m.decisionDB.contains("stale.example") || opReadCount(t, m.pfb.pfbPyCount) != "1\n" {
		t.Errorf("reload: (ok, memo cleared, pfb_py_count) = (%v, %v, %q), want (true, true, 1)", ok, !m.decisionDB.contains("stale.example"), opReadCount(t, m.pfb.pfbPyCount))
	}
}

// issue #1049: an init that skips a loader closes the parse-stage entry a previous run could have left open.
func opLedgerSeed(t *testing.T, dir string, items ...string) {
	t.Helper()
	m := &pfbUnbound{}
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	for _, item := range items {
		m.pfbPyStatusOpen("dnsbl", filepath.Join(dir, item), "parse", "left open by an earlier run")
	}
}

func TestInitStandardClosesTheLoaderEntriesItSkips(t *testing.T) {
	owned := []string{"pfb_py_sources.json", "pfb_py_zone.txt", "pfb_py_data.txt", "pfb_py_whitelist.txt", "pfb_py_hsts.txt", "pfb_py_ss.txt"}

	// python_enable off: every owned entry is closed, an entry of another stage or facility is not.
	dir := opManifestModule(t, nil, nil)
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opLedgerSeed(t, dir, owned...)
	other := &pfbUnbound{}
	other.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	other.pfbPyStatusOpen("dnsbl", filepath.Join(dir, "pfb_py_hsts.txt"), "apply", "a PHP-owned stage")
	modMust(t, dir)
	left := opLedgerItems(t, filepath.Join(dir, "pfb_py_status.json"))
	if len(left) != 1 || left[0] != filepath.Join(dir, "pfb_py_hsts.txt") {
		t.Errorf("ledger after a python_enable-off init = %v, want only the apply-stage entry", left)
	}

	// python_enable on, no manifest: the retired zone/data/whitelist loaders and the absent HSTS and SafeSearch files
	// close theirs; the manifest entry is the build's to keep until a good build.
	dir = opManifestModule(t, nil, nil)
	opLedgerSeed(t, dir, owned...)
	modMust(t, dir)
	left = opLedgerItems(t, filepath.Join(dir, "pfb_py_status.json"))
	if want := []string{filepath.Join(dir, "pfb_py_sources.json")}; !slices.Equal(left, want) {
		t.Errorf("ledger after a python_enable-on init without files = %v, want only the manifest entry (an absent manifest opens it again)", left)
	}

	// No earlier entries and nothing skipped to report: no ledger file appears.
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	modMust(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "pfb_py_status.json")); err == nil {
		t.Errorf("an init with nothing to close wrote a ledger")
	}
}

// --- _load_ini_config's ledger entry (tests/test_adr61_py_status.py TestLoadIniConfigLedgerWiring) ---

func opIniModule(t *testing.T) (*pfbUnbound, string, string) {
	t.Helper()
	dir := t.TempDir()
	m := &pfbUnbound{}
	m.pfb.pfbUnboundIni = filepath.Join(dir, "pfb_unbound.ini")
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	return m, m.pfb.pfbUnboundIni, m.pfb.pfbPyStatus
}

func TestLoadIniConfigMissingFileOpensNoEntry(t *testing.T) {
	m, _, ledger := opIniModule(t)
	if c := m.loadIniConfig(); c != nil {
		t.Errorf("loadIniConfig = %v, want nil for a missing file", c)
	}
	if _, err := os.Stat(ledger); err == nil {
		t.Errorf("a ledger was written for a missing ini, want none")
	}
}

func TestLoadIniConfigParseFailureOpensAnEntryAndKeepsTheLog(t *testing.T) {
	m, ini, ledger := opIniModule(t)
	logs := modCaptureLog(t)
	if err := os.WriteFile(ini, []byte("bogus_line_with_no_section_header\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	config := m.loadIniConfig()

	if config == nil || config.hasSection("MAIN") {
		t.Errorf("config = %v, want the empty config a failed parse falls through to", config)
	}
	if !strings.Contains(logs.String(), "Failed to load ini configuration") {
		t.Errorf("log = %q, want the free-text diagnostic unchanged", logs.String())
	}
	entries := statusRead(t, ledger)
	if len(entries) != 1 || entries[0]["facility"] != "dnsbl" || entries[0]["item"] != ini || entries[0]["stage"] != "parse" ||
		!strings.HasPrefix(fmt.Sprint(entries[0]["message"]), "Failed to load ini configuration: ") {
		t.Errorf("ledger = %v, want one dnsbl/parse entry for %s with the failure as its message", entries, ini)
	}

	// A good file clears it; a file that is gone afterwards closes an entry a failure left open.
	if err := os.WriteFile(ini, []byte("[MAIN]\npython_enable = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := m.loadIniConfig(); c == nil || !c.hasSection("MAIN") {
		t.Fatalf("loadIniConfig(good) = %v, want the MAIN section", c)
	}
	if entries := statusRead(t, ledger); len(entries) != 0 {
		t.Errorf("ledger after a good read = %v, want the entry cleared", entries)
	}

	if err := os.WriteFile(ini, []byte("bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.loadIniConfig()
	if len(statusRead(t, ledger)) != 1 { // before-state: the entry is open
		t.Fatalf("the failed read did not reopen the entry")
	}
	if err := os.Remove(ini); err != nil {
		t.Fatal(err)
	}
	if c := m.loadIniConfig(); c != nil {
		t.Errorf("loadIniConfig(removed) = %v, want nil", c)
	}
	if entries := statusRead(t, ledger); len(entries) != 0 {
		t.Errorf("ledger after the file is removed = %v, want the orphaned entry closed", entries)
	}
}
