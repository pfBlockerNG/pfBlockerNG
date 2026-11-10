// Tests of the module-less reply log (#3791 step A): dns_reply_log.py's ReplyLog in Go. The rows are the Python oracle's:
// tests/fixtures/dns_reply_standalone_rows.json, taken from tests/dns_proxy/test_reply_log.py running the shipped
// pfb_unbound.py's own row writer behind a fake Unbound.
package decider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

const standaloneRowsFile = "../../../tests/fixtures/dns_reply_standalone_rows.json"

type standaloneRows struct {
	Stamp  string              `json:"stamp"`
	Client string              `json:"client"`
	Rows   map[string][]string `json:"rows"`
}

func loadStandaloneRows(t *testing.T) standaloneRows {
	t.Helper()
	raw, err := os.ReadFile(standaloneRowsFile)
	if err != nil {
		t.Fatal(err)
	}
	var rows standaloneRows
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// fixedClock is the stamp of the oracle's rows.
func fixedClock() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local) }

// withGeoIP points the module's GeoIP database at path.
func withGeoIP(t *testing.T, path string) {
	t.Helper()
	previous := maxmindDBPath
	maxmindDBPath = path
	t.Cleanup(func() { maxmindDBPath = previous })
}

// replyLogRows is a module-less decider whose reply log hands its rows to the test, in the oracle's time.
func replyLogRows(t *testing.T) (*Frontend, *[]string) {
	t.Helper()
	f := openOK(t, Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	rows := &[]string{}
	f.replyLog.clock = fixedClock
	f.replyLog.logSink = func(name, line string) {
		if name == dnsReplyLogName {
			*rows = append(*rows, line)
		}
	}
	return f, rows
}

// oracleZone, oracleVerdicts and fakeUnbound are test_reply_log.py's ZONE and VERDICTS behind frontend_helpers.FakeUnbound.
var oracleZone = map[string][]string{
	"allowed.example.|1":   {"allowed.example. 300 IN A 192.0.2.77"},
	"allowed.example.|28":  {"allowed.example. 300 IN AAAA 2001:db8::77"},
	"allowed.example.|16":  {`allowed.example. 300 IN TXT "hello world"`},
	"allowed.example.|6":   {"allowed.example. 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 60"},
	"allowed.example.|255": {"allowed.example. 300 IN A 192.0.2.77"},
	"alias.example.|1":     {"alias.example. 300 IN CNAME allowed.example.", "allowed.example. 300 IN A 192.0.2.77"},
	"nodata.example.|28":   {},
	"geo.example.|1":       {"geo.example. 300 IN A 216.160.83.56"},
	"lan.example.|1":       {"lan.example. 300 IN A 10.1.2.3"},
}

type oracleVerdict struct {
	rcode   uint16
	answers []string
}

var oracleVerdicts = map[string]oracleVerdict{
	"refused.example.":  {rcode: 5},
	"servfail.example.": {rcode: 2},
	"nxd.example.":      {rcode: 3},
	"nxcname.example.":  {rcode: 3, answers: []string{"{name} 300 IN CNAME allowed.example."}},
}

const upstreamSOA = "example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 60"

func rrs(t *testing.T, texts []string, name string) []dnswire.RR {
	t.Helper()
	var out []dnswire.RR
	for _, text := range texts {
		rr, err := dnswire.RRFromText(strings.ReplaceAll(text, "{name}", name))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rr)
	}
	return out
}

func fakeUnbound(t *testing.T) func([]byte) []byte {
	return func(wire []byte) []byte {
		query := parse(t, wire)
		q := query.Questions[0]
		name := strings.ToLower(q.Name)
		reply := &dnswire.Message{ID: query.ID, Questions: query.Questions}
		if verdict, ok := oracleVerdicts[name]; ok {
			reply.Flags = dnswire.QR | (query.Flags & dnswire.RD) | verdict.rcode | dnswire.RA
			reply.Answers = rrs(t, verdict.answers, q.Name)
			if len(verdict.answers) == 0 {
				reply.Authority = rrs(t, []string{upstreamSOA}, "")
			}
			return encode(t, reply)
		}
		zone, known := oracleZone[name+"|"+strconv.Itoa(int(q.Qtype))]
		reply.Flags = dnswire.QR | dnswire.RA | (query.Flags & dnswire.RD)
		if !known {
			reply.Flags |= 3
		}
		reply.Answers = rrs(t, zone, "")
		return encode(t, reply)
	}
}

type oracleCase struct {
	qname  string
	qtype  uint16
	silent bool
}

const hostile = "a,b\"c<d>\\010e&'.example." // comma, quotes, markup, a newline (\010) and an ampersand in one name

var oracleCases = map[string]oracleCase{
	"a":                     {qname: allowed, qtype: 1},
	"aaaa":                  {qname: allowed, qtype: 28},
	"txt":                   {qname: allowed, qtype: 16},
	"soa":                   {qname: allowed, qtype: 6},
	"any":                   {qname: allowed, qtype: 255},
	"cname-chain":           {qname: "alias.example.", qtype: 1},
	"nxdomain":              {qname: "nx.example.", qtype: 1},
	"nxdomain-with-soa":     {qname: "nxd.example.", qtype: 1},
	"nxdomain-with-cname":   {qname: "nxcname.example.", qtype: 1},
	"no-answer":             {qname: "nodata.example.", qtype: 28},
	"refused":               {qname: "refused.example.", qtype: 1},
	"servfail-from-unbound": {qname: "servfail.example.", qtype: 1},
	"unbound-silent":        {qname: "silent.example.", qtype: 1, silent: true},
	"hostile-name":          {qname: hostile, qtype: 1},
}

func (c oracleCase) wire(t *testing.T) []byte { return qtypeWire(t, c.qname, c.qtype) }

func (c oracleCase) upstream(t *testing.T) forward {
	if c.silent {
		return func([]byte) []byte { return nil }
	}
	return fakeUnbound(t)
}

// --- the rows -------------------------------------------------------------------------------------

// "The rows are the module mode's, call for call": a reply row after Unbound's reply, a SERVFAIL through the servfail
// callback, two rows for a SERVFAIL Unbound sent.
func TestReplyLogWritesTheOraclesRows(t *testing.T) {
	oracle := loadStandaloneRows(t)
	f, rows := replyLogRows(t)
	for id, c := range oracleCases {
		*rows = nil
		f.Resolve(c.wire(t), oracle.Client, c.upstream(t), "Unknown", "", "")
		var want []string
		for _, row := range oracle.Rows[id] {
			want = append(want, row+",Unknown,,")
		}
		if !slices.Equal(*rows, want) {
			t.Errorf("%s: rows\n %q\nwant\n %q", id, *rows, want)
		}
	}
}

func TestReplyLogNeverChangesWhatTheClientGets(t *testing.T) {
	oracle := loadStandaloneRows(t)
	logged, _ := replyLogRows(t)
	plain := openOK(t, Options{LogDir: testLogDir, NoModule: true})
	for id, c := range oracleCases {
		got := logged.Resolve(c.wire(t), oracle.Client, c.upstream(t), "Unknown", "", "")
		if want := plain.Resolve(c.wire(t), oracle.Client, c.upstream(t), "Unknown", "", ""); got == nil || !bytes.Equal(got, want) {
			t.Errorf("%s: with the log %x, without it %x, want the same answer", id, got, want)
		}
	}
}

// What get_details_reply writes for the listener and transport the gateway names, as module mode does.
func TestReplyLogCarriesTheTransportAndTheListener(t *testing.T) {
	f, rows := replyLogRows(t)
	f.Resolve(qtypeWire(t, allowed, 1), testClient, fakeUnbound(t), "DoT", "192.0.2.1", "igb0")
	if want := "DNS-reply,2026-10-18 12:00:00,reply,A,A,300,allowed.example,192.0.2.10,192.0.2.77,unk,DoT,192.0.2.1,igb0"; !slices.Equal(*rows, []string{want}) {
		t.Errorf("rows = %q, want %q", *rows, want)
	}
}

// Unbound's access-control REFUSED carries no question section at all: relayed as it is, and logged as Refused.
func TestReplyLogLogsAHeaderOnlyRefusedReplyAndRelaysItAsItIs(t *testing.T) {
	f, rows := replyLogRows(t)
	refused := header(0x1234, dnswire.QR|dnswire.RD|dnswire.RA|5, 0, 0, 0, 0)
	got := f.Resolve(qtypeWire(t, "allowed.example.", 1), testClient, answering(refused).forward, "Unknown", "", "")
	if !bytes.Equal(got, refused) {
		t.Errorf("reply = %x, want Unbound's %x unchanged", got, refused)
	}
	if len(*rows) != 1 {
		t.Fatalf("rows = %q, want one", *rows)
	}
	if fields := strings.Split((*rows)[0], ","); fields[2] != "reply" || fields[6] != "allowed.example" || fields[7] != testClient || fields[8] != "Refused" {
		t.Errorf("row = %q, want a reply row for allowed.example from %s as Refused", (*rows)[0], testClient)
	}
}

// A reply too short for a header is no reply: the proxy's SERVFAIL and one servfail row.
func TestReplyLogLogsAReplyTooShortForAHeaderAsTheProxysServfail(t *testing.T) {
	f, rows := replyLogRows(t)
	got := f.Resolve(qtypeWire(t, allowed, 1), testClient, answering([]byte{1, 2, 3}).forward, "Unknown", "", "")
	wantBare(t, "short reply", got, 0x1234, dnswire.QR|dnswire.RD|dnswire.RA|RCODE_SERVFAIL, RCODE_SERVFAIL, question(allowed, dnswire.CLASS_IN))
	if len(*rows) != 1 || strings.Split((*rows)[0], ",")[2] != "servfail" {
		t.Errorf("rows = %q, want one servfail row", *rows)
	}
}

// A packet that is not a query is dropped or answered with a header-only FORMERR before anything is logged.
func TestReplyLogLogsNothingForAPacketThatIsNotAnswerableByUnbound(t *testing.T) {
	f, rows := replyLogRows(t)
	for name, wire := range map[string][]byte{
		"a response":     append(header(1, dnswire.QR, 1, 0, 0, 0), qtc...),
		"no header":      {1, 2, 3, 4, 5},
		"two questions":  append(header(2, dnswire.RD, 2, 0, 0, 0), qtc...),
		"no question":    header(3, dnswire.RD, 0, 0, 0, 0),
		"a bad question": header(4, dnswire.RD, 1, 0, 0, 0),
	} {
		f.Resolve(wire, testClient, answering([]byte("unreachable")).forward, "Unknown", "", "")
		if len(*rows) != 0 {
			t.Errorf("%s: rows = %q, want none", name, *rows)
		}
	}
}

// Python's ReplyLog.__call__ never raises: a reply that does not parse is relayed as it is, costs its row and one error line.
func TestReplyLogFailureStillAnswersAndIsReportedOnce(t *testing.T) {
	log := captureLog(t)
	f, rows := replyLogRows(t)
	garbage := []byte("not a DNS message at all")
	for range 2 {
		if got := f.Resolve(qtypeWire(t, allowed, 1), testClient, answering(garbage).forward, "Unknown", "", ""); !bytes.Equal(got, garbage) {
			t.Errorf("reply = %x, want Unbound's bytes unchanged", got)
		}
	}
	if len(*rows) != 0 {
		t.Errorf("rows = %q, want none for a reply that does not parse", *rows)
	}
	if got := strings.Count(log.String(), "DNS Reply logging failed, further failures are silent: "); got != 1 {
		t.Errorf("the failure was logged %d times over two replies, want once; log = %q", got, log.String())
	}
}

// --- setup, as ReplyLog._setup ----------------------------------------------------------------------

func TestOpeningTheReplyLogSaysWhatItIsOnce(t *testing.T) {
	log := captureLockedLog(t)
	openOK(t, Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	const want = "pfb_dns_proxy info: DNS Reply logging is on: pfb_unbound.py is loaded for its row writer only, no DNSBL runs\n"
	if got := strings.Count(log.String(), want); got != 1 {
		t.Errorf("the startup line was logged %d times, want once; log = %q", got, log.String())
	}
}

// Only what init_standard would have set up for the one function: the DNS Reply Logging switch, the RCODE names and no
// noAAAA table; nothing of the DNSBL lifecycle.
func TestReplyLogSetsUpOnlyTheRowWriter(t *testing.T) {
	f := openOK(t, Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	m := f.replyLog
	snap := m.snapshot.Load()
	if snap == nil || !snap.settings.pythonReply || snap.settings.pythonBlacklist || len(snap.noAAAADB) != 0 {
		t.Errorf("snapshot = %+v, want python_reply on, no blacklist, no noAAAA", snap)
	}
	if m.sqlite3ResolverCon.Load() || m.sqlite3DnsblCon.Load() || m.reloadStop != nil || m.controlStop != nil || m.dbWorker.Load() != nil {
		t.Errorf("the reply log started DNSBL machinery: stats DBs %v/%v, watchers %v/%v, DB worker %v",
			m.sqlite3ResolverCon.Load(), m.sqlite3DnsblCon.Load(), m.reloadStop != nil, m.controlStop != nil, m.dbWorker.Load() != nil)
	}
	if m.logs == nil {
		t.Errorf("the log pipeline is not running")
	}
}

// The table is a literal copy of RCODES in src/usr/local/pkg/pfblockerng/dns_proxy/dns_reply_log.py, so that a name edited
// on one side only fails here; comparing the table with itself would not.
func TestReplyLogRcodeNamesAreTheModulesOwnTable(t *testing.T) {
	want := map[int]string{
		0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDOMAIN", 4: "NotImp", 5: "Refused", 6: "YXDomain", 7: "YXRRSet",
		8: "NXRRSet", 9: "NotAuth", 10: "NotZone", 11: "DSOTYPENI", 16: "BADVERS", 17: "BADKEY", 18: "BADTIME",
		19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC", 23: "BADCOOKIE",
	}
	if got := rcodeNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("rcodeNames() = %v, want dns_reply_log.py's RCODES %v", got, want)
	}
	f := openOK(t, Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	module := modMust(t, moduleDir(t))
	if !reflect.DeepEqual(f.replyLog.rcodeDB, want) || !reflect.DeepEqual(module.rcodeDB, want) {
		t.Errorf("rcode names = %v (reply log), %v (module), want both %v", f.replyLog.rcodeDB, module.rcodeDB, want)
	}
}

// The GeoIP reader as the module opens it, when its database is installed: a public address is its country, a private
// one prv. Close closes it.
func TestReplyLogFillsTheGeoIPColumnWhenTheDatabaseIsThere(t *testing.T) {
	withGeoIP(t, filepath.Join("testdata", "GeoLite2-Country-Test.mmdb"))
	f, rows := replyLogRows(t)
	if f.replyLog.maxmind == nil || !f.replyLog.snapshot.Load().settings.pythonMaxmind {
		t.Fatalf("GeoIP reader = %v, want it open with python_maxmind on", f.replyLog.maxmind)
	}
	var got []string
	for _, name := range []string{"geo.example.", "lan.example.", "nx.example."} {
		*rows = nil
		f.Resolve(qtypeWire(t, name, 1), testClient, fakeUnbound(t), "Unknown", "", "")
		got = append(got, strings.Split((*rows)[0], ",")[9])
	}
	if want := []string{"US", "prv", "unk"}; !slices.Equal(got, want) {
		t.Errorf("GeoIP column of (public, private, no answer) = %v, want %v", got, want)
	}
	f.Close()
	if f.replyLog.maxmind != nil {
		t.Errorf("Close left the GeoIP reader open")
	}
}

// --- the file ----------------------------------------------------------------------------------------

// The real pipeline: Close writes what is queued, to dns_reply.log in the log directory.
func TestReplyLogWritesDnsReplyLogAndCloseFlushesIt(t *testing.T) {
	dir := t.TempDir()
	withLogDir(t, dir)
	f, err := Open(Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	if err != nil {
		t.Fatal(err)
	}
	f.replyLog.clock = fixedClock
	f.Resolve(qtypeWire(t, allowed, 1), testClient, fakeUnbound(t), "Unknown", "", "")
	f.Close()
	f.Close()
	raw, err := os.ReadFile(filepath.Join(dir, "dns_reply.log"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "DNS-reply,2026-10-18 12:00:00,reply,A,A,300,allowed.example,192.0.2.10,192.0.2.77,unk,Unknown,,\n"
	if string(raw) != want {
		t.Errorf("dns_reply.log = %q, want %q", raw, want)
	}
}

// DNS must not go down with its log: with an unwritable log directory the writer reports the failure once and every
// query is still answered.
func TestReplyLogWithAnUnwritableLogDirectoryServesAndReportsOnce(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	withLogDir(t, filepath.Join(file, "no-such-dir")) // a path under a regular file cannot be created
	log := captureLockedLog(t)
	f, err := Open(Options{LogDir: testLogDir, NoModule: true, ReplyLog: true})
	if err != nil {
		t.Fatalf("Open = %v, want the decider to serve without its log", err)
	}
	wire := qtypeWire(t, allowed, 1)
	reply := replyTo(t, wire, 0, aRecord(allowed, 300, 77))
	for range 3 {
		if got := f.Resolve(wire, testClient, answering(reply).forward, "Unknown", "", ""); !bytes.Equal(got, reply) {
			t.Errorf("reply = %x, want Unbound's %x", got, reply)
		}
	}
	f.Close() // writes what is queued, and fails to
	if got := strings.Count(log.String(), "Failed to write "); got != 1 {
		t.Errorf("the failed write was reported %d times, want once; log = %q", got, log.String())
	}
}
