// Tests for pfb_unbound_evaluate.go. Each test names the Python test it ports; rows tagged "oracle" were produced by
// running the Python function on the same fixture (uv run python, Python 3.11, this worktree) and are pasted, never
// recomputed by Go code.
//
// A Python test that builds its cfg dict directly builds an evaluateConfig here; a cfg key the Python test leaves out
// reads Python's .get default, which evCfg sets (block-malicious on, builtin log flag "0", the warn ceiling default).
package decider

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

type dd = dnsblDecision

const evLogPrefix = "pfb_dns_proxy error: "

// evSyncBuffer is a log sink several goroutines may write to.
type evSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *evSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *evSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func evCaptureLog(t *testing.T) *evSyncBuffer {
	t.Helper()
	out := &evSyncBuffer{}
	previous := logOutput
	logOutput = out
	t.Cleanup(func() { logOutput = previous })
	return out
}

// evCfg is the per-query cfg of the Python tests' _cfg() with every presence gate off.
func evCfg() evaluateConfig {
	return evaluateConfig{
		pythonBlocking:          true,
		dnsblIpv4:               "10.10.10.1",
		dnsblIpv6:               "::1",
		regexWarnMs:             REGEX_WARN_MS_DEFAULT,
		pythonTldSeg:            2,
		hstsTlds:                []string{"app", "dev"},
		builtinLogFlag:          "0",
		pythonIdnBlockMalicious: true,
		regex:                   newRegexRuntime(),
	}
}

// evCfgAll is test_adr65_decision_oracle.py's _cfg(): every presence gate on, no HSTS TLDs.
func evCfgAll() evaluateConfig {
	cfg := evCfg()
	cfg.dataDB, cfg.zoneDB, cfg.whiteDB, cfg.regexDB, cfg.allowRegexDB = true, true, true, true, true
	cfg.userRegexDB, cfg.userAllowRegexDB, cfg.hstsDB = true, true, true
	cfg.hstsTlds = nil
	return cfg
}

func evBlk(log string, index, band int) *blockEntry {
	return &blockEntry{log: log, index: index, important: band == PRIO_FEED_BLOCK_IMPORTANT, band: band}
}

// evWhite is the whiteDB dict shape; band 0 leaves the "band" key out.
func evWhite(wildcard, important bool, band int) whiteEntry {
	return whiteEntry{wildcard: wildcard, important: important, band: band, hasBand: band != 0}
}

func evLegacyWhite(wildcard bool) whiteEntry { return whiteEntry{legacy: true, wildcard: wildcard} }

type evRule struct {
	name, pattern string
	band          int
	important     bool
	owner, origin string
}

func evRx(name, pattern string, band int) evRule {
	return evRule{name: name, pattern: pattern, band: band}
}

func evRegexDB(rules ...evRule) *regexDB {
	db := &regexDB{}
	for _, r := range rules {
		db.set(r.name, &regexEntry{re: regexp.MustCompile(r.pattern), important: r.important, band: r.band, groupOwner: r.owner, groupOrigin: r.origin})
	}
	return db
}

var evFG = map[int]feedGroup{0: {"TestFeed", "TestGroup"}}

func evEval(q, tld string, isCname bool, cfg evaluateConfig, c matcherContainers) *dnsblDecision {
	return evaluateDomain(q, q, tld, isCname, cfg, c)
}

func evDump(d dnsblDecision) string {
	alert := "nil"
	if d.idnAlert != nil {
		alert = fmt.Sprintf("%+v", *d.idnAlert)
	}
	d.idnAlert = nil
	return fmt.Sprintf("%+v idnAlert=%s", d, alert)
}

func evCheck(t *testing.T, label string, got *dnsblDecision, want dnsblDecision) {
	t.Helper()
	if got == nil || !reflect.DeepEqual(*got, want) {
		var g dnsblDecision
		if got != nil {
			g = *got
		}
		t.Errorf("%s:\n got  %s\n want %s", label, evDump(g), evDump(want))
	}
}

// evNone is what a name no list catches decides: Python's defaults, log_type False.
var evNone = dd{nullBlocking: true, bType: "Python", pType: "Python", feed: "Unknown", group: "Unknown"}

// test_adr65_decision_oracle.py A1, A2, A3, A9, A14, A15, A16 (the arms built without the manifest build).
func TestEvaluateDomainDecisionArms(t *testing.T) {
	q := "exact-hit.uuid1001.com"
	evCheck(t, "A1 dataDB exact hit blocks and attributes", evEval(q, "com", false, evCfgAll(),
		matcherContainers{dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK)}, feedGroupIndexDB: evFG}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "TestFeed", group: "TestGroup", bEval: q, groupOwner: "TestGroup", groupOrigin: "custom"})

	parent, child := "zone-parent.uuid1002.net", "deep.sub.zone-parent.uuid1002.net"
	evCheck(t, "A2 zoneDB suffix hit blocks the subdomain, attributed to the parent", evEval(child, "net", false, evCfgAll(),
		matcherContainers{zoneDB: map[string]*blockEntry{parent: evBlk("1", 0, PRIO_FEED_BLOCK)}, feedGroupIndexDB: evFG}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "TLD", pType: "Python", feed: "TestFeed", group: "TestGroup", bEval: parent, groupOwner: "TestGroup", groupOrigin: "custom"})

	q = "regex-hit-42.uuid1003.org"
	evCheck(t, "A3 feed block-regex hit blocks and attributes", evEval(q, "org", false, evCfgAll(),
		matcherContainers{regexDB: evRegexDB(evRx("MyBlockRegex", `^regex-hit-\d+\.uuid1003\.org$`, PRIO_FEED_BLOCK))}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "MyBlockRegex", group: "DNSBL_Regex", bEval: q})

	q = "hsts-listed.uuid1009.com"
	evCheck(t, "A9 an HSTS-listed block resolves real with the HSTS attribution", evEval(q, "com", false, evCfgAll(),
		matcherContainers{dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK)}, hstsDB: map[string]struct{}{q: {}}, feedGroupIndexDB: evFG}),
		dd{isFound: true, inHsts: true, nullBlocking: true, logType: "1", bType: "DNSBL", pType: "HSTS", feed: "TestFeed", group: "TestGroup", bEval: q, groupOwner: "TestGroup", groupOrigin: "custom"})

	q = "nx-listed.uuid1014.com"
	evCheck(t, "A14 log 3 clears the HSTS attribution even for an HSTS-listed name", evEval(q, "com", false, evCfgAll(),
		matcherContainers{dataDB: map[string]*blockEntry{q: evBlk("3", 0, PRIO_FEED_BLOCK)}, hstsDB: map[string]struct{}{q: {}}, feedGroupIndexDB: evFG}),
		dd{isFound: true, nxdomain: true, nullBlocking: true, logType: "3", bType: "DNSBL", pType: "Python", feed: "TestFeed", group: "TestGroup", bEval: q, groupOwner: "TestGroup", groupOrigin: "custom"})

	q = "cname-target.uuid1015.net"
	got := evEval(q, "net", true, evCfgAll(), matcherContainers{dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK)}, feedGroupIndexDB: evFG})
	if got.bType != "DNSBL_CNAME" {
		t.Errorf("A15 cname suffixes b_type: got %q, want DNSBL_CNAME", got.bType)
	}

	evCheck(t, "A16 an unlisted name resolves with no attribution", evEval("totally-clean.uuid1016.com", "com", false, evCfgAll(), matcherContainers{}), evNone)
}

// test_adr65_decision_oracle.py A5, A6, A8.
func TestEvaluateDomainAllowBlockPrecedence(t *testing.T) {
	q := "fastpath-allow.uuid1006.net"
	got := evEval(q, "net", false, evCfgAll(), matcherContainers{
		dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK)}, whiteDB: map[string]whiteEntry{q: evLegacyWhite(true)}, feedGroupIndexDB: evFG})
	if !got.isFound || !got.inWhitelist {
		t.Errorf("A6 fast path: whitelist overrides a block: got isFound=%v inWhitelist=%v, want true true", got.isFound, got.inWhitelist)
	}

	q = "allow-wins.uuid1005.com"
	cfg := evCfgAll()
	cfg.importantRules = true
	got = evEval(q, "com", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK)}, whiteDB: map[string]whiteEntry{q: evWhite(false, false, PRIO_FEED_ALLOW)}, feedGroupIndexDB: evFG})
	if !got.isFound || !got.inWhitelist {
		t.Errorf("A5 allow band 2 beats block band 1: got isFound=%v inWhitelist=%v, want true true", got.isFound, got.inWhitelist)
	}

	q = "important-wins.uuid1008.org"
	got = evEval(q, "org", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{q: evBlk("1", 0, PRIO_FEED_BLOCK_IMPORTANT)}, whiteDB: map[string]whiteEntry{q: evWhite(false, false, PRIO_FEED_ALLOW)}, feedGroupIndexDB: evFG})
	if !got.isFound || got.inWhitelist || got.nullBlocking {
		t.Errorf("A8 important block band 3 beats allow band 2: got isFound=%v inWhitelist=%v nullBlocking=%v, want true false false", got.isFound, got.inWhitelist, got.nullBlocking)
	}
}

// test_adr65_decision_oracle.py A10, A11, A12 and oracle rows for the arms around them: the Confusable BLOCK of a
// suspicious name when escalated, the ALERT of a malicious name when blocking is off, the All-IDN block under the
// numeric path, and the legacy python_idn fallback when idn_mode is absent or unrecognised.
func TestEvaluateDomainIdnArms(t *testing.T) {
	const malicious, suspicious = "xn--pple-43d.com", "xn--bnk-1ce.com"

	cfg := evCfgAll()
	cfg.idnMode = IdnModeConfusable
	evCheck(t, "A10 Confusable block attributes the malicious dual form", evEval(malicious, "com", false, cfg, matcherContainers{}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "Homoglyph", group: "DNSBL_Homoglyph", bEval: "xn--pple-43d [аpple] Cyrillic Latin", groupOwner: "DNSBL_Homoglyph", groupOrigin: "builtin"})

	cfg = evCfgAll()
	cfg.idnMode = IdnModeAll
	evCheck(t, "A11 All-IDN blocks any xn-- query", evEval("xn--any1234.uuid1011.com", "com", false, cfg, matcherContainers{}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "IDN", group: "DNSBL_IDN", bEval: "xn--any1234.uuid1011.com", groupOwner: "DNSBL_IDN", groupOrigin: "builtin"})

	cfg = evCfgAll()
	cfg.idnMode = IdnModeConfusable
	evCheck(t, "A12 Confusable ALERT does not block but records the attribution", evEval(suspicious, "com", false, cfg, matcherContainers{}),
		dd{nullBlocking: true, bType: "Python", pType: "Python", feed: "Unknown", group: "Unknown",
			idnAlert: &idnAlert{feed: "Homoglyph_Suspect", group: "DNSBL_Homoglyph_Suspect", bEval: "xn--bnk-1ce [bաnk] Armenian Latin"}})

	cfg.pythonIdnEscalateSuspicious = true
	evCheck(t, "oracle: escalated suspicious name blocks", evEval(suspicious, "com", false, cfg, matcherContainers{}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "Homoglyph_Suspect", group: "DNSBL_Homoglyph_Suspect", bEval: "xn--bnk-1ce [bաnk] Armenian Latin", groupOwner: "DNSBL_Homoglyph_Suspect", groupOrigin: "builtin"})

	cfg = evCfgAll()
	cfg.idnMode, cfg.pythonIdnBlockMalicious = IdnModeConfusable, false
	evCheck(t, "oracle: malicious name with blocking off is an ALERT", evEval(malicious, "com", false, cfg, matcherContainers{}),
		dd{nullBlocking: true, bType: "Python", pType: "Python", feed: "Unknown", group: "Unknown",
			idnAlert: &idnAlert{feed: "Homoglyph", group: "DNSBL_Homoglyph", bEval: "xn--pple-43d [аpple] Cyrillic Latin"}})

	cfg = evCfgAll()
	cfg.idnMode, cfg.importantRules = IdnModeAll, true
	evCheck(t, "oracle: the All-IDN block carries the feed band, a feed allow (band 2) overrides it",
		evEval("xn--any1234.uuid1011.com", "com", false, cfg, matcherContainers{whiteDB: map[string]whiteEntry{"xn--any1234.uuid1011.com": evWhite(false, false, 2)}}),
		dd{isFound: true, inWhitelist: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "IDN", group: "DNSBL_IDN", bEval: "xn--any1234.uuid1011.com", groupOwner: "DNSBL_IDN", groupOrigin: "builtin"})

	// oracle: cfg.get("idn_mode") absent (None) or unrecognised falls back to python_idn; an explicit "off" is not bypassed.
	for _, row := range []struct {
		name      string
		mode      IdnMode
		pythonIdn bool
		blocked   bool
	}{
		{"mode absent, python_idn on", "", true, true},
		{"mode absent, python_idn off", "", false, false},
		{"mode unrecognised, python_idn on", "bogus", true, true},
		{"mode off wins over python_idn on", IdnModeOff, true, false},
	} {
		cfg := evCfgAll()
		cfg.idnMode, cfg.pythonIdn = row.mode, row.pythonIdn
		if got := evEval("xn--any1234.uuid1011.com", "com", false, cfg, matcherContainers{}); got.isFound != row.blocked {
			t.Errorf("%s: isFound = %v, want %v", row.name, got.isFound, row.blocked)
		}
	}
}

// test_adr66_tld_naming_oracle.py Oracle A (A1-A10) and test_adr65_decision_oracle.py A13: the TLD-Allow arm.
func TestEvaluateDomainTldAllow(t *testing.T) {
	tldCfg := func(enabled bool, list ...string) evaluateConfig {
		cfg := evCfg()
		cfg.pythonBlocking = false
		cfg.tldAllow, cfg.tldAllowList = enabled, list
		return cfg
	}
	blocked := func(q string, over func(*dd)) dd {
		d := dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "TLD_Allow", group: "DNSBL_TLD_Allow", bEval: q, groupOwner: "DNSBL_TLD_Allow", groupOrigin: "builtin"}
		if over != nil {
			over(&d)
		}
		return d
	}

	if got := evEval("uuid-a1f0.net", "net", false, tldCfg(false, "com"), matcherContainers{}); got.isFound {
		t.Errorf("A1 disabled is a no-op: isFound = true")
	}
	if got := evEval("uuid-a2f0.com", "com", false, tldCfg(true, "com", "net"), matcherContainers{}); got.isFound {
		t.Errorf("A2 a TLD on the list resolves: isFound = true")
	}

	cfg := tldCfg(true, "com", "net")
	cfg.builtinLogFlag = "1"
	evCheck(t, "A3 the frozen shape of a TLD-Allow block (VIP flag)", evEval("uuid-a3f0.org", "org", false, cfg, matcherContainers{}),
		blocked("uuid-a3f0.org", func(d *dd) { d.logType, d.nullBlocking = "1", false }))
	evCheck(t, "A3 the default builtin log flag is Null Blocking", evEval("uuid-a3f0.org", "org", false, tldCfg(true, "com", "net"), matcherContainers{}),
		blocked("uuid-a3f0.org", nil))

	if got := evEval("uuid-a4f0.org", "org", false, tldCfg(true), matcherContainers{}); got.isFound {
		t.Errorf("A4 enabled with an empty list is a no-op (#713): isFound = true")
	}

	cfg = tldCfg(true, "com")
	if got := evEval("uuid-a6f0.net", "net", false, cfg, matcherContainers{}); !got.isFound || got.feed != "TLD_Allow" || got.group != "DNSBL_TLD_Allow" {
		t.Errorf("A6 a disallowed TLD blocks: got %+v", *got)
	}
	if got := evEval("uuid-a6f0.com", "com", false, cfg, matcherContainers{}); got.isFound {
		t.Errorf("A6 an allowed TLD resolves: isFound = true")
	}
	if got := evEval("uuid-a7f0.net", "net", true, cfg, matcherContainers{}); !got.isFound || got.bType != "Python_CNAME" {
		t.Errorf("A7 a TLD-Allow block on a CNAME chain: got isFound=%v bType=%q, want true Python_CNAME", got.isFound, got.bType)
	}

	// A8: the VIP address is exempt; the control query on the same cfg blocks.
	for _, vip := range []struct{ control, vip string }{{"uuid-vip.1", "10.10.10.1"}, {"uuid-vip6.1", "::1"}} {
		if got := evEval(vip.control, "1", false, cfg, matcherContainers{}); !got.isFound || got.feed != "TLD_Allow" {
			t.Errorf("A8 control %q: got %+v, want a TLD_Allow block", vip.control, *got)
		}
		if got := evEval(vip.vip, "1", false, cfg, matcherContainers{}); got.isFound {
			t.Errorf("A8 the VIP query %q is exempt: isFound = true", vip.vip)
		}
	}
	if got := evEval("uuid-a9f0.org", "", false, cfg, matcherContainers{}); got.isFound {
		t.Errorf("A9 an empty tld is a no-op: isFound = true")
	}

	// A10: a dataDB hit wins outright.
	cfg = tldCfg(true, "com")
	cfg.pythonBlocking, cfg.dataDB = true, true
	if got := evEval("uuid-a10.org", "org", false, cfg, matcherContainers{}); !got.isFound || got.feed != "TLD_Allow" {
		t.Errorf("A10 control: got %+v, want TLD_Allow", *got)
	}
	got := evEval("uuid-a10.org", "org", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{"uuid-a10.org": evBlk("1", 5, PRIO_FEED_BLOCK)}, feedGroupIndexDB: map[int]feedGroup{5: {"Feed_X", "Group_X"}}})
	if !got.isFound || got.feed != "Feed_X" || got.group != "Group_X" || got.bType != "DNSBL" {
		t.Errorf("A10 an upstream dataDB hit: got %+v, want Feed_X / Group_X / DNSBL", *got)
	}

	// A13.
	q := "anything.uuid1013.org"
	cfg = evCfgAll()
	cfg.tldAllow, cfg.tldAllowList = true, []string{"com", "net"}
	if got := evEval(q, "org", false, cfg, matcherContainers{}); !got.isFound || got.feed != "TLD_Allow" || got.group != "DNSBL_TLD_Allow" {
		t.Errorf("A13 a disallowed TLD blocks via TLD_Allow: got %+v", *got)
	}

	// oracle: builtin_log_flag shapes the block like any other log flag.
	for _, row := range []struct {
		flag string
		want func(*dd)
	}{
		{"3", func(d *dd) { d.logType, d.nxdomain = "3", true }},
		{"5", func(d *dd) { d.logType = "5" }},
		{"1", func(d *dd) { d.logType, d.nullBlocking = "1", false }},
	} {
		cfg := tldCfg(true, "com")
		cfg.builtinLogFlag = row.flag
		evCheck(t, "oracle: builtin_log_flag "+row.flag, evEval("x.example.net", "net", false, cfg, matcherContainers{}), blocked("x.example.net", row.want))
	}
	cfg = tldCfg(true, "com")
	cfg.builtinLogFlag, cfg.hstsDB = "1", true
	evCheck(t, "oracle: a TLD-Allow block on an HSTS TLD resolves real", evEval("x.example.app", "app", false, cfg, matcherContainers{}),
		blocked("x.example.app", func(d *dd) { d.logType, d.inHsts, d.pType = "1", true, "HSTS_TLD" }))

	// oracle: a TLD-Allow block comes before the IDN feed.
	cfg = tldCfg(true, "com")
	cfg.idnMode = IdnModeAll
	evCheck(t, "oracle: TLD_Allow before IDN", evEval("xn--any1234.net", "net", false, cfg, matcherContainers{}), blocked("xn--any1234.net", nil))
}

// oracle: _tld_allow_blocks fails closed on a structurally invalid name even under an allowed TLD (empty label), and
// judges a trailing-dot or non-ASCII name by its suffix.
func TestTldAllowBlocksStructuralNames(t *testing.T) {
	cfg := evCfg()
	cfg.tldAllow, cfg.tldAllowList = true, []string{"com"}
	for _, row := range []struct {
		q       string
		blocked bool
	}{
		{"a..example.com", true},
		{".com", true},
		{"example..", true},
		{"..com", true},
		{"example.com.", false},
		{"example.com", false},
		{"x.example.com", false},
		{"bücher.example.com", false},
	} {
		got := evEval(row.q, "com", false, cfg, matcherContainers{})
		if got.isFound != row.blocked || (row.blocked && got.feed != "TLD_Allow") {
			t.Errorf("%q: isFound=%v feed=%q, want blocked=%v", row.q, got.isFound, got.feed, row.blocked)
		}
	}
	if got := evEval("bücher.example.net", "net", false, cfg, matcherContainers{}); !got.isFound {
		t.Errorf("a non-ASCII name under an unselected TLD is blocked: isFound = false")
	}
}

// test_adr07_matcher_strata.py TestFastPathPreserved.
func TestEvaluateDomainFastPath(t *testing.T) {
	cfg := evCfg()
	cfg.dataDB = true
	got := evEval("evil.com", "com", false, cfg, matcherContainers{dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK)}})
	if !got.isFound || got.inWhitelist || got.nullBlocking {
		t.Errorf("block no allow: got isFound=%v inWhitelist=%v nullBlocking=%v, want true false false", got.isFound, got.inWhitelist, got.nullBlocking)
	}

	cfg.whiteDB = true
	got = evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK)}, whiteDB: map[string]whiteEntry{"evil.com": evWhite(false, true, 0)}})
	if !got.isFound || !got.inWhitelist || !got.nullBlocking {
		t.Errorf("whitelist overrides block: got isFound=%v inWhitelist=%v nullBlocking=%v, want true true true", got.isFound, got.inWhitelist, got.nullBlocking)
	}

	got = evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK_IMPORTANT)}, whiteDB: map[string]whiteEntry{"evil.com": evLegacyWhite(false)}})
	if !got.inWhitelist {
		t.Errorf("fast path ignores the important field on a block: inWhitelist = false, want true (any allow overrides)")
	}

	cfg = evCfg()
	cfg.dataDB, cfg.allowRegexDB = true, true
	got = evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK)}, allowRegexDB: evRegexDB(evRx("r", "evil", PRIO_FEED_ALLOW))})
	if got.inWhitelist || got.nullBlocking {
		t.Errorf("fast path does not consult allow-regex: got inWhitelist=%v nullBlocking=%v, want false false", got.inWhitelist, got.nullBlocking)
	}
}

// test_adr07_matcher_strata.py TestNumericBandResolution.
func TestEvaluateDomainNumericBands(t *testing.T) {
	user := func(pattern string, band int, important bool) *regexDB {
		return evRegexDB(evRule{name: "r", pattern: pattern, band: band, important: important})
	}
	userWhite := map[string]whiteEntry{"evil.com": evWhite(false, true, 0)}
	for _, row := range []struct {
		name           string
		blockImportant bool
		white          map[string]whiteEntry
		allow          *regexDB
		want           bool
	}{
		{"b1 block, no allow: block stands", false, nil, nil, false},
		{"b2 feed allow-regex beats b1 block", false, nil, user("evil", PRIO_FEED_ALLOW, false), true},
		{"b6 user allow beats b1 block", false, userWhite, nil, true},
		{"b3 important block beats b2 feed allow", true, nil, user("evil", PRIO_FEED_ALLOW, false), false},
		{"b4 important feed allow beats b3 important block", true, nil, user("evil", PRIO_FEED_ALLOW_IMPORTANT, true), true},
		{"b6 user allow beats b3 important block", true, userWhite, nil, true},
		{"b3 important block beats b2 non-important whitelist", true, map[string]whiteEntry{"evil.com": evLegacyWhite(false)}, nil, false},
		{"b2 non-important whitelist beats b1 block", false, map[string]whiteEntry{"evil.com": evLegacyWhite(false)}, nil, true},
		{"the highest allow wins: user allow beside a feed allow", true, userWhite, user("evil", PRIO_FEED_ALLOW, false), true},
		{"an allow-regex that matches another name leaves the block", false, nil, user("benign", PRIO_FEED_ALLOW, false), false},
	} {
		cfg := evCfg()
		cfg.dataDB, cfg.whiteDB, cfg.allowRegexDB, cfg.importantRules = true, len(row.white) > 0, row.allow.len() > 0, true
		got := evEval("evil.com", "com", false, cfg, matcherContainers{
			dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 0, blockPriority(row.blockImportant, false))}, whiteDB: row.white, allowRegexDB: row.allow})
		if got.inWhitelist != row.want {
			t.Errorf("%s: inWhitelist = %v, want %v", row.name, got.inWhitelist, row.want)
		}
	}
}

// test_adr07_matcher_strata.py TestTldAllowNumericBand and test_adr66_tld_naming_oracle.py A5/A5c.
func TestEvaluateDomainTldAllowNumericBand(t *testing.T) {
	decide := func(tld string, allow *regexDB) *dnsblDecision {
		cfg := evCfg()
		cfg.tldAllow, cfg.tldAllowList, cfg.importantRules, cfg.allowRegexDB = true, []string{"com"}, true, allow.len() > 0
		return evEval("host."+tld, tld, false, cfg, matcherContainers{allowRegexDB: allow})
	}
	if got := decide("xyz", nil); !got.isFound || got.feed != "TLD_Allow" || got.inWhitelist {
		t.Errorf("a disallowed TLD stands blocked with no allow: got %+v", *got)
	}
	if got := decide("com", nil); got.isFound {
		t.Errorf("an allowed TLD is not a block: isFound = true")
	}
	if got := decide("xyz", evRegexDB(evRx("r", "host", PRIO_FEED_ALLOW))); !got.inWhitelist {
		t.Errorf("a feed allow (band 2) overrides the TLD_Allow block (band 1): inWhitelist = false")
	}
	if got := decide("xyz", evRegexDB(evRx("r", "zzz-never-match", PRIO_FEED_ALLOW))); !got.isFound || got.inWhitelist {
		t.Errorf("a non-matching allow-regex leaves the block standing: got %+v", *got)
	}
	// oracle: a wildcard whitelist entry (band 2) overrides it, a non-wildcard one on the parent does not.
	cfg := evCfg()
	cfg.tldAllow, cfg.tldAllowList, cfg.whiteDB, cfg.importantRules = true, []string{"com"}, true, true
	for _, row := range []struct {
		wildcard bool
		want     bool
	}{{true, true}, {false, false}} {
		got := evEval("x.example.net", "net", false, cfg, matcherContainers{whiteDB: map[string]whiteEntry{"example.net": evWhite(row.wildcard, false, 2)}})
		if !got.isFound || got.inWhitelist != row.want {
			t.Errorf("whitelist example.net wildcard=%v: got isFound=%v inWhitelist=%v, want true %v", row.wildcard, got.isFound, got.inWhitelist, row.want)
		}
	}
}

// test_adr07_matcher_strata.py TestUserRegexSovereign.
func TestEvaluateDomainUserRegexSovereign(t *testing.T) {
	decide := func(white map[string]whiteEntry, allow *regexDB) bool {
		cfg := evCfg()
		cfg.regexDB, cfg.whiteDB, cfg.allowRegexDB, cfg.importantRules = true, len(white) > 0, allow.len() > 0, true
		user := evRegexDB(evRx("Regex_1", "evil", PRIO_USER_BLOCK))
		return evEval("evil.com", "com", false, cfg, matcherContainers{regexDB: user, whiteDB: white, allowRegexDB: allow}).inWhitelist
	}
	for _, row := range []struct {
		name  string
		white map[string]whiteEntry
		allow *regexDB
		want  bool
	}{
		{"blocks with no allow", nil, nil, false},
		{"beats a feed allow-regex (5 > 2)", nil, evRegexDB(evRx("r", "evil", PRIO_FEED_ALLOW)), false},
		{"beats a feed important allow (5 > 4)", nil, evRegexDB(evRule{name: "r", pattern: "evil", band: PRIO_FEED_ALLOW_IMPORTANT, important: true}), false},
		{"beats a feed domain allow (whiteDB band 2)", map[string]whiteEntry{"evil.com": evWhite(false, false, 2)}, nil, false},
		{"loses to the user whitelist (6 > 5)", map[string]whiteEntry{"evil.com": evWhite(false, true, 0)}, nil, true},
	} {
		if got := decide(row.white, row.allow); got != row.want {
			t.Errorf("%s: inWhitelist = %v, want %v", row.name, got, row.want)
		}
	}
}

// test_adr07_matcher_strata.py TestWinningEntryAttribution (issue #47).
func TestEvaluateDomainWinningEntryAttribution(t *testing.T) {
	cfg := evCfg()
	cfg.dataDB, cfg.regexDB, cfg.importantRules, cfg.builtinLogFlag = true, true, true, "1"
	evCheck(t, "user regex band 5 wins over feed data band 1 (VIP, DNSBL_Regex)", evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB:           map[string]*blockEntry{"evil.com": evBlk("2", 7, PRIO_FEED_BLOCK)},
		regexDB:          evRegexDB(evRx("Regex_1", "evil", PRIO_USER_BLOCK)),
		feedGroupIndexDB: map[int]feedGroup{7: {"FeedA", "GroupA"}}}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "Python", pType: "Python", feed: "Regex_1", group: "DNSBL_Regex", bEval: "evil.com"})

	cfg = evCfg()
	cfg.dataDB, cfg.zoneDB, cfg.importantRules = true, true, true
	evCheck(t, "important zone band 3 wins over feed data band 1, re-attributed to the zone", evEval("sub.evil.com", "com", false, cfg, matcherContainers{
		dataDB:           map[string]*blockEntry{"sub.evil.com": evBlk("2", 1, PRIO_FEED_BLOCK)},
		zoneDB:           map[string]*blockEntry{"evil.com": evBlk("1", 2, PRIO_FEED_BLOCK_IMPORTANT)},
		feedGroupIndexDB: map[int]feedGroup{1: {"DataFeed", "DataGroup"}, 2: {"ZoneFeed", "ZoneGroup"}}}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "TLD", pType: "Python", feed: "ZoneFeed", group: "ZoneGroup", bEval: "evil.com", groupOwner: "ZoneGroup", groupOrigin: "custom"})

	cfg = evCfg()
	cfg.dataDB, cfg.regexDB, cfg.importantRules = true, true, true
	evCheck(t, "a tie keeps the first-discovered attribution", evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB:           map[string]*blockEntry{"evil.com": evBlk("1", 3, PRIO_USER_BLOCK)},
		regexDB:          evRegexDB(evRx("Regex_1", "evil", PRIO_USER_BLOCK)),
		feedGroupIndexDB: map[int]feedGroup{3: {"UserFeed", "Custom_List"}}}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "UserFeed", group: "Custom_List", bEval: "evil.com", groupOwner: "Custom_List", groupOrigin: "custom"})

	cfg.whiteDB = true
	got := evEval("evil.com", "com", false, cfg, matcherContainers{
		dataDB:           map[string]*blockEntry{"evil.com": evBlk("2", 7, PRIO_FEED_BLOCK)},
		regexDB:          evRegexDB(evRx("Regex_1", "evil", PRIO_USER_BLOCK)),
		whiteDB:          map[string]whiteEntry{"evil.com": evWhite(false, true, 0)},
		feedGroupIndexDB: map[int]feedGroup{7: {"FeedA", "GroupA"}}})
	if !got.inWhitelist {
		t.Errorf("the winning regex still loses to the user whitelist (6 > 5): inWhitelist = false")
	}
}

// test_adr07_matcher_strata.py TestWidenedPayloadCompat.
func TestEvaluateDomainWidenedPayload(t *testing.T) {
	cfg := evCfg()
	cfg.dataDB = true
	got := evEval("evil.com", "com", false, cfg, matcherContainers{dataDB: map[string]*blockEntry{"evil.com": {log: "1", index: 0, band: PRIO_FEED_BLOCK}}})
	if !got.isFound || got.nullBlocking {
		t.Errorf("a payload without the important key still blocks: got isFound=%v nullBlocking=%v", got.isFound, got.nullBlocking)
	}
	for _, important := range []bool{false, true} {
		cfg := evCfg()
		cfg.zoneDB, cfg.whiteDB, cfg.allowRegexDB, cfg.importantRules = true, true, true, true
		got := evEval("sub.evil.com", "com", false, cfg, matcherContainers{
			zoneDB: map[string]*blockEntry{"evil.com": {log: "1", index: 0, important: important, band: blockPriority(important, false)}}})
		if !got.isFound || got.inWhitelist {
			t.Errorf("zone payload important=%v: got isFound=%v inWhitelist=%v, want true false", important, got.isFound, got.inWhitelist)
		}
	}
}

const evPSL = "// ===BEGIN ICANN DOMAINS===\ncom\nio\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n" +
	"// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"

func evPslContainers(t *testing.T, roots []string, allowPrivate bool) matcherContainers {
	t.Helper()
	rules, err := parsePslRules(evPSL)
	if err != nil {
		t.Fatal(err)
	}
	return matcherContainers{pslRules: rules, tldAllowRoots: roots, pslAllowPrivate: allowPrivate}
}

func evAllowCfg(list ...string) evaluateConfig {
	cfg := evCfg()
	cfg.pythonBlocking, cfg.tldAllow, cfg.tldAllowList, cfg.hstsTlds = false, true, list, nil
	return cfg
}

// test_psl_runtime_integration.py (the evaluate_domain rows) and test_adr66_tld_naming_oracle.py TestOracleATldAllowPslPrivate.
// The Python cfg carries psl_allow_private; here only the containers do (matcherContainers always has the key, so the
// cfg fallback evaluate_domain reads for a hand-built containers dict without it has no Go counterpart).
func TestEvaluateDomainPslTldAllow(t *testing.T) {
	// A selected IANA root always wins, even under a PRIVATE suffix, and a trailing dot is ignored.
	c := evPslContainers(t, []string{"com"}, false)
	if got := evEval("x.github.io.", "io", false, evAllowCfg("io"), c); got.isFound {
		t.Errorf("selected root io admits x.github.io.: isFound = true")
	}
	if got := evEval("x.example.net", "net", false, evAllowCfg("com"), c); !got.isFound || got.feed != "TLD_Allow" {
		t.Errorf("a non-selected ICANN root stays blocked: got %+v", *got)
	}
	// PRIVATE allowance is explicit and does not broaden ICANN roots.
	c = evPslContainers(t, []string{"com"}, true)
	if got := evEval("x.github.io", "io", false, evAllowCfg("com"), c); got.isFound {
		t.Errorf("allow-private admits the github.io boundary: isFound = true")
	}
	if got := evEval("x.example.net", "net", false, evAllowCfg("com"), c); !got.isFound {
		t.Errorf("allow-private does not broaden ICANN roots: isFound = false")
	}

	// An exception TLD (!www.ck) is not private_active, so PRIVATE allowance must not open it; github.io still is.
	c = evPslContainers(t, nil, true)
	if got := evEval("www.ck", "ck", false, evAllowCfg("com"), c); !got.isFound || got.feed != "TLD_Allow" {
		t.Errorf("www.ck stays blocked under allow-private: got %+v", *got)
	}
	if got := evEval("x.github.io", "io", false, evAllowCfg("com"), c); got.isFound {
		t.Errorf("x.github.io is admitted by allow-private: isFound = true")
	}

	// Underscore service labels are judged by their suffix, like any other name.
	c = evPslContainers(t, []string{"com"}, false)
	for _, name := range []string{"_dmarc.example.com", "_sip._tcp.example.com", "_acme-challenge.example.com"} {
		if got := evEval(name, "com", false, evAllowCfg("com"), c); got.isFound {
			t.Errorf("%s under a selected root: isFound = true", name)
		}
	}
	if got := evEval("_dmarc.example.net", "net", false, evAllowCfg("com"), c); !got.isFound || got.feed != "TLD_Allow" {
		t.Errorf("_dmarc.example.net under an unselected root: got %+v", *got)
	}

	// pfb_psl_allow_private stands alone: the include-private toggle never reaches TLD-Allow.
	c = evPslContainers(t, []string{"com"}, true)
	c.pslIncludePrivate = false
	if got := evEval("x.github.io", "io", false, evAllowCfg("com"), c); got.isFound {
		t.Errorf("allow-private independent of include-private: isFound = true")
	}
	if got := evEval("x.io", "io", false, evAllowCfg("com"), c); !got.isFound || got.feed != "TLD_Allow" {
		t.Errorf("allow-private never opens the parent TLD: got %+v", *got)
	}

	// Allow-private off: the private boundary and its parent stay blocked.
	c = evPslContainers(t, []string{"com"}, false)
	for _, name := range []string{"x.github.io", "x.io"} {
		if got := evEval(name, "io", false, evAllowCfg("com"), c); !got.isFound || got.feed != "TLD_Allow" {
			t.Errorf("%s with allow-private off: got %+v, want a TLD_Allow block", name, *got)
		}
	}

	// test_adr66_tld_naming_oracle.py: a selected root io allows the private suffix query; allow-private matches only
	// the winning private boundary.
	rules, err := parsePslRules("// ===BEGIN ICANN DOMAINS===\nio\ncom\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := evEval("x.github.io", "io", false, evAllowCfg("io"), matcherContainers{pslRules: rules, tldAllowRoots: []string{"io"}}); got.isFound {
		t.Errorf("selected root allows a private suffix query: isFound = true")
	}
	if got := evEval("x.github.io", "io", false, evAllowCfg("com"), matcherContainers{pslRules: rules, pslAllowPrivate: true}); got.isFound {
		t.Errorf("allow-private matches the winning private boundary: isFound = true")
	}
	if got := evEval("x.example.net", "net", false, evAllowCfg("com"), matcherContainers{}); !got.isFound {
		t.Errorf("an unrelated public name stays blocked: isFound = false")
	}

	// The cfg list wins over the snapshot roots only when it is non-empty (Python's `or`); an empty cfg list falls
	// back to the containers' roots. oracle.
	cfg := evAllowCfg()
	if got := evEval("x.example.com", "com", false, cfg, matcherContainers{tldAllowRoots: []string{"com"}}); got.isFound {
		t.Errorf("empty cfg list, containers root com: isFound = true")
	}
	if got := evEval("x.example.net", "net", false, cfg, matcherContainers{tldAllowRoots: []string{"com"}}); !got.isFound {
		t.Errorf("empty cfg list, containers root com, query net: isFound = false")
	}
	if got := evEval("x.example.net", "net", false, evAllowCfg("net"), matcherContainers{tldAllowRoots: []string{"com"}}); got.isFound {
		t.Errorf("cfg list net wins over containers root com: isFound = true")
	}
}

// oracle: DnsblDecision rows from running evaluate_domain in Python on the same fixtures: attribution of the group
// fields, the CNAME name list, the HSTS and log-type arms, the gates, and the first-hit orders.
func TestEvaluateDomainOracleRows(t *testing.T) {
	fg := map[int]feedGroup{1: {"FeedA", "GroupA"}, 2: {"ZoneFeed", "ZoneGroup"}}
	dataEvil := map[string]*blockEntry{"evil.com": evBlk("1", 1, PRIO_FEED_BLOCK)}
	hstsEvil := map[string]struct{}{"evil.com": {}}
	cfgOf := func(over func(*evaluateConfig)) evaluateConfig {
		cfg := evCfg()
		over(&cfg)
		return cfg
	}
	data := func(c *evaluateConfig) { c.dataDB = true }

	evCheck(t, "R1 a regex rule carries its group_owner/origin", evEval("evil.example", "example", false,
		cfgOf(func(c *evaluateConfig) { c.regexDB = true }),
		matcherContainers{regexDB: evRegexDB(evRule{name: "F#0", pattern: "evil", band: 1, owner: "GrpX", origin: "custom"})}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "F#0", group: "DNSBL_Regex", bEval: "evil.example", groupOwner: "GrpX", groupOrigin: "custom"})
	evCheck(t, "R1b a user regex rule", evEval("evil.example", "example", false,
		cfgOf(func(c *evaluateConfig) { c.userRegexDB = true }),
		matcherContainers{userRegexDB: evRegexDB(evRule{name: "U#0", pattern: "evil", band: 5, owner: "DNSBL_Regex", origin: "builtin"})}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "U#0", group: "DNSBL_Regex", bEval: "evil.example", groupOwner: "DNSBL_Regex", groupOrigin: "builtin"})

	zone := evBlk("1", 1, PRIO_FEED_BLOCK)
	zone.groupOwner, zone.hasGroupOwner, zone.groupOrigin, zone.hasGroupOrigin = "Owner", true, "builtin", true
	evCheck(t, "R2 a zone entry's group_owner/origin win over the defaults", evEval("a.evil.com", "com", false,
		cfgOf(func(c *evaluateConfig) { c.zoneDB = true }), matcherContainers{zoneDB: map[string]*blockEntry{"evil.com": zone}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "TLD", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "Owner", groupOrigin: "builtin"})
	evCheck(t, "R2b data entry: group_owner is the group, origin custom", evEval("evil.com", "com", false, cfgOf(data),
		matcherContainers{dataDB: dataEvil, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})
	evCheck(t, "R2c an unknown feed index is Unknown / Unknown", evEval("evil.com", "com", false, cfgOf(data),
		matcherContainers{dataDB: map[string]*blockEntry{"evil.com": evBlk("1", 99, PRIO_FEED_BLOCK)}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "Unknown", group: "Unknown", bEval: "evil.com", groupOwner: "Unknown", groupOrigin: "custom"})

	zoneHi := evBlk("1", 2, PRIO_FEED_BLOCK_IMPORTANT)
	zoneHi.groupOwner, zoneHi.hasGroupOwner, zoneHi.groupOrigin, zoneHi.hasGroupOrigin = "ZO", true, "builtin", true
	evCheck(t, "R3 the band re-scan re-attributes to a regex with its group fields", evEval("evil.com", "com", false,
		cfgOf(func(c *evaluateConfig) {
			c.dataDB, c.regexDB, c.importantRules, c.builtinLogFlag = true, true, true, "1"
		}),
		matcherContainers{dataDB: map[string]*blockEntry{"evil.com": evBlk("2", 1, PRIO_FEED_BLOCK)},
			regexDB: evRegexDB(evRule{name: "R#0", pattern: "evil", band: 5, owner: "GO", origin: "GOr"}), feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "Python", pType: "Python", feed: "R#0", group: "DNSBL_Regex", bEval: "evil.com", groupOwner: "GO", groupOrigin: "GOr"})
	evCheck(t, "R3b the band re-scan re-attributes to a zone with its group fields", evEval("sub.evil.com", "com", false,
		cfgOf(func(c *evaluateConfig) { c.dataDB, c.zoneDB, c.importantRules = true, true, true }),
		matcherContainers{dataDB: map[string]*blockEntry{"sub.evil.com": evBlk("2", 1, PRIO_FEED_BLOCK)}, zoneDB: map[string]*blockEntry{"evil.com": zoneHi}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "TLD", pType: "Python", feed: "ZoneFeed", group: "ZoneGroup", bEval: "evil.com", groupOwner: "ZO", groupOrigin: "builtin"})

	// R4: a CNAME target is also judged by the name the client asked for.
	numeric := cfgOf(func(c *evaluateConfig) { c.dataDB, c.whiteDB, c.importantRules = true, true, true })
	target := map[string]*blockEntry{"target.net": evBlk("1", 1, PRIO_FEED_BLOCK)}
	white := map[string]whiteEntry{"orig.com": evWhite(false, false, 2)}
	blockedTarget := dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "target.net", groupOwner: "GroupA", groupOrigin: "custom"}
	allowedTarget := blockedTarget
	allowedTarget.inWhitelist, allowedTarget.nullBlocking = true, true
	evCheck(t, "R4a numeric path, cname: the original name's allow wins", evaluateDomain("target.net", "orig.com", "net", true, numeric,
		matcherContainers{dataDB: target, whiteDB: white, feedGroupIndexDB: fg}), allowedTarget)
	evCheck(t, "R4b numeric path, not a cname: the original name is not consulted", evaluateDomain("target.net", "orig.com", "net", false, numeric,
		matcherContainers{dataDB: target, whiteDB: white, feedGroupIndexDB: fg}), blockedTarget)
	evCheck(t, "R4c fast path, cname: the original name's whitelist wins", evaluateDomain("target.net", "orig.com", "net", true,
		cfgOf(func(c *evaluateConfig) { c.dataDB, c.whiteDB = true, true }),
		matcherContainers{dataDB: target, whiteDB: map[string]whiteEntry{"orig.com": evLegacyWhite(true)}, feedGroupIndexDB: fg}), allowedTarget)

	// R6, R7: HSTS and the log-type arms.
	hsts := cfgOf(func(c *evaluateConfig) { c.dataDB, c.hstsDB = true, true })
	evCheck(t, "R6 an HSTS TLD", evEval("evil.app", "app", false, hsts, matcherContainers{dataDB: map[string]*blockEntry{"evil.app": evBlk("1", 1, PRIO_FEED_BLOCK)}, feedGroupIndexDB: fg}),
		dd{isFound: true, inHsts: true, nullBlocking: true, logType: "1", bType: "DNSBL", pType: "HSTS_TLD", feed: "FeedA", group: "GroupA", bEval: "evil.app", groupOwner: "GroupA", groupOrigin: "custom"})
	evCheck(t, "R6b an HSTS parent of a zone hit", evEval("sub.evil.com", "com", false, cfgOf(func(c *evaluateConfig) { c.zoneDB, c.hstsDB = true, true }),
		matcherContainers{zoneDB: dataEvil, hstsDB: hstsEvil, feedGroupIndexDB: fg}),
		dd{isFound: true, inHsts: true, nullBlocking: true, logType: "1", bType: "TLD", pType: "HSTS", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})
	evCheck(t, "R6d a whitelisted HSTS name is not HSTS", evEval("evil.com", "com", false, cfgOf(func(c *evaluateConfig) { c.dataDB, c.hstsDB, c.whiteDB = true, true, true }),
		matcherContainers{dataDB: dataEvil, hstsDB: hstsEvil, whiteDB: map[string]whiteEntry{"evil.com": evLegacyWhite(true)}, feedGroupIndexDB: fg}),
		dd{isFound: true, inWhitelist: true, nullBlocking: true, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})
	evCheck(t, "R6e the hstsDB gate off", evEval("evil.com", "com", false, cfgOf(data), matcherContainers{dataDB: dataEvil, hstsDB: hstsEvil, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})

	for _, row := range []struct {
		log  string
		want func(*dd)
	}{
		{"0", func(d *dd) { d.inHsts, d.pType = true, "HSTS" }},
		{"1", func(d *dd) { d.inHsts, d.pType = true, "HSTS" }},
		{"2", func(d *dd) { d.inHsts, d.pType = true, "HSTS" }},
		{"3", func(d *dd) { d.nxdomain = true }},
		{"4", func(d *dd) { d.nxdomain = true }},
		{"5", func(d *dd) {}},
		{"6", func(d *dd) {}},
	} {
		want := dd{isFound: true, nullBlocking: true, logType: row.log, bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"}
		row.want(&want)
		evCheck(t, "R7 log "+row.log, evEval("evil.com", "com", false, hsts, matcherContainers{
			dataDB: map[string]*blockEntry{"evil.com": evBlk(row.log, 1, PRIO_FEED_BLOCK)}, hstsDB: hstsEvil, feedGroupIndexDB: fg}), want)
	}
	evCheck(t, "R7 nxdomain on a CNAME", evEval("evil.com", "com", true, cfgOf(data), matcherContainers{
		dataDB: map[string]*blockEntry{"evil.com": evBlk("3", 1, PRIO_FEED_BLOCK)}, feedGroupIndexDB: fg}),
		dd{isFound: true, nxdomain: true, nullBlocking: true, logType: "3", bType: "DNSBL_CNAME", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})

	// R8: python_blocking gates data and zone, not TLD-Allow.
	evCheck(t, "R8 python_blocking off", evEval("evil.com", "com", false,
		cfgOf(func(c *evaluateConfig) {
			c.pythonBlocking, c.dataDB, c.tldAllow, c.tldAllowList = false, true, true, []string{"net"}
		}),
		matcherContainers{dataDB: dataEvil, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "TLD_Allow", group: "DNSBL_TLD_Allow", bEval: "evil.com", groupOwner: "DNSBL_TLD_Allow", groupOrigin: "builtin"})
	// R9: the presence gates.
	evCheck(t, "R9a dataDB gate off", evEval("evil.com", "com", false, evCfg(), matcherContainers{dataDB: dataEvil, feedGroupIndexDB: fg}), evNone)
	evCheck(t, "R9b zoneDB gate off", evEval("a.evil.com", "com", false, evCfg(), matcherContainers{zoneDB: dataEvil, feedGroupIndexDB: fg}), evNone)
	// R10, R11: the first-hit order (data, zone, TLD-Allow, IDN, user regex, feed regex).
	evCheck(t, "R10 data before zone", evEval("evil.com", "com", false, cfgOf(func(c *evaluateConfig) { c.dataDB, c.zoneDB = true, true }),
		matcherContainers{dataDB: dataEvil, zoneDB: map[string]*blockEntry{"evil.com": evBlk("1", 2, PRIO_FEED_BLOCK)}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})
	evCheck(t, "R11 data before regex", evEval("evil.com", "com", false, cfgOf(func(c *evaluateConfig) { c.dataDB, c.regexDB = true, true }),
		matcherContainers{dataDB: dataEvil, regexDB: evRegexDB(evRx("R", "evil", 1)), feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: false, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "evil.com", groupOwner: "GroupA", groupOrigin: "custom"})
	regexCfg := cfgOf(func(c *evaluateConfig) { c.regexDB = true })
	evCheck(t, "R11b an empty query name skips the regex arm", evEval("", "", false, regexCfg, matcherContainers{regexDB: evRegexDB(evRx("R", "", 1))}), evNone)
	evCheck(t, "R11c a regex without the case-insensitive flag is case-sensitive", evEval("EVIL.com", "com", false, regexCfg, matcherContainers{regexDB: evRegexDB(evRx("R", "evil", 1))}), evNone)
	evCheck(t, "R11d the case-insensitive flag matches the query as given", evEval("EVIL.com", "com", false, regexCfg, matcherContainers{regexDB: evRegexDB(evRx("R", "(?i)evil", 1))}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "R", group: "DNSBL_Regex", bEval: "EVIL.com"})
	// R12: the VIP query is exempt from TLD-Allow.
	evCheck(t, "R12 the VIP query is exempt", evEval("10.10.10.1", "1", false, cfgOf(func(c *evaluateConfig) { c.tldAllow, c.tldAllowList = true, []string{"com"} }), matcherContainers{}), evNone)
}

// test_adr07_user_regex_containers.py TestUserRegexIsEvaluatedFirst (the evaluate_domain rows).
func TestUserRegexIsEvaluatedFirst(t *testing.T) {
	ci := func(name, pattern string, band int, important bool) evRule {
		return evRule{name: name, pattern: "(?i)" + pattern, band: band, important: important}
	}
	cfg := evCfg()
	cfg.regexDB, cfg.userRegexDB = true, true
	if got := evEval("evil.example", "example", false, cfg, matcherContainers{
		regexDB: evRegexDB(ci("F#0", "evil", PRIO_FEED_BLOCK, false)), userRegexDB: evRegexDB(ci("U#0", "evil", PRIO_USER_BLOCK, false))}); !got.isFound || got.feed != "U#0" || got.group != "DNSBL_Regex" {
		t.Errorf("the discovery scan reaches the user list first: got %+v", *got)
	}
	only := evCfg()
	only.userRegexDB = true
	if got := evEval("evil.example", "example", false, only, matcherContainers{userRegexDB: evRegexDB(ci("U#0", "evil", PRIO_USER_BLOCK, false))}); !got.isFound || got.feed != "U#0" {
		t.Errorf("a user regex blocks with no feed regex loaded: got %+v", *got)
	}
	if got := evEval("evil.example", "example", false, cfg, matcherContainers{
		regexDB: evRegexDB(ci("F#0", "evil", PRIO_FEED_BLOCK, false)), userRegexDB: evRegexDB(ci("U#0", "other", PRIO_USER_BLOCK, false))}); !got.isFound || got.feed != "F#0" {
		t.Errorf("a feed regex still blocks when the user list does not match: got %+v", *got)
	}

	for _, allowBand := range []int{PRIO_FEED_ALLOW, PRIO_FEED_ALLOW_IMPORTANT} {
		cfg := evCfg()
		cfg.userRegexDB, cfg.allowRegexDB, cfg.importantRules = true, true, true
		got := evEval("evil.example", "example", false, cfg, matcherContainers{
			userRegexDB:  evRegexDB(ci("U#0", "evil", PRIO_USER_BLOCK, false)),
			allowRegexDB: evRegexDB(ci("A#0", "evil", allowBand, allowBand == PRIO_FEED_ALLOW_IMPORTANT))})
		if !got.isFound || got.inWhitelist {
			t.Errorf("a user block regex beats a feed allow regex of band %d: got isFound=%v inWhitelist=%v", allowBand, got.isFound, got.inWhitelist)
		}
	}

	cfg = evCfg()
	cfg.regexDB, cfg.userAllowRegexDB, cfg.importantRules = true, true, true
	if got := evEval("evil.example", "example", false, cfg, matcherContainers{
		regexDB:          evRegexDB(ci("F#0", "evil", PRIO_FEED_BLOCK_IMPORTANT, true)),
		userAllowRegexDB: evRegexDB(ci("UA#0", "evil", PRIO_USER_ALLOW, false))}); !got.isFound || !got.inWhitelist {
		t.Errorf("a user allow regex beats an important feed block regex: got isFound=%v inWhitelist=%v", got.isFound, got.inWhitelist)
	}
	cfg = evCfg()
	cfg.userRegexDB, cfg.userAllowRegexDB, cfg.importantRules = true, true, true
	if got := evEval("evil.example", "example", false, cfg, matcherContainers{
		userRegexDB:      evRegexDB(ci("U#0", "evil", PRIO_USER_BLOCK, false)),
		userAllowRegexDB: evRegexDB(ci("UA#0", "evil", PRIO_USER_ALLOW, false))}); !got.isFound || !got.inWhitelist {
		t.Errorf("a user allow regex beats a user block regex: got isFound=%v inWhitelist=%v", got.isFound, got.inWhitelist)
	}
}

func evMeta(m *blockMeta) string {
	if m == nil {
		return "nil"
	}
	return fmt.Sprintf("{kind:%s key:%s matched:%s}", m.kind, m.key, m.matched)
}

// test_adr07_user_regex_containers.py (the band re-scan rows) and test_branch_coverage_gaps.py TestScanBlockBand.
func TestScanBlockBand(t *testing.T) {
	ci := func(name, pattern string, band int, important bool) evRule {
		return evRule{name: name, pattern: "(?i)" + pattern, band: band, important: important}
	}

	zoneCfg := evCfg()
	zoneCfg.zoneDB = true
	zoneDB := map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK_IMPORTANT), "com": evBlk("1", 1, PRIO_FEED_BLOCK)}
	if band, meta := scanBlockBand("x.evil.com", zoneCfg, nil, zoneDB, nil, nil); band != PRIO_FEED_BLOCK_IMPORTANT || meta == nil || meta.kind != "zone" || meta.matched != "evil.com" {
		t.Errorf("the higher zone band wins and a later lower one does not replace it: got (%d, %s)", band, evMeta(meta))
	}

	feed := evRegexDB(ci("F#0", "evil", PRIO_FEED_BLOCK_IMPORTANT, true))
	user := evRegexDB(ci("U#0", "evil", PRIO_USER_BLOCK, false))
	both := evCfg()
	both.regexDB, both.userRegexDB = true, true
	for _, row := range []struct {
		name     string
		cfg      evaluateConfig
		feed     *regexDB
		user     *regexDB
		band     int
		wantName string
	}{
		{"both lists, the user rule wins", both, feed, user, PRIO_USER_BLOCK, "U#0"},
		{"feed list alone", both, feed, nil, PRIO_FEED_BLOCK_IMPORTANT, "F#0"},
		{"user list alone", func() evaluateConfig { c := evCfg(); c.userRegexDB = true; return c }(), nil, user, PRIO_USER_BLOCK, "U#0"},
	} {
		band, meta := scanBlockBand("evil.example", row.cfg, nil, nil, row.feed, row.user)
		if band != row.band || meta == nil || meta.kind != "regex" || meta.key != row.wantName {
			t.Errorf("%s: got (%d, %s), want (%d, regex %s)", row.name, band, evMeta(meta), row.band, row.wantName)
		}
	}

	// A band tie keeps the rule scanned first: data before regex, the user list before the feed list.
	dataEntry := evBlk("1", 0, PRIO_FEED_BLOCK)
	tie := evCfg()
	tie.dataDB, tie.regexDB, tie.userRegexDB = true, true, true
	feedTie := evRegexDB(ci("F#0", "evil", PRIO_FEED_BLOCK, false))
	userTie := evRegexDB(ci("U#0", "evil", PRIO_FEED_BLOCK, false))
	band, meta := scanBlockBand("evil.example", tie, map[string]*blockEntry{"evil.example": dataEntry}, nil, feedTie, nil)
	if band != PRIO_FEED_BLOCK || meta == nil || meta.kind != "data" || meta.block != dataEntry {
		t.Errorf("data before regex on a tie: got (%d, %s), want (1, data with the same entry)", band, evMeta(meta))
	}
	band, meta = scanBlockBand("evil.example", tie, nil, nil, feedTie, userTie)
	if band != PRIO_FEED_BLOCK || meta == nil || meta.kind != "regex" || meta.key != "U#0" {
		t.Errorf("the user list before the feed list on a tie: got (%d, %s), want (1, regex U#0)", band, evMeta(meta))
	}

	// Nothing matches: (0, None), and an empty query name skips the regex lists.
	if band, meta := scanBlockBand("nomatch.example", both, nil, nil, feed, user); band != 0 || meta != nil {
		t.Errorf("no match: got (%d, %s), want (0, nil)", band, evMeta(meta))
	}
	if band, meta := scanBlockBand("", both, nil, nil, evRegexDB(evRx("R", "", PRIO_FEED_BLOCK)), nil); band != 0 || meta != nil {
		t.Errorf("an empty query name: got (%d, %s), want (0, nil)", band, evMeta(meta))
	}
	// A TOP1M-filtered zone entry yields to its fallback, or blocks nothing.
	top := evBlk("1", 0, PRIO_FEED_BLOCK)
	top.hasTop1m, top.top1m = true, map[string]struct{}{"evil.com": {}}
	if band, meta := scanBlockBand("evil.com", zoneCfg, nil, map[string]*blockEntry{"evil.com": top}, nil, nil); band != 0 || meta != nil {
		t.Errorf("a TOP1M-listed name with no fallback blocks nothing: got (%d, %s)", band, evMeta(meta))
	}
}

// test_adr07_user_regex_containers.py (the allow re-scan row) and test_branch_coverage_gaps.py TestScanAllowRegexBand.
func TestScanAllowRegexBand(t *testing.T) {
	rt := newRegexRuntime()
	feed := evRegexDB(evRule{name: "A#0", pattern: "(?i)evil", band: PRIO_FEED_ALLOW_IMPORTANT, important: true})
	user := evRegexDB(evRule{name: "UA#0", pattern: "(?i)evil", band: PRIO_USER_ALLOW})
	for _, row := range []struct {
		name       string
		feed, user *regexDB
		want       int
	}{
		{"both lists", feed, user, PRIO_USER_ALLOW},
		{"user list alone", nil, user, PRIO_USER_ALLOW},
		{"feed list alone", feed, nil, PRIO_FEED_ALLOW_IMPORTANT},
	} {
		if got := scanAllowRegexBand(rt, "evil.example", row.feed, row.user, 10.0); got != row.want {
			t.Errorf("%s: band = %d, want %d", row.name, got, row.want)
		}
	}
	if got := scanAllowRegexBand(rt, "", evRegexDB(evRx("R", "x", PRIO_FEED_ALLOW)), nil, 10.0); got != 0 {
		t.Errorf("an empty query name: band = %d, want 0", got)
	}
	if got := scanAllowRegexBand(rt, "benign.example", feed, user, 10.0); got != 0 {
		t.Errorf("no match: band = %d, want 0", got)
	}
}

// _resolve_numeric_allow: an allow overrides iff allow_band >= block_band; a CNAME also consults the original name.
func TestResolveNumericAllow(t *testing.T) {
	cfg := evCfg()
	cfg.whiteDB, cfg.allowRegexDB, cfg.userAllowRegexDB = true, true, true
	white := map[string]whiteEntry{"orig.com": evWhite(false, false, 4), "a.com": evWhite(false, false, 2)}
	allow := evRegexDB(evRx("A", "viaregex", PRIO_FEED_ALLOW_IMPORTANT))
	userAllow := evRegexDB(evRx("UA", "viauser", PRIO_USER_ALLOW))
	for _, row := range []struct {
		name      string
		q, orig   string
		isCname   bool
		blockBand int
		want      bool
	}{
		{"allow band 2 vs block band 1", "a.com", "a.com", false, 1, true},
		{"allow band 2 vs block band 3", "a.com", "a.com", false, 3, false},
		{"no allow match, block band 1", "none.com", "none.com", false, 1, false},
		{"no allow match, block band 0 (an allow >= 0 always overrides)", "none.com", "none.com", false, 0, true},
		{"cname: the original name's band 4 beats block 3", "t.net", "orig.com", true, 3, true},
		{"not a cname: the original name is not consulted", "t.net", "orig.com", false, 3, false},
		{"allow regex band 4 beats block 3", "x.viaregex.net", "x.viaregex.net", false, 3, true},
		{"user allow regex band 6 beats block 5", "x.viauser.net", "x.viauser.net", false, 5, true},
		{"allow regex band 4 loses to block 5", "x.viaregex.net", "x.viaregex.net", false, 5, false},
	} {
		got := resolveNumericAllow(row.q, row.orig, row.isCname, cfg, white, allow, userAllow, row.blockBand)
		if got != row.want {
			t.Errorf("%s: got %v, want %v", row.name, got, row.want)
		}
	}
	// The whiteDB / allow-regex gates: a lookup is skipped when the gate is off, however the data looks.
	off := evCfg()
	if got := resolveNumericAllow("a.com", "a.com", false, off, white, allow, userAllow, 1); got {
		t.Errorf("gates off: got true, want false (no allow consulted)")
	}
}

// _first_regex_match: the first matching rule in insertion order, timed through the scan.
func TestFirstRegexMatch(t *testing.T) {
	rt := newRegexRuntime()
	db := evRegexDB(evRx("one", "nomatch", 1), evRx("two", "evil", 1), evRx("three", "evil", 5))
	scan := newRegexScan(rt, "DNSBL_Regex", 10.0, false)
	name, rule := firstRegexMatch(db, "evil.com", &scan)
	if name != "two" || rule != mustGet(t, db, "two") || scan.rules != 2 {
		t.Errorf("got (%q, %v) after %d rules timed, want (two, the second rule) after 2", name, rule, scan.rules)
	}
	scan = newRegexScan(rt, "DNSBL_Regex", 10.0, false)
	if name, rule := firstRegexMatch(db, "benign.org", &scan); name != "" || rule != nil || scan.rules != 3 {
		t.Errorf("no match: got (%q, %v) after %d rules timed, want (\"\", nil) after 3", name, rule, scan.rules)
	}
	scan = newRegexScan(rt, "DNSBL_Regex", 10.0, false)
	if name, rule := firstRegexMatch(nil, "evil.com", &scan); name != "" || rule != nil {
		t.Errorf("a nil list: got (%q, %v), want (\"\", nil)", name, rule)
	}
}

func mustGet(t *testing.T, db *regexDB, name string) *regexEntry {
	t.Helper()
	entry, ok := db.get(name)
	if !ok {
		t.Fatalf("rule %q missing", name)
	}
	return entry
}

// _regex_candidates is "every rule is a candidate" here (see the shortcut comment): the names in insertion order.
func TestRegexCandidates(t *testing.T) {
	db := evRegexDB(evRx("b", "x", 1), evRx("a", "y", 1), evRx("c", "z", 1))
	if got := regexCandidates(db, "anything.example"); !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Errorf("candidates = %q, want [b a c]", got)
	}
	if got := regexCandidates(nil, "anything.example"); len(got) != 0 {
		t.Errorf("candidates of a nil list = %q, want none", got)
	}
}

// evMeasured stands in for the timer: each rule measures a fixed time keyed by its pattern text, so the answer does not
// depend on the order a scan visits the rules in (test_adr07_regex_safety.py _Measured).
type evMeasured struct{ ms map[string]float64 }

func newEvMeasured(rt *regexRuntime) *evMeasured {
	m := &evMeasured{ms: map[string]float64{}}
	rt.timedSearch = func(re *regexp.Regexp, qName string) (bool, float64) { return re.MatchString(qName), m.ms[re.String()] }
	return m
}

// db is a regex DB with one rule per entry of msList (rule i measures msList[i]); rule matchAt matches slow.example
// (-1: none does). Every rule is an alternation, as in the Python helper.
func (m *evMeasured) db(prefix string, band int, msList []float64, matchAt int) *regexDB {
	db := &regexDB{}
	for index, ms := range msList {
		text := fmt.Sprintf("^(?:no%s%d|zz)$", prefix, index)
		if index == matchAt {
			text = fmt.Sprintf(`^(?:slow\.example|never%s%d)$`, prefix, index)
		}
		m.ms[text] = ms
		db.set(fmt.Sprintf("%s#%d", prefix, index), &regexEntry{re: regexp.MustCompile(text), band: band})
	}
	return db
}

// evScripted is the fake thread clock: each match measures the next scripted time (test_adr07_regex_safety.py
// _install_clock).
func evScripted(t *testing.T, ms ...float64) func(*regexp.Regexp, string) (bool, float64) {
	scripted := len(ms)
	return func(re *regexp.Regexp, qName string) (bool, float64) {
		t.Helper()
		if len(ms) == 0 {
			t.Fatalf("timedSearch called more often than the %d scripted times", scripted)
		}
		next := ms[0]
		ms = ms[1:]
		return re.MatchString(qName), next
	}
}

func evRuleLine(label, name, took string) string {
	return fmt.Sprintf("%s[pfBlockerNG]: slow %s regex [ %s ] took %s ms (warn ceiling 10.0 ms)\n", evLogPrefix, label, name, took)
}

func evListLine(label, total string, count int, slowest, top string) string {
	return fmt.Sprintf("%s[pfBlockerNG]: slow %s regex list scan took %s ms over %d rules (warn ceiling 10.0 ms); slowest [ %s ] %s ms\n",
		evLogPrefix, label, total, count, slowest, top)
}

// test_adr07_regex_safety.py TestSlowRegexIsWarnedAndKept and TestFastPathUnchanged.
func TestSlowRegexIsWarnedAndKept(t *testing.T) {
	const slowMs = 150.0 // over both the warn ceiling and the old 100 ms evict ceiling
	slowDB := func() *regexDB { return evRegexDB(evRx("F#0", `slow\.example$`, PRIO_FEED_BLOCK)) }
	oneWarning := func(t *testing.T, log *evSyncBuffer, want string) {
		t.Helper()
		if got := strings.Count(log.String(), want); got != 1 {
			t.Errorf("%q written %d times, want once; log:\n%s", want, got, log.String())
		}
	}

	t.Run("discovery scan keeps a rule measured over the old evict ceiling", func(t *testing.T) {
		log := evCaptureLog(t)
		db := slowDB()
		cfg := evCfg()
		cfg.regexDB = true
		cfg.regex.timedSearch = evScripted(t, slowMs, slowMs)
		for i := range 2 {
			got := evEval("slow.example", "example", false, cfg, matcherContainers{regexDB: db})
			if !got.isFound || got.group != "DNSBL_Regex" || got.feed != "F#0" {
				t.Errorf("query %d: got %+v, want a DNSBL_Regex block by F#0", i+1, *got)
			}
			if _, ok := db.get("F#0"); !ok {
				t.Errorf("query %d: the rule was removed from the live list", i+1)
			}
		}
		oneWarning(t, log, "slow DNSBL_Regex regex [ F#0 ]")
	})
	t.Run("block band scan keeps a rule measured over the old evict ceiling", func(t *testing.T) {
		log := evCaptureLog(t)
		db := slowDB()
		cfg := evCfg()
		cfg.regexDB = true
		cfg.regex.timedSearch = evScripted(t, slowMs, slowMs)
		for i := range 2 {
			band, meta := scanBlockBand("slow.example", cfg, nil, nil, db, nil)
			if band != PRIO_FEED_BLOCK || meta == nil || meta.kind != "regex" || meta.key != "F#0" {
				t.Errorf("scan %d: got (%d, %s), want (1, regex F#0)", i+1, band, evMeta(meta))
			}
		}
		oneWarning(t, log, "slow DNSBL_Regex regex [ F#0 ]")
	})
	t.Run("allow scan keeps a rule measured over the old evict ceiling", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		rt.timedSearch = evScripted(t, slowMs, slowMs)
		db := evRegexDB(evRx("A#0", `slow\.example$`, PRIO_FEED_ALLOW))
		for i := range 2 {
			if got := scanAllowRegexBand(rt, "slow.example", db, nil, 10.0); got != PRIO_FEED_ALLOW {
				t.Errorf("scan %d: band = %d, want %d", i+1, got, PRIO_FEED_ALLOW)
			}
		}
		oneWarning(t, log, "slow DNSBL_AllowRegex regex [ A#0 ]")
	})
	t.Run("a rule over the warn ceiling is warned once and still blocks", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := evCfg()
		cfg.regexDB = true
		cfg.regex.timedSearch = evScripted(t, 20.0)
		got := evEval("slow.example", "example", false, cfg, matcherContainers{regexDB: slowDB()})
		if !got.isFound || got.group != "DNSBL_Regex" {
			t.Errorf("got %+v, want a DNSBL_Regex block", *got)
		}
		oneWarning(t, log, "slow DNSBL_Regex regex [ F#0 ]")
	})
	t.Run("a slow user rule is kept and blocks", func(t *testing.T) {
		evCaptureLog(t)
		user := evRegexDB(evRx("MyUserRegex", `slow\.example$`, PRIO_USER_BLOCK))
		cfg := evCfg()
		cfg.userRegexDB = true
		cfg.regex.timedSearch = evScripted(t, 200.0)
		got := evEval("slow.example", "example", false, cfg, matcherContainers{userRegexDB: user})
		if !got.isFound || got.feed != "MyUserRegex" {
			t.Errorf("got %+v, want a block by MyUserRegex", *got)
		}
		if _, ok := user.get("MyUserRegex"); !ok {
			t.Errorf("the slow user rule was removed from the live list")
		}
	})
	t.Run("a slow rule among many does not disturb the scan", func(t *testing.T) {
		evCaptureLog(t)
		db := &regexDB{}
		for i := range 5 {
			db.set(fmt.Sprintf("P#%d", i), &regexEntry{re: regexp.MustCompile(fmt.Sprintf(`nomatch%d\.x$`, i)), band: 1})
		}
		db.set("SLOW", &regexEntry{re: regexp.MustCompile(`slow\.example$`), band: 1})
		cfg := evCfg()
		cfg.regexDB = true
		cfg.regex.timedSearch = evScripted(t, 1.0, 1.0, 1.0, 1.0, 1.0, 300.0)
		got := evEval("slow.example", "example", false, cfg, matcherContainers{regexDB: db})
		if !got.isFound || got.feed != "SLOW" || db.len() != 6 {
			t.Errorf("got isFound=%v feed=%q with %d rules loaded, want true SLOW 6", got.isFound, got.feed, db.len())
		}
	})
	t.Run("an allow regex under the warn ceiling is silent and kept", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		rt.timedSearch = evScripted(t, 2.0)
		db := evRegexDB(evRx("A#0", `slow\.example$`, PRIO_FEED_ALLOW))
		if got := scanAllowRegexBand(rt, "slow.example", db, nil, 10.0); got != PRIO_FEED_ALLOW {
			t.Errorf("band = %d, want %d", got, PRIO_FEED_ALLOW)
		}
		if log.String() != "" {
			t.Errorf("log = %q, want silence", log.String())
		}
	})
	t.Run("no regex lists, no timing", func(t *testing.T) {
		cfg := evCfg()
		cfg.dataDB = true
		got := evEval("blocked.example", "example", false, cfg, matcherContainers{dataDB: map[string]*blockEntry{"blocked.example": evBlk("1", 0, 1)}})
		if !got.isFound || got.bType != "DNSBL" {
			t.Errorf("got %+v, want a DNSBL block", *got)
		}
	})
	t.Run("a fast regex match blocks and nothing is warned", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := evCfg()
		cfg.regexDB = true
		cfg.regex.timedSearch = evScripted(t, 0.5)
		if got := evEval("slow.example", "example", false, cfg, matcherContainers{regexDB: slowDB()}); !got.isFound {
			t.Errorf("isFound = false, want a block")
		}
		if log.String() != "" || len(cfg.regex.warned) != 0 {
			t.Errorf("log = %q, warned = %v, want silence and an empty set", log.String(), cfg.regex.warned)
		}
	})
}

// test_adr07_regex_safety.py TestSlowListScanIsReported (the evaluate_domain and scan rows); the rebuild_and_swap re-arm
// is regexRuntime.reset, which swap calls.
func TestSlowListScanIsReported(t *testing.T) {
	discover := func(cfg evaluateConfig, c matcherContainers) *dnsblDecision {
		return evEval("slow.example", "example", false, cfg, c)
	}
	feedCfg := func() evaluateConfig { c := evCfg(); c.regexDB = true; return c }

	t.Run("a discovery scan over the ceiling in total logs one line for its list", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		c := matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{3, 4, 5}, -1)}
		if discover(cfg, c).isFound {
			t.Errorf("isFound = true, want no match")
		}
		if got, want := log.String(), evListLine("DNSBL_Regex", "12.0", 3, "F#2", "5.0"); got != want {
			t.Errorf("log = %q, want %q", got, want)
		}
		before := log.String()
		discover(cfg, c)
		if log.String() != before {
			t.Errorf("a second query over the same list wrote %q, want nothing", strings.TrimPrefix(log.String(), before))
		}
	})
	for _, row := range []struct {
		name string
		ms   []float64
	}{{"under the ceiling in total is silent", []float64{3, 3, 3}}, {"summing exactly to the ceiling is silent", []float64{5, 5}}} {
		t.Run("a list scan "+row.name, func(t *testing.T) {
			log := evCaptureLog(t)
			cfg := feedCfg()
			m := newEvMeasured(cfg.regex)
			discover(cfg, matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, row.ms, -1)})
			if log.String() != "" {
				t.Errorf("log = %q, want silence", log.String())
			}
		})
	}
	t.Run("a scan that stops on its first match still counts what it timed", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		if got := discover(cfg, matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{6, 7, 9}, 1)}); got.feed != "F#1" {
			t.Errorf("feed = %q, want F#1", got.feed)
		}
		if got, want := log.String(), evListLine("DNSBL_Regex", "13.0", 2, "F#1", "7.0"); got != want {
			t.Errorf("log = %q, want %q", got, want)
		}
	})
	t.Run("the block band re-scan reports the same list once", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		db := m.db("F", PRIO_FEED_BLOCK, []float64{3, 4, 5}, -1)
		if band, meta := scanBlockBand("slow.example", cfg, nil, nil, db, nil); band != 0 || meta != nil {
			t.Errorf("got (%d, %s), want (0, nil)", band, evMeta(meta))
		}
		want := evListLine("DNSBL_Regex", "12.0", 3, "F#2", "5.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
		scanBlockBand("slow.example", cfg, nil, nil, db, nil)
		if log.String() != want {
			t.Errorf("the second re-scan wrote %q, want nothing", strings.TrimPrefix(log.String(), want))
		}
	})
	t.Run("the discovery scan and the band re-scan share one line per list", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		db := m.db("F", PRIO_FEED_BLOCK, []float64{3, 4, 5}, -1)
		discover(cfg, matcherContainers{regexDB: db})
		scanBlockBand("slow.example", cfg, nil, nil, db, nil)
		if got := strings.Count(log.String(), "regex list scan took"); got != 1 {
			t.Errorf("list lines = %d, want 1; log:\n%s", got, log.String())
		}
	})
	t.Run("the allow scan reports its own list", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		m := newEvMeasured(rt)
		db := m.db("A", PRIO_FEED_ALLOW, []float64{3, 4, 5}, -1)
		if got := scanAllowRegexBand(rt, "slow.example", db, nil, 10.0); got != 0 {
			t.Errorf("band = %d, want 0", got)
		}
		want := evListLine("DNSBL_AllowRegex", "12.0", 3, "A#2", "5.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
		scanAllowRegexBand(rt, "slow.example", db, nil, 10.0)
		if log.String() != want {
			t.Errorf("the second scan wrote %q, want nothing", strings.TrimPrefix(log.String(), want))
		}
	})
	t.Run("the block and allow lists are reported separately", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		scanBlockBand("slow.example", cfg, nil, nil, m.db("F", PRIO_FEED_BLOCK, []float64{3, 4, 5}, -1), nil)
		scanAllowRegexBand(cfg.regex, "slow.example", m.db("A", PRIO_FEED_ALLOW, []float64{3, 5, 4}, -1), nil, 10.0)
		want := evListLine("DNSBL_Regex", "12.0", 3, "F#2", "5.0") + evListLine("DNSBL_AllowRegex", "12.0", 3, "A#1", "5.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
	t.Run("a swap re-arms the list report", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		c := matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{3, 4, 5}, -1)}
		discover(cfg, c)
		discover(cfg, c)
		if got := strings.Count(log.String(), "regex list scan took"); got != 1 {
			t.Errorf("list lines before the swap = %d, want 1", got)
		}
		cfg.regex.reset()
		discover(cfg, c)
		if got := strings.Count(log.String(), "regex list scan took"); got != 2 {
			t.Errorf("list lines after the swap = %d, want 2", got)
		}
	})
	t.Run("a rule over the ceiling still gets its own line besides the list line", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		discover(cfg, matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{20}, -1)})
		want := evRuleLine("DNSBL_Regex", "F#0", "20.0") + evListLine("DNSBL_Regex", "20.0", 1, "F#0", "20.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
	t.Run("same-named rules of different lists warn independently", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := evCfg()
		cfg.regexDB, cfg.userRegexDB = true, true
		m := newEvMeasured(cfg.regex)
		discover(cfg, matcherContainers{regexDB: m.db("X", PRIO_FEED_BLOCK, []float64{20}, -1), userRegexDB: m.db("X", PRIO_USER_BLOCK, []float64{20}, -1)})
		scanAllowRegexBand(cfg.regex, "slow.example", m.db("X", PRIO_FEED_ALLOW, []float64{20}, -1), m.db("X", PRIO_USER_ALLOW, []float64{20}, -1), 10.0)
		var got []string
		for _, line := range strings.Split(strings.TrimSuffix(log.String(), "\n"), "\n") {
			if strings.Contains(line, "regex [ X#0 ]") {
				got = append(got, line)
			}
		}
		want := []string{
			evLogPrefix + "[pfBlockerNG]: slow user DNSBL_Regex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
			evLogPrefix + "[pfBlockerNG]: slow DNSBL_Regex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
			evLogPrefix + "[pfBlockerNG]: slow user DNSBL_AllowRegex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
			evLogPrefix + "[pfBlockerNG]: slow DNSBL_AllowRegex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
		}
		if !slices.Equal(got, want) {
			t.Errorf("rule lines:\n got  %q\n want %q", got, want)
		}
	})
	t.Run("every slow rule of one list warns for itself", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := feedCfg()
		m := newEvMeasured(cfg.regex)
		discover(cfg, matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{20, 30}, -1)})
		want := evRuleLine("DNSBL_Regex", "F#0", "20.0") + evRuleLine("DNSBL_Regex", "F#1", "30.0") + evListLine("DNSBL_Regex", "50.0", 2, "F#1", "30.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
	t.Run("the user and the feed block lists report a slow scan separately", func(t *testing.T) {
		log := evCaptureLog(t)
		cfg := evCfg()
		cfg.regexDB, cfg.userRegexDB = true, true
		m := newEvMeasured(cfg.regex)
		got := discover(cfg, matcherContainers{regexDB: m.db("F", PRIO_FEED_BLOCK, []float64{4, 4, 4}, -1), userRegexDB: m.db("U", PRIO_USER_BLOCK, []float64{3, 4, 5}, -1)})
		if got.isFound {
			t.Errorf("isFound = true, want no match")
		}
		want := evListLine("user DNSBL_Regex", "12.0", 3, "U#2", "5.0") + evListLine("DNSBL_Regex", "12.0", 3, "F#0", "4.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
	t.Run("the user and the feed allow lists report a slow scan separately", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		m := newEvMeasured(rt)
		feed := m.db("A", PRIO_FEED_ALLOW, []float64{3, 5, 4}, -1)
		user := m.db("UA", PRIO_USER_ALLOW, []float64{3, 4, 5}, -1)
		if got := scanAllowRegexBand(rt, "slow.example", feed, user, 10.0); got != 0 {
			t.Errorf("band = %d, want 0", got)
		}
		want := evListLine("user DNSBL_AllowRegex", "12.0", 3, "UA#2", "5.0") + evListLine("DNSBL_AllowRegex", "12.0", 3, "A#1", "5.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
}

// test_branch_coverage_gaps.py TestRegexWarnSlowBranches, test_adr07_regex_safety.py (the per-rule line) and oracle rows
// for the "{:.1f}" the two warning lines format with.
func TestRegexWarnSlow(t *testing.T) {
	t.Run("warns once, then skips the re-warn", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		rt.warnSlow("RX", 50.0, REGEX_WARN_MS_DEFAULT, "DNSBL_Regex")
		want := evRuleLine("DNSBL_Regex", "RX", "50.0")
		if log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
		rt.warnSlow("RX", 50.0, REGEX_WARN_MS_DEFAULT, "DNSBL_Regex")
		if log.String() != want {
			t.Errorf("the re-warn wrote %q, want nothing", strings.TrimPrefix(log.String(), want))
		}
	})
	t.Run("a match at or under the warn ceiling is silent", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		rt.warnSlow("RX", REGEX_WARN_MS_DEFAULT, REGEX_WARN_MS_DEFAULT, "DNSBL_Regex")
		if log.String() != "" || len(rt.warned) != 0 {
			t.Errorf("log = %q, warned = %v, want silence and an empty set", log.String(), rt.warned)
		}
	})
	t.Run("the warning names the list, the rule and both times", func(t *testing.T) {
		log := evCaptureLog(t)
		newRegexRuntime().warnSlow("RX#7", 123.4, 10.0, "DNSBL_AllowRegex")
		if want := evLogPrefix + "[pfBlockerNG]: slow DNSBL_AllowRegex regex [ RX#7 ] took 123.4 ms (warn ceiling 10.0 ms)\n"; log.String() != want {
			t.Errorf("log = %q, want %q", log.String(), want)
		}
	})
	t.Run("reset re-arms the warning of a rule", func(t *testing.T) {
		log := evCaptureLog(t)
		rt := newRegexRuntime()
		rt.warnSlow("X", 20.0, 10.0, "L")
		rt.warnSlow("X", 20.0, 10.0, "L")
		if got := strings.Count(log.String(), "regex [ X ]"); got != 1 {
			t.Errorf("lines before reset = %d, want 1", got)
		}
		rt.reset()
		rt.warnSlow("X", 20.0, 10.0, "L")
		if got := strings.Count(log.String(), "regex [ X ]"); got != 2 {
			t.Errorf("lines after reset = %d, want 2; log:\n%s", got, log.String())
		}
	})
	// oracle: "{:.1f}".format(ms) of Python, which Go's %.1f must equal (both round the exact binary value half-to-even).
	for _, row := range []struct {
		ms   float64
		want string
	}{
		{0.05, "0.1"}, {0.15, "0.1"}, {0.25, "0.2"}, {2.675, "2.7"}, {10.05, "10.1"}, {12.25, "12.2"}, {1e-05, "0.0"},
		{123456.789, "123456.8"}, {9.95, "9.9"}, {99.95, "100.0"}, {1.005, "1.0"}, {150.0, "150.0"},
	} {
		log := evCaptureLog(t)
		newRegexRuntime().warnSlow("R", row.ms, -1, "L")
		if want := evLogPrefix + fmt.Sprintf("[pfBlockerNG]: slow L regex [ R ] took %s ms (warn ceiling -1.0 ms)\n", row.want); log.String() != want {
			t.Errorf("ms %v: log = %q, want %q", row.ms, log.String(), want)
		}
	}
}

// test_branch_coverage_gaps.py TestRegexTimedSearchFallback: the timer still returns the match and a non-negative time.
func TestRegexTimedSearch(t *testing.T) {
	if matched, ms := regexTimedSearch(regexp.MustCompile("evil"), "evil.com"); !matched || ms < 0 {
		t.Errorf("got (%v, %v), want (true, a non-negative time)", matched, ms)
	}
	if matched, ms := regexTimedSearch(regexp.MustCompile("evil"), "good.com"); matched || ms < 0 {
		t.Errorf("got (%v, %v), want (false, a non-negative time)", matched, ms)
	}
}

// The warned set is shared by every concurrent query of a module: a rule warns once however many queries trip it at
// the same moment, and concurrent evaluations through one runtime are race-free (go test -race).
func TestRegexRuntimeConcurrentQueries(t *testing.T) {
	log := evCaptureLog(t)
	rt := newRegexRuntime()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rt.warnSlow("RX", 50.0, 10.0, "DNSBL_Regex")
		}()
	}
	wg.Wait()
	if got := strings.Count(log.String(), "slow DNSBL_Regex regex [ RX ]"); got != 1 {
		t.Errorf("warnings = %d, want exactly 1; log:\n%s", got, log.String())
	}

	cfg := evCfg()
	cfg.regexDB, cfg.userRegexDB, cfg.importantRules = true, true, true
	c := matcherContainers{
		regexDB:     evRegexDB(evRx("F#0", `^(?:slow\.example|zz)$`, PRIO_FEED_BLOCK)),
		userRegexDB: evRegexDB(evRx("U#0", `^(?:slow\.example|zz)$`, PRIO_USER_BLOCK)),
	}
	cfg.regex.timedSearch = func(re *regexp.Regexp, qName string) (bool, float64) { return re.MatchString(qName), 20.0 }
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := evEval("slow.example", "example", false, cfg, c); !got.isFound || got.feed != "U#0" {
				t.Errorf("got %+v, want the user rule U#0", *got)
			}
		}()
	}
	wg.Wait()
	for _, name := range []string{"slow user DNSBL_Regex regex [ U#0 ]", "slow DNSBL_Regex regex [ F#0 ]"} {
		if got := strings.Count(log.String(), name); got > 1 {
			t.Errorf("%q written %d times, want at most once", name, got)
		}
	}
}

func evSnapshot(settings *pfbSettings) *snapshot {
	snap := newSnapshot()
	snap.settings = settings
	return snap
}

func evCfgDiff(got, want evaluateConfig) string {
	if !slices.Equal(got.tldAllowList, want.tldAllowList) {
		return fmt.Sprintf("tldAllowList = %q, want %q", got.tldAllowList, want.tldAllowList)
	}
	if !slices.Equal(got.hstsTlds, want.hstsTlds) {
		return fmt.Sprintf("hstsTlds = %q, want %q", got.hstsTlds, want.hstsTlds)
	}
	got.tldAllowList, want.tldAllowList, got.hstsTlds, want.hstsTlds = nil, nil, nil, nil
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("\n got  %+v\n want %+v", got, want)
	}
	return ""
}

// _evaluate_cfg: the presence gates and important_rules come from the snapshot, the remaining keys from the snapshot's
// settings (never from the pfbUnbound the swap does not refresh), the TLD-Allow list from the snapshot's frozen roots.
func TestEvaluateCfg(t *testing.T) {
	m := &pfbUnbound{regexRuntime: newRegexRuntime()}
	m.pfb.pythonBlocking = false // a swap does not refresh this; the snapshot's settings decide
	settings := &pfbSettings{
		pythonBlocking: true, tldAllow: true, tldAllowList: []string{"com"}, dnsblIpv4: "10.0.0.1", dnsblIpv6: "fd00::1",
		pythonIdn: true, idnMode: IdnModeConfusable, pythonIdnBlockMalicious: false, pythonIdnEscalateSuspicious: true,
		regexWarnMs: 7.5, pythonTldSeg: 3, hstsTlds: []string{"app"},
	}
	snap := evSnapshot(settings)
	snap.dataDB = map[string]*blockEntry{"evil.com": evBlk("1", 0, 1)}
	snap.whiteDB = map[string]whiteEntry{"ok.com": evLegacyWhite(false)}
	snap.regexDB = evRegexDB(evRx("F#0", "x", 1))
	snap.userRegexDB = evRegexDB(evRx("U#0", "x", 5))
	snap.hstsDB = map[string]struct{}{"evil.com": {}}
	snap.importantRules, snap.builtinLogFlag = true, "1"
	snap.hasTldAllowRoots, snap.tldAllowRoots = true, []string{"io"}

	want := evaluateConfig{
		pythonBlocking: true, dataDB: true, zoneDB: false, tldAllow: true, tldAllowList: []string{"io"},
		dnsblIpv4: "10.0.0.1", dnsblIpv6: "fd00::1", pythonIdn: true, idnMode: IdnModeConfusable,
		pythonIdnBlockMalicious: false, pythonIdnEscalateSuspicious: true,
		regexDB: true, whiteDB: true, allowRegexDB: false, userRegexDB: true, userAllowRegexDB: false,
		importantRules: true, regexWarnMs: 7.5, pythonTldSeg: 3, hstsDB: true, hstsTlds: []string{"app"},
		builtinLogFlag: "1", regex: m.regexRuntime,
	}
	if diff := evCfgDiff(m.evaluateCfg(snap), want); diff != "" {
		t.Errorf("evaluateCfg: %s", diff)
	}

	// test_adr07_regex_safety.py TestNoRuntimeEviction: the cfg carries the settings' warn ceiling.
	if got := m.evaluateCfg(snap).regexWarnMs; got != settings.regexWarnMs {
		t.Errorf("regexWarnMs = %v, want %v", got, settings.regexWarnMs)
	}
}

// _evaluate_cfg, ADR-10: a swap that introduces a stratum opens its gate; the gates are read off the snapshot, not the
// settings.
func TestEvaluateCfgGatesFollowTheSnapshot(t *testing.T) {
	m := &pfbUnbound{regexRuntime: newRegexRuntime()}
	settings := &pfbSettings{pythonBlocking: true}
	empty := evSnapshot(settings)
	if cfg := m.evaluateCfg(empty); cfg.dataDB || cfg.zoneDB || cfg.whiteDB || cfg.regexDB || cfg.allowRegexDB || cfg.userRegexDB || cfg.userAllowRegexDB || cfg.hstsDB || cfg.importantRules {
		t.Errorf("an empty snapshot: got gates %+v, want all off", cfg)
	}
	swapped := evSnapshot(settings)
	swapped.zoneDB = map[string]*blockEntry{"evil.com": evBlk("1", 0, 1)}
	swapped.allowRegexDB = evRegexDB(evRx("A#0", "x", 2))
	swapped.userAllowRegexDB = evRegexDB(evRx("UA#0", "x", 6))
	cfg := m.evaluateCfg(swapped)
	if !cfg.zoneDB || !cfg.allowRegexDB || !cfg.userAllowRegexDB || cfg.dataDB || cfg.regexDB {
		t.Errorf("a swapped-in stratum: got gates zone=%v allowRegex=%v userAllowRegex=%v data=%v regex=%v, want true true true false false",
			cfg.zoneDB, cfg.allowRegexDB, cfg.userAllowRegexDB, cfg.dataDB, cfg.regexDB)
	}
}

// _evaluate_cfg: idn_mode is the stored mode unless it is absent, then the legacy python_idn (the explicit Off is not
// bypassed, ADR-28); tld_allow_list is the snapshot's frozen roots, else the settings' list normalised.
func TestEvaluateCfgIdnModeAndTldRoots(t *testing.T) {
	m := &pfbUnbound{regexRuntime: newRegexRuntime()}
	for _, row := range []struct {
		name      string
		mode      IdnMode
		pythonIdn bool
		want      IdnMode
	}{
		{"absent, python_idn on", "", true, IdnModeAll},
		{"absent, python_idn off", "", false, IdnModeOff},
		{"off wins over python_idn on", IdnModeOff, true, IdnModeOff},
		{"confusable is kept", IdnModeConfusable, false, IdnModeConfusable},
	} {
		if got := m.evaluateCfg(evSnapshot(&pfbSettings{idnMode: row.mode, pythonIdn: row.pythonIdn})).idnMode; got != row.want {
			t.Errorf("idn_mode %s: got %q, want %q", row.name, got, row.want)
		}
	}

	// oracle: _selected_tld_roots(pfb["tld_allow_list"]) for a snapshot that carries no frozen roots.
	for _, row := range []struct {
		list []string
		want []string
	}{
		{[]string{"com"}, []string{"com"}},
		{[]string{" .COM.", "com", "Net"}, []string{"com", "net"}},
		{[]string{"", ".", " "}, nil},
		{[]string{"io", ".IO", "example.COM."}, []string{"io", "example.com"}},
		{nil, nil},
	} {
		if got := m.evaluateCfg(evSnapshot(&pfbSettings{tldAllowList: row.list})).tldAllowList; !slices.Equal(got, row.want) {
			t.Errorf("tld_allow_list %q: got %q, want %q", row.list, got, row.want)
		}
	}

	// test_psl_runtime_integration.py: a snapshot with frozen (even empty) roots ignores a later global selection;
	// a legacy snapshot without them has empty roots for the matcher.
	rules, err := parsePslRules(evPSL)
	if err != nil {
		t.Fatal(err)
	}
	settings := &pfbSettings{tldAllow: true, tldAllowList: []string{"com"}}
	frozen := evSnapshot(settings)
	frozen.pslRules, frozen.hasTldAllowRoots = rules, true
	cfg := m.evaluateCfg(frozen)
	if len(cfg.tldAllowList) != 0 {
		t.Errorf("frozen empty roots: tldAllowList = %q, want empty", cfg.tldAllowList)
	}
	if got := evaluateDomain("x.example.net", "x.example.net", "net", false, cfg, frozen.containers()); got.isFound {
		t.Errorf("frozen empty roots: x.example.net is blocked, want it to resolve")
	}

	legacy := evSnapshot(&pfbSettings{tldAllow: true})
	legacy.pslRules = rules
	if len(legacy.tldAllowRoots) != 0 || legacy.hasTldAllowRoots {
		t.Fatalf("a legacy snapshot has no frozen roots")
	}
	if got := evaluateDomain("x.example.net", "x.example.net", "net", false, m.evaluateCfg(legacy), legacy.containers()); got.isFound {
		t.Errorf("legacy snapshot roots: x.example.net is blocked, want it to resolve")
	}
}

// test_pfb_unbound.py TestGetTld. The qname list carries the trailing root label, so the TLD is [-2].
func TestGetTld(t *testing.T) {
	qstateOf := func(qname string) *moduleQstate {
		return newModuleQstate(queryInfo{qnameStr: qname, qtype: 1, qclass: 1}, "192.0.2.1", 5300, 0, "UDP", "", "")
	}
	for _, row := range []struct{ name, qname, want string }{
		{"multilabel", "sub.example.com.", "com"},
		{"a bare-TLD query", "com.", "com"},
		{"the root query has no TLD", ".", ""},
		{"a mixed-case wire label is lowercased (#720)", "sub.ExAmPlE.CoM.", "com"},
		{"oracle: a non-ASCII label is lowercased like str.lower", "ünï.CÖM.", "cöm"},
	} {
		if got := getTld(qstateOf(row.qname)); got != row.want {
			t.Errorf("%s: getTld(%q) = %q, want %q", row.name, row.qname, got, row.want)
		}
	}
	if got := getTld(nil); got != "" {
		t.Errorf("a nil qstate: getTld = %q, want empty", got)
	}

	// Issue #328: a label that is not UTF-8 makes the qname list raise; get_tld swallows it, logs, and returns "".
	log := evCaptureLog(t)
	if got := getTld(qstateOf(`\255.example.`)); got != "" {
		t.Errorf("an invalid UTF-8 qname: getTld = %q, want empty", got)
	}
	if !strings.HasPrefix(log.String(), evLogPrefix+"[pfBlockerNG]: Failed get_tld: ") || strings.Count(log.String(), "\n") != 1 {
		t.Errorf("log = %q, want one \"[pfBlockerNG]: Failed get_tld: ...\" line", log.String())
	}
}

// test_pfb_unbound.py TestGetTldFromName plus oracle rows: the last label of the dot-split name, lowercased.
func TestGetTldFromName(t *testing.T) {
	for _, row := range []struct{ name, want string }{
		{"sub.example.com", "com"},
		{"evil.net", "net"},
		{"evil.net.", "net"},
		{"com", ""},
		{"", ""},
		{"sub.ExAmPlE.CoM", "com"},
		{".", ""},
		{"a..b", "b"},
		{"a.b..", "b"},
		{"ünï.CÖM", "cöm"},
	} {
		if got := getTldFromName(row.name); got != row.want {
			t.Errorf("getTldFromName(%q) = %q, want %q", row.name, got, row.want)
		}
	}
}
