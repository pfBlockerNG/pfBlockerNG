// Tests for the Go translation of pfb_unbound.py's module config read (init_standard up to the rcodeDB block,
// parse_tld_allow, _parse_ini_int, _load_ini_config, IdnMode) and its operate() skeleton. They mirror
// tests/test_pfb_unbound.py (TestParseTldAllow, TestParseIniInt, TestFeedSuffixPolicyIniRead) and
// tests/test_adr28_cfg_adapters.py (the idn_mode truth table); the expected values are the Python source's.
package decider

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func modCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	previous := logOutput
	logOutput = &out
	t.Cleanup(func() { logOutput = previous })
	return &out
}

// modIniDir is a fresh module directory holding the given pfb_unbound.ini.
func modIniDir(t *testing.T, ini string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func modMust(t *testing.T, dir string) *pfbUnbound {
	t.Helper()
	m, err := initStandard(MODULE_ID, dir, testLogDir)
	if err != nil || m == nil {
		t.Fatalf("initStandard(%q) = (%v, %v), want a module and nil", dir, m, err)
	}
	stopModule(t, m)
	return m
}

// modMain boots a module whose ini holds only a [MAIN] section with the given lines.
func modMain(t *testing.T, lines ...string) *pfbUnbound {
	t.Helper()
	return modMust(t, modIniDir(t, "[MAIN]\n"+strings.Join(lines, "\n")+"\n"))
}

// modDefaults is what init_standard sets before any ini key is read, typed out from pfb_unbound.py lines
// 1643-1840 (zero values are the Python False / "" / 0 defaults).
func modDefaults(dir string) pfbSettings {
	in := func(name string) string { return filepath.Join(dir, name) }
	return pfbSettings{
		idnMode:                 IdnModeOff,
		pythonIdnBlockMalicious: true,
		pslIncludePrivate:       true,
		pslFeedPrivatePolicy:    "honor",
		pslFeedIcannPolicy:      "honor",
		regexWarnMs:             10.0,
		decisiondbMax:           10000,

		pfbUnboundIni:       in("pfb_unbound.ini"),
		pfbPyWhitelist:      in("pfb_py_whitelist.txt"),
		pfbPyZone:           in("pfb_py_zone.txt"),
		pfbPyData:           in("pfb_py_data.txt"),
		pfbPyHsts:           in("pfb_py_hsts.txt"),
		pfbPyTop1m:          in("pfb_py_top1m.txt"),
		pfbPyPsl:            in("dnsbl_psl"),
		pfbPySs:             in("pfb_py_ss.txt"),
		pfbPySources:        in("pfb_py_sources.json"),
		pfbPyReload:         in("pfb_py_reload"),
		pfbPyReloadApplied:  in("pfb_py_reload.applied"),
		pfbPyControl:        in("pfb_py_control"),
		pfbPyControlApplied: in("pfb_py_control.applied"),
		pfbPyQuery:          in("pfb_py_query"),
		pfbPyQueryReply:     in("pfb_py_query.reply"),
		pfbPyCount:          in("pfb_py_count"),
		pfbPyRegexCount:     in("pfb_py_regex_count"),
		pfbPyRejectStats:    in("pfb_py_reject_stats.json"),
		pfbPyStatus:         in("pfb_py_status.json"),
		pfbPyDnsbl:          in("pfb_py_dnsbl.sqlite"),
		pfbPyResolver:       in("pfb_py_resolver.sqlite"),

		rrTypes: []uint16{1, 28, 255, 5, 39, 24, 15, 2, 12, 33, 16, 64, 65},
		hstsTlds: []string{
			"android", "app", "bank", "chrome", "dev", "foo", "gle", "gmail", "google",
			"hangout", "insurance", "meet", "new", "page", "play", "search", "youtube",
		},
	}
}

// modDiff reports every pfb field that differs, by name; an empty slice equals a nil one.
func modDiff(t *testing.T, what string, got, want pfbSettings) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range g.NumField() {
		gf, wf := g.Field(i), w.Field(i)
		if gf.Kind() == reflect.Slice && gf.Len() == 0 && wf.Len() == 0 {
			continue
		}
		if fmt.Sprintf("%#v", gf) != fmt.Sprintf("%#v", wf) {
			t.Errorf("%s: pfb.%s = %#v, want %#v", what, g.Type().Field(i).Name, gf, wf)
		}
	}
}

func TestParseTldAllow(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"", nil},    // issue #713: an empty value is [], not ['']
		{"   ", nil}, // whitespace only
		{"com, net ,org", []string{"com", "net", "org"}},
		{"CoM, LOCAL", []string{"com", "local"}}, // issue #720: lower-cased
		{",,com,, ,net,", []string{"com", "net"}},
	} {
		if got := parseTldAllow(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("parseTldAllow(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseIniInt(t *testing.T) {
	c := cfgParse(t, "[MAIN]\nok = 3\nneg = -4\nbad = not-an-int\nfloat = 1.5\npct = 5%\n")
	for _, tc := range []struct {
		option  string
		want    int
		wantOk  bool
		wantErr bool
	}{
		{"ok", 3, true, false},
		{"neg", -4, true, false},
		{"bad", 0, false, false},   // a ValueError is swallowed: the caller keeps its default
		{"float", 0, false, false}, // int("1.5") is a ValueError too
		{"pct", 0, false, true},    // an interpolation error is not a ValueError: it escapes, as in Python
	} {
		got, ok, err := parseIniInt(c, "MAIN", tc.option)
		if ok != tc.wantOk || (err != nil) != tc.wantErr || (ok && int64(got) != int64(tc.want)) {
			t.Errorf("parseIniInt(%s) = (%d, %v, %v), want (%d, %v, error=%v)", tc.option, got, ok, err, tc.want, tc.wantOk, tc.wantErr)
		}
	}
}

// decisiondb_max is a Python int; past the build's int range the LRU cap saturates instead of wrapping.
func TestIntOfKeepsTheValueOrSaturates(t *testing.T) {
	for _, c := range []struct{ in, want int64 }{
		{5, 5}, {-5, -5}, {0, 0},
		{4294967296, min(4294967296, math.MaxInt)},
		{math.MaxInt64, math.MaxInt}, {math.MinInt64, math.MinInt},
	} {
		if got := intOf(c.in); int64(got) != c.want {
			t.Errorf("intOf(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIdnModeFromLegacy(t *testing.T) {
	if got := idnModeFromLegacy(true); got != IdnModeAll {
		t.Errorf("idnModeFromLegacy(true) = %q, want %q", got, IdnModeAll)
	}
	if got := idnModeFromLegacy(false); got != IdnModeOff {
		t.Errorf("idnModeFromLegacy(false) = %q, want %q: Confusable cannot arise from the legacy flag", got, IdnModeOff)
	}
	for mode, token := range map[IdnMode]string{IdnModeAll: "on", IdnModeConfusable: "confusable", IdnModeOff: "off"} {
		if string(mode) != token {
			t.Errorf("IdnMode backing value = %q, want %q (the canonical ini token)", string(mode), token)
		}
	}
	if IDN_MODE_OFF != "off" || IDN_MODE_ALL != "on" || IDN_MODE_CONFUSABLE != "confusable" {
		t.Errorf("IDN_MODE_* = (%q, %q, %q), want (off, on, confusable)", IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE)
	}
}

// The 14 ini-value x python_idn rows of test_adr28_cfg_adapters.py, plus case folding.
func TestInitStandardIdnModeTruthTable(t *testing.T) {
	for _, tc := range []struct {
		iniValue  string
		present   bool
		pythonIdn bool
		want      IdnMode
	}{
		{"off", true, true, IdnModeOff}, {"off", true, false, IdnModeOff},
		{"on", true, true, IdnModeAll}, {"on", true, false, IdnModeAll},
		{"confusable", true, true, IdnModeConfusable}, {"confusable", true, false, IdnModeConfusable},
		{"all", true, true, IdnModeAll}, {"all", true, false, IdnModeOff}, // the dropped alpha token falls back to python_idn
		{"bogus", true, true, IdnModeAll}, {"bogus", true, false, IdnModeOff},
		{"", true, true, IdnModeOff}, {"", true, false, IdnModeOff}, // present empty is an explicit Off
		{"", false, true, IdnModeAll}, {"", false, false, IdnModeOff}, // absent falls back to python_idn
		{"CONFUSABLE", true, false, IdnModeConfusable}, {"ON", true, false, IdnModeAll}, {"Off", true, true, IdnModeOff},
	} {
		lines := []string{"python_enable = false", fmt.Sprintf("python_idn = %v", tc.pythonIdn)}
		if tc.present {
			lines = append(lines, "idn_mode = "+tc.iniValue)
		}
		if got := modMain(t, lines...).pfb.idnMode; got != tc.want {
			t.Errorf("idn_mode=%q (present=%v) python_idn=%v: idnMode = %q, want %q", tc.iniValue, tc.present, tc.pythonIdn, got, tc.want)
		}
	}
}

func TestInitStandardPslFeedPolicies(t *testing.T) {
	read := func(options ...string) (string, string) {
		m := modMain(t, options...)
		return m.pfb.pslFeedPrivatePolicy, m.pfb.pslFeedIcannPolicy
	}
	check := func(what string, private, icann, wantPrivate, wantIcann string) {
		t.Helper()
		if private != wantPrivate || icann != wantIcann {
			t.Errorf("%s: (private, icann) = (%q, %q), want (%q, %q)", what, private, icann, wantPrivate, wantIcann)
		}
	}
	private, icann := read("python_enable = false")
	check("absent options default to honor", private, icann, "honor", "honor")
	for _, value := range []string{"ignore", "apex", "honor"} {
		private, icann = read("psl_feed_private_policy = "+value, "psl_feed_icann_policy = "+value)
		check("canonical value "+value, private, icann, value, value)
	}
	private, icann = read("psl_feed_private_policy = ignore", "psl_feed_icann_policy = apex")
	check("independent per section", private, icann, "ignore", "apex")
	private, icann = read("psl_feed_private_policy =", "psl_feed_icann_policy =")
	check("empty value", private, icann, "honor", "honor")
	private, icann = read("psl_feed_private_policy = BOGUS", "psl_feed_icann_policy = also-bogus")
	check("garbage value", private, icann, "honor", "honor")
	private, icann = read("psl_feed_private_policy = APEX", "psl_feed_icann_policy = IGNORE")
	check("upper-case canonical value is case-folded", private, icann, "apex", "ignore")
	// str.lower() maps U+0130 to "i" plus U+0307, so "İgnore" is no policy word in Python and falls back to honor.
	private, icann = read("psl_feed_private_policy = \u0130gnore", "psl_feed_icann_policy = \u0130GNORE")
	check("dotted capital I is not an i", private, icann, "honor", "honor")
}

// loadIni is loadIniConfig for the ini at path, on a module that has no other state.
func loadIni(path string) *configParser {
	m := &pfbUnbound{}
	m.pfb.pfbUnboundIni = path
	return m.loadIniConfig()
}

func TestLoadIniConfig(t *testing.T) {
	dir := t.TempDir()
	logs := modCaptureLog(t)
	if c := loadIni(filepath.Join(dir, "absent.ini")); c != nil {
		t.Errorf("loadIniConfig(absent file) = %v, want nil", c)
	}
	if c := loadIni(dir); c != nil {
		t.Errorf("loadIniConfig(directory) = %v, want nil: os.path.isfile is false for a directory", c)
	}
	if logs.Len() != 0 {
		t.Errorf("an absent ini logs %q, want nothing: the caller logs the missing file", logs.String())
	}

	good := filepath.Join(dir, "good.ini")
	if err := os.WriteFile(good, []byte("[MAIN]\nk = v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := loadIni(good); c == nil || !c.hasOption("MAIN", "k") || logs.Len() != 0 {
		t.Errorf("loadIniConfig(good) = (%v, log %q), want a config holding MAIN.k and no log", c, logs.String())
	}

	// A failed read still yields the (partially) read config and one stderr line.
	for _, tc := range []struct {
		name, content, wantLog string
		wantKept               bool
	}{
		{"garbage line", "[MAIN]\na = 1\ngarbage\nb = 2\n", "parsing errors", true},
		{"no section header", "a = 1\n[MAIN]\nb = 2\n", "no section headers", false},
		{"undecodable bytes", "[MAIN]\na = \xff\n", "utf-8", false},
		{"duplicate option", "[MAIN]\na = 1\na = 2\nb = 3\n", "already exists", true},
	} {
		path := filepath.Join(dir, "bad.ini")
		if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
			t.Fatal(err)
		}
		logs.Reset()
		c := loadIni(path)
		if c == nil {
			t.Errorf("%s: loadIniConfig = nil, want the partially read config", tc.name)
			continue
		}
		if got := logs.String(); !strings.Contains(got, "pfb_dns_proxy error: [pfBlockerNG]: Failed to load ini configuration: ") || !strings.Contains(got, tc.wantLog) || strings.Count(got, "pfb_dns_proxy error:") != 1 || !strings.HasSuffix(got, "\n") {
			t.Errorf("%s: log = %q, want one error line 'Failed to load ini configuration: ...%s...'", tc.name, got, tc.wantLog)
		}
		if kept := c.hasOption("MAIN", "a"); kept != tc.wantKept {
			t.Errorf("%s: hasOption(MAIN, a) = %v, want %v", tc.name, kept, tc.wantKept)
		}
	}
}

func TestInitStandardWithoutAnIniFile(t *testing.T) {
	logs := modCaptureLog(t)
	dir := t.TempDir()
	m := modMust(t, dir)
	modDiff(t, "no ini", m.pfb, modDefaults(dir)) // including dnsbl_ipv6 "": the "::" fallback lives inside the MAIN branch
	if len(m.rcodeDB) != 0 {
		t.Errorf("rcodeDB = %v, want unset: it is only built under a [MAIN] section", m.rcodeDB)
	}
	if want := "pfb_dns_proxy info: [pfBlockerNG]: Failed to load ini configuration. Ini file missing.\n"; logs.String() != want {
		t.Errorf("log = %q, want %q", logs.String(), want)
	}
}

func TestInitStandardIniWithoutAMainSection(t *testing.T) {
	logs := modCaptureLog(t)
	dir := modIniDir(t, "[OTHER]\nk = v\n")
	m := modMust(t, dir)
	modDiff(t, "no [MAIN]", m.pfb, modDefaults(dir))
	if len(m.rcodeDB) != 0 {
		t.Errorf("rcodeDB = %v, want unset without a [MAIN] section", m.rcodeDB)
	}
	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing: the ini exists, it just has no [MAIN]", logs.String())
	}
}

func TestInitStandardEmptyMainSection(t *testing.T) {
	dir := modIniDir(t, "[MAIN]\n")
	m := modMust(t, dir)
	want := modDefaults(dir)
	want.dnsblIpv6 = "::" // pfb_unbound.py 1981: an unset or empty dnsbl_ipv6 becomes "::"
	modDiff(t, "empty [MAIN]", m.pfb, want)
	wantRcodes := map[int]string{
		0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDOMAIN", 4: "NotImp", 5: "Refused", 6: "YXDomain", 7: "YXRRSet",
		8: "NXRRSet", 9: "NotAuth", 10: "NotZone", 11: "DSOTYPENI", 16: "BADVERS", 17: "BADKEY", 18: "BADTIME",
		19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC", 23: "BADCOOKIE",
	}
	if !reflect.DeepEqual(m.rcodeDB, wantRcodes) {
		t.Errorf("rcodeDB = %v, want %v", m.rcodeDB, wantRcodes)
	}
}

type modBoolKey struct {
	key string
	get func(*pfbSettings) bool
	def bool
}

var modBoolKeys = []modBoolKey{
	{"metrics_client_ip", func(p *pfbSettings) bool { return p.metricsClientIp }, false},
	{"python_enable", func(p *pfbSettings) bool { return p.pythonEnable }, false},
	{"python_reply", func(p *pfbSettings) bool { return p.pythonReply }, false},
	{"python_blocking", func(p *pfbSettings) bool { return p.pythonBlocking }, false},
	{"python_hsts", func(p *pfbSettings) bool { return p.pythonHsts }, false},
	{"python_tld_wildcard", func(p *pfbSettings) bool { return p.pythonTldWildcard }, false},
	{"python_idn", func(p *pfbSettings) bool { return p.pythonIdn }, false},
	{"python_idn_block_malicious", func(p *pfbSettings) bool { return p.pythonIdnBlockMalicious }, true},
	{"python_idn_escalate_suspicious", func(p *pfbSettings) bool { return p.pythonIdnEscalateSuspicious }, false},
	{"tld_allow", func(p *pfbSettings) bool { return p.tldAllow }, false},
	{"psl_include_private", func(p *pfbSettings) bool { return p.pslIncludePrivate }, true},
	{"psl_allow_private", func(p *pfbSettings) bool { return p.pslAllowPrivate }, false},
	{"python_nolog", func(p *pfbSettings) bool { return p.pythonNolog }, false},
	{"python_cname", func(p *pfbSettings) bool { return p.pythonCname }, false},
	{"python_control", func(p *pfbSettings) bool { return p.pythonControl }, false},
	{"python_control_legacy", func(p *pfbSettings) bool { return p.pythonControlLegacy }, false},
	{"forwarding", func(p *pfbSettings) bool { return p.forwarding }, false},
	{"regex_cap", func(p *pfbSettings) bool { return p.regexCap }, false},
}

// Each boolean key flips its own setting and no other: a wrong key-to-field mapping fails the row.
func TestInitStandardReadsEveryMainBoolean(t *testing.T) {
	modCaptureLog(t)
	for _, flipped := range modBoolKeys {
		value := "off"
		if !flipped.def {
			value = "on"
		}
		m := modMain(t, flipped.key+" = "+value)
		for _, k := range modBoolKeys {
			want := k.def
			if k.key == flipped.key {
				want = !k.def
			}
			if got := k.get(&m.pfb); got != want {
				t.Errorf("%s = %s: setting %s = %v, want %v", flipped.key, value, k.key, got, want)
			}
		}
	}
}

func TestInitStandardReadsStringIntAndFloatKeys(t *testing.T) {
	dir := modIniDir(t, "[MAIN]\ndnsbl_ipv4 = 10.10.10.1\ndnsbl_ipv6 = 2001:db8::1\npython_tld_seg = 3\ndecisiondb_max = 500\nregex_warn_ms = 2.5\ntld_allow_list = COM, net\n")
	want := modDefaults(dir)
	want.dnsblIpv4 = "10.10.10.1"
	want.dnsblIpv6 = "2001:db8::1"
	want.pythonTldSeg = 3
	want.decisiondbMax = 500
	want.regexWarnMs = 2.5
	want.tldAllowList = []string{"com", "net"}
	modDiff(t, "string, int and float keys", modMust(t, dir).pfb, want)

	// 0 is a valid decisiondb_max (an unbounded cache), and an empty dnsbl_ipv6 falls back to "::".
	m := modMain(t, "decisiondb_max = 0", "dnsbl_ipv6 =")
	if m.pfb.decisiondbMax != 0 || m.pfb.dnsblIpv6 != "::" {
		t.Errorf("(decisiondb_max, dnsbl_ipv6) = (%d, %q), want (0, \"::\")", m.pfb.decisiondbMax, m.pfb.dnsblIpv6)
	}
}

func TestInitStandardMalformedNumbersKeepTheirDefaults(t *testing.T) {
	dir := modIniDir(t, "[MAIN]\npython_tld_seg = abc\ndecisiondb_max = 1.5\nregex_warn_ms = abc\nforwarding = on\n")
	want := modDefaults(dir)
	want.dnsblIpv6 = "::"
	want.forwarding = true // the read went on past the three malformed numbers
	modDiff(t, "malformed numbers", modMust(t, dir).pfb, want)
}

func TestInitStandardWarnsWhenTheLegacyControlTransportIsOn(t *testing.T) {
	const text = "pfb_dns_proxy warning: [pfBlockerNG]: DNSBL Control legacy DNS-TXT transport is enabled. It is deprecated and less " +
		"secure than the CLI and will be removed in a future release; migrate CRON/Scheduler tasks to the 'pfblockerng dnsbl-control' CLI.\n"
	logs := modCaptureLog(t)
	modMain(t, "python_control_legacy = on")
	if logs.String() != text {
		t.Errorf("log with python_control_legacy on = %q, want %q", logs.String(), text)
	}
	for _, line := range []string{"python_control_legacy = off", "python_control = on"} {
		logs.Reset()
		modMain(t, line)
		if logs.Len() != 0 {
			t.Errorf("log with %q = %q, want nothing", line, logs.String())
		}
	}
}

func TestInitStandardDerivesPythonBlacklist(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  bool
	}{
		{"python_idn on", []string{"python_idn = on"}, true},
		{"idn_mode on", []string{"idn_mode = on"}, true},
		{"idn_mode confusable", []string{"idn_mode = confusable"}, true},
		{"idn_mode off but python_idn on", []string{"idn_mode = off", "python_idn = on"}, true},
		{"idn_mode empty, python_idn off", []string{"idn_mode =", "python_idn = off"}, false},
		{"tld_allow with a list", []string{"tld_allow = on", "tld_allow_list = com"}, true},
		{"tld_allow with an empty list", []string{"tld_allow = on", "tld_allow_list ="}, false},
		{"tld_allow with a blank list", []string{"tld_allow = on", "tld_allow_list =  , "}, false}, // issue #713
		{"a list without tld_allow", []string{"tld_allow = off", "tld_allow_list = com"}, false},
		{"nothing enabled", nil, false},
	} {
		m := modMain(t, append([]string{"python_enable = on"}, tc.lines...)...)
		if got := m.pfb.pythonBlacklist; got != tc.want {
			t.Errorf("python_enable on, %s: pythonBlacklist = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The derivation only runs when python_enable is on.
	m := modMain(t, "python_enable = off", "python_idn = on", "tld_allow = on", "tld_allow_list = com")
	if m.pfb.pythonBlacklist {
		t.Errorf("python_enable off: pythonBlacklist = true, want false")
	}
}

func TestInitStandardFailsWhereTheIniReadRaisesInPython(t *testing.T) {
	for _, tc := range []struct{ line, key, want string }{
		{"python_enable = maybe", "python_enable", "Not a boolean: maybe"},
		{"forwarding = 2", "forwarding", "Not a boolean: 2"},
		{"python_idn_block_malicious =", "python_idn_block_malicious", "Not a boolean: "},
		{"python_tld_seg = 5%", "python_tld_seg", "'%' must be followed by '%' or '('"}, // _parse_ini_int only swallows ValueError
		{"decisiondb_max = %(nope)s", "decisiondb_max", "Bad value substitution"},
		{"regex_warn_ms = 5%", "regex_warn_ms", "'%' must be followed by '%' or '('"},
		{"dnsbl_ipv4 = %(nope)s", "dnsbl_ipv4", "Bad value substitution"},
		{"dnsbl_ipv6 = %(nope)s", "dnsbl_ipv6", "Bad value substitution"},
		{"idn_mode = 5%", "idn_mode", "'%' must be followed by '%' or '('"},
		{"tld_allow_list = %q", "tld_allow_list", "'%' must be followed by '%' or '('"},
		{"psl_feed_private_policy = %z", "psl_feed_private_policy", "'%' must be followed by '%' or '('"},
		{"psl_feed_icann_policy = %z", "psl_feed_icann_policy", "'%' must be followed by '%' or '('"},
	} {
		m, err := initStandard(MODULE_ID, modIniDir(t, "[MAIN]\n"+tc.line+"\n"), testLogDir)
		if m != nil || err == nil || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: initStandard = (%v, %v), want (nil, an error naming %q and containing %q)", tc.line, m, err, tc.key, tc.want)
		}
	}
}

func TestInitStandardGoesOnWithAPartiallyReadIni(t *testing.T) {
	logs := modCaptureLog(t)
	m := modMain(t, "python_enable = true", "garbage", "forwarding = on")
	if !m.pfb.pythonEnable || !m.pfb.forwarding {
		t.Errorf("(pythonEnable, forwarding) = (%v, %v), want (true, true): the keys around a bad line are read", m.pfb.pythonEnable, m.pfb.forwarding)
	}
	if got := logs.String(); !strings.Contains(got, "Failed to load ini configuration: ") || !strings.Contains(got, "parsing errors") {
		t.Errorf("log = %q, want the parse failure logged", got)
	}

	logs.Reset()
	dir := modIniDir(t, "k = v\n[MAIN]\npython_enable = true\n")
	m = modMust(t, dir)
	want := modDefaults(dir) // the read stopped at the first line: an empty config, no [MAIN]
	modDiff(t, "ini without a first section header", m.pfb, want)
	if got := logs.String(); !strings.Contains(got, "no section headers") || strings.Contains(got, "Ini file missing") {
		t.Errorf("log = %q, want the missing-header failure and not 'Ini file missing'", got)
	}
}

// pfb_unbound.py keeps its settings in module globals; the Go module keeps them in the value initStandard returns.
func TestTwoBootedModulesShareNoState(t *testing.T) {
	modCaptureLog(t)
	a := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\n"))
	b := modMust(t, modIniDir(t, "[MAIN]\nforwarding = on\n"))
	if !a.pfb.pythonEnable || a.pfb.forwarding || b.pfb.pythonEnable || !b.pfb.forwarding {
		t.Errorf("(a.pythonEnable, a.forwarding, b.pythonEnable, b.forwarding) = (%v, %v, %v, %v), want (true, false, false, true)",
			a.pfb.pythonEnable, a.pfb.forwarding, b.pfb.pythonEnable, b.pfb.forwarding)
	}
	if a.pfb.pfbUnboundIni == b.pfb.pfbUnboundIni {
		t.Errorf("both modules resolve their files to %q, want one per module directory", a.pfb.pfbUnboundIni)
	}
	a.rcodeDB[3] = "changed"
	a.pfb.rrTypes[0] = 9
	a.pfb.hstsTlds[0] = "changed"
	if b.rcodeDB[3] != "NXDOMAIN" || b.pfb.rrTypes[0] != 1 || b.pfb.hstsTlds[0] != "android" {
		t.Errorf("after changing a: b has (rcodeDB[3], rrTypes[0], hstsTlds[0]) = (%q, %d, %q), want (NXDOMAIN, 1, android)",
			b.rcodeDB[3], b.pfb.rrTypes[0], b.pfb.hstsTlds[0])
	}
}

func modQstate(qname string) *moduleQstate {
	return newModuleQstate(queryInfo{qnameStr: qname, qtype: RR_TYPE_A, qclass: RR_CLASS_IN}, "192.0.2.1", 5353, 0, "UDP", "192.0.2.2", "em0")
}

func TestGetQNameQstate(t *testing.T) {
	withReturn := func(qname, returned string) *moduleQstate {
		q := modQstate(qname)
		q.returnMsg = &dnsMsg{qinfo: queryInfo{qnameStr: returned}}
		return q
	}
	for _, tc := range []struct {
		name   string
		qstate *moduleQstate
		want   string
	}{
		{"trailing dot dropped, case kept", modQstate("Example.COM."), "Example.COM"},
		{"no trailing dot", modQstate("example.com"), "example.com"},
		{"every trailing dot dropped", modQstate("a.b.c.."), "a.b.c"},
		{"whitespace is not stripped from a usable name", modQstate(" x. "), " x. "},
		{"the query name wins over the reply's", withReturn("Primary.", "Other."), "Primary"},
		{"empty query name falls back to the reply's", withReturn("", "Back.Example."), "Back.Example"},
		{"blank query name falls back to the reply's", withReturn("   ", "Back.Example."), "Back.Example"},
		{"empty everywhere", withReturn("", ""), "Unknown"},
		{"empty with no reply", modQstate(""), "Unknown"},
		{"the root", modQstate("."), "Unknown"},
		{"no qstate", nil, "Unknown"},
	} {
		if got := getQNameQstate(tc.qstate); got != tc.want {
			t.Errorf("%s: getQNameQstate = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestGetQIpAndIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		qstate   *moduleQstate
		wantAddr string
	}{
		{"an IPv4 client", modQstate("x."), "192.0.2.1"},
		{"an IPv6 client", newModuleQstate(queryInfo{qnameStr: "x."}, "2001:db8::7", 1, 0, "TCP", "", ""), "2001:db8::7"},
		{"no client address", newModuleQstate(queryInfo{qnameStr: "x."}, "", 0, 0, "UDP", "", ""), "Unknown"},
		{"no qstate", nil, "Unknown"},
	} {
		if got := getQIp(tc.qstate); got != tc.wantAddr {
			t.Errorf("%s: getQIp = %q, want %q", tc.name, got, tc.wantAddr)
		}
	}
	if isUnknown("") != "Unknown" || isUnknown("x") != "x" {
		t.Errorf("isUnknown(\"\"), isUnknown(\"x\") = (%q, %q), want (Unknown, x)", isUnknown(""), isUnknown("x"))
	}
}

// pfb_unbound.py 8286-8316: NEW and PASS wait for the module chain, MODDONE finishes, anything else is an error.
func TestPfbUnboundOperateEvents(t *testing.T) {
	logs := modCaptureLog(t)
	m := modMust(t, t.TempDir())
	for _, tc := range []struct {
		name         string
		event, id    int
		wantState    int
		wantBadEvent bool
	}{
		{"NEW", MODULE_EVENT_NEW, 0, MODULE_WAIT_MODULE, false},
		{"PASS", MODULE_EVENT_PASS, 0, MODULE_WAIT_MODULE, false},
		{"NEW in another module slot", MODULE_EVENT_NEW, 3, MODULE_WAIT_MODULE, false},
		{"MODDONE", MODULE_EVENT_MODDONE, 0, MODULE_FINISHED, false},
		{"MODDONE in another module slot", MODULE_EVENT_MODDONE, 7, MODULE_FINISHED, false},
		{"event 9", 9, 0, MODULE_ERROR, true},
		{"event 2", 2, 0, MODULE_ERROR, true},
		{"event 6", 6, 4, MODULE_ERROR, true},
		{"a negative event", -1, 0, MODULE_ERROR, true},
	} {
		logs.Reset()
		qstate := modQstate("Example.COM.")
		if !m.operate(tc.id, tc.event, qstate, nil) {
			t.Errorf("%s: operate returned false, want true", tc.name)
		}
		var want [16]int
		want[tc.id] = tc.wantState
		if qstate.extState != want {
			t.Errorf("%s: extState = %v, want %v: only slot %d changes", tc.name, qstate.extState, want, tc.id)
		}
		if qstate.returnMsg != nil || qstate.returnRcode != RCODE_NOERROR || qstate.noCacheStore != 0 {
			t.Errorf("%s: (returnMsg, returnRcode, noCacheStore) = (%v, %d, %d), want the qstate's reply untouched", tc.name, qstate.returnMsg, qstate.returnRcode, qstate.noCacheStore)
		}
		wantLog := ""
		if tc.wantBadEvent {
			wantLog = "pfb_dns_proxy error: [pfBlockerNG]: BAD event\n"
		}
		if logs.String() != wantLog {
			t.Errorf("%s: log = %q, want %q", tc.name, logs.String(), wantLog)
		}
	}
}
