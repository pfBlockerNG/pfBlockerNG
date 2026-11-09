// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the Unbound Python module: the settings
// init_standard reads from pfb_unbound.ini, and operate().
//
// pfb_unbound.py keeps its state in module globals (pfb, rcodeDB, the DBs); pfbUnbound holds it so two booted
// modules never share any. Python runs with the module directory as its working directory, so every file name
// here is joined onto moduleDir.
//
// Not translated yet, each arriving with the family that needs it: the user regex list, the noAAAA section, the
// Group Policy bypass list, SafeSearch, the HSTS file, the manifest build and matcher snapshot, the sqlite, MaxMind
// and thread setup, the log files and stderr redirect, the module fingerprint, the retired-cache sweep, and the
// DNSBL / noAAAA / SafeSearch / control branches of operate().
package decider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const REGEX_WARN_MS_DEFAULT = 10.0

const (
	IDN_MODE_OFF        = "off"
	IDN_MODE_ALL        = "on"
	IDN_MODE_CONFUSABLE = "confusable"
)

// IdnMode is the IDN-feature mode, backed by the canonical ini token; All reuses the legacy 'on'.
type IdnMode string

const (
	IdnModeAll        IdnMode = IDN_MODE_ALL
	IdnModeConfusable IdnMode = IDN_MODE_CONFUSABLE
	IdnModeOff        IdnMode = IDN_MODE_OFF
)

func idnModeFromLegacy(pythonIdn bool) IdnMode {
	if pythonIdn {
		return IdnModeAll
	}
	return IdnModeOff
}

// pfbSettings is the pfb dict init_standard fills: the settings a decision reads, the DNSBL files, the ini toggles.
// The "<x>DB loaded" flags, important_rules, group_policy and the sqlite/maxmind/thread flags are set only by the
// loaders that are not translated yet, so they are not here either.
type pfbSettings struct {
	metricsClientIp             bool
	pythonEnable                bool
	pythonReply                 bool
	pythonBlocking              bool
	pythonHsts                  bool
	pythonTldWildcard           bool
	pythonIdn                   bool
	idnMode                     IdnMode
	pythonIdnBlockMalicious     bool
	pythonIdnEscalateSuspicious bool
	pythonTldSeg                int64
	decisiondbMax               int64
	tldAllow                    bool
	tldAllowList                []string
	pslIncludePrivate           bool
	pslAllowPrivate             bool
	pslFeedPrivatePolicy        string
	pslFeedIcannPolicy          string
	dnsblIpv4                   string
	dnsblIpv6                   string
	pythonNolog                 bool
	pythonCname                 bool
	pythonControl               bool
	pythonControlLegacy         bool
	forwarding                  bool
	regexCap                    bool
	regexWarnMs                 float64
	pythonBlacklist             bool

	pfbUnboundIni       string
	pfbPyWhitelist      string
	pfbPyZone           string
	pfbPyData           string
	pfbPyHsts           string
	pfbPyTop1m          string
	pfbPyPsl            string
	pfbPySs             string
	pfbPySources        string
	pfbPyReload         string
	pfbPyReloadApplied  string
	pfbPyControl        string
	pfbPyControlApplied string
	pfbPyQuery          string
	pfbPyQueryReply     string
	pfbPyCount          string
	pfbPyRegexCount     string
	pfbPyRejectStats    string
	pfbPyStatus         string
	pfbPyDnsbl          string
	pfbPyResolver       string

	rrTypes  []uint16
	hstsTlds []string
}

type pfbUnbound struct {
	pfb     pfbSettings
	rcodeDB map[int]string

	// regexRuntime is what the regex scans keep in module globals in Python (the slow-match warning set, the prefilter
	// slots); evaluateConfig passes it through.
	regexRuntime *regexRuntime
}

// parseTldAllow turns the MAIN-ini tld_allow_list value into a cleaned list: stripped, lower-cased, blank entries
// dropped, so an empty value is an empty list (issues #713, #720).
func parseTldAllow(raw string) []string {
	var tlds []string
	for _, part := range strings.Split(raw, ",") {
		if tld := pyStrip(part); tld != "" {
			tlds = append(tlds, pysem.Lower(tld))
		}
	}
	return tlds
}

func isValueError(err error) bool {
	var valueErr *valueError
	return errors.As(err, &valueErr)
}

// parseIniInt reads an integer MAIN-ini option; ok is false for a malformed (non-integer) value, so the caller keeps
// its current one. Only the ValueError is swallowed, any other error escapes as in Python.
func parseIniInt(config *configParser, section, option string) (value int64, ok bool, err error) {
	value, err = config.getint(section, option)
	if isValueError(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

func warnIfLegacyControlEnabled(enabled bool) {
	if enabled {
		logWarn("[pfBlockerNG]: DNSBL Control legacy DNS-TXT transport is enabled. It is " +
			"deprecated and less secure than the CLI and will be removed in a future " +
			"release; migrate CRON/Scheduler tasks to the 'pfblockerng dnsbl-control' CLI.")
	}
}

// loadIniConfig parses the ini at path: nil when the file is absent, otherwise the (partially) read config, with
// a read failure written to the error log.
func loadIniConfig(path string) *configParser {
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	config := newConfigParser()
	if err := config.read(path); err != nil {
		logErr("[pfBlockerNG]: Failed to load ini configuration: " + err.Error())
	}
	return config
}

func mainOptionError(option string, err error) error {
	return fmt.Errorf("init_standard: [MAIN] %s: %w", option, err)
}

// initStandard builds the module from the ini and the files in moduleDir. An error is what makes init_standard
// raise in Python: a MAIN value that is no boolean, or an interpolation error in a value that is read.
func initStandard(id int, moduleDir string) (*pfbUnbound, error) {
	m := &pfbUnbound{regexRuntime: newRegexRuntime()}
	pfb := &m.pfb

	// A key not set here keeps Go's zero value, which is its Python default (False / "" / 0 / empty list).
	pfb.idnMode = IdnModeOff
	pfb.pythonIdnBlockMalicious = true
	pfb.pslIncludePrivate = true
	pfb.pslFeedPrivatePolicy = "honor"
	pfb.pslFeedIcannPolicy = "honor"
	pfb.regexWarnMs = REGEX_WARN_MS_DEFAULT
	pfb.decisiondbMax = 10000

	in := func(name string) string { return filepath.Join(moduleDir, name) }
	pfb.pfbUnboundIni = in("pfb_unbound.ini")
	pfb.pfbPyWhitelist = in("pfb_py_whitelist.txt")
	pfb.pfbPyZone = in("pfb_py_zone.txt")
	pfb.pfbPyData = in("pfb_py_data.txt")
	pfb.pfbPyHsts = in("pfb_py_hsts.txt")
	pfb.pfbPyTop1m = in("pfb_py_top1m.txt")
	pfb.pfbPyPsl = in("dnsbl_psl")
	pfb.pfbPySs = in("pfb_py_ss.txt")
	pfb.pfbPySources = in("pfb_py_sources.json")
	pfb.pfbPyReload = in("pfb_py_reload")
	pfb.pfbPyReloadApplied = in("pfb_py_reload.applied")
	pfb.pfbPyControl = in("pfb_py_control")
	pfb.pfbPyControlApplied = in("pfb_py_control.applied")
	pfb.pfbPyQuery = in("pfb_py_query")
	pfb.pfbPyQueryReply = in("pfb_py_query.reply")
	pfb.pfbPyCount = in("pfb_py_count")
	pfb.pfbPyRegexCount = in("pfb_py_regex_count")
	pfb.pfbPyRejectStats = in("pfb_py_reject_stats.json")
	pfb.pfbPyStatus = in("pfb_py_status.json")
	pfb.pfbPyDnsbl = in("pfb_py_dnsbl.sqlite")
	pfb.pfbPyResolver = in("pfb_py_resolver.sqlite")

	pfb.rrTypes = []uint16{
		RR_TYPE_A,
		RR_TYPE_AAAA,
		RR_TYPE_ANY,
		RR_TYPE_CNAME,
		RR_TYPE_DNAME,
		RR_TYPE_SIG,
		RR_TYPE_MX,
		RR_TYPE_NS,
		RR_TYPE_PTR,
		RR_TYPE_SRV,
		RR_TYPE_TXT,
		64,
		65,
	}

	pfb.hstsTlds = []string{
		"android",
		"app",
		"bank",
		"chrome",
		"dev",
		"foo",
		"gle",
		"gmail",
		"google",
		"hangout",
		"insurance",
		"meet",
		"new",
		"page",
		"play",
		"search",
		"youtube",
	}

	config := loadIniConfig(pfb.pfbUnboundIni)
	if config != nil {
		if config.hasSection("MAIN") {
			mainBool := func(option string, dst *bool) error {
				if !config.hasOption("MAIN", option) {
					return nil
				}
				value, err := config.getboolean("MAIN", option)
				if err != nil {
					return mainOptionError(option, err)
				}
				*dst = value
				return nil
			}
			mainString := func(option string, dst *string) error {
				if !config.hasOption("MAIN", option) {
					return nil
				}
				value, err := config.get("MAIN", option)
				if err != nil {
					return mainOptionError(option, err)
				}
				*dst = value
				return nil
			}
			// issue #2371: feed-at-suffix PSL policy; a missing option, an empty value or an unrecognised token keep "honor".
			mainPslPolicy := func(option string, dst *string) error {
				if !config.hasOption("MAIN", option) {
					return nil
				}
				raw, err := config.get("MAIN", option)
				if err != nil {
					return mainOptionError(option, err)
				}
				*dst = "honor"
				if policy := pysem.Lower(pyStrip(raw)); policy == "ignore" || policy == "apex" || policy == "honor" {
					*dst = policy
				}
				return nil
			}

			if err := mainBool("metrics_client_ip", &pfb.metricsClientIp); err != nil {
				return nil, err
			}
			if err := mainBool("python_enable", &pfb.pythonEnable); err != nil {
				return nil, err
			}
			if err := mainBool("python_reply", &pfb.pythonReply); err != nil {
				return nil, err
			}
			if err := mainBool("python_blocking", &pfb.pythonBlocking); err != nil {
				return nil, err
			}
			if err := mainBool("python_hsts", &pfb.pythonHsts); err != nil {
				return nil, err
			}
			if err := mainBool("python_tld_wildcard", &pfb.pythonTldWildcard); err != nil {
				return nil, err
			}
			if err := mainBool("python_idn", &pfb.pythonIdn); err != nil {
				return nil, err
			}
			// ADR-08: the IDN mode. A present idn_mode wins, '' being an explicit Off; an absent or unrecognised
			// one falls back to the legacy python_idn.
			if config.hasOption("MAIN", "idn_mode") {
				raw, err := config.get("MAIN", "idn_mode")
				if err != nil {
					return nil, mainOptionError("idn_mode", err)
				}
				switch rawIdn := pysem.Lower(pyStrip(raw)); rawIdn {
				case "":
					pfb.idnMode = IdnModeOff
				case IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE:
					pfb.idnMode = IdnMode(rawIdn)
				default:
					pfb.idnMode = idnModeFromLegacy(pfb.pythonIdn)
				}
			} else {
				pfb.idnMode = idnModeFromLegacy(pfb.pythonIdn)
			}
			if err := mainBool("python_idn_block_malicious", &pfb.pythonIdnBlockMalicious); err != nil {
				return nil, err
			}
			if err := mainBool("python_idn_escalate_suspicious", &pfb.pythonIdnEscalateSuspicious); err != nil {
				return nil, err
			}
			// issue #713: a malformed python_tld_seg / decisiondb_max keeps the current value.
			if config.hasOption("MAIN", "python_tld_seg") {
				parsedTldSeg, ok, err := parseIniInt(config, "MAIN", "python_tld_seg")
				if err != nil {
					return nil, mainOptionError("python_tld_seg", err)
				}
				if ok {
					pfb.pythonTldSeg = parsedTldSeg
				}
			}
			if config.hasOption("MAIN", "decisiondb_max") {
				parsedDecisiondbMax, ok, err := parseIniInt(config, "MAIN", "decisiondb_max")
				if err != nil {
					return nil, mainOptionError("decisiondb_max", err)
				}
				if ok {
					pfb.decisiondbMax = parsedDecisiondbMax
				}
			}
			if err := mainBool("tld_allow", &pfb.tldAllow); err != nil {
				return nil, err
			}
			if config.hasOption("MAIN", "tld_allow_list") {
				raw, err := config.get("MAIN", "tld_allow_list")
				if err != nil {
					return nil, mainOptionError("tld_allow_list", err)
				}
				pfb.tldAllowList = parseTldAllow(raw)
			}
			if err := mainBool("psl_include_private", &pfb.pslIncludePrivate); err != nil {
				return nil, err
			}
			if err := mainBool("psl_allow_private", &pfb.pslAllowPrivate); err != nil {
				return nil, err
			}
			if err := mainPslPolicy("psl_feed_private_policy", &pfb.pslFeedPrivatePolicy); err != nil {
				return nil, err
			}
			if err := mainPslPolicy("psl_feed_icann_policy", &pfb.pslFeedIcannPolicy); err != nil {
				return nil, err
			}
			if err := mainString("dnsbl_ipv4", &pfb.dnsblIpv4); err != nil {
				return nil, err
			}
			if err := mainString("dnsbl_ipv6", &pfb.dnsblIpv6); err != nil {
				return nil, err
			}
			if err := mainBool("python_nolog", &pfb.pythonNolog); err != nil {
				return nil, err
			}
			if err := mainBool("python_cname", &pfb.pythonCname); err != nil {
				return nil, err
			}
			if err := mainBool("python_control", &pfb.pythonControl); err != nil {
				return nil, err
			}
			if err := mainBool("python_control_legacy", &pfb.pythonControlLegacy); err != nil {
				return nil, err
			}
			warnIfLegacyControlEnabled(pfb.pythonControlLegacy)

			if err := mainBool("forwarding", &pfb.forwarding); err != nil {
				return nil, err
			}

			// ADR-07: regex_cap is the opt-in length cap; a malformed regex_warn_ms keeps the default.
			if err := mainBool("regex_cap", &pfb.regexCap); err != nil {
				return nil, err
			}
			if config.hasOption("MAIN", "regex_warn_ms") {
				regexWarnMs, err := config.getfloat("MAIN", "regex_warn_ms")
				switch {
				case err == nil:
					pfb.regexWarnMs = regexWarnMs
				case !isValueError(err):
					return nil, mainOptionError("regex_warn_ms", err)
				}
			}

			if pfb.dnsblIpv6 == "" {
				pfb.dnsblIpv6 = "::"
			}

			m.rcodeDB = map[int]string{
				0:  "NoError",
				1:  "FormErr",
				2:  "ServFail",
				3:  "NXDOMAIN",
				4:  "NotImp",
				5:  "Refused",
				6:  "YXDomain",
				7:  "YXRRSet",
				8:  "NXRRSet",
				9:  "NotAuth",
				10: "NotZone",
				11: "DSOTYPENI",
				16: "BADVERS",
				17: "BADKEY",
				18: "BADTIME",
				19: "BADMODE",
				20: "BADNAME",
				21: "BADALG",
				22: "BADTRUNC",
				23: "BADCOOKIE",
			}
		}

		if pfb.pythonEnable {
			// Enable the Blacklist functions (IDN): any active IDN mode needs the blacklist machinery.
			if pfb.pythonIdn || pfb.idnMode != IdnModeOff {
				pfb.pythonBlacklist = true
			}

			// Enable the Blacklist functions (TLD Allow): an empty list must not enable the gate (issue #713).
			if pfb.tldAllow && len(pfb.tldAllowList) > 0 {
				pfb.pythonBlacklist = true
			}
		}
	} else {
		logInfo("[pfBlockerNG]: Failed to load ini configuration. Ini file missing.")
	}
	return m, nil
}

func isUnknown(x string) string {
	if x == "" {
		return "Unknown"
	}
	return x
}

func getQNameQstate(qstate *moduleQstate) string {
	qName := ""
	name := ""
	if qstate != nil {
		name = qstate.qinfo.qnameStr
		if pyStrip(name) == "" && qstate.returnMsg != nil {
			name = qstate.returnMsg.qinfo.qnameStr
		}
	}
	if pyStrip(name) != "" {
		qName = strings.TrimRight(name, ".")
	}
	return isUnknown(qName)
}

// getQIp is the client address; mesh_info.reply_list.query_reply.addr is flattened to qstate.clientIP.
func getQIp(qstate *moduleQstate) string {
	qIP := ""
	if qstate != nil {
		qIP = qstate.clientIP
	}
	return isUnknown(qIP)
}

func (m *pfbUnbound) operate(id int, event int, qstate *moduleQstate, qdata any) bool {
	qstateValid := false
	var qType uint16
	qNameOriginal := ""
	qIP := ""
	if qstate != nil {
		qstateValid = true
		qType = qstate.qinfo.qtype
		qNameOriginal = pysem.Lower(getQNameQstate(qstate))
		qIP = getQIp(qstate)
	} else {
		logErr("[pfBlockerNG] qstate is not None and qstate.qinfo.qtype is not None")
	}
	// The branches that read these four are the ones not translated yet (see the file header).
	_, _, _, _ = qstateValid, qType, qNameOriginal, qIP

	if event == MODULE_EVENT_NEW || event == MODULE_EVENT_PASS {
		qstate.extState[id] = MODULE_WAIT_MODULE
		return true
	}

	if event == MODULE_EVENT_MODDONE {
		qstate.extState[id] = MODULE_FINISHED
		return true
	}

	logErr("[pfBlockerNG]: BAD event")
	qstate.extState[id] = MODULE_ERROR
	return true
}
