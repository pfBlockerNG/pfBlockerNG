// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the Unbound Python module: the settings
// init_standard reads from pfb_unbound.ini and the loaders it runs (the user regex list, noAAAA, the Group Policy
// bypass list, SafeSearch, the manifest build, HSTS), rebuild_and_swap, the loaders' helpers, and operate().
//
// pfb_unbound.py keeps its state in module globals (pfb, rcodeDB, the DBs); pfbUnbound holds it so two booted
// modules never share any. Python runs with the module directory as its working directory, so every file name
// here is joined onto moduleDir. The decision data (the DBs, the settings a decision reads) lives in the one
// snapshot the module publishes, not in module fields: see pfbUnbound.snapshot.
//
// Not translated, because the decider does not need them: the module fingerprint (the code record it feeds is replaced by
// the gateway's executable SHA-256 record, #3791) and the retired-cache sweep (pfb_py_cache.sqlite*: nothing reads or
// writes it any more). The stderr redirect is a documented difference: Python sends its stderr to py_error.log through
// pfb_async_io, the decider writes those lines to its own stderr (logOutput). The live update (the reload watcher, its RAM
// gate, its applied marker and the reload builder) is in pfb_unbound_reload.go, the DNSBL control surface
// (pfb_apply_control_command, its timers and the control watcher) in pfb_unbound_control.go, the ADR-65 query channel
// (pfb_query_watcher and its verdict) in pfb_unbound_query.go, and the log rows, their files and the GeoIP reader in
// pfb_unbound_log.go, pfb_unbound_logfile.go and pfb_unbound_geoip.go. deinit (pfbUnbound.deinit) stops what init
// started, bounded as Python's joins are.
package decider

import (
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const DNSBL_NODATA_SOA_RDATA = "pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600"

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
// important_rules is the snapshot's own importantRules, and group_policy and the thread flags are set only by code that
// is not translated yet, so they are not here. The sqlite flags are pfbUnbound's own (pfb_unbound_sqlite.go).
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
	pythonMaxmind               bool
	pythonCname                 bool
	pythonControl               bool
	pythonControlLegacy         bool
	forwarding                  bool
	regexCap                    bool
	regexWarnMs                 float64
	pythonBlacklist             bool

	// The "<x>DB loaded" flags a loader sets and operate() reads. dataDB, zoneDB, whiteDB, regexDB, allowRegexDB and
	// hstsDB have flags in Python too, but nothing reads them: evaluate_domain's gates come from the snapshot's own
	// dicts (ADR-10), so they are not here.
	gpListDB     bool
	noAAAADB     bool
	safeSearchDB bool

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

	// snapshot is the live matcher snapshot, every piece of decision data in one immutable value. rebuildAndSwap
	// is the only place it is bound; a query Loads it once (moduleQstate.snap).
	snapshot atomic.Pointer[snapshot]
	// decisionDB is the unified per-name LRU query memo, each entry stamped with the snapshot generation that
	// produced it.
	decisionDB *lruCache[*decision]
	// regexRuntime is what the regex scans keep in module globals in Python (the slow-match warning set, the prefilter
	// slots); evaluateConfig passes it through.
	regexRuntime *regexRuntime

	// readFile reads a loader's file; Python's tests fail open() to reach a loader's failure arm, a test fails this.
	readFile func(name string) ([]byte, error)
	// statusMu is _pfb_py_status_lock; statusClock is pfb_py_status_open's clock_fn (nil: the real clock).
	statusMu    sync.Mutex
	statusClock func() int64

	// publishMu serializes the publishers of snapshot: rebuildAndSwap, a control command and a control timer's expiry.
	// Each loads the live snapshot, derives the next from it and stores it, so two of them at once would lose a write.
	publishMu sync.Mutex
	// retired is set by deinit under publishMu: from then on nothing is published (a snapshot, an applied marker, the
	// counts, the status ledger) and the stats database is not opened, so that a reload or a control record that outlives
	// the bounded stop of its watcher cannot act on a closed module when it ends. The snapshot publishers read it under
	// publishMu, so that a swap is either stored before deinit or refused; the file writers read it without a lock.
	retired atomic.Bool
	// afterFunc starts a control timer (time.AfterFunc's shape; nil is the real one). A test replaces it to fire the
	// expiry by hand; it must not run f before it returns, as the caller holds publishMu.
	afterFunc func(delay time.Duration, f func())
	// controlMu guards controlActive, the names of the running control timers (Python: threading.enumerate()).
	controlMu     sync.Mutex
	controlActive map[string]struct{}
	// controlTick is the control watcher's poll tick and its release (nil: a RELOAD_POLL_INTERVAL ticker). A test
	// replaces it to drive the watcher without a clock.
	controlTick func() (tick <-chan time.Time, stop func())
	// controlStop stops the control watcher and waits for it to end; nil is pfb["control_watcher"] False.
	controlStop func()
	// queryTick and queryStop are the query channel's (pfb_unbound_query.go), as controlTick and controlStop are the control
	// watcher's; queryStop is nil when pfb["query_watcher"] is False.
	queryTick func() (tick <-chan time.Time, stop func())
	queryStop func()

	// The live update (pfb_unbound_reload.go). reloadStop stops the reload watcher and waits for it to end; nil is
	// pfb["reload_watcher"] False. reloadTick is its poll tick and the tick's release (nil: a RELOAD_POLL_INTERVAL ticker),
	// reloadBuilder its builder (nil: reloadBuildSnapshot) and totalRAM the RAM gate's probe of total physical memory (nil:
	// totalPhysicalRAM); a test replaces them to drive a reload without a clock, a manifest or a particular host.
	reloadStop    func()
	reloadTick    func() (tick <-chan time.Time, stop func())
	reloadBuilder func() (*snapshot, error)
	totalRAM      func() (uint64, bool)

	// logs is the log writer (pfb["log_listener"]), nil when none runs: rows are then appended directly. logDir is the
	// directory it writes. logSink, when set, takes every row instead (Python's tests replace pfb_log).
	logs    *logPipeline
	logDir  string
	logSink func(name, line string)
	// clock is the time source of the rows' timestamp and the cache TTL; nil is the local time.
	clock func() time.Time
	// maxmind is maxmindReader, nil when python_maxmind is off.
	maxmind *maxminddb.Reader
	// dnsblLast is _dnsbl_last_event, the previous block, which a repeat of marks its row a duplicate.
	dnsblLastMu sync.Mutex
	dnsblLast   *dnsblEvent

	// The stats databases (pfb_unbound_sqlite.go). dbMu is _db_lock, held for every use of a connection, the retries of a
	// failed write included; dbRecoveryMu is _db_recovery_lock, taken before dbMu and never inside it. sqlite3ResolverCon and
	// sqlite3DnsblCon are pfb["sqlite3_resolver_con"] and pfb["sqlite3_dnsbl_con"]: the counters are enqueued only while
	// their database is open. metricsPrivacyEpochs is pfb["metrics_privacy_epochs"], written by init before the first
	// query. dbWorker is the DB I/O worker, nil when none runs (pfb["db_worker"] False), and dbDropped counts the events
	// its full queue refused (pfb["db_dropped"]).
	dbMu, dbRecoveryMu   sync.Mutex
	dbClosed             bool // set by closeDb under dbMu: no connection is opened again
	dbConns              map[int]*dbConn
	sqlite3ResolverCon   atomic.Bool
	sqlite3DnsblCon      atomic.Bool
	metricsPrivacyEpochs map[int]string
	dbWorker             atomic.Pointer[dbWorker]
	dbDropped            atomic.Int64
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

// loadIniConfig parses the module's ini: nil when the file is absent, otherwise the (partially) read config. A read
// failure is written to the error log and opens the ini's parse-stage ledger entry; an absent file or a good read
// closes it.
func (m *pfbUnbound) loadIniConfig() *configParser {
	path := m.pfb.pfbUnboundIni
	if !isFile(path) {
		m.pfbPyStatusClose("dnsbl", path, "parse")
		return nil
	}
	config := newConfigParser()
	if err := config.read(path); err != nil {
		failure := "Failed to load ini configuration: " + err.Error()
		logErr("[pfBlockerNG]: " + failure)
		m.pfbPyStatusOpen("dnsbl", path, "parse", failure)
	} else {
		m.pfbPyStatusClose("dnsbl", path, "parse")
	}
	return config
}

func mainOptionError(option string, err error) error {
	return fmt.Errorf("init_standard: [MAIN] %s: %w", option, err)
}

// initStandard builds the module from the ini and the files in moduleDir. An error is what makes init_standard
// raise in Python: a MAIN value that is no boolean, or an interpolation error in a value that is read.
func initStandard(id int, moduleDir, logDir string) (*pfbUnbound, error) {
	m := &pfbUnbound{regexRuntime: newRegexRuntime(), readFile: os.ReadFile, logDir: logDir}
	// scratch collects the strata the loaders below fill; it becomes the module's first snapshot at the end.
	scratch := newSnapshot()
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

	config := m.loadIniConfig()
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

			m.rcodeDB = rcodeNames()
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

			// Collect user-defined Regex patterns: the always-on admission gate and the opt-in length cap apply to this
			// un-vetted list; the list has no rule limit.
			if userRegex := dnsblCompileUserRegex(loadUserRegexEntries(config), pfb.regexCap); userRegex.len() > 0 {
				regexDBUpdate(scratch.userRegexDB, userRegex)
				pfb.pythonBlacklist = true
			}

			// Collect user-defined no AAAA domains. config.items interpolates every value outside the try block in
			// Python, so a bad '%' escapes init_standard.
			if config.hasSection("noAAAA") {
				noaaaaConfig, err := config.items("noAAAA", false)
				if err != nil {
					return nil, fmt.Errorf("init_standard: [noAAAA]: %w", err)
				}
				if len(noaaaaConfig) > 0 {
					for _, row := range noaaaaConfig {
						key, line := row[0], row[1]
						data := strings.Split(strings.TrimRight(line, "\r\n"), ",")
						if len(data) == 2 {
							scratch.noAAAADB[data[0]] = data[1] == "1"
						} else {
							logErr(fmt.Sprintf("[pfBlockerNG]: Failed to parse: noAAAA: row:%s line:%s", key, line))
						}
					}
					pfb.noAAAADB = true
				}
			}

			// Collect user-defined Group Policy Global Bypass List
			m.loadGpBypassList(config, scratch)

			// Collect SafeSearch Redirection list
			m.loadSafesearchDb(scratch.safeSearchDB)

			// ADR-65: the manifest is the SOLE DNSBL source: an absent, unparseable or unbuildable manifest leaves the
			// dicts EMPTY (no fallback); the ledger entry the build opens signals the failure instead.
			if build := m.dnsblBuildFromManifest(pfb.pfbPySources); build != nil {
				scratch.dataDB = build.dataDB
				scratch.zoneDB = build.zoneDB
				scratch.feedGroupIndexDB = build.feedGroupIndexDB
				scratch.whiteDB = build.whiteDB
				scratch.pslRules = build.pslRules
				scratch.builtinLogFlag = build.builtinLogFlag

				// ADR-07: the feed block-regex and the @@/re/ allow-regex, and the Custom_List /re/ and @@/re/ rows
				// behind the MAIN.regex_list patterns compiled above.
				regexDBUpdate(scratch.regexDB, build.regexDB)
				regexDBUpdate(scratch.allowRegexDB, build.allowRegexDB)
				regexDBUpdate(scratch.userRegexDB, build.userRegexDB)
				regexDBUpdate(scratch.userAllowRegexDB, build.userAllowRegexDB)

				// The fast path stays byte-identical while important_rules is False; it flips True only when an ABP
				// $important / feed @@ / feed regex / user regex (Regex List or Custom_List) loaded.
				scratch.importantRules = build.importantRules || scratch.userRegexDB.len() > 0
				if len(scratch.dataDB) > 0 || len(scratch.zoneDB) > 0 || scratch.regexDB.len() > 0 || scratch.allowRegexDB.len() > 0 ||
					scratch.userRegexDB.len() > 0 || scratch.userAllowRegexDB.len() > 0 {
					pfb.pythonBlacklist = true
				}

				// Emit pfb_py_count (the LOADED total) for the UI, and the ADR-48 (issue #789) per-entry reject tally PHP
				// reads after this run.
				dnsblEmitCount(pfb.pfbPyCount, build.counts)
				dnsblEmitRejectStats(pfb.pfbPyRejectStats, build.rejects)
			}

			// ADR-65: the retired zone/data/whitelist CSV loaders only close the parse-stage entries a pre-ADR-65 init
			// could have left open (issue #1049); HSTS is independent of the manifest gate.
			m.pfbPyStatusClose("dnsbl", pfb.pfbPyZone, "parse")
			m.pfbPyStatusClose("dnsbl", pfb.pfbPyData, "parse")
			m.pfbPyStatusClose("dnsbl", pfb.pfbPyWhitelist, "parse")
			m.loadHstsDb(scratch.hstsDB)

			// Emit the admitted regex total (feed and user, block and allow) for PHP's DNSBL_Regex alias, even when only
			// feed regex is enabled.
			dnsblEmitCount(pfb.pfbPyRegexCount, scratch.regexDB.len()+scratch.allowRegexDB.len()+scratch.userRegexDB.len()+scratch.userAllowRegexDB.len())

			// Validate the SQLite3 database connections. A false validate (issue #900) is the corrupt or broken database:
			// validateDbWithRecovery deletes the file and retries once, and one that still fails leaves its flag off, no
			// crash and no endless retry, but logged.
			if m.validateDbWithRecovery(dbResolver) {
				m.sqlite3ResolverCon.Store(true)
			} else {
				logErr("[pfBlockerNG]: Failed to open pfb_py_resolver.sqlite database")
			}
			// Enable DNSBL statistics: forwarding-gated too, not just blacklist-gated (issue #860).
			if m.dnsblStatsWanted(pfb) {
				if m.validateDbWithRecovery(dbDnsbl) {
					m.sqlite3DnsblCon.Store(true)
				} else {
					logErr("[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database")
				}
			}

			// Open MaxMind db reader for DNS Reply GeoIP logging.
			m.openMaxmind()
		} else {
			// issue #1049: python_enable OFF skips every DNSBL loader above: close their parse-stage entries instead of
			// stranding them open.
			for _, item := range []string{pfb.pfbPySources, pfb.pfbPyZone, pfb.pfbPyData, pfb.pfbPyWhitelist, pfb.pfbPyHsts, pfb.pfbPySs} {
				m.pfbPyStatusClose("dnsbl", item, "parse")
			}
		}
	} else {
		logInfo("[pfBlockerNG]: Failed to load ini configuration. Ini file missing.")
	}

	// ADR-10: bundle the loaded strata into ONE immutable snapshot and install it through rebuildAndSwap, on every
	// path (python_enable or not, ini or not), so a snapshot is always present for operate(). counts and the others
	// are the swap's own, and emit_counts is off: init keeps its path-specific inline emits above. The group epochs are
	// read from the DNSBL database when the snapshot is built (_db_group_epochs): the counter authority a query takes
	// from its snapshot.
	m.decisionDB = newLruCache[*decision](intOf(pfb.decisiondbMax))
	m.rebuildAndSwap(func() (*snapshot, error) {
		m.finishSnapshot(scratch, pfb, m.dnsblStatsWanted(pfb))
		return scratch, nil
	}, false)
	m.dbCapturePrivacyEpochs()

	// Start the background DB-write worker (persistent sqlite connection, batched).
	m.startDbWorker()

	// ADR-10: start the zero-downtime reload watcher, after the init swap, whatever python_enable says (Python gates it on
	// threading alone).
	m.startReloadWatcher()

	// PFBL-03: start the DNSBL-control command-channel reader when the feature is enabled.
	if pfb.pythonControl {
		m.startControlWatcher()
	}

	// ADR-65: start the read-only DNSBL decision query channel's reader, always on (Python gates it on threading alone).
	m.startQueryWatcher()
	m.pfbSetupLogging()
	return m, nil
}

// rcodeNames is the RCODE table init_standard builds rcodeDB from (a table of its own per module): the name a reply row
// shows for a non-NOERROR return code. dns_reply_log.py's RCODES is the same table, held equal by a test.
func rcodeNames() map[int]string {
	return map[int]string{
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

// whileNotRetired runs f unless deinit has begun, so that nothing is written once the module is closing. It holds no lock:
// f writes a file that may block (a FIFO nobody reads), and deinit must not wait behind it.
func (m *pfbUnbound) whileNotRetired(f func()) {
	if !m.retired.Load() {
		f()
	}
}

// deinit is deinit(): the reload, control and query watchers stop (each waited for at most watcherStopWait: Python's
// join(timeout=5)), the database worker drains and the connections close, the log writer writes what is queued and the
// GeoIP reader closes. The watchers come first, ahead of Python's close of the reader: a watcher mid-build must not meet a
// closed database. The module has no query in flight by then. A watcher that does not stop within its bound is left
// running, and retirement (above all, the closed database) is what keeps it from publishing or opening anything.
func (m *pfbUnbound) deinit() {
	m.publishMu.Lock()
	m.retired.Store(true) // before the stops: a watcher that outlives its bound publishes and opens nothing from here on
	m.publishMu.Unlock()
	m.stopReloadWatcher()
	m.stopControlWatcher()
	m.stopQueryWatcher()
	m.closeDb()
	m.stopLogging()
	m.closeMaxmind()
	logInfo("[pfBlockerNG]: pfb_unbound.py script exiting")
}

// finishSnapshot fills the fields init and a reload derive the same way once the strata are loaded into s: the group
// epochs (statsWanted opens the DNSBL database that holds them), the counts, and the TLD Allow roots and PSL policies of
// the settings. A snapshot's own settings are never written here.
func (m *pfbUnbound) finishSnapshot(s *snapshot, set *pfbSettings, statsWanted bool) {
	s.groupEpochs = m.dbGroupEpochs(statsWanted, s)
	s.counts = len(s.dataDB) + len(s.zoneDB)
	s.regexCount = s.regexDB.len() + s.allowRegexDB.len() + s.userRegexDB.len() + s.userAllowRegexDB.len()
	s.tldAllowRoots = selectedTldRoots(set.tldAllowList)
	s.hasTldAllowRoots = true
	s.pslIncludePrivate = set.pslIncludePrivate
	s.pslAllowPrivate = set.pslAllowPrivate
	s.pslFeedPrivatePolicy = set.pslFeedPrivatePolicy
	s.pslFeedIcannPolicy = set.pslFeedIcannPolicy
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

// isFile is os.path.isfile: a regular file, a symlink to one included.
func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// pyTextLines is the lines a Python text-mode file iteration yields: universal newlines, undecodable bytes replaced
// (errors="replace").
// shortcut: Go replaces every invalid byte with U+FFFD where Python replaces a truncated sequence with one; the files
// are PHP-written domain lists, so a name with undecodable bytes matches no query either way.
func pyTextLines(data []byte) []string {
	text := string([]rune(string(data)))
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// loadHstsDb parses the HSTS preload file into hstsDB, gated on python_hsts (not on the ADR-06 manifest: hstsDB is
// no part of the manifest build).
// shortcut: a read failure's text is Go's where Python's is OSError's ("[Errno 13] ..."): it only reaches the log and
// the status message.
func (m *pfbUnbound) loadHstsDb(hstsDB map[string]struct{}) {
	pfb := &m.pfb
	if !(pfb.pythonHsts && isFile(pfb.pfbPyHsts)) {
		m.pfbPyStatusClose("dnsbl", pfb.pfbPyHsts, "parse")
		return
	}
	data, err := m.readFile(pfb.pfbPyHsts)
	if err != nil {
		failure := fmt.Sprintf("Failed to load: %s: %v", pfb.pfbPyHsts, err)
		logErr("[pfBlockerNG]: " + failure)
		m.pfbPyStatusOpen("dnsbl", pfb.pfbPyHsts, "parse", failure)
		return
	}
	addHstsLines(hstsDB, data)
	m.pfbPyStatusClose("dnsbl", pfb.pfbPyHsts, "parse")
}

// addHstsLines adds the HSTS preload file's keys to hstsDB; init and a reload parse the file the same way.
func addHstsLines(hstsDB map[string]struct{}, data []byte) {
	for _, line := range pyTextLines(data) {
		// The PSL parser skips comment and whitespace-only lines; '0' stays valid.
		key := pyStrip(line)
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}
		hstsDB[key] = struct{}{}
	}
}

// pyListRepr is repr() of a list of str.
func pyListRepr(row []string) string {
	reprs := make([]string, len(row))
	for i, field := range row {
		reprs[i] = pysem.Repr(field)
	}
	return "[" + strings.Join(reprs, ", ") + "]"
}

// loadSafesearchDb parses the SafeSearch Redirection CSV into safeSearchDB: 3 columns (domain, A, AAAA: an A/AAAA
// rewrite or nxdomain) or 5 (domain, cname, target, baked v4, baked v6: a CNAME redirect, issue #149).
// shortcut: encoding/csv skips a blank line where Python's csv.reader yields an empty row that is reported as
// "Failed to parse ...: []", and it reads `"a"b,c,d` as the one field `a"b,c,d` where Python reads the three columns
// ab, c and d. Probed on both; every other row shape the loader meets (quoted separators, doubled quotes, empty and
// padded fields) reads alike. PHP writes the file as one unquoted row per domain, so neither difference can occur;
// upgrade to a port of the excel dialect if the file ever has another writer.
func (m *pfbUnbound) loadSafesearchDb(safeSearchDB map[string]safeSearchEntry) {
	pfb := &m.pfb
	if !isFile(pfb.pfbPySs) {
		m.pfbPyStatusClose("dnsbl", pfb.pfbPySs, "parse")
		return
	}
	data, err := m.readFile(pfb.pfbPySs)
	if err == nil {
		reader := csv.NewReader(strings.NewReader(strings.Join(pyTextLines(data), "\n")))
		reader.FieldsPerRecord = -1
		reader.LazyQuotes = true
		for {
			var row []string
			if row, err = reader.Read(); err != nil {
				break
			}
			switch len(row) {
			case 3:
				safeSearchDB[row[0]] = safeSearchEntry{a: row[1], aaaa: row[2]}
			case 5:
				safeSearchDB[row[0]] = safeSearchEntry{a: row[1], aaaa: row[2], v4: row[3], v6: row[4]}
			default:
				logErr(fmt.Sprintf("[pfBlockerNG]: Failed to parse: %s: %s", pfb.pfbPySs, pyListRepr(row)))
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		// #714 FIX #6: name the SafeSearch source, not the zone list.
		failure := fmt.Sprintf("Failed to load: %s: %v", pfb.pfbPySs, err)
		logErr("[pfBlockerNG]: " + failure)
		m.pfbPyStatusOpen("dnsbl", pfb.pfbPySs, "parse", failure)
		return
	}
	pfb.safeSearchDB = true
	m.pfbPyStatusClose("dnsbl", pfb.pfbPySs, "parse")
}

// safesearchEntry looks up, and memoizes on the Decision, the SafeSearch entry for a name: the matched entry, or
// false for no match. The verdict lives on the name's Decision (safesearch axis): UNSET = not yet evaluated, an entry
// = rewrite, nil = no match. The pre-resolution (NEW) and post-resolution (MODDONE) passes share it.
func (m *pfbUnbound) safesearchEntry(snap *snapshot, qNameOriginal string) (safeSearchEntry, bool) {
	dec := decisionFor(m.decisionDB, qNameOriginal, snap.gen)
	if dec.getSafesearch() == UNSET {
		entry, found := snap.safeSearchDB[qNameOriginal]
		// Validate 'www.' Domains
		if !found && !strings.HasPrefix(qNameOriginal, "www.") {
			entry, found = snap.safeSearchDB["www."+qNameOriginal]
		}
		if found {
			dec.setSafesearch(entry)
		} else {
			dec.setSafesearch(nil)
		}
	}
	entry, found := dec.getSafesearch().(safeSearchEntry)
	return entry, found
}

// ipNet is ipaddress.ip_network(text, strict=False): the network as a prefix, and for a host network (the prefix is
// the family's full length) the key str(network_address), a zone id included.
type ipNet struct {
	prefix netip.Prefix
	host   bool
	key    string
}

// prefixFromPrefixString is _prefix_from_prefix_string: ASCII digits, at most maxBits.
func prefixFromPrefixString(text string, maxBits int) (int, bool) {
	if !pysem.IsASCIIDigits(text) {
		return 0, false
	}
	value := 0
	for i := range len(text) {
		value = min(value*10+int(text[i]-'0'), maxBits+1) // saturates: leading zeros are fine, size is not
	}
	return value, value <= maxBits
}

// prefixFromIPInt is _prefix_from_ip_int for IPv4: the prefix length of a netmask (1* then 0*).
func prefixFromIPInt(ip uint32) (int, bool) {
	trailing := 32
	if ip != 0 {
		trailing = bits.TrailingZeros32(ip)
	}
	prefix := 32 - trailing
	return prefix, uint64(ip)>>trailing == uint64(1)<<prefix-1
}

// ipv4PrefixFromMask is IPv4Network's netmask argument: a prefix length, else a netmask, else a hostmask.
func ipv4PrefixFromMask(mask string) (int, bool) {
	if prefix, ok := prefixFromPrefixString(mask, 32); ok {
		return prefix, true
	}
	value, err := pysem.IPv4Address(mask)
	if err != nil {
		return 0, false
	}
	if prefix, ok := prefixFromIPInt(value); ok {
		return prefix, true
	}
	return prefixFromIPInt(^value)
}

func ipNetwork(text string) (ipNet, bool) {
	address, mask, hasMask := strings.Cut(text, "/")
	if strings.Contains(mask, "/") {
		return ipNet{}, false
	}
	if value, err := pysem.IPv4Address(address); err == nil {
		prefixLen := 32
		if hasMask {
			var ok bool
			if prefixLen, ok = ipv4PrefixFromMask(mask); !ok {
				return ipNet{}, false
			}
		}
		network := netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, value&(^uint32(0)<<(32-prefixLen)))))
		return ipNet{netip.PrefixFrom(network, prefixLen), prefixLen == 32, network.String()}, true
	}
	packed, err := pysem.IPv6Address(address)
	if err != nil {
		return ipNet{}, false
	}
	prefixLen := 128
	if hasMask {
		var ok bool
		if prefixLen, ok = prefixFromPrefixString(mask, 128); !ok {
			return ipNet{}, false
		}
	}
	host := [16]byte(packed)
	if prefixLen == 128 {
		key := netip.AddrFrom16(host).String()
		if _, scope, hasScope := strings.Cut(address, "%"); hasScope {
			key += "%" + scope
		}
		return ipNet{netip.PrefixFrom(netip.AddrFrom16(host), 128), true, key}, true
	}
	for i := range host {
		keep := min(max(prefixLen-8*i, 0), 8)
		host[i] &= byte(0xFF << (8 - keep))
	}
	network := netip.AddrFrom16(host)
	return ipNet{netip.PrefixFrom(network, prefixLen), false, network.String()}, true
}

// loadGpBypassList loads [GP_Bypass_List]. A full-length entry (a bare IP, /32, /128) is an exact gpListDB key, the
// one structure a runtime add/removebypass edits, and a shorter prefix is a gpNetDB network. An unparseable row is
// reported and skipped, never aborting the rest of the load.
func (m *pfbUnbound) loadGpBypassList(config *configParser, snap *snapshot) {
	if !config.hasSection("GP_Bypass_List") {
		return
	}
	// raw: a link-local zone id ('fe80::1%em0') is not a '%' interpolation, so items cannot fail here.
	rows, err := config.items("GP_Bypass_List", true)
	if err != nil {
		logErr("[pfBlockerNG]: Failed to read: GP_Bypass_List: " + err.Error())
		return
	}
	for _, row := range rows {
		key, line := row[0], row[1]
		network, ok := ipNetwork(line)
		if !ok {
			logErr(fmt.Sprintf("[pfBlockerNG]: Failed to parse: GP_Bypass_List: row:%s line:%s", key, line))
			continue
		}
		if network.host {
			snap.gpListDB[network.key] = 0
		} else {
			snap.gpNetDB = append(snap.gpNetDB, network.prefix)
		}
	}
	if len(snap.gpListDB) > 0 || len(snap.gpNetDB) > 0 {
		m.pfb.gpListDB = true
	}
}

// gpNetMatch is whether client address qIP lies inside a configured gpNetDB network.
// shortcut: linear scan; fine for an admin-sized list, use a prefix trie if it reaches thousands.
func gpNetMatch(gpNetDB []netip.Prefix, qIP string) bool {
	packed, err := pysem.IPAddress(qIP)
	if err != nil {
		return false
	}
	addr, _ := netip.AddrFromSlice(packed)
	return slices.ContainsFunc(gpNetDB, func(network netip.Prefix) bool { return network.Contains(addr) })
}

// gpBypassed is whether the query's client is on the Group Policy bypass list (exact IP or CIDR).
func gpBypassed(snap *snapshot, qstate *moduleQstate) bool {
	if !snap.settings.gpListDB {
		return false
	}
	qIP := getQIp(qstate)
	if qIP == "Unknown" {
		return false
	}
	_, listed := snap.gpListDB[qIP]
	return listed || (len(snap.gpNetDB) > 0 && gpNetMatch(snap.gpNetDB, qIP))
}

// convertOther decodes an rr_data payload shaped like an uncompressed RFC 1035 3.3.1 domain name: a 2-byte RDATA
// length prefix (as convert_ipv4 / convert_ipv6 read it) and labels (a 1-63 length octet, that many bytes), ended by a
// zero-length root label. A length octet over 63 (a compression pointer) or one that overruns the buffer is malformed,
// and so is a bare root label with no labels: "Unknown". A TXT character-string has no root terminator, so a buffer
// that ends mid-walk without a zero octet still returns the labels read so far (the lenient case).
func convertOther(x []byte) string {
	final := ""
	if len(x) > 0 {
		var labels []string
		buf := x[min(2, len(x)):]
		pos := 0
		malformed, rooted := false, false
		for pos < len(buf) {
			length := int(buf[pos])
			pos++
			if length == 0 {
				rooted = true
				break
			}
			if length > 63 || pos+length > len(buf) {
				malformed = true
				break
			}
			label := make([]rune, length)
			for i, b := range buf[pos : pos+length] {
				label[i] = rune(b) // decode("latin-1")
			}
			labels = append(labels, string(label))
			pos += length
		}
		if !malformed && (len(labels) > 0 || rooted) {
			final = strings.Join(labels, ".")
		}
	}
	return isUnknown(final)
}

// regexDBUpdate is dict.update: a new name is appended, an existing one keeps its position and takes the new entry.
func regexDBUpdate(dst, src *regexDB) {
	for name, entry := range src.items() {
		dst.set(name, entry)
	}
}

// intOf is an int64 ini value as an int; a value past int's range saturates (32-bit), where Python's int does not.
func intOf(value int64) int {
	if value > math.MaxInt {
		return math.MaxInt
	}
	if value < math.MinInt {
		return math.MinInt
	}
	return int(value)
}

// rebuildAndSwap is ADR-10's single fail-closed step: build a brand-new snapshot, publish it atomically, reset the
// query memo. buildSnapshot returns a snapshot built off to the side (it must write nothing live) or an error for a
// failed build; a nil snapshot is a failed build too, and so is a panic of the builder, which is logged like an error
// (Python's `except Exception`). On success the new snapshot is stored, decisionDB is cleared
// (the clear alone is no guard, since a query that captured the OLD snapshot can memoize after it, issue #1074:
// every memo is also stamped with its snapshot's generation, and a reader rejects a foreign one), the regex runtime is
// reset, and with emitCounts the UI counts and the reject-stats artifact are rewritten from the new snapshot. On
// failure the old snapshot and the memo are untouched, so the resolver keeps serving the last good lists.
//
// The snapshot carries its settings. Python flips pfb["python_blacklist"] after the swap when the new lists have any
// block or allow stratum (a regex-only reload into a module that had no lists must start blocking); here the flip is
// made on a copy of the settings before the snapshot is published, because a published snapshot is never written.
// The base is the builder's own settings, else the live snapshot's (the module's at init). The base is read and the
// next snapshot stored under publishMu, so a control command that lands meanwhile is carried, not overwritten.
// A swap that newly satisfies _dnsbl_stats_wanted (python_blacklist just flipped on) opens the DNSBL database init left
// closed (issues #862, #870).
//
// A snapshot built with carryRuntime (a reload) takes noAAAADB, safeSearchDB, gpListDB and gpNetDB from the live snapshot
// at the same moment, under publishMu: Python keeps them as module globals a swap never touches, so a runtime addbypass
// survives it and one that lands while the reload builds is carried. A published table is never written (a control
// command clones before it writes), so the new snapshot shares the live one's maps.
func (m *pfbUnbound) rebuildAndSwap(buildSnapshot func() (*snapshot, error), emitCounts bool) bool {
	next, err := func() (next *snapshot, err error) {
		defer func() { // Python's `except Exception` around build_snapshot(): a raise reads as a returned failure
			if v := recover(); v != nil {
				err = fmt.Errorf("%v", v)
			}
		}()
		return buildSnapshot()
	}()
	if err != nil {
		logErr("[pfBlockerNG]: DNSBL rebuild failed, keeping current snapshot: " + err.Error())
		return false
	}
	if next == nil {
		return false
	}

	m.publishMu.Lock()
	if m.retired.Load() {
		m.publishMu.Unlock()
		return false
	}
	base := next.settings
	if base == nil {
		base = &m.pfb
		if live := m.snapshot.Load(); live != nil {
			base = live.settings
		}
	}
	settings := *base
	if len(next.dataDB) > 0 || len(next.zoneDB) > 0 || next.regexDB.len() > 0 || next.allowRegexDB.len() > 0 ||
		next.userRegexDB.len() > 0 || next.userAllowRegexDB.len() > 0 {
		settings.pythonBlacklist = true
	}
	next.settings = &settings
	if next.carryRuntime {
		if live := m.snapshot.Load(); live != nil {
			next.noAAAADB, next.safeSearchDB, next.gpListDB, next.gpNetDB = live.noAAAADB, live.safeSearchDB, live.gpListDB, live.gpNetDB
		}
	}

	m.snapshot.Store(next)
	m.publishMu.Unlock()
	m.decisionDB.clear()
	// #714 FIX #2: a swap installs brand-new regex DBs, so the warn suppression keyed on a rule name must not outlive it.
	m.regexRuntime.reset()
	m.openDnsblStatsDbIfWanted(&settings)
	if emitCounts {
		m.whileNotRetired(func() {
			dnsblEmitCount(settings.pfbPyCount, next.counts)
			dnsblEmitCount(settings.pfbPyRegexCount, next.regexCount)
			// ADR-48 (issue #789): the reject-stats artifact too; a module built without the path emits none.
			if settings.pfbPyRejectStats != "" {
				dnsblEmitRejectStats(settings.pfbPyRejectStats, next.rejects)
			}
		})
	}
	return true
}

// ssAnswerHasCnameTo is whether the resolved answer carries a CNAME pointing at target. It identifies the post-restart
// pass of the SafeSearch CNAME redirect: the iterator has chased the orig -> CNAME -> target referral we planted, so
// the answer now contains that CNAME. A genuine answer for the original name would not CNAME to our SafeSearch target.
func ssAnswerHasCnameTo(qstate *moduleQstate, target string) bool {
	rm := qstate.returnMsg
	if rm == nil || rm.rep == nil {
		return false
	}
	rep := rm.rep
	target = pysem.Lower(strings.TrimRight(target, "."))
	for i := range rep.anNumrrsets {
		rr := rep.rrsets[i]
		if rr.rk.typeStr != "CNAME" {
			continue
		}
		for j := range rr.entry.data.count {
			if pysem.Lower(strings.TrimRight(convertOther(rr.entry.data.rrData[j]), ".")) == target {
				return true
			}
		}
	}
	return false
}

// ssAnswerHasAddress is whether the resolved answer carries at least one A/AAAA RRset. On the post-restart pass this
// means the iterator successfully chased the CNAME to the target's address (the #1 live path); its absence means the
// chase produced only a bare CNAME and the #2 baked fallback must answer.
func ssAnswerHasAddress(qstate *moduleQstate) bool {
	rm := qstate.returnMsg
	if rm == nil || rm.rep == nil {
		return false
	}
	rep := rm.rep
	for i := range rep.anNumrrsets {
		if typeStr := rep.rrsets[i].rk.typeStr; typeStr == "A" || typeStr == "AAAA" {
			return true
		}
	}
	return false
}

// safesearchBakedFallback is the #2 fallback: answer a SafeSearch CNAME name with the baked target IP. Used when the #1
// live chase yields no address (this Unbound refuses to chase a module-planted CNAME, or the target failed to resolve).
// The baked v4/v6 are resolved by PHP at list-build and kept ~15-min-fresh by the freshness cron. Returns true if it
// answered (the caller must return true), false to fall through (no baked IP available for this qtype).
func safesearchBakedFallback(id int, qstate *moduleQstate, qType uint16, isSafeSearch safeSearchEntry) bool {
	ip, rrtype := isSafeSearch.v6, "AAAA"
	if qType == RR_TYPE_A {
		ip, rrtype = isSafeSearch.v4, "A"
	}
	if ip == "" {
		return false
	}
	qname := qstate.qinfo.qnameStr
	msg := newDNSMessage(qname, qType, RR_CLASS_IN, PKT_QR|PKT_RA)
	msg.answer = append(msg.answer, fmt.Sprintf("%s 300 IN %s %s", qname, rrtype, ip))
	if !msg.setReturnMsg(qstate) {
		qstate.extState[id] = MODULE_ERROR
		return true
	}
	qstate.returnRcode = RCODE_NOERROR
	// Synthesized, deliberately unsigned -> stop the validator marking it bogus.
	qstate.returnMsg.rep.security = secStatusInsecure
	qstate.extState[id] = MODULE_FINISHED
	return true
}

// safesearchCnameRedirect is the SafeSearch CNAME redirect (e.g. duckduckgo.com -> safe.duckduckgo.com). Unbound will
// not chase a CNAME a module hands it (NLnetLabs/unbound #976), so this uses the field-proven nxforward technique
// post-resolution (MODDONE):
//
//  1. First pass: plant the synthetic orig -> CNAME -> target into Unbound's message cache as a REFERRAL and restart
//     the iterator (MODULE_RESTART_NEXT) so the ITERATOR chases the target's A/AAAA itself. If the plant fails to
//     store (real Unbound's silent falsy failure -- issue #749), restarting would chase a referral that was never
//     actually cached, so this falls back to the baked target IP (#2) instead -- never MODULE_RESTART_NEXT on a
//     failed store.
//  2. Post-restart pass (the answer now carries our CNAME): if the chase produced an address, force rep.security so
//     the unsigned synthesized hop is not marked bogus (the historical DNSSEC blocker, issue #149), re-cache as a
//     final answer and finish -- a failure to re-cache here (issue #749) only means the chased answer isn't cached,
//     not that the already-built, already-validated reply is invalid, so it still finishes; if the chase produced no
//     address, fall back to the baked target IP (#2).
//
// Runs only for A/AAAA queries. Returns true if it took over the query (the caller must return true), false to let
// normal processing continue. snap is the query's own snapshot, which Group Policy is read from.
func safesearchCnameRedirect(snap *snapshot, id int, qstate *moduleQstate, qType uint16, isSafeSearch safeSearchEntry) bool {
	target := isSafeSearch.aaaa
	if target == "" || (qType != RR_TYPE_A && qType != RR_TYPE_AAAA) {
		return false
	}

	// Post-restart pass: the iterator has chased our planted CNAME.
	if ssAnswerHasCnameTo(qstate, target) {
		if ssAnswerHasAddress(qstate) {
			qstate.returnRcode = RCODE_NOERROR
			// The orig->target hop is synthesized (unsigned); without this the validator marks a signed original zone
			// bogus -> SERVFAIL (issue #149).
			qstate.returnMsg.rep.security = secStatusInsecure
			invalidateQueryInCache(qstate, qstate.qinfo)
			// A bypassed client's answer stays out of the shared cache (issue #3508).
			if gpBypassed(snap, qstate) {
				qstate.extState[id] = MODULE_FINISHED
				return true
			}
			qstate.noCacheStore = 0
			if !storeQueryInCache(qstate, qstate.qinfo, qstate.returnMsg.rep, 0) {
				// A cache-store failure must not SERVFAIL an already-built, already-validated answer -- log it and
				// finish anyway (issue #749).
				logInfo(fmt.Sprintf("[pfBlockerNG]: SafeSearch: failed to re-cache chased answer for %s", qstate.qinfo.qnameStr))
			}
			qstate.extState[id] = MODULE_FINISHED
			return true
		}
		// #1 chase yielded only a bare CNAME -> #2 baked fallback.
		return safesearchBakedFallback(id, qstate, qType, isSafeSearch)
	}

	// First pass: plant the synthetic CNAME referral and restart the iterator.
	qname := qstate.qinfo.qnameStr
	cnameMsg := newDNSMessage(qname, qType, RR_CLASS_IN, PKT_QR|PKT_RD|PKT_RA)
	cnameMsg.answer = append(cnameMsg.answer, fmt.Sprintf("%s 3600 IN CNAME %s", qname, target))
	if !cnameMsg.setReturnMsg(qstate) {
		qstate.extState[id] = MODULE_ERROR
		return true
	}
	invalidateQueryInCache(qstate, qstate.returnMsg.qinfo)
	if !storeQueryInCache(qstate, qstate.returnMsg.qinfo, qstate.returnMsg.rep, 1) {
		// The planted referral isn't actually in cache -- restarting the iterator would chase nothing and fruitlessly
		// loop back into this first pass (issue #749). Fall back to the baked target IP instead of restarting.
		logInfo(fmt.Sprintf("[pfBlockerNG]: SafeSearch: failed to store planted CNAME referral for %s", qname))
		if safesearchBakedFallback(id, qstate, qType, isSafeSearch) {
			return true
		}
		qstate.extState[id] = MODULE_ERROR
		return true
	}
	qstate.noCacheStore = 1
	qstate.extState[id] = MODULE_RESTART_NEXT
	return true
}

// operate is the module's query callback. A query's matcher snapshot is Loaded once, on its first event, into
// qstate.snap and every later event (MODDONE, the CNAME pass) reuses it; Python re-reads the module's _snapshot per
// event, the owner's 2026-11-09 rule makes one query one generation. Every reader below (noAAAA, SafeSearch, Group
// Policy, evaluate_domain, the settings) reads that snapshot, never a field of m a swap could change.
func (m *pfbUnbound) operate(id int, event int, qstate *moduleQstate, qdata any) bool {
	qstateValid := false
	var qType uint16
	qNameOriginal := ""
	qIP := ""
	var snap *snapshot
	var settings *pfbSettings
	if qstate != nil {
		qstateValid = true
		qType = qstate.qinfo.qtype
		qNameOriginal = pysem.Lower(getQNameQstate(qstate))
		qIP = getQIp(qstate)
		if qstate.snap == nil {
			qstate.snap = m.snapshot.Load()
		}
		snap = qstate.snap
		settings = snap.settings
	} else {
		logErr("[pfBlockerNG] qstate is not None and qstate.qinfo.qtype is not None")
	}

	if event == MODULE_EVENT_NEW || event == MODULE_EVENT_PASS {
		// no AAAA validation. The verdict is memoized on the name's Decision (noaaaa axis): UNSET = not yet evaluated,
		// true = block, false = allow.
		if qstateValid && qType == RR_TYPE_AAAA && settings.noAAAADB {
			dec := decisionFor(m.decisionDB, qNameOriginal, snap.gen)
			if dec.getNoaaaa() == UNSET {
				dec.setNoaaaa(evaluateNoaaaa(qNameOriginal, snap.noAAAADB))
			}

			// Create FQDN Reply Message (AAAA -> A)
			if blocked, _ := dec.getNoaaaa().(bool); blocked {
				msg := newDNSMessage(qstate.qinfo.qnameStr, RR_TYPE_A, RR_CLASS_IN, PKT_QR|PKT_RA)
				// issue #3224: empty answer -> RFC 2308 Type-2 NODATA (SOA in AUTHORITY).
				msg.authority = append(msg.authority, fmt.Sprintf("%s. 3600 IN SOA %s", qNameOriginal, DNSBL_NODATA_SOA_RDATA))
				if !msg.setReturnMsg(qstate) {
					qstate.extState[id] = MODULE_ERROR
					return true
				}

				qstate.returnRcode = RCODE_NOERROR
				qstate.returnMsg.rep.security = secStatusIndeterminate
				qstate.extState[id] = MODULE_FINISHED
				return true
			}
		}

		// SafeSearch Redirection validation
		if qstateValid && settings.safeSearchDB {
			if isSafeSearch, found := m.safesearchEntry(snap, qNameOriginal); found {
				ssFound := false
				var msg *DNSMessage
				switch {
				case isSafeSearch.a == "nxdomain":
					qstate.returnRcode = RCODE_NXDOMAIN
					qstate.extState[id] = MODULE_FINISHED
					return true

				// CNAME redirect (duckduckgo.com / pixabay.com) is deferred to the post-resolution MODDONE pass: Unbound
				// will not chase a CNAME handed to it here (issue #149 / unbound #976).
				case isSafeSearch.a == "cname":

				default:
					if (qType == RR_TYPE_A && isSafeSearch.a != "") || (qType == RR_TYPE_AAAA && isSafeSearch.aaaa == "") {
						msg = newDNSMessage(qstate.qinfo.qnameStr, RR_TYPE_A, RR_CLASS_IN, PKT_QR|PKT_RA)
						msg.answer = append(msg.answer, fmt.Sprintf("%s 300 IN %s %s", qstate.qinfo.qnameStr, "A", isSafeSearch.a))
						ssFound = true
					} else if qType == RR_TYPE_AAAA && isSafeSearch.aaaa != "" {
						msg = newDNSMessage(qstate.qinfo.qnameStr, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR|PKT_RA)
						msg.answer = append(msg.answer, fmt.Sprintf("%s 300 IN %s %s", qstate.qinfo.qnameStr, "AAAA", isSafeSearch.aaaa))
						ssFound = true
					}
				}

				if ssFound {
					if !msg.setReturnMsg(qstate) {
						qstate.extState[id] = MODULE_ERROR
						return true
					}

					qstate.returnRcode = RCODE_NOERROR
					qstate.returnMsg.rep.security = secStatusIndeterminate
					qstate.extState[id] = MODULE_FINISHED
					return true
				}
			}
		}

		// Python_control - Receive TXT commands from pfSense local IP
		// PFBL-03: DEPRECATED legacy DNS-TXT control transport. Inert unless the operator explicitly opts back in via
		// python_control_legacy; DNSBL control is CLI-driven over the local privileged command file. This whole branch is
		// deprecated and will be removed in a future release.
		if settings.pythonControlLegacy && qstateValid && qType == RR_TYPE_TXT && strings.HasPrefix(qNameOriginal, "python_control.") {
			// PFBL-03: accept the loopback address over either family (the old check was IPv4-only).
			if settings.pythonControl && (qIP == "127.0.0.1" || qIP == "::1" || qIP == "::ffff:127.0.0.1") {
				controlCommand := strings.Split(qNameOriginal, ".")
				// PFBL-03: route to the SINGLE shared handler (also used by the local privileged command channel) -- one
				// implementation of the grammar.
				controlRcd, controlMsg := m.pfbApplyControlCommand(controlCommand)

				qReply := "python_control"
				if !controlRcd {
					if controlMsg == "" {
						controlMsg = fmt.Sprintf("Python_control: Command not authorized! [ %s ]", qNameOriginal)
					}
					qReply = "python_control_fail"
				}

				txtMsg := newDNSMessage(qstate.qinfo.qnameStr, RR_TYPE_TXT, RR_CLASS_IN, PKT_QR|PKT_RA)
				txtMsg.answer = append(txtMsg.answer, fmt.Sprintf("%s. 0 IN TXT \"%s\"", qReply, controlMsg))

				if !txtMsg.setReturnMsg(qstate) {
					qstate.extState[id] = MODULE_ERROR
					return true
				}

				qstate.returnRcode = RCODE_NOERROR
				qstate.returnMsg.rep.security = secStatusIndeterminate
				qstate.extState[id] = MODULE_FINISHED
				return true
			}
		}
	}

	// DNSBL Validation for specific RR_TYPES only
	if qstateValid && settings.pythonBlacklist && slices.Contains(settings.rrTypes, qType) {
		// Group Policy - Bypass DNSBL Validation
		bypassDnsbl := gpBypassed(snap, qstate)

		// Cache hits are served before operate() runs: a bypassed answer must never reach other clients through the
		// shared cache (issue #3508).
		if bypassDnsbl {
			qstate.noCacheStore = 1
		}

		// Create list of Domain/CNAMES to be evaluated
		var validate []string

		// Skip 'in-addr.arpa' domains
		if !strings.HasSuffix(qNameOriginal, ".in-addr.arpa") && !bypassDnsbl {
			validate = append(validate, qNameOriginal)

			// DNSBL CNAME Validation
			if settings.pythonCname && qstate.returnMsg != nil {
				r := qstate.returnMsg.rep
				if r.anNumrrsets > 1 {
					for i := range r.anNumrrsets {
						rr := r.rrsets[i]

						if rr.rk.typeStr != "CNAME" {
							continue
						}

						for j := range rr.entry.data.count {
							// #714 FIX #3: compare the is_unknown() sentinel BEFORE lowering it: convert_other returns the
							// literal "Unknown" on a decode failure, which lowered never equals it.
							domain := convertOther(rr.entry.data.rrData[j])
							if domain != "Unknown" {
								validate = append(validate, pysem.Lower(domain))
							}
						}
					}
				}
			}
		}

		isCNAME := false
		for valCounter, qName := range validate {
			if valCounter > 0 {
				isCNAME = true
			}

			// One coherent verdict per name in decisionDB: a block, OR an allow ("let Unbound resolve it" / whitelisted),
			// both memoized. issue #1074: a foreign-generation memo is stale, so the stamp, not mere presence, decides
			// validity.
			var memo any = UNSET
			if dec, ok := m.decisionDB.get(qName); ok && dec.snapGen == snap.gen {
				memo = dec.getDnsbl()
			}
			var dnsbl *dnsblDecision
			if memo == UNSET {
				// The original query's TLD comes from qstate; a CNAME target has its own TLD, so derive it from the target
				// being evaluated, else the TLD-Allow / HSTS checks use the wrong TLD for the target.
				var tld string
				if isCNAME {
					tld = getTldFromName(qName)
				} else {
					tld = getTld(qstate)
				}
				dnsbl = evaluateDomain(qName, qNameOriginal, tld, isCNAME, m.evaluateCfg(snap), snap.containers())

				// A block found via a CNAME chain is recorded against the ORIGINAL queried name, so a later query for it
				// short-circuits on this entry.
				if dnsbl.isFound && !dnsbl.inWhitelist && isCNAME {
					qName = qNameOriginal
				}

				// Memoize the verdict on the name's Decision (block OR allow), stamped with this query's generation.
				// Bug #3775 is not reproduced: the allow of a CNAME chain whose original name is whitelisted is the
				// chain's verdict, not the target's own, so it is not memoized under the target's name (a direct query for
				// the target would resolve for every client); the cost is evaluating that target again.
				if !(isCNAME && dnsbl.inWhitelist) {
					decisionFor(m.decisionDB, qName, snap.gen).setDnsbl(dnsbl)
				}

				// ADR-08: a Confusable-mode ALERT (suspicious/flagged, or malicious with block disabled) does NOT block but is
				// surfaced once, here, on the fresh evaluation, in the same dnsbl.log shape as a block; a repeat query reuses the
				// cached decision and is not re-logged (issue #1349: block and alert stay exclusive after cache retirement).
				if dnsbl.idnAlert != nil && !(dnsbl.isFound && !dnsbl.inWhitelist) {
					listenerIP, listenerInterface := getQListener(qstate, nil)
					m.logIdnAlert(qName, qIP, *dnsbl.idnAlert, getQType(qstate, nil), getQTransport(qstate, nil), listenerIP, listenerInterface)
				}
			} else {
				dnsbl = memo.(*dnsblDecision)
				if isCNAME && dnsbl.isFound && !dnsbl.inWhitelist {
					// Memo hit on the CNAME *target*: re-evaluate in the original QNAME's CNAME-chain context so the
					// original's whitelist still applies (issue #3222), then answer in the original's bailiwick only if that
					// context is still a block.
					dnsbl = evaluateDomain(qName, qNameOriginal, getTldFromName(qName), true, m.evaluateCfg(snap), snap.containers())
					if dnsbl.isFound && !dnsbl.inWhitelist {
						qName = qNameOriginal
						decisionFor(m.decisionDB, qNameOriginal, snap.gen).setDnsbl(dnsbl)
					}
				}
			}

			// Block iff found and not whitelisted; an allow decision falls through to the resolver (the WAIT_MODULE below).
			if dnsbl.isFound && !dnsbl.inWhitelist {
				// issue #31: NXDOMAIN block shape ("3" logged / "4" silent): a bare NXDOMAIN rcode with NO answer records,
				// uncached for the same #43 reasons as the VIP/null path below; still attributed and logged (get_details_dnsbl
				// drops the row for log type 4).
				if dnsbl.nxdomain {
					m.getDetailsDnsbl("dnsbl", nil, qstate, &logKwargs{pfbAddr: &qIP}, dnsbl, snap.groupEpochs[[2]string{dnsbl.groupOwner, dnsbl.groupOrigin}])
					qstate.returnRcode = RCODE_NXDOMAIN
					qstate.noCacheStore = 1
					qstate.extState[id] = MODULE_FINISHED
					return true
				}

				// Create FQDN Reply Message
				msg := newDNSMessage(qstate.qinfo.qnameStr, qType, RR_CLASS_IN, PKT_QR|PKT_RA)

				if dnsbl.logType != "5" && dnsbl.logType != "6" {
					if qType == RR_TYPE_A || qType == RR_TYPE_ANY {
						ip := settings.dnsblIpv4
						if dnsbl.nullBlocking {
							ip = "0.0.0.0"
						}
						msg.answer = append(msg.answer, fmt.Sprintf("%s. 3600 IN A %s", qName, ip))
					}
					if qType == RR_TYPE_AAAA || qType == RR_TYPE_ANY {
						ip := settings.dnsblIpv6
						if dnsbl.nullBlocking {
							ip = "::"
						}
						msg.answer = append(msg.answer, fmt.Sprintf("%s. 3600 IN AAAA %s", qName, ip))
					}
				}
				// issue #3222: empty answer -> RFC 2308 Type-2 NODATA (SOA in AUTHORITY).
				if len(msg.answer) == 0 {
					msg.authority = append(msg.authority, fmt.Sprintf("%s. 3600 IN SOA %s", qName, DNSBL_NODATA_SOA_RDATA))
				}

				if !msg.setReturnMsg(qstate) {
					qstate.extState[id] = MODULE_ERROR
					return true
				}

				// Log entry.
				m.getDetailsDnsbl("dnsbl", nil, qstate, &logKwargs{pfbAddr: &qIP}, dnsbl, snap.groupEpochs[[2]string{dnsbl.groupOwner, dnsbl.groupOrigin}])

				qstate.returnRcode = RCODE_NOERROR
				qstate.returnMsg.rep.security = secStatusIndeterminate
				// Do not store the synthetic block reply in Unbound's C message cache (#43): a cached block is served ahead
				// of this module, so repeat queries would skip operate() and the feed-attributed logger, and a name removed
				// from a list would keep blocking until the TTL.
				qstate.noCacheStore = 1
				qstate.extState[id] = MODULE_FINISHED
				return true
			}
		}
	}

	if event == MODULE_EVENT_NEW || event == MODULE_EVENT_PASS {
		qstate.extState[id] = MODULE_WAIT_MODULE
		return true
	}

	if event == MODULE_EVENT_MODDONE {
		// SafeSearch CNAME redirect (duckduckgo.com / pixabay.com). Handled here, post-resolution, because Unbound will
		// not chase a CNAME the module hands it (issue #149 / unbound #976): we plant the synthetic CNAME in the cache
		// and restart the iterator so it chases the target itself. The first pass (plant + restart) and the second
		// pass (fix DNSSEC + finish, or the baked fallback) are distinguished inside safesearchCnameRedirect by the
		// resolved answer.
		if qstateValid && settings.safeSearchDB {
			if isSafeSearch, found := m.safesearchEntry(snap, qNameOriginal); found && isSafeSearch.a == "cname" {
				if safesearchCnameRedirect(snap, id, qstate, qType, isSafeSearch) {
					return true
				}
			}
		}

		// Log entry. A record too short for its type is the IndexError Python lets out of operate(): a module error.
		var replyErr error
		if qstateValid && qstate.returnMsg != nil {
			replyErr = m.getDetailsReply("reply", nil, qstate, qstate.returnMsg.rep, &logKwargs{pfbAddr: &qIP})
		} else {
			replyErr = m.getDetailsReply("reply", nil, qstate, nil, nil)
		}
		if replyErr != nil {
			logErr("[pfBlockerNG]: get_details_reply: " + replyErr.Error())
			qstate.extState[id] = MODULE_ERROR
			return true
		}

		qstate.extState[id] = MODULE_FINISHED
		return true
	}

	logErr("[pfBlockerNG]: BAD event")
	qstate.extState[id] = MODULE_ERROR
	return true
}
