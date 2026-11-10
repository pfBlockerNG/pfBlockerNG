// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the decision evaluator: the regex scan machinery
// (5606-5800), the band resolution and its scans (7130-7343), _tld_allow_blocks and evaluate_domain (7371-7676),
// _evaluate_cfg (7679-7731) and get_tld / get_tld_from_name (2757-2795).
//
// Every function here reads only its arguments: evaluateDomain takes the cfg and containers the query's one snapshot
// produced (see evaluateCfg), so a swap that lands mid-query never reaches it. The module globals the regex scans
// keep in Python (_regex_warned, the prefilter index slots) are a regexRuntime the pfbUnbound holds.
package decider

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// REGEX_REFUSAL_LOG_MAX: the first this many refusal lines of a regex list are written, the rest are counted into one
// summary line.
const REGEX_REFUSAL_LOG_MAX = 20

// regexRuntime is what the regex scans keep in module globals in Python: the set that rate-limits the slow-match
// warnings to one line per rule and one per list. It is shared by every concurrent query of a module, hence the mutex.
// The four literal-prefilter index slots are not here: regexCandidates has no prefilter to cache.
type regexRuntime struct {
	mu     sync.Mutex
	warned map[string]struct{}
	// timedSearch is _regex_timed_search; tests replace it with a fixed measurement.
	timedSearch func(re *regexp.Regexp, qName string) (matched bool, elapsedMs float64)
}

func newRegexRuntime() *regexRuntime {
	return &regexRuntime{warned: map[string]struct{}{}, timedSearch: regexTimedSearch}
}

// reset is Python's `_regex_warned.clear()`, run on every (re)load so a swapped-in list warns afresh.
func (r *regexRuntime) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.warned)
}

// firstWarning adds key to the warned set and reports whether it was not in it yet.
func (r *regexRuntime) firstWarning(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.warned[key]; ok {
		return false
	}
	r.warned[key] = struct{}{}
	return true
}

// shortcut: Python times a match with time.thread_time (per-thread CPU, so a descheduled thread is not reported slow)
// and falls back to time.perf_counter where it is absent. A goroutine migrates between threads and Go has no
// per-goroutine CPU clock, so this is Python's own fallback, the wall clock: a descheduled goroutine can only
// over-report, which writes a spurious slow-match warning and never changes a decision. Upgrade if the warning proves
// noisy on a loaded box.
func regexTimedSearch(re *regexp.Regexp, qName string) (bool, float64) {
	start := time.Now()
	matched := re.MatchString(qName)
	return matched, float64(time.Since(start)) / float64(time.Millisecond)
}

// warnSlow logs ONE warning per rule when a match of rule name of the list label took elapsedMs, over warnMs. Rule
// names repeat across lists, so a rule is known by its list and its name. Warn only: the rule stays loaded.
func (r *regexRuntime) warnSlow(name string, elapsedMs, warnMs float64, label string) {
	if elapsedMs <= warnMs || !r.firstWarning(label+":"+name) {
		return
	}
	logErr(fmt.Sprintf("[pfBlockerNG]: slow %s regex [ %s ] took %.1f ms (warn ceiling %.1f ms)", label, name, elapsedMs, warnMs))
}

// regexScan is one pass over one regex list: it times every match, warns per slow rule, and report writes the ONE
// per-list line (per load) when the rules of the pass summed over the warn ceiling. A pass that stops on its first
// match reports what it timed.
type regexScan struct {
	rt        *regexRuntime
	label     string
	warnMs    float64
	rules     int
	totalMs   float64
	slowest   string
	slowestMs float64
}

// newRegexScan starts a pass over the list of group; a user list is labelled apart from the feed list of the same
// group, and warns for its rules apart too.
func newRegexScan(rt *regexRuntime, group string, warnMs float64, user bool) regexScan {
	label := group
	if user {
		label = "user " + group
	}
	return regexScan{rt: rt, label: label, warnMs: warnMs}
}

func (s *regexScan) search(name string, rule *regexEntry, qName string) bool {
	matched, elapsedMs := s.rt.timedSearch(rule.re, qName)
	s.rt.warnSlow(name, elapsedMs, s.warnMs, s.label)
	s.rules++
	s.totalMs += elapsedMs
	if elapsedMs > s.slowestMs {
		s.slowest, s.slowestMs = name, elapsedMs
	}
	return matched
}

func (s *regexScan) report() {
	if s.totalMs <= s.warnMs || !s.rt.firstWarning("list:"+s.label) {
		return
	}
	logErr(fmt.Sprintf("[pfBlockerNG]: slow %s regex list scan took %.1f ms over %d rules (warn ceiling %.1f ms); slowest [ %s ] %.1f ms",
		s.label, s.totalMs, s.rules, s.warnMs, s.slowest, s.slowestMs))
}

// regexCandidates is the names of the rules of regexDB that can match qName.
//
// shortcut: Python buckets the rules by the first character of a literal that every match must contain (read from
// CPython's private re._parser) and skips the rules whose literal the query lacks. That prefilter only drops rules
// that cannot match, so the blocked / allowed verdict and its band are the same with every rule a candidate. Two
// observable differences remain. (1) Go times every rule of the list where Python times only the prefilter
// candidates, so the per-list slow-scan line (the rule count and the slowest rule) can differ from Python's; it is
// log text only, no decision reads it. (2) Candidates keep list order, where Python iterates a set (hash order, which
// varies with PYTHONHASHSEED): when two rules of one list match at the SAME band, the one scanned first holds the
// meta, so the feed, group, group_owner and group_origin the band re-scan re-attributes to can differ from Python's
// pick; the band, and so the decision, cannot. Go needs its own walk of regexp/syntax for the same skip. Upgrade
// when scanning a large list shows up in a profile. The returned slice is the list's own; never modify it.
func regexCandidates(regexDB *regexDB, qName string) []string {
	if regexDB == nil {
		return nil
	}
	return regexDB.names
}

// blockMeta describes the entry that carries the best block band, so the caller can re-attribute feed / group /
// log_type / b_type / b_eval to the rule that actually won (issue #47): kind "data" (b_type DNSBL, b_eval the query),
// "zone" (b_type TLD, matched the suffix) or "regex" (feed = key, group DNSBL_Regex).
type blockMeta struct {
	kind    string
	key     string
	matched string
	block   *blockEntry // data and zone
	regex   *regexEntry // regex
}

// bestBlockRegex folds the matching rules among candidates of one block-regex list into (best, bestMeta): a rule
// replaces the holder only with a strictly higher band. A regex payload is not a blockEntry, so its band is read
// directly where Python calls _block_entry_band.
func bestBlockRegex(regexDB *regexDB, candidates []string, qName string, scan *regexScan, best int, bestMeta *blockMeta) (int, *blockMeta) {
	for _, key := range candidates {
		rule, _ := regexDB.get(key)
		if scan.search(key, rule, qName) {
			if band := rule.band; band > best {
				best, bestMeta = band, &blockMeta{kind: "regex", key: key, regex: rule}
			}
		}
	}
	scan.report()
	return best, bestMeta
}

// bestAllowRegex is the highest allow band among the matching rules of candidates of one allow-regex list and best.
func bestAllowRegex(allowRegexDB *regexDB, candidates []string, qName string, scan *regexScan, best int) int {
	for _, key := range candidates {
		rule, _ := allowRegexDB.get(key)
		if scan.search(key, rule, qName) {
			best = max(best, rule.band)
		}
	}
	scan.report()
	return best
}

// scanBlockBand is the highest block band that matches qName across dataDB (exact), zoneDB (the suffix walk) and the
// block-regex DBs (the user list, then the feed list), AND the winning entry that carries it; (0, nil) when nothing
// matched. The numeric 6-band resolution takes the max block band (decide() semantics), where the fast-path discovery
// short-circuits on the first hit. On a tie the first scanned kind (data, zone, regex; the user list before the feed
// one) holds the meta, and the caller only re-attributes when this band strictly exceeds the discovered one.
func scanBlockBand(qName string, cfg evaluateConfig, dataDB, zoneDB map[string]*blockEntry, regexDB, userRegexDB *regexDB) (int, *blockMeta) {
	best := 0
	var bestMeta *blockMeta
	if cfg.dataDB {
		if entry := dataDB[qName]; entry != nil {
			if band := blockEntryBand(entry); band > best {
				best, bestMeta = band, &blockMeta{kind: "data", block: entry}
			}
		}
	}
	if cfg.zoneDB {
		for q := range iterDomainSuffixes(qName) {
			if entry := zoneDB[q]; entry != nil {
				if entry = zoneEntryFor(qName, entry); entry != nil {
					if band := blockEntryBand(entry); band > best {
						best, bestMeta = band, &blockMeta{kind: "zone", block: entry, matched: q}
					}
				}
			}
		}
	}
	if qName != "" {
		// Each match is timed (ADR-07): a rule over the warn ceiling logs once, a list over it in total logs once, the
		// same policy as the discovery scan; no rule is removed from the live DBs.
		if cfg.userRegexDB {
			scan := newRegexScan(cfg.regex, "DNSBL_Regex", cfg.regexWarnMs, true)
			best, bestMeta = bestBlockRegex(userRegexDB, regexCandidates(userRegexDB, qName), qName, &scan, best, bestMeta)
		}
		if cfg.regexDB {
			scan := newRegexScan(cfg.regex, "DNSBL_Regex", cfg.regexWarnMs, false)
			best, bestMeta = bestBlockRegex(regexDB, regexCandidates(regexDB, qName), qName, &scan, best, bestMeta)
		}
	}
	return best, bestMeta
}

// scanAllowRegexBand is the highest allow band over the allow-regex (@@/re/) entries, the user list then the feed
// list, that match qName; 0 if none match. Each match is timed like scanBlockBand's.
func scanAllowRegexBand(rt *regexRuntime, qName string, allowRegexDB, userAllowRegexDB *regexDB, warnMs float64) int {
	if qName == "" {
		return 0
	}
	best := 0
	if userAllowRegexDB.len() > 0 {
		scan := newRegexScan(rt, "DNSBL_AllowRegex", warnMs, true)
		best = bestAllowRegex(userAllowRegexDB, regexCandidates(userAllowRegexDB, qName), qName, &scan, best)
	}
	if allowRegexDB.len() > 0 {
		scan := newRegexScan(rt, "DNSBL_AllowRegex", warnMs, false)
		best = bestAllowRegex(allowRegexDB, regexCandidates(allowRegexDB, qName), qName, &scan, best)
	}
	return best
}

// firstRegexMatch is the first rule of one block-regex list that matches qName as (name, payload), or ("", nil). The
// pass is timed through scan and reports what it timed even when it stops on the match.
func firstRegexMatch(regexDB *regexDB, qName string, scan *regexScan) (string, *regexEntry) {
	var foundName string
	var found *regexEntry
	for key, rule := range regexDB.items() {
		if scan.search(key, rule, qName) {
			foundName, found = key, rule
			break
		}
	}
	scan.report()
	return foundName, found
}

// resolveNumericAllow is the numeric 6-band resolution (ADR.md SS2): true iff an ALLOW overrides the matched BLOCK (the
// name resolves), mapped onto in_whitelist so the downstream hsts / null-blocking logic is shared with the fast path.
// A block always matched here (the caller gates on is_found); blockBand is its highest matching band. Blocked iff
// blockBand > allow band; with no allow match the allow band is 0, so the block stands.
func resolveNumericAllow(qName, qNameOriginal string, isCname bool, cfg evaluateConfig, whiteDB map[string]whiteEntry, allowRegexDB, userAllowRegexDB *regexDB, blockBand int) bool {
	allowBand := 0
	if cfg.whiteDB {
		allowBand = max(allowBand, whitelistLookupBand(qName, whiteDB, cfg.pythonTldSeg))
		if isCname {
			allowBand = max(allowBand, whitelistLookupBand(qNameOriginal, whiteDB, cfg.pythonTldSeg))
		}
	}
	if cfg.userAllowRegexDB || cfg.allowRegexDB {
		allowBand = max(allowBand, scanAllowRegexBand(cfg.regex, qName, allowRegexDB, userAllowRegexDB, cfg.regexWarnMs))
	}
	return allowBand >= blockBand
}

// blockGroupFields is the entry's group_owner / group_origin, where Python reads .get("group_owner", group) and
// .get("group_origin", "custom").
func blockGroupFields(entry *blockEntry, group string) (owner, origin string) {
	owner, origin = group, "custom"
	if entry.hasGroupOwner {
		owner = entry.groupOwner
	}
	if entry.hasGroupOrigin {
		origin = entry.groupOrigin
	}
	return owner, origin
}

// lastLabel is s.rsplit(".", 1)[-1].
func lastLabel(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// tldAllowBlocks reports whether PSL-aware TLD-Allow should create its synthetic block.
//
// shortcut: Python falls back to cfg["psl_rules"] / cfg["psl_allow_private"] when a hand-built containers dict lacks
// the key; matcherContainers always carries both, so the cfg fallback has no Go counterpart.
func tldAllowBlocks(qName, tld string, cfg evaluateConfig, containers matcherContainers) bool {
	if !cfg.tldAllow {
		return false
	}
	selected := cfg.tldAllowList
	if len(selected) == 0 {
		selected = containers.tldAllowRoots
	}
	roots := selectedTldRoots(selected)
	if len(roots) == 0 || tld == "" {
		return false
	}
	labels, err := pslNormalizeQuery(strings.TrimRight(qName, "."))
	if err != nil {
		// Structurally invalid names cannot be matched safely; fail closed.
		return true
	}
	icannSets, combinedSets := containers.pslRules.index()
	icannSuffix, publicSuffix := pslPrevailing(labels, icannSets, combinedSets)
	for _, suffix := range [4]string{icannSuffix, publicSuffix, lastLabel(icannSuffix), lastLabel(publicSuffix)} {
		if slices.Contains(roots, suffix) {
			return false
		}
	}
	// The allow toggle stands alone: PRIVATE recognition (psl_include_private) gates wildcard CLASSIFICATION only,
	// never TLD-Allow precision.
	if containers.pslAllowPrivate && strings.Count(publicSuffix, ".") > strings.Count(icannSuffix, ".") {
		return false
	}
	return true
}

// evaluateConfig is the per-query cfg dict evaluate_domain reads, built by evaluateCfg from one snapshot. The
// presence gates (dataDB .. hstsDB) say whether that list is non-empty. cfg's psl_rules / psl_include_private /
// psl_allow_private are not here: evaluate_domain only reads them as a fallback for a containers dict without them.
type evaluateConfig struct {
	pythonBlocking              bool
	dataDB                      bool
	zoneDB                      bool
	tldAllow                    bool
	tldAllowList                []string
	dnsblIpv4                   string
	dnsblIpv6                   string
	pythonIdn                   bool
	idnMode                     IdnMode
	pythonIdnBlockMalicious     bool
	pythonIdnEscalateSuspicious bool
	regexDB                     bool
	whiteDB                     bool
	allowRegexDB                bool
	userRegexDB                 bool
	userAllowRegexDB            bool
	importantRules              bool
	regexWarnMs                 float64
	pythonTldSeg                int64
	hstsDB                      bool
	hstsTlds                    []string
	builtinLogFlag              string
	regex                       *regexRuntime
}

func evaluateDomain(qName, qNameOriginal, tld string, isCname bool, cfg evaluateConfig, containers matcherContainers) *dnsblDecision {
	isFound := false
	logType := ""
	inWhitelist := false
	inHsts := false
	nullBlocking := true
	nxdomain := false
	bType := "Python"
	pType := "Python"
	feed := "Unknown"
	group := "Unknown"
	groupOwner := ""
	groupOrigin := ""
	bEval := ""
	// ADR-08: a Confusable-mode ALERT (non-blocking) records its attribution here so operate() can log it while the
	// name still resolves; nil on the common path.
	var alert *idnAlert
	// The dual-form description of a Confusable BLOCK (xn-- [decoded] script), captured in the IDN branch and written
	// into b_eval AFTER the generic "b_eval = q_name" below, so the log line is actionable instead of the bare A-label.
	idnBlockBEval, hasIdnBlockBEval := "", false

	// blockBand carries the discovered block's numeric band (1-5) into the numeric resolution below; the fast path
	// never reads it.
	blockBand := 0

	// STEP A/B/C strata (ADR.md SS2): user-allow / user-block / feed rules. Provenance is not tagged on loaded entries
	// yet, so today's discovery is structurally the feed stratum: data (exact), zone (wildcard), tld-allow, idn,
	// block-regex.
	if cfg.pythonBlocking {
		if cfg.dataDB {
			if dataEntry := containers.dataDB[qName]; dataEntry != nil {
				isFound = true
				logType = dataEntry.log
				feed, group = resolveFeedGroup(dataEntry.index, containers.feedGroupIndexDB)
				groupOwner, groupOrigin = group, "custom"
				bType = "DNSBL"
				bEval = qName
				blockBand = blockEntryBand(dataEntry)
			}
		}

		if !isFound && cfg.zoneDB {
			matchedQ, zoneEntry := findZoneMatch(qName, containers.zoneDB)
			if zoneEntry != nil {
				isFound = true
				logType = zoneEntry.log
				feed, group = resolveFeedGroup(zoneEntry.index, containers.feedGroupIndexDB)
				groupOwner, groupOrigin = blockGroupFields(zoneEntry, group)
				bType = "TLD"
				bEval = matchedQ
				blockBand = blockEntryBand(zoneEntry)
			}
		}
	}

	if !isFound {
		if qName != cfg.dnsblIpv4 && qName != cfg.dnsblIpv6 && tldAllowBlocks(qName, tld, cfg, containers) {
			isFound = true
			feed = "TLD_Allow"
			group = "DNSBL_TLD_Allow"
			groupOwner, groupOrigin = "DNSBL_TLD_Allow", "builtin"
			// Feed-stratum block band: without it blockBand stays 0, and the numeric resolution (blocked iff
			// blockBand > allow band) would treat band 0 as already overridden by any allow (allow band >= 0 is always
			// true), so a disallowed-TLD query would resolve instead of being blocked.
			blockBand = PRIO_FEED_BLOCK
		}

		// ADR-08: the IDN feed. idn_mode is the three-valued selector; an absent or unrecognised one falls back to the
		// legacy python_idn (True: All-IDN), preserving the pre-ADR-08 behaviour.
		if !isFound {
			idnMode := cfg.idnMode
			switch idnMode {
			case IdnModeOff, IdnModeAll, IdnModeConfusable:
			default:
				idnMode = idnModeFromLegacy(cfg.pythonIdn)
			}
			// All-IDN / Off arm: idn_mode_decision blocks IFF All-IDN on an xn-- query.
			if idnModeDecision(qName, idnMode) {
				isFound = true
				feed = "IDN"
				group = "DNSBL_IDN"
				groupOwner, groupOrigin = "DNSBL_IDN", "builtin"
				// An IDN block is a feed-stratum block: give it the feed band so the numeric path doesn't treat
				// blockBand=0 as already overridden (allow band >= 0 is always true) and resolve it anyway.
				blockBand = PRIO_FEED_BLOCK
			} else if idnMode == IdnModeConfusable {
				// Confusable arm: decode + TR39 mixed-script analysis, PER-LABEL, gated by is_idn_domain (a non-xn--
				// query pays nothing). classify_idn is decode-safe: a malformed label is FLAGGED, never raised.
				action, verdict := idnConfusableAction(qName, cfg.pythonIdnBlockMalicious, cfg.pythonIdnEscalateSuspicious)
				if action == IDN_ACT_BLOCK && verdict != nil {
					// Malicious (or escalated suspicious / flagged) -> block, attributed apart from the All-IDN feed.
					isFound = true
					blockBand = PRIO_FEED_BLOCK
					if verdict.severity == SEV_MALICIOUS {
						feed = IDN_FEED_MALICIOUS
						group = IDN_GROUP_MALICIOUS
					} else {
						feed = IDN_FEED_SUSPECT
						group = IDN_GROUP_SUSPECT
					}
					groupOwner, groupOrigin = group, "builtin"
					idnBlockBEval, hasIdnBlockBEval = idnDualForm(verdict), true
				} else if action == IDN_ACT_ALERT && verdict != nil {
					// Suspicious/flagged (or malicious with block disabled) -> ALERT only: the name still resolves
					// (isFound stays false); record the attribution so operate() emits a log line in the block-line shape.
					if verdict.severity == SEV_MALICIOUS {
						alert = &idnAlert{feed: IDN_FEED_MALICIOUS, group: IDN_GROUP_MALICIOUS, bEval: idnDualForm(verdict)}
					} else {
						alert = &idnAlert{feed: IDN_FEED_SUSPECT, group: IDN_GROUP_SUSPECT, bEval: idnDualForm(verdict)}
					}
				}
				// IDN_ACT_NONE (legit, or a non-xn-- name) -> no IDN action, resolves.
			}
		}

		if !isFound && qName != "" {
			// User block-regex first, then the feed list. Each match is TIMED; a pattern over the warn ceiling logs once,
			// and so does a list over it in total. A slow measurement is reported and never acted on.
			for _, l := range [2]struct {
				db             *regexDB
				loaded, isUser bool
			}{{containers.userRegexDB, cfg.userRegexDB, true}, {containers.regexDB, cfg.regexDB, false}} {
				if !l.loaded {
					continue
				}
				scan := newRegexScan(cfg.regex, "DNSBL_Regex", cfg.regexWarnMs, l.isUser)
				if name, rule := firstRegexMatch(l.db, qName, &scan); rule != nil {
					isFound = true
					feed = name
					group = "DNSBL_Regex"
					blockBand = rule.band
					groupOwner = rule.groupOwner
					groupOrigin = rule.groupOrigin
					break
				}
			}
		}

		if isFound {
			bEval = qName
			logType = cfg.builtinLogFlag // issue #3291: built-ins inherit the global mechanism
			// ADR-08: a Confusable BLOCK reports the dual form (xn-- [decoded] script) instead of the bare A-label. Only
			// set on the homoglyph block path; every other stratum keeps b_eval = q_name.
			if hasIdnBlockBEval {
				bEval = idnBlockBEval
			}
		}
	}

	// Resolution stratum. FAST PATH (important_rules False): the historical "a block is found, then an allow overrides
	// it": whiteDB checked as a plain override. The numeric 6-band resolution is the important_rules branch, reached
	// once an ABP feed (or user regex / Custom_List) loads a feed @@ / $important / feed-regex.
	if isFound {
		if !cfg.importantRules {
			if cfg.whiteDB {
				inWhitelist = whitelistCheckDomain(qName, containers.whiteDB, cfg.pythonTldSeg)
				if !inWhitelist && isCname {
					inWhitelist = whitelistCheckDomain(qNameOriginal, containers.whiteDB, cfg.pythonTldSeg)
				}
			}
		} else {
			// NUMERIC 6-band path: decide() resolves by the HIGHEST matching block band vs the highest matching allow
			// band, so augment the first-discovered block's band with a full scan over every matching block. When a
			// STRICTLY higher band wins, re-attribute feed/group/log_type/b_type/b_eval to that entry (issue #47): the
			// band decides priority, but reporting AND the response shape must follow the rule that actually won. A tie
			// keeps the discovered attribution (block bands are distinct odds, so a tie is the same entry / priority).
			scanBand, scanMeta := scanBlockBand(qName, cfg, containers.dataDB, containers.zoneDB, containers.regexDB, containers.userRegexDB)
			if scanMeta != nil && scanBand > blockBand {
				blockBand = scanBand
				if scanMeta.kind == "regex" {
					feed = scanMeta.key
					group = "DNSBL_Regex"
					groupOwner = scanMeta.regex.groupOwner
					groupOrigin = scanMeta.regex.groupOrigin
					logType = cfg.builtinLogFlag // issue #3291
					bType = "Python"
					bEval = qName
				} else {
					entry := scanMeta.block
					logType = entry.log
					feed, group = resolveFeedGroup(entry.index, containers.feedGroupIndexDB)
					groupOwner, groupOrigin = blockGroupFields(entry, group)
					if scanMeta.kind == "zone" {
						bType = "TLD"
						bEval = scanMeta.matched
					} else { // data
						bType = "DNSBL"
						bEval = qName
					}
				}
			}
			inWhitelist = resolveNumericAllow(qName, qNameOriginal, isCname, cfg, containers.whiteDB, containers.allowRegexDB, containers.userAllowRegexDB, blockBand)
		}
	}

	if isFound && !inWhitelist {
		if cfg.hstsDB {
			inHsts, pType = hstsCheckDomain(qName, containers.hstsDB, cfg.hstsTlds, tld)
		}

		if logType == "1" && !inHsts {
			nullBlocking = false
		} else if logType == "3" || logType == "4" || logType == "5" || logType == "6" {
			// NXDOMAIN and NODATA bypass address replies; HSTS did not cause the block.
			inHsts = false
			pType = "Python"
			nxdomain = logType == "3" || logType == "4"
		}

		if isCname {
			bType += "_CNAME"
		}
	}

	return &dnsblDecision{
		isFound:      isFound,
		inWhitelist:  inWhitelist,
		inHsts:       inHsts,
		nullBlocking: nullBlocking,
		nxdomain:     nxdomain,
		logType:      logType,
		bType:        bType,
		pType:        pType,
		feed:         feed,
		group:        group,
		bEval:        bEval,
		idnAlert:     alert,
		groupOwner:   groupOwner,
		groupOrigin:  groupOrigin,
	}
}

// evaluateCfg is operate()'s per-query cfg assembly (ADR-65), kept in one place so operate and the query channel
// cannot drift.
//
// ADR-10: the presence gates and importantRules come from snap, the snapshot the query captured, and every other key
// from the settings that snapshot carries; never from m.pfb, which a background swap does not refresh. Reading the
// gates from m.pfb would freeze them at the last restart's state, so a swap that introduced a NEW stratum would leave
// its gate false and the newly swapped block would never apply.
func (m *pfbUnbound) evaluateCfg(snap *snapshot) evaluateConfig {
	settings := snap.settings
	tldAllowList := snap.tldAllowRoots
	if !snap.hasTldAllowRoots {
		tldAllowList = selectedTldRoots(settings.tldAllowList)
	}
	// ADR-08: derive defensively so a settings value that predates idn_mode still resolves to today's mode.
	idnMode := settings.idnMode
	if idnMode == "" {
		idnMode = idnModeFromLegacy(settings.pythonIdn)
	}
	return evaluateConfig{
		pythonBlocking:              settings.pythonBlocking,
		dataDB:                      len(snap.dataDB) > 0,
		zoneDB:                      len(snap.zoneDB) > 0,
		tldAllow:                    settings.tldAllow,
		tldAllowList:                tldAllowList,
		dnsblIpv4:                   settings.dnsblIpv4,
		dnsblIpv6:                   settings.dnsblIpv6,
		pythonIdn:                   settings.pythonIdn,
		idnMode:                     idnMode,
		pythonIdnBlockMalicious:     settings.pythonIdnBlockMalicious,
		pythonIdnEscalateSuspicious: settings.pythonIdnEscalateSuspicious,
		regexDB:                     snap.regexDB.len() > 0,
		whiteDB:                     len(snap.whiteDB) > 0,
		allowRegexDB:                snap.allowRegexDB.len() > 0,
		userRegexDB:                 snap.userRegexDB.len() > 0,
		userAllowRegexDB:            snap.userAllowRegexDB.len() > 0,
		importantRules:              snap.importantRules,
		regexWarnMs:                 settings.regexWarnMs,
		pythonTldSeg:                settings.pythonTldSeg,
		hstsDB:                      len(snap.hstsDB) > 0,
		hstsTlds:                    settings.hstsTlds,
		builtinLogFlag:              snap.builtinLogFlag,
		regex:                       m.regexRuntime,
	}
}

// getTld is the TLD of the query: the second-to-last entry of the qname list (which carries the trailing root label),
// lowercased (RFC 4343: DNS names compare case-insensitively, but Unbound's qname_list keeps the client's wire case,
// e.g. dns0x20, while tld_allow_list / hsts_tlds are stored lowercase, #720).
func getTld(qstate *moduleQstate) string {
	tld := ""
	if qstate != nil {
		labels, err := qstate.qinfo.qnameList()
		if err != nil {
			// A qname carrying invalid UTF-8 makes Unbound's qname_list raise while decoding the labels; fall back to an
			// empty TLD rather than crashing the module on that query (mirrors get_q_name_qstate).
			logErr("[pfBlockerNG]: Failed get_tld: " + err.Error())
		} else if len(labels) > 1 {
			tld = pysem.Lower(labels[len(labels)-2])
		}
	}
	return tld
}

// getTldFromName is the TLD get_tld reads from the qname list, derived from a name string: for a CNAME target
// evaluated mid-chain, whose TLD differs from the original query's. Qname_list carries the trailing root label, so
// qname_list[-2] is the TLD; from a string the equivalent is the LAST label of the dot-split name (#706), lowercased
// like get_tld (#720).
func getTldFromName(qName string) string {
	name := strings.TrimRight(qName, ".")
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return pysem.Lower(name[i+1:])
}
