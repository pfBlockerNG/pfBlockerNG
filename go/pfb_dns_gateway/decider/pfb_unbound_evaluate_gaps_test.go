// Rows added after a mutation run over pfb_unbound_evaluate_test.go left them alive: the band ties between the
// discovery and the re-scan, the built-in strata's feed band under the numeric path, the tie order inside
// scanBlockBand, and the CNAME allow band taking the higher of the two names. The expected decisions of the evaluate
// rows were produced by running evaluate_domain in Python (uv run python, Python 3.11, this worktree).
package decider

import "testing"

func TestEvaluateDomainBandTiesAndBuiltinBands(t *testing.T) {
	fg := map[int]feedGroup{1: {"FeedA", "GroupA"}}
	// python_blocking off: the discovery skips data and zone, but the numeric re-scan still reads them.
	numeric := func(over func(*evaluateConfig)) evaluateConfig {
		cfg := evCfg()
		cfg.pythonBlocking, cfg.importantRules = false, true
		over(&cfg)
		return cfg
	}

	// A tie keeps the discovered attribution: TLD_Allow (band 1) against a data entry of band 1.
	evCheck(t, "E1 a tie with the TLD_Allow discovery", evEval("x.example.net", "net", false,
		numeric(func(c *evaluateConfig) { c.dataDB, c.tldAllow, c.tldAllowList = true, true, []string{"com"} }),
		matcherContainers{dataDB: map[string]*blockEntry{"x.example.net": evBlk("2", 1, PRIO_FEED_BLOCK)}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "TLD_Allow", group: "DNSBL_TLD_Allow", bEval: "x.example.net", groupOwner: "DNSBL_TLD_Allow", groupOrigin: "builtin"})
	// A strictly higher band wins: the important data entry (band 3) takes over from TLD_Allow.
	evCheck(t, "E1b a higher band wins over the TLD_Allow discovery", evEval("x.example.net", "net", false,
		numeric(func(c *evaluateConfig) { c.dataDB, c.tldAllow, c.tldAllowList = true, true, []string{"com"} }),
		matcherContainers{dataDB: map[string]*blockEntry{"x.example.net": evBlk("2", 1, PRIO_FEED_BLOCK_IMPORTANT)}, feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: true, logType: "2", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "x.example.net", groupOwner: "GroupA", groupOrigin: "custom"})
	// A tie keeps the discovered user regex against a data entry of the same band, which the re-scan reads first.
	evCheck(t, "E2 a tie with the regex discovery", evEval("evil.com", "com", false,
		numeric(func(c *evaluateConfig) { c.dataDB, c.userRegexDB = true, true }),
		matcherContainers{dataDB: map[string]*blockEntry{"evil.com": evBlk("2", 1, PRIO_USER_BLOCK)}, userRegexDB: evRegexDB(evRx("U#0", "evil", PRIO_USER_BLOCK)), feedGroupIndexDB: fg}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "U#0", group: "DNSBL_Regex", bEval: "evil.com"})

	// The IDN blocks carry the feed band, so under the numeric path with no allow they stand (band 1 > 0), where a
	// band of 0 would read as already overridden.
	cfg := evCfg()
	cfg.importantRules, cfg.idnMode = true, IdnModeAll
	evCheck(t, "E3a All-IDN under the numeric path, no allow", evEval("xn--any1234.uuid1011.com", "com", false, cfg, matcherContainers{}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "IDN", group: "DNSBL_IDN", bEval: "xn--any1234.uuid1011.com", groupOwner: "DNSBL_IDN", groupOrigin: "builtin"})
	cfg.idnMode = IdnModeConfusable
	evCheck(t, "E3b Confusable block under the numeric path, no allow", evEval("xn--pple-43d.com", "com", false, cfg, matcherContainers{}),
		dd{isFound: true, nullBlocking: true, logType: "0", bType: "Python", pType: "Python", feed: "Homoglyph", group: "DNSBL_Homoglyph", bEval: "xn--pple-43d [аpple] Cyrillic Latin", groupOwner: "DNSBL_Homoglyph", groupOrigin: "builtin"})

	// E4: a CNAME target is allowed at the higher band of its own name (4) and the original name (2), against block 3.
	cfg = evCfg()
	cfg.dataDB, cfg.whiteDB, cfg.importantRules = true, true, true
	evCheck(t, "E4 the CNAME allow takes the higher band of the two names", evaluateDomain("t.net", "orig.com", "net", true, cfg, matcherContainers{
		dataDB:           map[string]*blockEntry{"t.net": evBlk("1", 1, PRIO_FEED_BLOCK_IMPORTANT)},
		whiteDB:          map[string]whiteEntry{"t.net": evWhite(false, false, 4), "orig.com": evWhite(false, false, 2)},
		feedGroupIndexDB: fg}),
		dd{isFound: true, inWhitelist: true, nullBlocking: true, logType: "1", bType: "DNSBL", pType: "Python", feed: "FeedA", group: "GroupA", bEval: "t.net", groupOwner: "GroupA", groupOrigin: "custom"})
}

// scanBlockBand keeps the first-scanned holder on a band tie: the deepest zone suffix, and data before zone.
func TestScanBlockBandTieOrder(t *testing.T) {
	cfg := evCfg()
	cfg.dataDB, cfg.zoneDB = true, true
	zone := map[string]*blockEntry{"evil.com": evBlk("1", 0, PRIO_FEED_BLOCK), "com": evBlk("1", 1, PRIO_FEED_BLOCK)}
	if band, meta := scanBlockBand("x.evil.com", cfg, nil, zone, nil, nil); band != PRIO_FEED_BLOCK || meta == nil || meta.kind != "zone" || meta.matched != "evil.com" {
		t.Errorf("two zone suffixes of one band: got (%d, %s), want (1, zone evil.com)", band, evMeta(meta))
	}
	data := map[string]*blockEntry{"x.evil.com": evBlk("1", 2, PRIO_FEED_BLOCK)}
	if band, meta := scanBlockBand("x.evil.com", cfg, data, zone, nil, nil); band != PRIO_FEED_BLOCK || meta == nil || meta.kind != "data" {
		t.Errorf("data and zone of one band: got (%d, %s), want (1, data)", band, evMeta(meta))
	}
}

// An empty query name evaluates no allow regex, even one that matches the empty string.
func TestScanAllowRegexBandEmptyNameMatchesNothing(t *testing.T) {
	rt := newRegexRuntime()
	matchAll := evRegexDB(evRx("R", "", PRIO_FEED_ALLOW))
	if got := scanAllowRegexBand(rt, "", matchAll, matchAll, 10.0); got != 0 {
		t.Errorf("band = %d, want 0 for an empty query name", got)
	}
	if got := scanAllowRegexBand(rt, "x.example", matchAll, nil, 10.0); got != PRIO_FEED_ALLOW {
		t.Errorf("control: band = %d, want %d for a named query", got, PRIO_FEED_ALLOW)
	}
}
