package decider

import "testing"

// A built-in regex block takes the log flag (the global mechanism) of the build config, never the log flag of the data
// entry it overrode. The numeric scan re-attributes a block to a STRICTLY higher-band regex rule when important rules
// are loaded, and the re-attributed block must carry builtinLogFlag; every flag but "1" tells that apart from a
// hard-coded "1".
func TestNumericReattributionToHigherBandRegexTakesTheBuiltinLogFlag(t *testing.T) {
	const q = "evil.com"
	for _, flag := range []string{"0", "1", "2", "3", "4", "5", "6"} {
		t.Run("flag "+flag, func(t *testing.T) {
			cfg := evCfg()
			cfg.dataDB, cfg.regexDB, cfg.importantRules = true, true, true
			cfg.builtinLogFlag = flag
			containers := matcherContainers{
				// the data hit is found first with a sentinel log flag that the re-attribution must replace
				dataDB:           map[string]*blockEntry{q: evBlk("9", 0, PRIO_FEED_BLOCK)},
				regexDB:          evRegexDB(evRule{name: "important-rule", pattern: "evil", band: PRIO_FEED_BLOCK_IMPORTANT, important: true}),
				feedGroupIndexDB: evFG,
			}
			got := evEval(q, "com", false, cfg, containers)
			if !got.isFound || got.inWhitelist || got.feed != "important-rule" || got.group != "DNSBL_Regex" {
				t.Fatalf("decision = %s, want the block re-attributed to important-rule / DNSBL_Regex", evDump(*got))
			}
			if got.logType != flag || got.pType != "Python" {
				t.Errorf("(logType, pType) = (%q, %q), want (%q, \"Python\")", got.logType, got.pType, flag)
			}
			switch flag {
			case "0", "1", "2": // issue #4053: flag 1 (the removed VIP) answers null like 0 and 2
				if !got.nullBlocking || got.nxdomain {
					t.Errorf("(nullBlocking, nxdomain) = (%v, %v), want (true, false)", got.nullBlocking, got.nxdomain)
				}
			case "3", "4":
				if !got.nxdomain {
					t.Errorf("nxdomain = false, want true")
				}
			default: // "5", "6"
				if got.nxdomain {
					t.Errorf("nxdomain = true, want false: NODATA is no NXDOMAIN")
				}
			}
		})
	}
}
