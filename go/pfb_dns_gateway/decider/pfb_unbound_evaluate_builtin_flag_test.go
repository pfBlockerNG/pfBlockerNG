package decider

import "testing"

// A built-in regex block takes the log flag (the global mechanism) of the build config, never the log flag of the data
// entry it overrode. The numeric scan re-attributes a block to a STRICTLY higher-band regex rule when important rules
// are loaded, and the re-attributed block must carry builtinLogFlag; every flag but "1" tells that apart from a
// hard-coded "1". Each flag runs with HSTS off and on, because the flag shapes the answer differently with the name in
// the HSTS list.
func TestNumericReattributionToHigherBandRegexTakesTheBuiltinLogFlag(t *testing.T) {
	const q = "evil.com"
	for _, flag := range []string{"0", "1", "2", "3", "4", "5", "6"} {
		for _, hsts := range []bool{false, true} {
			name := "flag " + flag + " hsts off"
			if hsts {
				name = "flag " + flag + " hsts on"
			}
			t.Run(name, func(t *testing.T) {
				cfg := evCfg()
				cfg.dataDB, cfg.regexDB, cfg.importantRules = true, true, true
				cfg.builtinLogFlag, cfg.hstsDB, cfg.hstsTlds = flag, hsts, nil
				containers := matcherContainers{
					// the data hit is found first with a sentinel log flag that the re-attribution must replace
					dataDB:           map[string]*blockEntry{q: evBlk("9", 0, PRIO_FEED_BLOCK)},
					regexDB:          evRegexDB(evRule{name: "important-rule", pattern: "evil", band: PRIO_FEED_BLOCK_IMPORTANT, important: true}),
					feedGroupIndexDB: evFG,
				}
				if hsts {
					containers.hstsDB = map[string]struct{}{q: {}}
				}
				got := evEval(q, "com", false, cfg, containers)
				if !got.isFound || got.inWhitelist || got.feed != "important-rule" || got.group != "DNSBL_Regex" {
					t.Fatalf("decision = %s, want the block re-attributed to important-rule / DNSBL_Regex", evDump(*got))
				}
				if got.logType != flag {
					t.Errorf("logType = %q, want the builtin flag %q", got.logType, flag)
				}
				switch flag {
				case "1":
					if got.nullBlocking != hsts || got.nxdomain || got.inHsts != hsts {
						t.Errorf("(nullBlocking, nxdomain, inHsts) = (%v, %v, %v), want (%v, false, %v): flag 1 is VIP unless the name is HSTS", got.nullBlocking, got.nxdomain, got.inHsts, hsts, hsts)
					}
				case "0", "2":
					if !got.nullBlocking || got.nxdomain || got.inHsts != hsts {
						t.Errorf("(nullBlocking, nxdomain, inHsts) = (%v, %v, %v), want (true, false, %v)", got.nullBlocking, got.nxdomain, got.inHsts, hsts)
					}
				case "3", "4":
					if !got.nxdomain || got.inHsts || got.pType != "Python" {
						t.Errorf("(nxdomain, inHsts, pType) = (%v, %v, %q), want (true, false, \"Python\"): NXDOMAIN bypasses HSTS", got.nxdomain, got.inHsts, got.pType)
					}
				default: // "5", "6"
					if got.nxdomain || got.inHsts {
						t.Errorf("(nxdomain, inHsts) = (%v, %v), want (false, false): NODATA bypasses HSTS", got.nxdomain, got.inHsts)
					}
				}
			})
		}
	}
}
