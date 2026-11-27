// issue #4286 (ported for #4287): a feed `$badfilter` prunes only rules of its own type.
//
// AdGuard's `$badfilter` disables the rule that is identical apart from the `$badfilter` modifier. reconcile()'s
// signature was (keyOrPattern, DNS options) with no rule type, so `||example.com^$badfilter` also pruned the regex
// `/example.com/`, whose inner pattern is the same string, and an `@@` rule's `$badfilter` pruned the block with the
// same target. A regex signature key is now `/pattern/`, and the prune matches on (kind, signature). Ported from
// release/4.0's tests/test_issue4286_badfilter_signature_type.py.
package decider

import "testing"

func badfilterBuild(t *testing.T, lines ...string) *buildResult {
	t.Helper()
	return bldMustBuild(t, []manifestFeed{bldFeed("f.raw", "FEED", "GRP")}, newBuildConfig(), bldReader(lines...))
}

func TestIssue4286AnAnchorBadfilterKeepsARegexWithTheSameText(t *testing.T) {
	result := badfilterBuild(t, "/example.com/", "||example.com^", "||example.com^$badfilter")
	if result.regexDB.len() != 1 || result.zoneDB["example.com"] != nil {
		t.Errorf("regexes=%d zone=%v", result.regexDB.len(), result.zoneDB["example.com"])
	}
}

func TestIssue4286ARegexBadfilterKeepsAnAnchorWithTheSameText(t *testing.T) {
	result := badfilterBuild(t, "/example.com/", "||example.com^", "/example.com/$badfilter")
	if result.regexDB.len() != 0 || result.zoneDB["example.com"] == nil {
		t.Errorf("regexes=%d zone=%v", result.regexDB.len(), result.zoneDB["example.com"])
	}
}

func TestIssue4286ABadfilterStillPrunesItsOwnRuleWithTheSameOptions(t *testing.T) {
	result := badfilterBuild(t, `/ads[0-9]+\./$important`, `/ads[0-9]+\./$important,badfilter`, `/ads[0-9]+\./`)
	var important []bool
	for _, entry := range result.regexDB.items() {
		important = append(important, entry.important)
	}
	if len(important) != 1 || important[0] {
		t.Errorf("regex important flags = %v, want [false]", important)
	}
}

func TestIssue4286AnAllowBadfilterKeepsTheBlockWithTheSameTarget(t *testing.T) {
	result := badfilterBuild(t, "||example.com^", "@@||example.com^$badfilter", `/ads[0-9]+\./`, `@@/ads[0-9]+\./$badfilter`)
	if result.zoneDB["example.com"] == nil || result.regexDB.len() != 1 {
		t.Errorf("zone=%v regexes=%d", result.zoneDB["example.com"], result.regexDB.len())
	}
}

func TestIssue4286ABlockBadfilterKeepsTheAllowWithTheSameTarget(t *testing.T) {
	result := badfilterBuild(t, "@@||example.com^", "||example.com^$badfilter", `@@/ads[0-9]+\./`, `/ads[0-9]+\./$badfilter`)
	if _, ok := result.whiteDB["example.com"]; !ok || result.allowRegexDB.len() != 1 {
		t.Errorf("white=%v allow regexes=%d", ok, result.allowRegexDB.len())
	}
}

func TestIssue4286AnAllowRegexBadfilterKeepsAnAllowAnchorWithTheSameText(t *testing.T) {
	result := badfilterBuild(t, "@@/example.com/", "@@||example.com^", "@@/example.com/$badfilter")
	if _, ok := result.whiteDB["example.com"]; !ok || result.allowRegexDB.len() != 0 {
		t.Errorf("white=%v allow regexes=%d", ok, result.allowRegexDB.len())
	}
}
