package decider

import "testing"

// issue #4272: AdGuard's extended cosmetic markers are cosmetic rules. The capture guard (dnsblIsAbpRuleLine(), the twin of
// PHP's pfb_dnsbl_is_abp_rule_line(), pinned to the same rows by tests/php/DnsblAbpExtendedCosmeticMarkerTest.php) routes
// them to parseAbp(), and parseAbp() skips them, so none becomes a domain block. Before, the AdGuard Turkish filter's
// eksisozluk.com#$?#... reached the plain path, where Lenient cut eksisozluk.com out of it. Ported from release/4.0's
// tests/test_issue4272_extended_cosmetic_markers.py.
func TestAnAdGuardExtendedCosmeticRuleIsCapturedAndNeverARule(t *testing.T) {
	for _, line := range []string{
		"eksisozluk.com#$?#.ads",
		`#$?#div:has(> a[href*="ads"])`,
		"site.com#@$?#.ads",
		"site.com#@?#div:has(.ad)",
		"site.com#@$#body { color: red }",
		"site.com#@%#//scriptlet('abort-on-property-read', 'ads')",
		"a.com,b.com#$?#.ads",
	} {
		if !dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%q) = false, want a captured cosmetic rule", line)
		}
		if r := abpParse(line); r != nil {
			t.Errorf("parseAbp(%q) = %+v, want nil (a cosmetic rule)", line, *r)
		}
	}
}

func TestACommentOrAPlainLineIsNotCaptured(t *testing.T) {
	for _, line := range []string{"#$?# comment", "example.com/path#$?#x"} {
		if dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%q) = true, want false", line)
		}
	}
}
