// Two behaviours of pfb_unbound_abp.go that neither the Python suites ported in pfb_unbound_abp_test.go nor the oracle
// rows pin, found by mutating the translation: a user $badfilter is never collected (reconcile step 1, "USER rules are
// IMMUNE") and the closing "/$" of a regex rule is the LAST one (rfind). Expectations were checked against Python.

package decider

import (
	"slices"
	"testing"
)

func TestReconcileUserBadfilterIsNeverCollected(t *testing.T) {
	rules := append(abpRules([]string{"||y.example.com^"}, RULE_PROV_FEED), abpRules([]string{"||y.example.com^$badfilter"}, RULE_PROV_USER)...)
	res := reconcile(rules, abpTlds, abpNoExclusion, nil)
	want := []blockDomainRule{{cls: DNSBL_CLASS_ZONE, key: "y.example.com", band: PRIO_FEED_BLOCK, provenance: RULE_PROV_FEED}}
	if res.pruned != 0 || res.skippedBadfilter != 1 || !slices.Equal(res.blockDomains, want) {
		t.Errorf("a user $badfilter pruned a feed rule: pruned=%d skipped=%d blocks=%+v", res.pruned, res.skippedBadfilter, res.blockDomains)
	}
}

func TestDnsblParseAbpRegexClosesAtTheLastSlashDollar(t *testing.T) {
	kind, inner, opts, ok := dnsblParseAbpRegex("/a/$b/$important")
	if !ok || kind != DNSBL_KIND_BLOCK || inner != "a/$b" || opts != "important" {
		t.Errorf("dnsblParseAbpRegex = %q %q %q %v", kind, inner, opts, ok)
	}
	expectRule(t, "/a/$b/$important", wantRegexRule(DNSBL_KIND_BLOCK, "a/$b", true, false))
}
