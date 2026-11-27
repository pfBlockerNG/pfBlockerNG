// issue #4284 (ported for #4287): AdGuard's subdomain-only mask `.host^` blocks the subdomains of `host`, never `host`.
//
// The capture guard (dnsblIsAbpRuleLine, the twin of PHP's pfb_dnsbl_is_abp_rule_line(), pinned to the same rows by
// tests/php/DnsblAbpSubdomainMaskTest.php) routes `.host^` to parseAbp, which reads it as a block rule that leaves out
// the apex. build() writes it as a zone entry whose apex payload is the one that blocked the key before it, or none:
// the suffix walk decides the key itself from that payload and walks on when there is none. On one zone key the merged
// entry keeps apex = a.apex || b.apex, so a `.host^` never unblocks a host another rule blocks. A `.host^` whose key
// cannot be a zone (TLD Exclusion, the PSL feed policy's `apex` demotion) is dropped: an exact block would cover only
// the host the rule excludes. Ported from release/4.0's tests/test_issue4284_zone_apex.py and
// tests/test_pfb_unbound.py's group-epoch row.
package decider

import (
	"fmt"
	"iter"
	"slices"
	"strings"
	"testing"
)

const apexPSL = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\nco.uk\n// ===END ICANN DOMAINS===\n" +
	"// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n"

type apexBuild struct {
	exclusion   []string
	icannPolicy string
	top1m       []string
	top1mFeeds  []int
}

// apexBuildFeeds builds one manifest row per feed, FEED<i>/GRP<i>, reading feeds[i] as its lines.
func apexBuildFeeds(t *testing.T, feeds [][]string, opts apexBuild) *buildResult {
	t.Helper()
	var rows []manifestFeed
	raws := map[string][]string{}
	for i, lines := range feeds {
		raw := fmt.Sprintf("feed%d.raw", i)
		raws[raw] = lines
		rows = append(rows, manifestFeed{raw: raw, feed: fmt.Sprintf("FEED%d", i), group: fmt.Sprintf("GRP%d", i),
			logFlag: "1", top1m: slices.Contains(opts.top1mFeeds, i)})
	}
	cfg := newBuildConfig()
	cfg.pslRules = bldRules(t, apexPSL)
	cfg.tldWildcardExclusion = opts.exclusion
	if opts.icannPolicy != "" {
		cfg.pslFeedIcannPolicy = opts.icannPolicy
	}
	reader := func(raw string) iter.Seq2[string, error] { return lineSeq(raws[raw]) }
	result, err := build(buildManifest{feeds: rows}, cfg, reader, len(opts.top1m) > 0, lineSeq(opts.top1m))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return result
}

// apexBlocks reports whether the build blocks qName; the fast path's exact + suffix walk and the numeric path's scan
// must agree.
func apexBlocks(t *testing.T, result *buildResult, qName string) bool {
	t.Helper()
	_, fastEntry := findZoneMatch(qName, result.zoneDB)
	fast := result.dataDB[qName] != nil || fastEntry != nil
	cfg := evaluateConfig{dataDB: len(result.dataDB) > 0, zoneDB: len(result.zoneDB) > 0}
	band, _ := scanBlockBand(qName, cfg, result.dataDB, result.zoneDB, nil, nil)
	if fast != (band > 0) {
		t.Fatalf("%s: the fast path says %v, the band scan %d", qName, fast, band)
	}
	return fast
}

// apexHit is the (band, group) both zone lookups attribute qName to.
func apexHit(t *testing.T, result *buildResult, qName string) (int, string) {
	t.Helper()
	_, entry := findZoneMatch(qName, result.zoneDB)
	if entry == nil {
		t.Fatalf("%s: no zone match", qName)
	}
	band, meta := scanBlockBand(qName, evaluateConfig{zoneDB: true}, nil, result.zoneDB, nil, nil)
	if meta == nil || meta.block != entry {
		t.Fatalf("%s: the band scan matched %+v, the suffix walk %+v", qName, meta, entry)
	}
	return band, result.feedGroupIndexDB[entry.index].group
}

func TestIssue4284ASubdomainOnlyMaskIsCaptured(t *testing.T) {
	for _, line := range []string{".webhop.net^", ".webhop.net^$important", ".Ads.Example.com^"} {
		if !dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%q) = false", line)
		}
	}
}

func TestIssue4284APathWildcardOrUnterminatedDotLineIsNotCaptured(t *testing.T) {
	for _, line := range []string{".imgur.com/lumbar.gif", ".webhop.net", ".top^*-960x80-*.gif", ".*.webhop.net^", ".web|hop.net^", ". webhop.net^"} {
		if dnsblIsAbpRuleLine(line) {
			t.Errorf("dnsblIsAbpRuleLine(%q) = true", line)
		}
	}
}

func TestIssue4284ParseAbpReadsASubdomainOnlyBlock(t *testing.T) {
	r := abpParse(".WebHop.net^$important")
	if r == nil || r.kind != DNSBL_KIND_BLOCK || r.target != RULE_TARGET_DOMAIN || r.keyOrPattern != "webhop.net" || !r.wildcard || !r.important {
		t.Fatalf("parseAbp(.WebHop.net^$important) = %+v", r)
	}
	anchored := abpParse("||webhop.net^$important")
	if anchored == nil || r.signature == anchored.signature {
		t.Errorf("the mask shares the anchor's signature: %+v vs %+v", r, anchored)
	}
}

func TestIssue4284ParseAbpSkipsASubdomainOnlyMaskWithAPageOption(t *testing.T) {
	if r := abpParse(".variti.ch^$third-party,popup"); r != nil {
		t.Errorf("parseAbp = %+v, want nil", r)
	}
}

func TestIssue4284ASubdomainOnlyMaskBlocksSubdomainsAndNotTheHost(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".webhop.net^"}}, apexBuild{})
	if result.zoneDB["webhop.net"] == nil {
		t.Fatal("no zone entry for webhop.net")
	}
	for q, want := range map[string]bool{"someone.webhop.net": true, "a.b.webhop.net": true, "webhop.net": false, "notwebhop.net": false} {
		if got := apexBlocks(t, result, q); got != want {
			t.Errorf("%s blocked = %v, want %v", q, got, want)
		}
	}
}

func TestIssue4284TheWalkContinuesPastASubdomainOnlyKey(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".ads.example.com^", "||example.com^"}}, apexBuild{})
	if !apexBlocks(t, result, "ads.example.com") {
		t.Error("ads.example.com is not blocked through example.com")
	}
}

func TestIssue4284ASubdomainOnlyMaskNeverUnblocksABlockedHost(t *testing.T) {
	for name, feeds := range map[string][][]string{
		"mask then anchor":          {{".webhop.net^", "||webhop.net^"}},
		"anchor then mask":          {{"||webhop.net^", ".webhop.net^"}},
		"plain feed then mask feed": {{"webhop.net"}, {".webhop.net^"}},
		"mask feed then hosts feed": {{".webhop.net^"}, {"0.0.0.0 webhop.net"}},
	} {
		result := apexBuildFeeds(t, feeds, apexBuild{})
		if !apexBlocks(t, result, "webhop.net") || !apexBlocks(t, result, "someone.webhop.net") {
			t.Errorf("%s: webhop.net or its subdomain is unblocked", name)
		}
	}
}

func TestIssue4284ABadfilterAnchorDoesNotPruneASubdomainOnlyMask(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".webhop.net^"}, {"||webhop.net^$badfilter"}}, apexBuild{})
	if !apexBlocks(t, result, "someone.webhop.net") {
		t.Error("||webhop.net^$badfilter pruned .webhop.net^")
	}
}

func TestIssue4284ASubdomainOnlyMaskOnTldExclusionIsDropped(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".webhop.net^"}}, apexBuild{exclusion: []string{"webhop.net"}})
	if apexBlocks(t, result, "webhop.net") || result.zoneDB["webhop.net"] != nil {
		t.Errorf("webhop.net blocked or zoned: data=%v zone=%v", result.dataDB["webhop.net"], result.zoneDB["webhop.net"])
	}
}

func TestIssue4284ASubdomainOnlyMaskTheSuffixPolicyDemotesIsDropped(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".co.uk^"}}, apexBuild{icannPolicy: "apex"})
	if apexBlocks(t, result, "co.uk") || result.zoneDB["co.uk"] != nil {
		t.Errorf("co.uk blocked or zoned: data=%v zone=%v", result.dataDB["co.uk"], result.zoneDB["co.uk"])
	}
	// Dropped, not demoted: no exact block exists for the Reject Stats to report.
	if tally := bldRejectRow(result, "FEED0", "GRP0"); tally["suffix_drop"] != 1 || tally["suffix_demote"] != 0 {
		t.Errorf("tally = %v, want suffix_drop 1 and no suffix_demote", tally)
	}
}

func TestIssue4284TwoSubdomainOnlyMasksOnOneHostLeaveTheHostUnblocked(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{".webhop.net^"}, {".webhop.net^"}}, apexBuild{})
	if apexBlocks(t, result, "webhop.net") || !apexBlocks(t, result, "someone.webhop.net") {
		t.Error("two masks blocked the host or left its subdomain unblocked")
	}
}

func TestIssue4284TheHostKeepsTheBandAndGroupOfTheRuleThatBlocksIt(t *testing.T) {
	for name, feeds := range map[string][][]string{
		"anchor then mask": {{"||webhop.net^"}, {".webhop.net^$important"}},
		"mask then anchor": {{".webhop.net^$important"}, {"||webhop.net^"}},
	} {
		anchor := slices.IndexFunc(feeds, func(lines []string) bool { return strings.HasPrefix(lines[0], "||") })
		result := apexBuildFeeds(t, feeds, apexBuild{})
		if band, group := apexHit(t, result, "webhop.net"); band != PRIO_FEED_BLOCK || group != fmt.Sprintf("GRP%d", anchor) {
			t.Errorf("%s: webhop.net hit (%d, %s), want (%d, GRP%d)", name, band, group, PRIO_FEED_BLOCK, anchor)
		}
	}
}

func TestIssue4284SubdomainsKeepTheLastWriterWhenAMaskFollowsAnAnchor(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{"||webhop.net^"}, {".webhop.net^$important"}}, apexBuild{})
	if band, group := apexHit(t, result, "someone.webhop.net"); group != "GRP1" || band <= PRIO_FEED_BLOCK {
		t.Errorf("someone.webhop.net hit (%d, %s), want GRP1 above band %d", band, group, PRIO_FEED_BLOCK)
	}
}

func TestIssue4284ATop1mFilteredAnchorNeverBlocksAListedHostThroughAMask(t *testing.T) {
	for _, anchorFirst := range []bool{true, false} {
		feeds, filtered := [][]string{{"||webhop.net^"}, {".webhop.net^"}}, 0
		if !anchorFirst {
			feeds, filtered = [][]string{{".webhop.net^"}, {"||webhop.net^"}}, 1
		}
		result := apexBuildFeeds(t, feeds, apexBuild{top1m: []string{"webhop.net"}, top1mFeeds: []int{filtered}})
		if apexBlocks(t, result, "webhop.net") || !apexBlocks(t, result, "someone.webhop.net") {
			t.Errorf("anchorFirst=%v: the listed host is blocked or its subdomain is not", anchorFirst)
		}
	}
}

func TestIssue4284AListedHostStaysUnblockedThroughNestedTop1mFallbacks(t *testing.T) {
	// Codex on #4285: a wrapped apex payload's fallback can itself be TOP1M-filtered.
	result := apexBuildFeeds(t, [][]string{{"||webhop.net^"}, {".webhop.net^"}, {"||webhop.net^"}, {".webhop.net^"}},
		apexBuild{top1m: []string{"webhop.net"}, top1mFeeds: []int{0, 2}})
	if apexBlocks(t, result, "webhop.net") || !apexBlocks(t, result, "someone.webhop.net") {
		t.Error("the listed host is blocked or its subdomain is not")
	}
}

func TestIssue4284AListedHostIsAttributedToTheUnfilteredEndOfItsFallbackChain(t *testing.T) {
	result := apexBuildFeeds(t, [][]string{{"||webhop.net^"}, {"||webhop.net^"}, {".webhop.net^"}, {"||webhop.net^"}, {".webhop.net^"}},
		apexBuild{top1m: []string{"webhop.net"}, top1mFeeds: []int{1, 3}})
	if band, group := apexHit(t, result, "webhop.net"); band != PRIO_FEED_BLOCK || group != "GRP0" {
		t.Errorf("webhop.net hit (%d, %s), want (%d, GRP0)", band, group, PRIO_FEED_BLOCK)
	}
}

func TestIssue4284ASubdomainOnlyBadfilterPrunesOnlySubdomainOnlyMasks(t *testing.T) {
	// CodeRabbit on #4285: '.example.com^$badfilter' shared the regex '/.example.com/' signature.
	res := abpReconcile([]string{"/.example.com/", ".example.com^", ".example.com^$badfilter"}, RULE_PROV_FEED, nil)
	var patterns []string
	for _, r := range res.blockRegexIrreducible {
		patterns = append(patterns, r.pattern)
	}
	if !slices.Equal(patterns, []string{".example.com"}) || res.pruned != 1 || len(res.blockDomains) != 0 {
		t.Errorf("regexes=%v pruned=%d blocks=%+v", patterns, res.pruned, res.blockDomains)
	}
}

func TestIssue4284TheGroupEpochCheckReachesTheApexPayloadOfASubdomainOnlyZone(t *testing.T) {
	// A '.host^' zone blocks its own key through its apex payload, so that payload's owner is counted against too.
	result := apexBuildFeeds(t, [][]string{{"||webhop.net^"}, {".webhop.net^"}}, apexBuild{})
	s := &snapshot{zoneDB: result.zoneDB, feedGroupIndexDB: result.feedGroupIndexDB}
	missing := missingEpochOwners(map[[2]string]string{{"GRP1", "custom"}: "e1"}, s)
	if !slices.Contains(missing, [2]string{"GRP0", "custom"}) {
		t.Errorf("missing = %v, want the apex payload's owner GRP0", missing)
	}
}
