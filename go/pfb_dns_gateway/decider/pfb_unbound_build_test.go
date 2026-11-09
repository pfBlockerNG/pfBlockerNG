// Tests of pfb_unbound_build.go. Ported from tests/test_adr06_build_module.py (the build() rows: reject tallies, the
// golden structure sanity, purity, no IP leak, TOP1M name normalisation and a user wildcard kept across TOP1M),
// tests/test_adr06_init_from_raw.py (the manifest rows: counts, the PSL oracle wiring, unlock, fallbacks),
// tests/test_dnsbl_manifest_v1_contract.py, tests/test_manifest_path_confinement.py,
// tests/test_issue3648_top1m_group_scope.py (its build-side structure), tests/test_issue2371_feed_suffix_policy.py,
// tests/test_adr07_user_regex_containers.py (the build rows), tests/test_issue1718_regex_transport.py (the user regex
// rows), tests/test_issue1284_dnsbl_feed_line_framing.py, tests/test_branch_coverage_gaps.py (TestBuildBranches,
// the manifest fallbacks, the two emitters) and tests/test_adr07_regex_safety.py (the loaders' rows).
//
// What the Python tests decide through evaluate_domain (the golden decision tables, the 3648 scenario answers, the
// leading-dot CNAME rows, Latin-1 \w) belongs to the evaluate and corpus families; here the same inputs are pinned as
// the structures build() hands them (pfb_unbound_build_oracle_test.go compares every one of them with Python's).
package decider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/paritycorpus"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/regexrules"
)

// ---------------------------------------------------------------------------------------------------------------
// helpers

func bldFeed(raw, feed, group string) manifestFeed {
	return manifestFeed{raw: raw, feed: feed, group: group, logFlag: "1"}
}

func bldReader(lines ...string) lineReader {
	return func(string) iter.Seq2[string, error] { return lineSeq(lines) }
}

func bldMustBuild(t *testing.T, feeds []manifestFeed, config buildConfig, reader lineReader) *buildResult {
	t.Helper()
	result, err := build(buildManifest{feeds: feeds}, config, reader, false, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return result
}

func bldRejectRow(result *buildResult, feed, group string) map[string]int {
	return result.rejects[[2]string{feed, group}]
}

func bldFixtureDir(name string) string {
	return filepath.Join(paritycorpus.Fixtures(), "..", "..", "..", "fixtures", name)
}

// bldAuthority is a PSL authority file with the given ICANN and PRIVATE rules.
func bldAuthority(icann []string, private ...string) string {
	return "// ===BEGIN ICANN DOMAINS===\n" + strings.Join(icann, "\n") + "\n// ===END ICANN DOMAINS===\n" +
		"// ===BEGIN PRIVATE DOMAINS===\n" + strings.Join(private, "\n") + "\n// ===END PRIVATE DOMAINS===\n"
}

func bldRules(t *testing.T, text string) pslRules {
	t.Helper()
	rules, err := parsePslRules(text)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func bldWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bldWriteManifest(t *testing.T, path string, manifest any) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// bldModuleIn is a module whose ledger lives in dir.
func bldModuleIn(dir string) *pfbUnbound {
	m := &pfbUnbound{}
	m.pfb.pslIncludePrivate = true
	m.pfb.pslFeedPrivatePolicy = "honor"
	m.pfb.pslFeedIcannPolicy = "honor"
	m.pfb.pfbPyStatus = filepath.Join(dir, "pfb_py_status.json")
	return m
}

func bldLedgerEntries(t *testing.T, dir string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "pfb_py_status.json"))
	if err != nil {
		return nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

type bldGoldenManifest struct {
	Feeds []struct {
		Raw        string `json:"raw"`
		Feed       string `json:"feed"`
		Group      string `json:"group"`
		LogFlag    string `json:"log_flag"`
		Top1m      bool   `json:"top1m"`
		Dialect    string `json:"dialect"`
		Provenance string `json:"provenance"`
	} `json:"feeds"`
}

type bldGoldenConfig struct {
	TldWildcardBlacklist []string `json:"tld_wildcard_blacklist"`
	TldWildcardExclusion []string `json:"tld_wildcard_exclusion"`
	UserWhitelist        []string `json:"user_whitelist"`
	Top1mList            []string `json:"top1m_list"`
}

func bldGoldenFixture(t *testing.T) (bldGoldenManifest, bldGoldenConfig, string) {
	t.Helper()
	dir := bldFixtureDir("adr06_golden")
	var manifest bldGoldenManifest
	var config bldGoldenConfig
	for name, into := range map[string]any{"manifest.json": &manifest, "config.json": &config} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	tld, err := os.ReadFile(filepath.Join(dir, "tld_master.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return manifest, config, string(tld)
}

// bldGoldenBuild is build() over the ADR-06 golden fixtures (test_adr06_build_module._run_build).
func bldGoldenBuild(t *testing.T, top1mEnabled bool) *buildResult {
	t.Helper()
	manifest, config, tld := bldGoldenFixture(t)
	cfg := newBuildConfig()
	cfg.pslRules = bldRules(t, bldAuthority(strings.Fields(tld)))
	cfg.tldWildcardBlacklist = config.TldWildcardBlacklist
	cfg.tldWildcardExclusion = config.TldWildcardExclusion
	cfg.userWhitelist = config.UserWhitelist
	cfg.builtinLogFlag = "1" // issue #3539: the golden contract pins VIP for TLD-blacklist zones
	var feeds []manifestFeed
	for _, row := range manifest.Feeds {
		feeds = append(feeds, manifestFeed{raw: row.Raw, feed: row.Feed, group: row.Group, logFlag: row.LogFlag, top1m: row.Top1m})
	}
	result, err := build(buildManifest{feeds: feeds}, cfg, dnsblFileLineReader(bldFixtureDir("adr06_golden"), true), top1mEnabled, lineSeq(config.Top1mList))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// bldStageGolden writes the golden fixtures as the box has them (test_adr06_init_from_raw._write_onbox_manifest): feeds
// under pfb_py_raw, the PSL authority as a shipped file, the TOP1M list as the sidecar.
func bldStageGolden(t *testing.T, top1mEnabled bool) (dir, manifestPath string) {
	t.Helper()
	manifest, config, tld := bldGoldenFixture(t)
	dir = t.TempDir()
	var feeds []map[string]any
	for _, row := range manifest.Feeds {
		data, err := os.ReadFile(filepath.Join(bldFixtureDir("adr06_golden"), row.Raw))
		if err != nil {
			t.Fatal(err)
		}
		rel := "pfb_py_raw/" + filepath.Base(row.Raw)
		bldWriteFile(t, filepath.Join(dir, rel), string(data))
		feeds = append(feeds, map[string]any{"raw": rel, "feed": row.Feed, "group": row.Group, "log_flag": row.LogFlag, "top1m": row.Top1m})
	}
	bldWriteFile(t, filepath.Join(dir, "dnsbl_psl"), bldAuthority(strings.Fields(tld)))
	if top1mEnabled {
		bldWriteFile(t, filepath.Join(dir, "pfb_py_top1m.txt"), strings.Join(config.Top1mList, "\n")+"\n")
	}
	manifestPath = filepath.Join(dir, "pfb_py_sources.json")
	bldWriteManifest(t, manifestPath, map[string]any{
		"version": 1,
		"config": map[string]any{
			"tld_wildcard_blacklist": orEmpty(config.TldWildcardBlacklist),
			"tld_wildcard_exclusion": orEmpty(config.TldWildcardExclusion),
			"user_whitelist":         orEmpty(config.UserWhitelist),
			"builtin_log_flag":       "1",
			"top1m_enabled":          top1mEnabled,
		},
		"feeds": feeds,
	})
	return dir, manifestPath
}

func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// bldGoldenModule is the module _stage_tld_oracle sets up: the shipped authority is read, Wildcard Blocking is on.
func bldGoldenModule(dir string, wildcard bool) *pfbUnbound {
	m := bldModuleIn(dir)
	m.pfb.pythonTldWildcard = wildcard
	m.pfb.pfbPyPsl = filepath.Join(dir, "dnsbl_psl")
	return m
}

// ---------------------------------------------------------------------------------------------------------------
// test_adr06_build_module.py: TestBuildStructureSanity, TestBuildPurity, TestBuildNoIpLeak, TestEntryRejectTally,
// TestUserListRejectTally, TestSkipClassesTallyZero and the build() rows of TestWhitelistNormalisation

func TestBuildStructureSanity(t *testing.T) {
	result := bldGoldenBuild(t, false)
	for _, name := range []string{"tracker.org", "malware.com", "shop.co.uk"} {
		if _, ok := result.zoneDB[name]; !ok {
			t.Errorf("zoneDB lacks %q", name)
		}
	}
	for _, name := range []string{"deep.host.cleandata.com", "deep.path.cleanmal.com", "excluded.com"} {
		if _, ok := result.dataDB[name]; !ok {
			t.Errorf("dataDB lacks %q", name)
		}
	}
	if _, ok := result.zoneDB["excluded.com"]; ok {
		t.Error("a TLD-excluded name is a zone")
	}
	zip, ok := result.zoneDB["zip"]
	if !ok {
		t.Fatal("zoneDB lacks the TLD-blacklist zone \"zip\"")
	}
	if got := result.feedGroupIndexDB[zip.index]; got != (feedGroup{"DNSBL_TLD", "DNSBL_TLD"}) {
		t.Errorf("zip is attributed to %+v, want DNSBL_TLD", got)
	}
	// tracker.org is in BOTH the hosts feed (Ads) and the plain feed (Malware); the build keeps LAST.
	if got := result.feedGroupIndexDB[result.zoneDB["tracker.org"].index]; got != (feedGroup{"PlainFeed", "Malware"}) {
		t.Errorf("tracker.org is attributed to %+v, want the last writer PlainFeed/Malware", got)
	}
	if got := result.zoneDB["silentblock.com"].log; got != "2" {
		t.Errorf("silentblock.com carries log flag %q, want the feed's \"2\"", got)
	}
	if result.counts != len(result.dataDB)+len(result.zoneDB) || result.counts == 0 {
		t.Errorf("counts = %d, want the loaded total %d", result.counts, len(result.dataDB)+len(result.zoneDB))
	}
	// no build-time whitelist pruning, no subdomain collapse
	for _, name := range []string{"phishing.net", "adblock.com"} {
		if _, ok := result.zoneDB[name]; !ok {
			t.Errorf("the whitelisted %q was pruned from zoneDB", name)
		}
	}
}

func TestBuildPurity(t *testing.T) {
	first, second := bldGoldenBuild(t, false), bldGoldenBuild(t, false)
	if !reflect.DeepEqual(first.dataDB, second.dataDB) || !reflect.DeepEqual(first.zoneDB, second.zoneDB) ||
		!reflect.DeepEqual(first.feedGroupIndexDB, second.feedGroupIndexDB) || !reflect.DeepEqual(first.whiteDB, second.whiteDB) ||
		first.counts != second.counts {
		t.Error("two builds of the same input differ")
	}
	for label, pair := range map[string][2]uintptr{
		"dataDB":           {reflect.ValueOf(first.dataDB).Pointer(), reflect.ValueOf(second.dataDB).Pointer()},
		"zoneDB":           {reflect.ValueOf(first.zoneDB).Pointer(), reflect.ValueOf(second.zoneDB).Pointer()},
		"feedGroupIndexDB": {reflect.ValueOf(first.feedGroupIndexDB).Pointer(), reflect.ValueOf(second.feedGroupIndexDB).Pointer()},
		"whiteDB":          {reflect.ValueOf(first.whiteDB).Pointer(), reflect.ValueOf(second.whiteDB).Pointer()},
	} {
		if pair[0] == pair[1] {
			t.Errorf("two builds share their %s", label)
		}
	}
}

// build is reentrant: concurrent builds over one shared manifest, config and PSL rule set (go test -race) agree.
func TestBuildIsReentrant(t *testing.T) {
	manifest, config, tld := bldGoldenFixture(t)
	cfg := newBuildConfig()
	cfg.pslRules = bldRules(t, bldAuthority(strings.Fields(tld)))
	cfg.tldWildcardBlacklist = config.TldWildcardBlacklist
	cfg.userWhitelist = config.UserWhitelist
	var feeds []manifestFeed
	for _, row := range manifest.Feeds {
		feeds = append(feeds, manifestFeed{raw: row.Raw, feed: row.Feed, group: row.Group, logFlag: row.LogFlag, top1m: row.Top1m})
	}
	reader := dnsblFileLineReader(bldFixtureDir("adr06_golden"), true)
	results := make([]*buildResult, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = build(buildManifest{feeds: feeds}, cfg, reader, true, lineSeq(config.Top1mList))
		}()
	}
	wg.Wait()
	for i, result := range results {
		if result == nil || !reflect.DeepEqual(result.dataDB, results[0].dataDB) || !reflect.DeepEqual(result.zoneDB, results[0].zoneDB) {
			t.Fatalf("concurrent build #%d differs from #0", i)
		}
	}
}

func TestBuildNoIpLeak(t *testing.T) {
	result := bldGoldenBuild(t, false)
	for _, ip := range []string{"198.51.100.23", "203.0.113.45"} {
		if _, ok := result.dataDB[ip]; ok {
			t.Errorf("%s leaked into dataDB", ip)
		}
		if _, ok := result.zoneDB[ip]; ok {
			t.Errorf("%s leaked into zoneDB", ip)
		}
	}
}

func TestBuildAbpFeedTalliesExactShapeAndWireCapCounts(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	name254 := strings.Join([]string{strings.Repeat("b", 61), strings.Repeat("b", 61), strings.Repeat("b", 61), strings.Repeat("b", 61)}, ".") + "." + strings.Repeat("b", 6)
	reader := bldReader(
		"||good.example.com^",  // accepted -- must not be counted
		"||no-dot-host^",       // shape: no "." in host
		"||-bad.example.com^",  // shape: edge-hyphen label
		"||"+longLabel+".com^", // wire_cap: 64-char label
		"||"+name254+"^",       // wire_cap: >253-char total
	)
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "RejFeed", "RejGroup")}, newBuildConfig(), reader)
	want := rejectTally{{"RejFeed", "RejGroup"}: {"shape": 2, "wire_cap": 2}}
	if !reflect.DeepEqual(result.rejects, want) {
		t.Errorf("rejects = %v, want %v", result.rejects, want)
	}
	_, inData := result.dataDB["good.example.com"]
	_, inZone := result.zoneDB["good.example.com"]
	if !inData && !inZone {
		t.Error("the accepted entry did not land in the block structures")
	}
}

func TestBuildPlainFeedTalliesNormaliseReject(t *testing.T) {
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "PlainFeed", "PlainGroup")}, newBuildConfig(), bldReader("good.example.com", "no-dot-host"))
	want := rejectTally{{"PlainFeed", "PlainGroup"}: {"shape": 1, "wire_cap": 0}}
	if !reflect.DeepEqual(result.rejects, want) {
		t.Errorf("rejects = %v, want %v", result.rejects, want)
	}
}

func TestBuildUserListRejectsAreTalliedPerListWithoutLogging(t *testing.T) {
	out := bldCaptureLog(t)
	cfg := newBuildConfig()
	cfg.userWhitelist = []string{"bad domain!", "ok.com"}
	cfg.userUnlock = []string{"-bad.com", "also-bad", "ok2.com"}
	result := bldMustBuild(t, nil, cfg, bldReader())
	want := rejectTally{
		{"user-whitelist", "DNSBL"}: {"shape": 1, "wire_cap": 0},
		{"user-unlock", "DNSBL"}:    {"shape": 2, "wire_cap": 0},
	}
	if !reflect.DeepEqual(result.rejects, want) {
		t.Errorf("rejects = %v, want %v", result.rejects, want)
	}
	if got := slices.Sorted(maps.Keys(result.whiteDB)); !slices.Equal(got, []string{"ok.com", "ok2.com"}) {
		t.Errorf("whiteDB keys = %q", got)
	}
	if out.Len() != 0 {
		t.Errorf("build logged %q", out.String())
	}
}

func TestBuildOverLengthUserLinesTallyWireCapNotShape(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".com"
	cfg := newBuildConfig()
	cfg.userWhitelist = []string{longLabel, "." + strings.Repeat("a", 64)}
	cfg.userUnlock = []string{longLabel}
	result := bldMustBuild(t, nil, cfg, bldReader())
	want := rejectTally{
		{"user-whitelist", "DNSBL"}: {"shape": 0, "wire_cap": 2},
		{"user-unlock", "DNSBL"}:    {"shape": 0, "wire_cap": 1},
	}
	if !reflect.DeepEqual(result.rejects, want) {
		t.Errorf("rejects = %v, want %v", result.rejects, want)
	}
}

func TestBuildRealFeedNamedLikeAUserListKeepsItsOwnRow(t *testing.T) {
	// Feed names are [A-Za-z0-9_]+, so the user-list tally keys must not be a legal feed name.
	cfg := newBuildConfig()
	cfg.userWhitelist = []string{"bad domain!"}
	cfg.userUnlock = []string{"also-bad"}
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "user_whitelist", "DNSBL")}, cfg, bldReader("good.example.com", "no-dot-host"))
	for key, want := range map[[2]string]map[string]int{
		{"user_whitelist", "DNSBL"}: {"shape": 1, "wire_cap": 0},
		{"user-whitelist", "DNSBL"}: {"shape": 1, "wire_cap": 0},
		{"user-unlock", "DNSBL"}:    {"shape": 1, "wire_cap": 0},
	} {
		if !reflect.DeepEqual(result.rejects[key], want) {
			t.Errorf("rejects[%v] = %v, want %v", key, result.rejects[key], want)
		}
	}
}

// A deliberate ABP SKIP is not a reject; the lines past the ABP-shaped ones fall to the plain validator and do tally.
func TestBuildSkipOnlyFeedTalliesNothing(t *testing.T) {
	skipLines := []string{
		"", "   ", "! Title: comment", "# plain comment", "example.com##.ad-banner", "##.global-ad", "example.net#@#.whitelisted-ad",
		"example.org#?#div:has(> .ad)", "example.com#%#//scriptlet('x')", "example.com#$#body { color: red; }",
		"||example.com/ads/*", "||cdn.example.net/track.js", "||shop.example^/affiliate?id=", "||wild.*^", "||203.0.113.7^",
		"||198.51.100.42^", "0.0.0.0 203.0.113.99", "127.0.0.1 10.0.0.1", "||gone.example^$badfilter",
	}
	notAbpShapedJunk := []string{"[Adblock Plus 2.0]", "not a domain at all", "/banners/*.gif"}
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "SkipFeed", "SkipGroup")}, newBuildConfig(), bldReader(append(skipLines, notAbpShapedJunk...)...))
	want := rejectTally{{"SkipFeed", "SkipGroup"}: {"shape": 3, "wire_cap": 0}}
	if !reflect.DeepEqual(result.rejects, want) {
		t.Errorf("rejects = %v, want %v", result.rejects, want)
	}
	if result.counts != 0 {
		t.Errorf("a skip-only feed loaded %d entries", result.counts)
	}
}

func TestBuildUserWildcardNotOverwrittenByTop1m(t *testing.T) {
	const apex = "collapex.com"
	cfg := newBuildConfig()
	cfg.userWhitelist = []string{"." + apex}
	result, err := build(buildManifest{}, cfg, bldReader(), true, lineSeq([]string{apex}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.whiteDB[apex].wildcard {
		t.Fatalf("whiteDB[%q] = %+v, want the user's wildcard", apex, result.whiteDB[apex])
	}
	for _, name := range []string{"stun.l." + apex, "a.b." + apex} {
		if !whitelistCheckDomain(name, result.whiteDB, 1) {
			t.Errorf("%s is not covered by the user's .%s", name, apex)
		}
	}
}

func TestDnsblTop1mNamesAreNormalisedAndInvalidEntriesRejected(t *testing.T) {
	names, err := dnsblTop1mNames(lineSeq([]string{" PopularCDN.COM. ", "popularcdn.com", "www.Example.COM", "", "bad domain!", ",retired.com,", "lan"}))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{}{"popularcdn.com": {}, "www.example.com": {}}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestDnsblTop1mNamesStopsAtTheSourceError(t *testing.T) {
	source := func(yield func(string, error) bool) {
		if yield("a.example", nil) {
			yield("", &dnsblGenerationError{"the sidecar changed"})
		}
	}
	if names, err := dnsblTop1mNames(source); err == nil || err.Error() != "the sidecar changed" || names != nil {
		t.Errorf("dnsblTop1mNames = (%v, %v), want (nil, the source error)", names, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// test_branch_coverage_gaps.py: TestBuildBranches

func TestBuildBlankBlacklistTldIsSkipped(t *testing.T) {
	cfg := newBuildConfig()
	cfg.tldWildcardBlacklist = []string{"."}
	if result := bldMustBuild(t, nil, cfg, bldReader()); len(result.zoneDB) != 0 {
		t.Errorf("zoneDB = %v, want empty: a \".\" blacklist entry strips to \"\"", result.zoneDB)
	}
}

func TestBuildPlainFeedLineFailingNormaliseDropped(t *testing.T) {
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "F", "G")}, newBuildConfig(), bldReader("singlelabelnodot", "good.com"))
	if _, ok := result.dataDB["singlelabelnodot"]; ok {
		t.Error("a single-label line was loaded")
	}
	_, inData := result.dataDB["good.com"]
	_, inZone := result.zoneDB["good.com"]
	if !inData && !inZone {
		t.Error("good.com was not loaded")
	}
}

func TestBuildFeedAllowImportantUpgradesLowerBandEntry(t *testing.T) {
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "F", "G")}, newBuildConfig(), bldReader("@@||x.com^", "@@||x.com^$important"))
	if entry := result.whiteDB["x.com"]; entry.band != PRIO_FEED_ALLOW_IMPORTANT || !entry.important {
		t.Errorf("whiteDB[x.com] = %+v, want the band-4 important allow", entry)
	}
}

func TestBuildSameBandExactAndWildcardAllowMergeWidens(t *testing.T) {
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "F", "G")}, newBuildConfig(), bldReader("@@||x.com^", `@@/^x\.com$/`))
	if entry := result.whiteDB["x.com"]; entry.band != PRIO_FEED_ALLOW || !entry.wildcard {
		t.Errorf("whiteDB[x.com] = %+v, want the wildcard kept at band 2", entry)
	}
}

func TestBuildFeedAllowDoesNotDowngradeUserWhitelist(t *testing.T) {
	cfg := newBuildConfig()
	cfg.userWhitelist = []string{"x.com"}
	result := bldMustBuild(t, []manifestFeed{bldFeed("r", "F", "G")}, cfg, bldReader("@@||x.com^"))
	if entry := result.whiteDB["x.com"]; entry.band != PRIO_USER_ALLOW {
		t.Errorf("whiteDB[x.com] = %+v, want the user's band 6", entry)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the line reader / reader errors reaching build

func TestBuildReaderErrorFailsTheBuild(t *testing.T) {
	failing := func(string) iter.Seq2[string, error] {
		return func(yield func(string, error) bool) {
			if yield("good.example", nil) {
				yield("", &dnsblGenerationError{"Failed while reading DNSBL feed"})
			}
		}
	}
	for _, mode := range []string{"deny", "permit"} {
		feed := bldFeed("r", "F", "G")
		feed.mode = mode
		if result, err := build(buildManifest{feeds: []manifestFeed{feed}}, newBuildConfig(), failing, false, nil); err == nil || result != nil {
			t.Errorf("%s feed: build = (%v, %v), want the reader's error and no result", mode, result, err)
		}
	}
}

func TestBuildTop1mSourceErrorFailsTheBuild(t *testing.T) {
	failing := func(yield func(string, error) bool) {
		yield("", &dnsblGenerationError{"TOP1M sidecar changed while reading"})
	}
	if result, err := build(buildManifest{}, newBuildConfig(), bldReader(), true, failing); err == nil || result != nil {
		t.Errorf("build = (%v, %v), want the sidecar's error and no result", result, err)
	}
	// a disabled TOP1M never reads its source
	if _, err := build(buildManifest{}, newBuildConfig(), bldReader(), false, failing); err != nil {
		t.Errorf("build with TOP1M off read the sidecar: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// issue #3648: the Group/TOP1M structure the build hands evaluate_domain

func bldTop1mBuild(t *testing.T, feeds ...struct {
	feed, group  string
	ticked, user bool
	lines        []string
}) *buildResult {
	t.Helper()
	var rows []manifestFeed
	files := map[string][]string{}
	for _, f := range feeds {
		row := bldFeed(f.feed+".raw", f.feed, f.group)
		row.top1m = f.ticked
		if f.user {
			row.provenance = "user"
		}
		rows = append(rows, row)
		files[row.raw] = f.lines
	}
	reader := func(raw string) iter.Seq2[string, error] { return lineSeq(files[raw]) }
	result, err := build(buildManifest{feeds: rows}, newBuildConfig(), reader, true, lineSeq([]string{"popular.example", "cdn.shared.example", "popular.zip"}))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type bldGroup = struct {
	feed, group  string
	ticked, user bool
	lines        []string
}

func TestTickedGroupDropsItsTop1mExactEntryAndKeepsTheRest(t *testing.T) {
	result := bldTop1mBuild(t, bldGroup{"PhishFeed", "DNSBL_Phish", true, false, []string{"popular.example", "evil.example"}})
	if _, ok := result.dataDB["popular.example"]; ok {
		t.Error("a ticked Group's exact entry for a TOP1M name was loaded")
	}
	if _, ok := result.dataDB["evil.example"]; !ok {
		t.Error("a ticked Group lost an entry TOP1M does not list")
	}
	cleared := bldTop1mBuild(t, bldGroup{"PhishFeed", "DNSBL_Phish", false, false, []string{"popular.example", "evil.example"}})
	if _, ok := cleared.dataDB["popular.example"]; !ok {
		t.Error("a cleared Group lost its TOP1M entry")
	}
}

func TestTickedGroupWildcardZoneCarriesTheTop1mNameSet(t *testing.T) {
	result := bldTop1mBuild(t, bldGroup{"PhishFeed", "DNSBL_Phish", true, false, []string{"||shared.example^", "||popular.example^"}})
	zone := result.zoneDB["popular.example"]
	if zone == nil || !zone.hasTop1m || zone.top1mFallback != nil {
		t.Fatalf("zoneDB[popular.example] = %+v, want a filtered zone with no fallback", zone)
	}
	if _, ok := zone.top1m["cdn.shared.example"]; !ok || len(zone.top1m) != 3 {
		t.Errorf("the zone's TOP1M set = %v, want the three listed names", zone.top1m)
	}
	// one immutable set shared by every filtered zone
	if reflect.ValueOf(zone.top1m).Pointer() != reflect.ValueOf(result.zoneDB["shared.example"].top1m).Pointer() {
		t.Error("two filtered zones hold different TOP1M sets")
	}
}

func TestClearedGroupWrittenAfterATickedOneOwnsTheZone(t *testing.T) {
	ticked := bldGroup{"PhishFeed", "DNSBL_Phish", true, false, []string{"||popular.example^"}}
	cleared := bldGroup{"AdsFeed", "DNSBL_Ads", false, false, []string{"||popular.example^"}}

	after := bldTop1mBuild(t, ticked, cleared)
	if zone := after.zoneDB["popular.example"]; zone.hasTop1m || zone.top1mFallback != nil {
		t.Errorf("cleared-last zone = %+v, want an unfiltered payload", zone)
	}
	if got := after.feedGroupIndexDB[after.zoneDB["popular.example"].index].group; got != "DNSBL_Ads" {
		t.Errorf("cleared-last zone is attributed to %q, want DNSBL_Ads", got)
	}

	before := bldTop1mBuild(t, cleared, ticked)
	zone := before.zoneDB["popular.example"]
	if !zone.hasTop1m || zone.top1mFallback == nil {
		t.Fatalf("ticked-last zone = %+v, want a filtered zone falling back to the cleared Group's payload", zone)
	}
	if got := before.feedGroupIndexDB[zone.top1mFallback.index].group; got != "DNSBL_Ads" {
		t.Errorf("the fallback is attributed to %q, want DNSBL_Ads", got)
	}
}

func TestTop1mBoxHasNoEffectWhileGlobalTop1mIsOff(t *testing.T) {
	row := bldFeed("r", "PhishFeed", "DNSBL_Phish")
	row.top1m = true
	result, err := build(buildManifest{feeds: []manifestFeed{row}}, newBuildConfig(), bldReader("popular.example", "||cdn.shared.example^"), false, lineSeq([]string{"popular.example", "cdn.shared.example"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.dataDB["popular.example"]; !ok {
		t.Error("a ticked Group dropped its entry while TOP1M is off")
	}
	if zone := result.zoneDB["cdn.shared.example"]; zone == nil || zone.hasTop1m {
		t.Errorf("zoneDB[cdn.shared.example] = %+v, want an unfiltered zone", zone)
	}
}

func TestTldBlacklistIsNeverFilteredByTop1m(t *testing.T) {
	cfg := newBuildConfig()
	cfg.tldWildcardBlacklist = []string{"zip"}
	row := bldFeed("r", "PhishFeed", "DNSBL_Phish")
	row.top1m = true
	result, err := build(buildManifest{feeds: []manifestFeed{row}}, cfg, bldReader("popular.zip"), true, lineSeq([]string{"popular.zip"}))
	if err != nil {
		t.Fatal(err)
	}
	zone := result.zoneDB["zip"]
	if zone == nil || zone.hasTop1m || zone.groupOwner != "DNSBL_TLD" || zone.groupOrigin != "builtin" {
		t.Errorf("zoneDB[zip] = %+v, want the unfiltered DNSBL_TLD built-in", zone)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// issue #2371: the feed-at-suffix policy (tests/test_issue2371_feed_suffix_policy.py)

const bld2371PSL = "// ===BEGIN ICANN DOMAINS===\ncom\nio\nco.uk\nxn--p1ai\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n" +
	"// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"

type bld2371Options struct {
	privatePolicy, icannPolicy string
	provenance                 string
	feed, group                string
	wildcardOff, privateOff    bool
}

func bld2371Build(t *testing.T, lines []string, opts bld2371Options) *buildResult {
	t.Helper()
	cfg := newBuildConfig()
	cfg.pslRules = bldRules(t, bld2371PSL)
	cfg.pslWildcardEnabled = !opts.wildcardOff
	cfg.pslIncludePrivate = !opts.privateOff
	cfg.pslFeedPrivatePolicy = orDefault(opts.privatePolicy, "honor")
	cfg.pslFeedIcannPolicy = orDefault(opts.icannPolicy, "honor")
	feed := bldFeed("feed.raw", orDefault(opts.feed, "FEED"), orDefault(opts.group, "GRP"))
	feed.provenance = opts.provenance
	return bldMustBuild(t, []manifestFeed{feed}, cfg, bldReader(lines...))
}

func bldBlock(result *buildResult, name string) (entry *blockEntry, isZone bool) {
	if zone, ok := result.zoneDB[name]; ok {
		return zone, true
	}
	return result.dataDB[name], false
}

func TestSuffixPolicyOnAPlainEntry(t *testing.T) {
	for _, tc := range []struct {
		name, line, private, icann string
		want                       string // "drop", "data" or "zone"
	}{
		{"private ignore drops", "github.io", "ignore", "honor", "drop"},
		{"private apex is exact data", "github.io", "apex", "honor", "data"},
		{"private honor is exact data", "github.io", "honor", "honor", "data"},
		{"icann ignore drops", "co.uk", "honor", "ignore", "drop"},
		{"icann apex is exact data", "co.uk", "honor", "apex", "data"},
		{"icann honor is exact data", "co.uk", "honor", "honor", "data"},
		// the winning rule's section selects the policy, not a fixed per-domain guess
		{"private rule beats its icann parent", "github.io", "ignore", "apex", "drop"},
		{"a single-label name never reaches the policy", "ck", "honor", "ignore", "gone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := bld2371Build(t, []string{tc.line}, bld2371Options{privatePolicy: tc.private, icannPolicy: tc.icann})
			entry, isZone := bldBlock(result, tc.line)
			switch tc.want {
			case "drop":
				if entry != nil {
					t.Errorf("%s was loaded (zone = %v)", tc.line, isZone)
				}
				if got := bldRejectRow(result, "FEED", "GRP")["suffix_drop"]; got != 1 {
					t.Errorf("suffix_drop = %d, want 1", got)
				}
			case "gone": // a single-label name is a shape reject, so the policy never sees it
				if entry != nil {
					t.Errorf("%s was loaded (zone = %v)", tc.line, isZone)
				}
			case "data":
				if entry == nil || isZone || entry.band != PRIO_FEED_BLOCK {
					t.Errorf("%s = (%+v, zone %v), want exact data at band 1", tc.line, entry, isZone)
				}
			}
		})
	}
}

func TestSuffixPolicyOnAnAbpAnchor(t *testing.T) {
	for _, tc := range []struct {
		name, line, private, icann string
		want                       string
	}{
		{"private ignore drops", "||github.io^", "ignore", "honor", "drop"},
		{"private apex demotes", "||github.io^$important", "apex", "honor", "demote"},
		{"private honor stays a zone", "||github.io^", "honor", "honor", "zone"},
		{"icann ignore drops", "||co.uk^", "honor", "ignore", "drop"},
		{"icann apex demotes", "||co.uk^", "honor", "apex", "demote"},
		{"icann honor stays a zone", "||co.uk^", "honor", "honor", "zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(tc.line, "$important"), "||"), "^")
			result := bld2371Build(t, []string{tc.line}, bld2371Options{privatePolicy: tc.private, icannPolicy: tc.icann})
			entry, isZone := bldBlock(result, name)
			row := bldRejectRow(result, "FEED", "GRP")
			switch tc.want {
			case "drop":
				if entry != nil || row["suffix_drop"] != 1 {
					t.Errorf("%s = %+v, tally %v, want dropped and tallied", name, entry, row)
				}
			case "demote":
				if entry == nil || isZone || row["suffix_demote"] != 1 {
					t.Errorf("%s = (%+v, zone %v), tally %v, want demoted to data and tallied", name, entry, isZone, row)
				}
				if strings.HasSuffix(tc.line, "$important") && (!entry.important || entry.log != "1") {
					t.Errorf("the demoted payload %+v lost its important flag or log", entry)
				}
			case "zone":
				if entry == nil || !isZone {
					t.Errorf("%s = (%+v, zone %v), want a wildcard zone", name, entry, isZone)
				}
			}
		})
	}
}

func TestSuffixPolicyNeverTouchesUserProvenance(t *testing.T) {
	for _, tc := range []struct {
		line   string
		isZone bool
	}{{"github.io", false}, {"||github.io^", true}} {
		result := bld2371Build(t, []string{tc.line}, bld2371Options{privatePolicy: "ignore", icannPolicy: "ignore", provenance: "user"})
		entry, isZone := bldBlock(result, "github.io")
		if entry == nil || isZone != tc.isZone {
			t.Errorf("%s as a user row = (%+v, zone %v), want kept (zone %v)", tc.line, entry, isZone, tc.isZone)
		}
		if len(bldRejectRow(result, "FEED", "GRP")) != 0 {
			t.Errorf("a user row tallied %v", bldRejectRow(result, "FEED", "GRP"))
		}
	}
}

func TestSuffixPolicyLeavesNonSuffixNamesAlone(t *testing.T) {
	corpus := []string{"example.com", "a.b.example.github.io", "sub.co.uk"}
	abp := []string{"||example.com^", "||a.b.example.github.io^", "||sub.co.uk^"}
	for _, lines := range [][]string{corpus, abp} {
		honor := bld2371Build(t, lines, bld2371Options{})
		restrictive := bld2371Build(t, lines, bld2371Options{privatePolicy: "ignore", icannPolicy: "ignore"})
		if !reflect.DeepEqual(honor.dataDB, restrictive.dataDB) || !reflect.DeepEqual(honor.zoneDB, restrictive.zoneDB) || !reflect.DeepEqual(honor.rejects, restrictive.rejects) {
			t.Errorf("%v classifies differently under a restrictive policy", lines)
		}
	}
}

func TestSuffixPolicyAppliesWithWildcardBlockingOff(t *testing.T) {
	result := bld2371Build(t, []string{"||co.uk^"}, bld2371Options{icannPolicy: "apex", wildcardOff: true})
	if _, ok := result.zoneDB["co.uk"]; ok || result.dataDB["co.uk"] == nil {
		t.Errorf("apex with Wildcard Blocking off: zone %v data %v, want exact data", result.zoneDB["co.uk"], result.dataDB["co.uk"])
	}
	result = bld2371Build(t, []string{"||co.uk^"}, bld2371Options{icannPolicy: "ignore", wildcardOff: true})
	if result.counts != 0 || bldRejectRow(result, "FEED", "GRP")["suffix_drop"] != 1 {
		t.Errorf("ignore with Wildcard Blocking off: counts %d tally %v, want dropped and tallied", result.counts, result.rejects)
	}
}

func TestSuffixPolicyWithPrivateRecognitionOff(t *testing.T) {
	for _, tc := range []struct {
		name, private, icann, provenance string
		want                             string // "demote", "drop", "zone"
	}{
		{"apex demotes the classifier zone", "apex", "honor", "", "demote"},
		{"ignore still drops", "ignore", "honor", "", "drop"},
		{"honor keeps the classifier zone", "honor", "honor", "", "zone"},
		{"a user row keeps the zone under apex", "apex", "apex", "user", "zone"},
		{"private honor is not demoted while icann arms the gate", "honor", "apex", "", "zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := bld2371Build(t, []string{"github.io"}, bld2371Options{privatePolicy: tc.private, icannPolicy: tc.icann, provenance: tc.provenance, privateOff: true})
			entry, isZone := bldBlock(result, "github.io")
			row := bldRejectRow(result, "FEED", "GRP")
			switch tc.want {
			case "demote":
				if entry == nil || isZone || entry.band != PRIO_FEED_BLOCK || row["suffix_demote"] != 1 {
					t.Errorf("= (%+v, zone %v), tally %v, want exact data and a demote", entry, isZone, row)
				}
			case "drop":
				if entry != nil || row["suffix_drop"] != 1 {
					t.Errorf("= %+v, tally %v, want dropped", entry, row)
				}
			case "zone":
				if entry == nil || !isZone || row["suffix_demote"] != 0 {
					t.Errorf("= (%+v, zone %v), tally %v, want the zone kept", entry, isZone, row)
				}
			}
		})
	}
}

func TestSuffixPolicyTalliesPerFeedGroup(t *testing.T) {
	honor := bld2371Build(t, []string{"github.io", "||co.uk^"}, bld2371Options{})
	if len(honor.rejects) != 0 {
		t.Errorf("honor tallied %v", honor.rejects)
	}
	result := bld2371Build(t, []string{"github.io", "||co.uk^"}, bld2371Options{privatePolicy: "ignore", icannPolicy: "apex", feed: "MyFeed", group: "MyGroup"})
	if row := bldRejectRow(result, "MyFeed", "MyGroup"); row["suffix_drop"] != 1 || row["suffix_demote"] != 1 {
		t.Errorf("tally = %v, want one drop and one demote", row)
	}
}

func TestSuffixPolicyDoesNotTouchAllowsAndIrreducibleRegex(t *testing.T) {
	result := bld2371Build(t, []string{"||github.io^", "@@||github.io^"}, bld2371Options{privatePolicy: "ignore", icannPolicy: "ignore"})
	if entry, _ := bldBlock(result, "github.io"); entry != nil {
		t.Error("the BLOCK anchor survived the policy")
	}
	if _, ok := result.whiteDB["github.io"]; !ok {
		t.Error("the ALLOW anchor at the same suffix name was dropped")
	}
	result = bld2371Build(t, []string{`/(a|b)\.github\.io$/`}, bld2371Options{privatePolicy: "ignore", icannPolicy: "ignore"})
	if result.regexDB.len() != 1 {
		t.Errorf("regexDB has %d rules, want the irreducible pattern kept", result.regexDB.len())
	}
}

// The policy is a third authority-load gate in dnsblConfigFromManifest, independent of Wildcard Blocking and TLD-Allow.
func TestSuffixPolicyIsAThirdAuthorityLoadGate(t *testing.T) {
	stage := func(t *testing.T, authority string) (*pfbUnbound, string) {
		dir := t.TempDir()
		bldWriteFile(t, filepath.Join(dir, "dnsbl_psl"), authority)
		bldWriteFile(t, filepath.Join(dir, "feed.raw"), "example.com\n")
		manifestPath := filepath.Join(dir, "pfb_py_sources.json")
		bldWriteManifest(t, manifestPath, map[string]any{
			"version": 1,
			"feeds":   []map[string]any{{"raw": "feed.raw", "feed": "feed", "group": "group", "log_flag": "1"}},
			"config":  map[string]any{"tld_wildcard_blacklist": []string{}, "tld_wildcard_exclusion": []string{}},
		})
		m := bldModuleIn(dir)
		m.pfb.pfbPyPsl = filepath.Join(dir, "dnsbl_psl")
		return m, manifestPath
	}

	t.Run("policy alone opens the authority", func(t *testing.T) {
		m, manifestPath := stage(t, bld2371PSL)
		m.pfb.pslFeedPrivatePolicy = "apex"
		result := m.dnsblBuildFromManifest(manifestPath)
		if result == nil || !slices.Equal(result.pslRules.privateExact, []string{"github.io"}) {
			t.Fatalf("result = %+v, want the authority loaded", result)
		}
	})
	t.Run("policy alone fails closed on a corrupt authority", func(t *testing.T) {
		bldCaptureLog(t)
		m, manifestPath := stage(t, "\xff")
		m.pfb.pslFeedPrivatePolicy = "ignore"
		if result := m.dnsblBuildFromManifest(manifestPath); result != nil {
			t.Errorf("result = %+v, want nil", result)
		}
	})
	t.Run("both honor and both old gates off never opens the authority", func(t *testing.T) {
		// A corrupt authority would fail the build if it were opened.
		m, manifestPath := stage(t, "\xff")
		result := m.dnsblBuildFromManifest(manifestPath)
		if result == nil || !reflect.DeepEqual(result.pslRules, pslRules{}) {
			t.Fatalf("result = %+v, want the empty rules", result)
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_dnsbl_manifest_v1_contract.py

// bldStageCorpus is _stage_fixture: the manifest-v1 corpus fixture and its raw feeds under one directory.
func bldStageCorpus(t *testing.T) (dir, manifestPath string, manifest map[string]any) {
	t.Helper()
	corpus := bldFixtureDir("dnsbl_corpus")
	data, err := os.ReadFile(filepath.Join(corpus, "manifest-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	for _, row := range manifest["feeds"].([]any) {
		rel := row.(map[string]any)["raw"].(string)
		content, err := os.ReadFile(filepath.Join(corpus, rel))
		if err != nil {
			t.Fatal(err)
		}
		bldWriteFile(t, filepath.Join(dir, rel), string(content))
	}
	sidecar, err := os.ReadFile(filepath.Join(corpus, "pfb_py_top1m.txt"))
	if err != nil {
		t.Fatal(err)
	}
	bldWriteFile(t, filepath.Join(dir, "pfb_py_top1m.txt"), string(sidecar))
	manifestPath = filepath.Join(dir, "pfb_py_sources.json")
	bldWriteManifest(t, manifestPath, manifest)
	return dir, manifestPath, manifest
}

func TestFixtureManifestV1BuildsAndConfigAffectsResult(t *testing.T) {
	dir, manifestPath, _ := bldStageCorpus(t)
	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)
	if result == nil {
		t.Fatal("the fixture manifest did not build")
	}
	if zip := result.zoneDB["zip"]; zip == nil || zip.index < 0 {
		t.Errorf("zoneDB[zip] = %+v", zip)
	}
	if _, ok := result.whiteDB["popularcdn.com"]; ok {
		t.Error("popularcdn.com is whitelisted: no Group in this vintage opts into TOP1M")
	}
	if entry := result.whiteDB["adblock.com"]; entry.wildcard {
		t.Errorf("whiteDB[adblock.com] = %+v, want exact", entry)
	}
	if entry := result.whiteDB["wildwhite.org"]; !entry.wildcard {
		t.Errorf("whiteDB[wildwhite.org] = %+v, want a wildcard", entry)
	}
	if entry := result.whiteDB["allowme.example"]; entry.band != PRIO_FEED_ALLOW {
		t.Errorf("whiteDB[allowme.example] = %+v, want a band-2 permit allow", entry)
	}
	groups := map[string]bool{}
	for _, row := range result.feedGroupIndexDB {
		groups[row.group] = true
	}
	for _, group := range []string{"\ufffd", "grp_custom", "grp_permit"} {
		if !groups[group] {
			t.Errorf("no feed is attributed to group %q (have %v)", group, groups)
		}
	}
}

func TestInBaseAbsoluteRawPathIsPreserved(t *testing.T) {
	dir, manifestPath, manifest := bldStageCorpus(t)
	first := manifest["feeds"].([]any)[0].(map[string]any)
	first["raw"] = filepath.Join(dir, first["raw"].(string))
	manifest["feeds"] = []any{first}
	bldWriteManifest(t, manifestPath, manifest)
	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)
	if result == nil || result.counts == 0 {
		t.Fatalf("result = %+v, want a build of the in-base absolute path", result)
	}
}

func TestEmptyFeedsAreValid(t *testing.T) {
	dir, manifestPath, manifest := bldStageCorpus(t)
	manifest["feeds"] = []any{}
	manifest["config"] = map[string]any{}
	bldWriteManifest(t, manifestPath, manifest)
	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)
	if result == nil || len(result.dataDB) != 0 || len(result.zoneDB) != 0 || result.counts != 0 {
		t.Fatalf("result = %+v, want an empty build", result)
	}
}

func TestEmptyGroupAndLogFlagAreValid(t *testing.T) {
	dir, manifestPath, manifest := bldStageCorpus(t)
	first := manifest["feeds"].([]any)[0].(map[string]any)
	first["group"], first["log_flag"] = "", ""
	manifest["feeds"] = []any{first}
	bldWriteManifest(t, manifestPath, manifest)
	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)
	if result == nil {
		t.Fatal("did not build")
	}
	found := false
	for _, row := range result.feedGroupIndexDB {
		found = found || row.group == ""
	}
	if !found {
		t.Error("no feed is attributed to the empty group")
	}
	if got := result.dataDB["plainhost1.example"]; got == nil || got.log != "" {
		t.Errorf("dataDB[plainhost1.example] = %+v, want the empty log flag", got)
	}
}

func TestUnknownAdditiveRootConfigAndFeedKeysAreAccepted(t *testing.T) {
	dir, manifestPath, manifest := bldStageCorpus(t)
	manifest["future_root"] = map[string]any{"enabled": true}
	manifest["config"].(map[string]any)["future_config"] = map[string]any{"value": 7}
	manifest["feeds"].([]any)[0].(map[string]any)["future_feed"] = []any{"kept additive"}
	bldWriteManifest(t, manifestPath, manifest)
	if bldModuleIn(dir).dnsblBuildFromManifest(manifestPath) == nil {
		t.Fatal("additive keys rejected the manifest")
	}
}

func TestInvalidV1ShapeIsRejectedBeforeAnyRawIO(t *testing.T) {
	// A row whose raw file is missing AND whose log_flag has the wrong type is refused for the type, which proves every
	// shape is checked before the first path.
	dir, manifestPath, manifest := bldStageCorpus(t)
	first := manifest["feeds"].([]any)[0].(map[string]any)
	first["raw"], first["log_flag"] = "missing.raw", 1
	bldWriteManifest(t, manifestPath, manifest)
	bldCaptureLog(t)
	if bldModuleIn(dir).dnsblBuildFromManifest(manifestPath) != nil {
		t.Fatal("built")
	}
	entries := bldLedgerEntries(t, dir)
	if len(entries) == 0 || !strings.Contains(entries[len(entries)-1]["message"].(string), "feeds[0].log_flag") {
		t.Errorf("ledger = %v, want the log_flag refusal", entries)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_manifest_path_confinement.py, tests/test_issue1284_dnsbl_feed_line_framing.py

func bldDrain(reader lineReader, raw string) (lines []string, err error) {
	for line, readErr := range reader(raw) {
		if readErr != nil {
			return lines, readErr
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func TestFeedPathConfinement(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	bldWriteFile(t, filepath.Join(base, "feed.txt"), "good.example\nblock.example\n")
	bldWriteFile(t, filepath.Join(root, "secret.txt"), "escaped.example\n")
	reader := dnsblFileLineReader(base, false)

	out := bldCaptureLog(t)
	if lines, _ := bldDrain(reader, "feed.txt"); !slices.Equal(lines, []string{"good.example", "block.example"}) {
		t.Errorf("in-base feed = %q", lines)
	}
	if strings.Contains(out.String(), "Refusing DNSBL feed") {
		t.Errorf("an in-base feed was refused: %s", out)
	}

	// before-state: the in-base equivalent of the same name WOULD be read
	bldWriteFile(t, filepath.Join(base, "secret.txt"), "inbase.example\n")
	if lines, _ := bldDrain(reader, "secret.txt"); !slices.Equal(lines, []string{"inbase.example"}) {
		t.Errorf("in-base secret.txt = %q", lines)
	}
	out.Reset()
	for name, raw := range map[string]string{"traversal": filepath.Join("..", "secret.txt"), "absolute": filepath.Join(root, "secret.txt")} {
		out.Reset()
		if lines, err := bldDrain(reader, raw); len(lines) != 0 || err != nil {
			t.Errorf("%s: lines = %q, err = %v, want nothing yielded and no error", name, lines, err)
		}
		if !strings.Contains(out.String(), "Refusing DNSBL feed outside base dir") {
			t.Errorf("%s: log = %q, want the refusal", name, out)
		}
	}
}

func TestFeedPathConfinementRefusesALinkOutOfBase(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	bldWriteFile(t, filepath.Join(root, "outside.raw"), "outside.example\n")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside.raw"), filepath.Join(base, "link.raw")); err != nil {
		t.Fatal(err)
	}
	out := bldCaptureLog(t)
	if lines, _ := bldDrain(dnsblFileLineReader(base, false), "link.raw"); len(lines) != 0 {
		t.Errorf("a link out of base yielded %q", lines)
	}
	if !strings.Contains(out.String(), "Refusing DNSBL feed outside base dir") {
		t.Errorf("log = %q", out)
	}
}

func TestFailClosedReaderReturnsTheRefusalAsAnError(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	bldWriteFile(t, filepath.Join(base, "ok.raw"), "a.example\n")
	bldWriteFile(t, filepath.Join(root, "outside.raw"), "b.example\n")
	if err := os.Mkdir(filepath.Join(base, "dir.raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	bldCaptureLog(t)
	reader := dnsblFileLineReader(base, true)
	for raw, want := range map[string]string{
		"../outside.raw": "Refusing DNSBL feed outside base dir: '" + base + "/../outside.raw'",
		"missing.raw":    "Failed to read DNSBL feed '" + base + "/missing.raw': [Errno 2] No such file or directory: '" + base + "/missing.raw'",
		"dir.raw":        "Failed to read DNSBL feed '" + base + "/dir.raw': [Errno 21] Is a directory: '" + base + "/dir.raw'",
	} {
		if _, err := bldDrain(reader, raw); err == nil || err.Error() != want {
			t.Errorf("reader(%q) error = %v, want %q", raw, err, want)
		}
	}
	if lines, err := bldDrain(reader, "ok.raw"); err != nil || !slices.Equal(lines, []string{"a.example"}) {
		t.Errorf("reader(ok.raw) = (%q, %v)", lines, err)
	}
}

func TestReaderLogsAndSkipsOpenFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "directory.raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"missing.raw", "directory.raw"} {
		out := bldCaptureLog(t)
		if lines, err := bldDrain(dnsblFileLineReader(dir, false), raw); len(lines) != 0 || err != nil {
			t.Errorf("%s: lines = %q, err = %v", raw, lines, err)
		}
		if !strings.Contains(out.String(), "Failed to read DNSBL feed") {
			t.Errorf("%s: log = %q, want the open failure", raw, out)
		}
	}
}

func TestReaderDefersOpenUntilIteration(t *testing.T) {
	out := bldCaptureLog(t)
	seq := dnsblFileLineReader(t.TempDir(), false)("missing.raw")
	if out.Len() != 0 {
		t.Fatalf("the reader did I/O before iteration: %q", out)
	}
	for range seq {
		t.Fatal("a missing feed yielded a line")
	}
	if !strings.Contains(out.String(), "Failed to read DNSBL feed") {
		t.Errorf("log = %q", out)
	}
}

func TestReaderStopsWhenTheConsumerDoes(t *testing.T) {
	dir := t.TempDir()
	bldWriteFile(t, filepath.Join(dir, "feed.raw"), "a\nb\nc\n")
	var got []string
	for line := range dnsblFileLineReader(dir, true)("feed.raw") {
		got = append(got, line)
		break
	}
	if !slices.Equal(got, []string{"a"}) {
		t.Errorf("got %q", got)
	}
}

func TestInvalidRawMemberRejectsTheWholeManifestAndOpensTheLedger(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "traversal", "absolute", "symlink_escape", "missing_key", "wrong_type"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "base")
			bldWriteFile(t, filepath.Join(root, "outside.raw"), "outside.example\n")
			if err := os.Mkdir(base, 0o755); err != nil {
				t.Fatal(err)
			}
			var raw any = "missing.raw"
			switch kind {
			case "directory":
				if err := os.Mkdir(filepath.Join(base, "directory.raw"), 0o755); err != nil {
					t.Fatal(err)
				}
				raw = "directory.raw"
			case "traversal":
				raw = "../outside.raw"
			case "absolute":
				raw = filepath.Join(root, "outside.raw")
			case "symlink_escape":
				if err := os.Symlink(filepath.Join(root, "outside.raw"), filepath.Join(base, "link.raw")); err != nil {
					t.Fatal(err)
				}
				raw = "link.raw"
			case "wrong_type":
				raw = []string{"feed.raw"}
			}
			row := map[string]any{"raw": raw, "feed": "Bad", "group": "Test", "log_flag": "1"}
			if kind == "missing_key" {
				delete(row, "raw")
			}
			manifestPath := filepath.Join(base, "pfb_py_sources.json")
			bldWriteManifest(t, manifestPath, map[string]any{"version": 1, "config": map[string]any{}, "feeds": []any{row}})
			bldCaptureLog(t)

			if result := bldModuleIn(base).dnsblBuildFromManifest(manifestPath); result != nil {
				t.Fatalf("%s raw reference produced a partial build", kind)
			}
			entries := bldLedgerEntries(t, base)
			if len(entries) != 1 || entries[0]["item"] != manifestPath || entries[0]["stage"] != "parse" {
				t.Errorf("ledger = %v, want one parse entry for %s", entries, manifestPath)
			}
		})
	}
}

func TestPathWithinBaseHelper(t *testing.T) {
	// base_dir resolving to "/": a child is contained (the old startswith(real_base + os.sep) form built "//").
	if !dnsblPathWithinBase("/var/unbound/x/y", "/") {
		t.Error("a child of / is rejected")
	}
	if dnsblPathWithinBase("/etc/passwd", "/var/unbound/pfb") {
		t.Error("a path outside the base is contained")
	}
}

// TestTldWildcardOracleGating: the PSL authority is the shipped file, gated by python_tld_wildcard, never the manifest.
func TestTldWildcardOracleGating(t *testing.T) {
	authority := bldAuthority([]string{"com", "net"})
	stage := func(t *testing.T) (*pfbUnbound, string) {
		dir := t.TempDir()
		bldWriteFile(t, filepath.Join(dir, "dnsbl_psl"), authority)
		m := bldModuleIn(dir)
		m.pfb.pfbPyPsl = filepath.Join(dir, "dnsbl_psl")
		return m, dir
	}
	t.Run("not loaded when the flag is off even if the file exists", func(t *testing.T) {
		m, dir := stage(t)
		cfg, err := m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{}}, dir)
		if err != nil || !reflect.DeepEqual(cfg.pslRules, pslRules{}) {
			t.Errorf("config = (%+v, %v), want the empty rules: OFF must never load the oracle", cfg.pslRules, err)
		}
	})
	t.Run("loaded when the flag is on and the file is present", func(t *testing.T) {
		m, dir := stage(t)
		m.pfb.pythonTldWildcard = true
		cfg, err := m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{}}, dir)
		if err != nil || !slices.Equal(cfg.pslRules.icannExact, []string{"com", "net"}) {
			t.Errorf("config = (%+v, %v), want icann_exact = com, net", cfg.pslRules, err)
		}
	})
	t.Run("fails closed when the flag is on but the file is missing", func(t *testing.T) {
		m, dir := stage(t)
		m.pfb.pythonTldWildcard = true
		m.pfb.pfbPyPsl = filepath.Join(dir, "does_not_exist")
		if _, err := m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{}}, dir); err == nil || !strings.Contains(err.Error(), "PSL authority") {
			t.Errorf("err = %v, want a PSL authority error", err)
		}
	})
	for _, flagOn := range []bool{false, true} {
		t.Run(fmt.Sprintf("a manifest tld_master key is ignored with the flag %v", flagOn), func(t *testing.T) {
			m, dir := stage(t)
			m.pfb.pythonTldWildcard = flagOn
			cfg, err := m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{"tld_master": "/etc/passwd"}}, dir)
			var want []string
			if flagOn {
				want = []string{"com", "net"}
			}
			if err != nil || !slices.Equal(cfg.pslRules.icannExact, want) {
				t.Errorf("icann_exact = %q (%v), want %q: only the shipped oracle, never the manifest's tld_master", cfg.pslRules.icannExact, err, want)
			}
		})
	}
}

func TestDnsblConfigFromManifest(t *testing.T) {
	m := bldModuleIn(t.TempDir())
	m.pfb.regexCap = true
	cfg, err := m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{
		"user_unlock": []any{"evil.com", ".wild.net"}, "regex_cap": false, "builtin_log_flag": "3",
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.userUnlock, []string{"evil.com", ".wild.net"}) {
		t.Errorf("userUnlock = %q: the unlock set passes through", cfg.userUnlock)
	}
	if cfg.regexCap || cfg.builtinLogFlag != "3" {
		t.Errorf("regexCap = %v, builtinLogFlag = %q: a manifest regex_cap beats the ini's; the log flag is read", cfg.regexCap, cfg.builtinLogFlag)
	}
	cfg, err = m.dnsblConfigFromManifest(map[string]any{"config": map[string]any{}}, "")
	if err != nil || len(cfg.userUnlock) != 0 || !cfg.regexCap || cfg.builtinLogFlag != "0" {
		t.Errorf("config = (%+v, %v), want an empty unlock set, the ini's regex_cap and the Null Blocking default", cfg, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_adr06_init_from_raw.py

func TestInitFromRawManifestRows(t *testing.T) {
	t.Run("counts is the loaded total and the emitter writes it", func(t *testing.T) {
		dir, manifestPath := bldStageGolden(t, false)
		result := bldGoldenModule(dir, true).dnsblBuildFromManifest(manifestPath)
		if result == nil || result.counts != len(result.dataDB)+len(result.zoneDB) || result.counts == 0 {
			t.Fatalf("result = %+v", result)
		}
		countPath := filepath.Join(dir, "pfb_py_count")
		if !dnsblEmitCount(countPath, result.counts) {
			t.Fatal("dnsblEmitCount failed")
		}
		if data, err := os.ReadFile(countPath); err != nil || string(data) != fmt.Sprintf("%d\n", result.counts) {
			t.Errorf("pfb_py_count = %q (%v), want %d and a newline", data, err, result.counts)
		}
	})
	t.Run("top1m_enabled flows from the manifest config", func(t *testing.T) {
		dir, manifestPath := bldStageGolden(t, true)
		enabled := bldGoldenModule(dir, true).dnsblBuildFromManifest(manifestPath)
		if enabled == nil {
			t.Fatal("did not build")
		}
		if _, ok := enabled.whiteDB["popularcdn.com"]; ok {
			t.Error("TOP1M added a sovereign whiteDB allow (#3648)")
		}
		if _, ok := enabled.dataDB["popularcdn.com"]; ok {
			t.Error("the ticked Group still blocks popularcdn.com with TOP1M on")
		}
		dir, manifestPath = bldStageGolden(t, false)
		disabled := bldGoldenModule(dir, true).dnsblBuildFromManifest(manifestPath)
		_, inData := disabled.dataDB["popularcdn.com"]
		_, inZone := disabled.zoneDB["popularcdn.com"]
		if !inData && !inZone {
			t.Error("popularcdn.com is not blocked with TOP1M off")
		}
	})
	t.Run("the oracle staged and on classifies a public suffix as a zone", func(t *testing.T) {
		dir, manifestPath := bldStageGolden(t, false)
		result := bldGoldenModule(dir, true).dnsblBuildFromManifest(manifestPath)
		if _, ok := result.zoneDB["shop.co.uk"]; !ok {
			t.Error("shop.co.uk is not a zone")
		}
		if _, ok := result.zoneDB["tracker.org"]; !ok {
			t.Error("tracker.org is not a zone")
		}
	})
	t.Run("the oracle off forces exact data even when the file is staged", func(t *testing.T) {
		dir, manifestPath := bldStageGolden(t, false)
		result := bldGoldenModule(dir, false).dnsblBuildFromManifest(manifestPath)
		if _, ok := result.zoneDB["shop.co.uk"]; ok || result.dataDB["shop.co.uk"] == nil {
			t.Errorf("shop.co.uk: zone %v data %v, want exact data", result.zoneDB["shop.co.uk"], result.dataDB["shop.co.uk"])
		}
	})
	t.Run("user_unlock merges into whiteDB", func(t *testing.T) {
		dir := t.TempDir()
		bldWriteFile(t, filepath.Join(dir, "feed.raw"), "evil.com\n")
		manifestPath := filepath.Join(dir, "pfb_py_sources.json")
		bldWriteManifest(t, manifestPath, map[string]any{
			"version": 1, "config": map[string]any{"user_unlock": []string{"evil.com"}},
			"feeds": []any{map[string]any{"raw": "feed.raw", "feed": "F", "group": "G", "log_flag": "1"}},
		})
		result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)
		if result == nil {
			t.Fatal("did not build")
		}
		want := whiteEntry{wildcard: false, important: true, band: PRIO_USER_ALLOW, hasBand: true}
		if got := result.whiteDB["evil.com"]; got != want {
			t.Errorf("whiteDB[evil.com] = %+v, want %+v", got, want)
		}
		// no oracle staged here: exact DATA, not a wildcard zone
		if result.dataDB["evil.com"] == nil || result.zoneDB["evil.com"] != nil {
			t.Errorf("evil.com: data %v zone %v, want exact data", result.dataDB["evil.com"], result.zoneDB["evil.com"])
		}
	})
}

func TestManifestFallback(t *testing.T) {
	t.Run("a missing manifest returns nil and opens the ledger", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nope.json")
		if bldModuleIn(dir).dnsblBuildFromManifest(path) != nil {
			t.Fatal("built")
		}
		entries := bldLedgerEntries(t, dir)
		if len(entries) != 1 || entries[0]["message"] != "DNSBL manifest absent: "+path+" -- DNSBL not loaded" {
			t.Errorf("ledger = %v", entries)
		}
	})
	t.Run("a broken manifest returns nil", func(t *testing.T) {
		dir := t.TempDir()
		bldWriteFile(t, filepath.Join(dir, "bad.json"), "{ this is not json")
		bldCaptureLog(t)
		if bldModuleIn(dir).dnsblBuildFromManifest(filepath.Join(dir, "bad.json")) != nil {
			t.Error("built")
		}
	})
	t.Run("a missing feed file rejects the whole generation", func(t *testing.T) {
		dir, _ := bldStageGolden(t, false)
		path := filepath.Join(dir, "m.json")
		bldWriteManifest(t, path, map[string]any{"version": 1, "config": map[string]any{}, "feeds": []any{
			map[string]any{"raw": "does_not_exist.txt", "feed": "Gone", "group": "Gone", "log_flag": "1"},
			map[string]any{"raw": "pfb_py_raw/feed_plain.txt", "feed": "PlainFeed", "group": "Malware", "log_flag": "1"},
		}})
		bldCaptureLog(t)
		if bldGoldenModule(dir, true).dnsblBuildFromManifest(path) != nil {
			t.Fatal("a partial build was exposed")
		}
		found := false
		for _, entry := range bldLedgerEntries(t, dir) {
			found = found || entry["facility"] == "dnsbl" && entry["item"] == path && entry["stage"] == "parse"
		}
		if !found {
			t.Error("the ledger has no dnsbl parse entry for the manifest")
		}
	})
	t.Run("an empty feeds manifest builds empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "m.json")
		bldWriteManifest(t, path, map[string]any{"version": 1, "config": map[string]any{}, "feeds": []any{}})
		result := bldModuleIn(dir).dnsblBuildFromManifest(path)
		if result == nil || result.counts != 0 || len(result.dataDB) != 0 || len(result.zoneDB) != 0 {
			t.Errorf("result = %+v", result)
		}
	})
	t.Run("a build that fails returns nil", func(t *testing.T) {
		// A feeds row missing "feed": Python's KeyError, a contract error here.
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.json")
		bldWriteManifest(t, path, map[string]any{"feeds": []any{map[string]any{"group": "g", "log_flag": "1", "raw": "x"}}, "config": map[string]any{}})
		bldCaptureLog(t)
		if bldModuleIn(dir).dnsblBuildFromManifest(path) != nil {
			t.Error("built")
		}
	})
	t.Run("a success closes the ledger entry a failure opened", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "m.json")
		bldWriteManifest(t, path, map[string]any{"version": 2})
		bldCaptureLog(t)
		m := bldModuleIn(dir)
		if m.dnsblBuildFromManifest(path) != nil || len(bldLedgerEntries(t, dir)) != 1 {
			t.Fatalf("the failed generation left %v", bldLedgerEntries(t, dir))
		}
		bldWriteManifest(t, path, map[string]any{"version": 1, "config": map[string]any{}, "feeds": []any{}})
		if m.dnsblBuildFromManifest(path) == nil || len(bldLedgerEntries(t, dir)) != 0 {
			t.Errorf("the good generation left %v", bldLedgerEntries(t, dir))
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// the TOP1M sidecar (the integrity checks of _dnsbl_fixed_top1m_lines)

func bldSidecar(t *testing.T, content string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "pfb_py_top1m.txt")
	bldWriteFile(t, path, content)
	return dir, path
}

func TestSidecarChangedWhileReading(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(t *testing.T, path string)
		wantErr string
	}{
		{"an append", func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("late.example\n")
			f.Close()
		}, "TOP1M sidecar changed while reading"},
		{"a truncation", func(t *testing.T, path string) {
			if err := os.Truncate(path, 3); err != nil {
				t.Fatal(err)
			}
		}, "TOP1M sidecar changed while reading"},
		{"a same-size rewrite", func(t *testing.T, path string) {
			bldWriteFile(t, path, "x.example\ny.example\nz.example\n")
		}, "TOP1M sidecar changed while reading"},
		{"a touch", func(t *testing.T, path string) {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			later := info.ModTime().Add(2 * time.Second)
			if err := os.Chtimes(path, later, later); err != nil {
				t.Fatal(err)
			}
		}, "TOP1M sidecar changed while reading"},
		{"a replacement by another file, which leaves the open one intact", func(t *testing.T, path string) {
			bldWriteFile(t, path+".new", "other.example\n")
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"nothing", func(*testing.T, string) {}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := bldSidecar(t, "a.example\nb.example\nc.example\n")
			var lines []string
			var gotErr error
			for line, err := range dnsblFixedTop1mLines(dir) {
				if err != nil {
					gotErr = err
					break
				}
				if len(lines) == 0 {
					tc.change(t, path)
				}
				lines = append(lines, line)
			}
			if tc.wantErr == "" {
				if gotErr != nil || !slices.Equal(lines, []string{"a.example", "b.example", "c.example"}) {
					t.Errorf("lines = %q, err = %v, want the file as it was opened", lines, gotErr)
				}
				return
			}
			if want := tc.wantErr + ": '" + path + "'"; gotErr == nil || gotErr.Error() != want {
				t.Errorf("err = %v, want %q", gotErr, want)
			}
		})
	}
}

func TestSidecarRefusesASymlinkAndANonRegularFile(t *testing.T) {
	dir, path := bldSidecar(t, "a.example\n")
	if err := os.Rename(path, filepath.Join(dir, "elsewhere.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere.txt"), path); err != nil {
		t.Fatal(err)
	}
	for range dnsblFixedTop1mLines(dir) {
	}
	var gotErr error
	for _, err := range dnsblFixedTop1mLines(dir) {
		gotErr = err
	}
	if want := "TOP1M sidecar is not a regular file: '" + path + "'"; gotErr == nil || gotErr.Error() != want {
		t.Errorf("symlink: err = %v, want %q", gotErr, want)
	}
}

func TestSidecarStopsWhenTheConsumerDoes(t *testing.T) {
	dir, _ := bldSidecar(t, "a.example\nb.example\n")
	count := 0
	for range dnsblFixedTop1mLines(dir) {
		count++
		break
	}
	if count != 1 {
		t.Errorf("count = %d", count)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// dnsbl_emit_count / dnsbl_emit_reject_stats (tests/test_branch_coverage_gaps.py, test_issue2371)

func TestEmitCount(t *testing.T) {
	out := bldCaptureLog(t)
	if dnsblEmitCount("/no/such/dir/count.txt", 42) {
		t.Error("an unwritable path reported success")
	}
	if !strings.Contains(out.String(), "Failed to write DNSBL count '/no/such/dir/count.txt': [Errno 2] No such file or directory") {
		t.Errorf("log = %q", out)
	}
	path := filepath.Join(t.TempDir(), "count.txt")
	if !dnsblEmitCount(path, 7) {
		t.Fatal("a writable path reported failure")
	}
	if data, _ := os.ReadFile(path); string(data) != "7\n" {
		t.Errorf("count file = %q, want \"7\\n\"", data)
	}
}

func TestEmitRejectStats(t *testing.T) {
	read := func(t *testing.T, path string) []map[string]any {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		if err := json.Unmarshal(data, &rows); err != nil {
			t.Fatalf("%q: %v", data, err)
		}
		return rows
	}
	t.Run("only nonzero rows are written", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pfb_py_reject_stats.json")
		tally := rejectTally{
			{"ZeroFeed", "ZeroGroup"}: {"shape": 0, "wire_cap": 0},
			{"RejFeed", "RejGroup"}:   {"shape": 3, "wire_cap": 5},
		}
		if !dnsblEmitRejectStats(path, tally) {
			t.Fatal("failed")
		}
		want := []map[string]any{{"feed": "RejFeed", "group": "RejGroup", "shape": 3.0, "wire_cap": 5.0}}
		if got := read(t, path); !reflect.DeepEqual(got, want) {
			t.Errorf("rows = %v, want %v", got, want)
		}
	})
	t.Run("an empty tally writes an empty array", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pfb_py_reject_stats.json")
		if !dnsblEmitRejectStats(path, rejectTally{}) {
			t.Fatal("failed")
		}
		if data, _ := os.ReadFile(path); string(data) != "[]" {
			t.Errorf("file = %q, want []", data)
		}
	})
	t.Run("the suffix buckets appear only when tallied", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pfb_py_reject_stats.json")
		tally := rejectTally{{"F", "G"}: {"shape": 0, "wire_cap": 0, "suffix_drop": 2, "suffix_demote": 1}, {"L", "G"}: {"shape": 3, "wire_cap": 5}}
		if !dnsblEmitRejectStats(path, tally) {
			t.Fatal("failed")
		}
		want := []map[string]any{
			{"feed": "F", "group": "G", "shape": 0.0, "wire_cap": 0.0, "suffix_drop": 2.0, "suffix_demote": 1.0},
			{"feed": "L", "group": "G", "shape": 3.0, "wire_cap": 5.0},
		}
		if got := read(t, path); !reflect.DeepEqual(got, want) {
			t.Errorf("rows = %v, want %v", got, want)
		}
	})
	t.Run("the write is atomic", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "pfb_py_reject_stats.json")
		if !dnsblEmitRejectStats(path, rejectTally{{"F", "G"}: {"shape": 1, "wire_cap": 0}}) {
			t.Fatal("failed")
		}
		if _, err := os.Stat(path + ".tmp"); err == nil {
			t.Error("the temp file was left behind")
		}
	})
	t.Run("an unwritable path reports failure and logs it", func(t *testing.T) {
		out := bldCaptureLog(t)
		if dnsblEmitRejectStats("/no/such/dir/pfb_py_reject_stats.json", rejectTally{}) {
			t.Error("reported success")
		}
		if !strings.Contains(out.String(), "Failed to write DNSBL reject stats '/no/such/dir/pfb_py_reject_stats.json'") {
			t.Errorf("log = %q", out)
		}
	})
	t.Run("a failed rename removes the temp file", func(t *testing.T) {
		bldCaptureLog(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "stats")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		bldWriteFile(t, filepath.Join(target, "keep"), "x") // a non-empty directory cannot be replaced
		if dnsblEmitRejectStats(target, rejectTally{}) {
			t.Error("reported success")
		}
		if _, err := os.Stat(target + ".tmp"); err == nil {
			t.Error("the temp file was left behind")
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_adr07_user_regex_containers.py: the build rows

type bldList struct {
	name  string
	lines []string
}

func bldRegexBuild(t *testing.T, regexCap bool, userFeeds []string, lists ...bldList) *buildResult {
	t.Helper()
	cfg := newBuildConfig()
	cfg.regexCap = regexCap
	var feeds []manifestFeed
	files := map[string][]string{}
	for _, list := range lists {
		row := bldFeed(list.name, list.name, list.name)
		if slices.Contains(userFeeds, list.name) {
			row.provenance = "user"
		}
		feeds = append(feeds, row)
		files[list.name] = list.lines
	}
	reader := func(raw string) iter.Seq2[string, error] { return lineSeq(files[raw]) }
	result, err := build(buildManifest{feeds: feeds}, cfg, reader, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// bldPatterns is {name: compiled pattern} of a regex DB, in its order.
func bldPatterns(db *regexDB) (names, patterns []string) {
	for name, entry := range db.items() {
		names = append(names, name)
		patterns = append(patterns, strings.TrimPrefix(entry.re.String(), "(?i)"))
	}
	return names, patterns
}

func bldWantRegexDB(t *testing.T, label string, db *regexDB, wantNames, wantPatterns []string) {
	t.Helper()
	names, patterns := bldPatterns(db)
	if !slices.Equal(names, wantNames) || !slices.Equal(patterns, wantPatterns) {
		t.Errorf("%s = %q %q, want %q %q", label, names, patterns, wantNames, wantPatterns)
	}
}

const (
	bldMine      = `/^mine[0-9]+\.example$/`
	bldMineAllow = `@@/^ok[0-9]+\.example$/`
)

func TestBuildSplitsRegexByProvenance(t *testing.T) {
	custom := bldList{"Custom", []string{bldMine, bldMineAllow}}
	feed := bldList{"Feed", []string{bldMine, bldMineAllow}}

	result := bldRegexBuild(t, false, []string{"Custom"}, custom)
	bldWantRegexDB(t, "userRegexDB", result.userRegexDB, []string{"Custom#0"}, []string{`^mine[0-9]+\.example$`})
	bldWantRegexDB(t, "userAllowRegexDB", result.userAllowRegexDB, []string{"Custom#0"}, []string{`^ok[0-9]+\.example$`})
	if entry, _ := result.userRegexDB.get("Custom#0"); entry.band != PRIO_USER_BLOCK {
		t.Errorf("user block band = %d, want %d", entry.band, PRIO_USER_BLOCK)
	}
	if entry, _ := result.userAllowRegexDB.get("Custom#0"); entry.band != PRIO_USER_ALLOW {
		t.Errorf("user allow band = %d, want %d", entry.band, PRIO_USER_ALLOW)
	}
	if result.regexDB.len() != 0 || result.allowRegexDB.len() != 0 {
		t.Error("a Custom_List regex reached the feed containers")
	}

	result = bldRegexBuild(t, false, nil, feed)
	bldWantRegexDB(t, "regexDB", result.regexDB, []string{"Feed#0"}, []string{`^mine[0-9]+\.example$`})
	bldWantRegexDB(t, "allowRegexDB", result.allowRegexDB, []string{"Feed#0"}, []string{`^ok[0-9]+\.example$`})
	if result.userRegexDB.len() != 0 || result.userAllowRegexDB.len() != 0 {
		t.Error("a feed regex reached the user containers")
	}

	result = bldRegexBuild(t, false, []string{"Custom"}, feed, custom)
	if sizes := [4]int{result.regexDB.len(), result.allowRegexDB.len(), result.userRegexDB.len(), result.userAllowRegexDB.len()}; sizes != [4]int{1, 1, 1, 1} || result.regexCount != 4 {
		t.Errorf("sizes = %v, regex_count = %d, want one of each and 4", sizes, result.regexCount)
	}
}

func TestBuildUserRegexTakesTheAdmissionGateAndTheOptInLengthCap(t *testing.T) {
	longRow := "^" + strings.Repeat("a", 210) + "$"
	hostile := "^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x"
	custom := bldList{"Custom", []string{"/" + hostile + "/", "/" + longRow + "/", `/^keep[0-9]+\.example$/`}}
	_, uncapped := bldPatterns(bldRegexBuild(t, false, []string{"Custom"}, custom).userRegexDB)
	if !slices.Equal(uncapped, []string{longRow, `^keep[0-9]+\.example$`}) {
		t.Errorf("uncapped = %q", uncapped)
	}
	_, capped := bldPatterns(bldRegexBuild(t, true, []string{"Custom"}, custom).userRegexDB)
	if !slices.Equal(capped, []string{`^keep[0-9]+\.example$`}) {
		t.Errorf("capped = %q", capped)
	}
}

func TestBuildUserRuleLoadsAfter1500FeedRules(t *testing.T) {
	var feedRules []string
	for i := range 1500 {
		feedRules = append(feedRules, fmt.Sprintf(`/^b[0-9]+x%d\.example$/`, i))
	}
	result := bldRegexBuild(t, false, []string{"Custom"}, bldList{"Feed", feedRules}, bldList{"Custom", []string{bldMine}})
	if result.regexDB.len() != 1500 || result.userRegexDB.len() != 1 || result.regexCount != 1501 {
		t.Errorf("regexDB %d, userRegexDB %d, regex_count %d, want 1500, 1 and 1501", result.regexDB.len(), result.userRegexDB.len(), result.regexCount)
	}
}

func TestBuildCompilesLeadingDotRunsBehindACaret(t *testing.T) {
	const row = `.*[0-9]\.x\.com$`
	const compiled = `^(?:(?s:.*)[0-9]\.x\.com$)`
	lines := []string{"/" + row + "/", "@@/" + row + "/"}
	feed := bldRegexBuild(t, false, nil, bldList{"Feed", lines})
	bldWantRegexDB(t, "regexDB", feed.regexDB, []string{"Feed#0"}, []string{compiled})
	bldWantRegexDB(t, "allowRegexDB", feed.allowRegexDB, []string{"Feed#0"}, []string{compiled})
	custom := bldRegexBuild(t, false, []string{"Custom"}, bldList{"Custom", lines})
	bldWantRegexDB(t, "userRegexDB", custom.userRegexDB, []string{"Custom#0"}, []string{compiled})
	bldWantRegexDB(t, "userAllowRegexDB", custom.userAllowRegexDB, []string{"Custom#0"}, []string{compiled})
}

func TestBuildImportantRulesFollowsTheUserRegexThatLoaded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		custom []string
		raised bool
	}{
		{"block", []string{bldMine}, true},
		{"allow", []string{bldMineAllow}, true},
		{"both", []string{bldMine, bldMineAllow}, true},
		{"refused-by-the-gate", []string{"/^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x/"}, false},
		{"plain-custom-rows", []string{"||x.example^", "@@||y.example^"}, false},
		{"no-custom-list", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bldCaptureLog(t)
			lists := []bldList{{"Feed", []string{"||ads.example.com^"}}}
			if tc.custom != nil {
				lists = append(lists, bldList{"Custom", tc.custom})
			}
			// plain-custom-rows: a user @@ domain allow is a user rule, not a feed one, so the fast path stays on
			if got := bldRegexBuild(t, false, []string{"Custom"}, lists...).importantRules; got != tc.raised {
				t.Errorf("important_rules = %v, want %v", got, tc.raised)
			}
		})
	}
	// a user @@/re/ raises it; a feed @@/re/ and a feed regex raise it as before
	result := bldRegexBuild(t, false, nil, bldList{"Feed", []string{"||ads.example.com^", `@@/^ads[0-9]?\.example\.com$/`}})
	if !result.importantRules {
		t.Error("a feed allow regex did not raise important_rules")
	}
}

// ---------------------------------------------------------------------------------------------------------------
// tests/test_issue1718_regex_transport.py, tests/test_issue2079: the user regex_list

func bldIni(t *testing.T, regexList string) *configParser {
	t.Helper()
	config := newConfigParser()
	if err := config.readString("[MAIN]\npython_enable = true\nregex_list = "+regexList+"\n", "<ini>"); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestInitialLoadDecodesBase64RowsAndPreservesNames(t *testing.T) {
	text := "# full comment\r\n A%=:;\"\\D#Foo desc \nB%=:;\"\\D#Foo desc\n unnamed#Inline description\rblank\r\n"
	config := bldIni(t, base64Of(text))
	entries := loadUserRegexEntries(config)
	db := dnsblCompileUserRegex(entries, false)
	bldWantRegexDB(t, "userRegexDB", db,
		[]string{"foo_desc", "foo_desc_2", "inline_description", "regex_4"},
		[]string{"A%=:;\"\\D", "B%=:;\"\\D", "unnamed", "blank"})
	for name, entry := range db.items() {
		if !strings.HasPrefix(entry.re.String(), "(?i)") || entry.important || entry.band != PRIO_USER_BLOCK ||
			entry.groupOwner != "DNSBL_Regex" || entry.groupOrigin != "builtin" {
			t.Errorf("%s = %+v, want a case-insensitive, non-important band-5 DNSBL_Regex builtin", name, entry)
		}
	}
}

func TestUnsafeUserRowIsDroppedByTheUserLoad(t *testing.T) {
	bldCaptureLog(t)
	unsafe := `^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$`
	safe := `^[a-z]+\.[a-z]+\.[a-z]+$`
	db := dnsblCompileUserRegex(loadUserRegexEntries(bldIni(t, base64Of(unsafe+"#unsafe\n"+safe+"#safe\n"))), false)
	bldWantRegexDB(t, "userRegexDB", db, []string{"safe"}, []string{safe})
}

func TestPresentMalformedOrNonUtf8MarkerFailsClosed(t *testing.T) {
	for _, payload := range []string{"%%%", base64Of("\xff")} {
		out := bldCaptureLog(t)
		if entries := loadUserRegexEntries(bldIni(t, payload)); len(entries) != 0 {
			t.Errorf("payload %q: entries = %v", payload, entries)
		}
		if !strings.Contains(out.String(), "Failed to decode MAIN.regex_list") {
			t.Errorf("payload %q: log = %q", payload, out)
		}
	}
}

func TestAbsentMarkerIgnoresObsoleteRegexSection(t *testing.T) {
	config := newConfigParser()
	if err := config.readString("[MAIN]\npython_enable = true\n[REGEX]\nlegacy = old\n", "<ini>"); err != nil {
		t.Fatal(err)
	}
	if entries := loadUserRegexEntries(config); len(entries) != 0 {
		t.Errorf("entries = %v", entries)
	}
}

func base64Of(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }

// ---------------------------------------------------------------------------------------------------------------
// tests/test_adr07_regex_safety.py: the loaders

func bldBlockRule(pattern string) regexRule {
	return regexRule{pattern: pattern, kind: DNSBL_KIND_BLOCK, band: PRIO_FEED_BLOCK, provenance: RULE_PROV_FEED, feed: "Feed", group: "DNSBL_Regex", log: "1"}
}

func bldAllowRule(pattern string) regexRule {
	rule := bldBlockRule(pattern)
	rule.kind, rule.band = DNSBL_KIND_ALLOW, PRIO_FEED_ALLOW
	return rule
}

func bldCompiled(db *regexDB) []string {
	_, patterns := bldPatterns(db)
	return patterns
}

func bldLogLines(out interface{ String() string }) []string {
	text := strings.TrimSuffix(out.String(), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func TestFeedLoaderDropsUnsafeSeparatorSpellingsWithBothCapModes(t *testing.T) {
	unsafe := []string{
		`^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$`,
		`^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$`,
		`^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$`,
	}
	safe := `^[a-z]+\.[a-z]+\.[a-z]+$`
	for _, capped := range []bool{false, true} {
		bldCaptureLog(t)
		var rules []regexRule
		for _, pattern := range unsafe {
			rules = append(rules, bldBlockRule(pattern))
		}
		db, admitted := dnsblCompileRegexRules(append(rules, bldBlockRule(safe)), capped)
		if admitted != 1 || !slices.Equal(bldCompiled(db), []string{safe}) {
			t.Errorf("cap %v: admitted %d, patterns %q, want only the safe row", capped, admitted, bldCompiled(db))
		}
	}
}

func TestStaticCapAtLoad(t *testing.T) {
	longBenign := "^(sub)?" + strings.Repeat("verylongsubdomainlabel", 10) + `\.example\.com$`
	if len(longBenign) <= regexrules.REGEX_STATIC_LEN_CAP {
		t.Fatalf("the fixture is %d characters, not over the cap", len(longBenign))
	}
	for _, tc := range []struct {
		name     string
		pattern  string
		capped   bool
		admitted int
	}{
		{"cap off keeps long but benign", longBenign, false, 1},
		{"cap on drops long but benign", longBenign, true, 0},
		{"exactly the cap length is admitted", "^" + strings.Repeat("a", regexrules.REGEX_STATIC_LEN_CAP-2) + "$", true, 1},
		{"one over the cap length is dropped", "^" + strings.Repeat("a", regexrules.REGEX_STATIC_LEN_CAP-1) + "$", true, 0},
		{"a quantified group is dropped with the cap off", `(a+)+x`, false, 0},
		{"a repeated alternation is dropped with the cap on", `(a|b)+c`, true, 0},
		{"oversized repeats are dropped", `a{300}`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bldCaptureLog(t)
			db, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(tc.pattern)}, tc.capped)
			if admitted != tc.admitted || db.len() != tc.admitted {
				t.Errorf("admitted %d, rules %d, want %d", admitted, db.len(), tc.admitted)
			}
		})
	}
}

func TestBuildThreadsRegexCapFromTheConfig(t *testing.T) {
	longRow := "^" + strings.Repeat("a", 210) + "$"
	for _, capped := range []bool{true, false} {
		bldCaptureLog(t)
		result := bldRegexBuild(t, capped, nil, bldList{"F", []string{"/" + longRow + "/"}})
		if got := result.regexDB.len(); got != map[bool]int{true: 0, false: 1}[capped] {
			t.Errorf("regex_cap %v: %d rules loaded", capped, got)
		}
	}
}

func TestUnexpectedCompileFailureDropsOnlyThatRule(t *testing.T) {
	out := bldCaptureLog(t)
	first, middle, last := `^first\.example$`, `^middle\.example$`, `^last\.example$`
	real := compileRegexText
	compileRegexText = func(text string) (*regexp.Regexp, error) {
		if text == middle {
			return nil, fmt.Errorf("simulated compile failure")
		}
		return real(text)
	}
	t.Cleanup(func() { compileRegexText = real })
	db, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(first), bldBlockRule(middle), bldBlockRule(last)}, false)
	if admitted != 2 || !slices.Equal(bldCompiled(db), []string{first, last}) {
		t.Errorf("admitted %d, patterns %q, want the first and last", admitted, bldCompiled(db))
	}
	if lines := bldLogLines(out); len(lines) != 1 || !strings.Contains(lines[0], "ABP regex compile error feed [ Feed ] pattern [ '^middle\\\\.example$' ]: error 'simulated compile failure'") {
		t.Errorf("log = %q", lines)
	}
}

func TestEveryAdmittedRuleOfAListLoadsHoweverManyThereAre(t *testing.T) {
	for _, count := range []int{1000, 1001, 1500} {
		out := bldCaptureLog(t)
		var rules []regexRule
		var want []string
		for i := range count {
			pattern := fmt.Sprintf(`^r%d\.example$`, i)
			rules = append(rules, bldBlockRule(pattern))
			want = append(want, pattern)
		}
		db, admitted := dnsblCompileRegexRules(rules, false)
		if admitted != count || !slices.Equal(bldCompiled(db), want) || out.Len() != 0 {
			t.Errorf("count %d: admitted %d, in order = %v, log %q", count, admitted, slices.Equal(bldCompiled(db), want), out)
		}
	}
}

func TestAListFarOverTheOldSummedCostBudgetLoadsInFull(t *testing.T) {
	out := bldCaptureLog(t)
	var rules []regexRule
	for i := range 300 {
		pattern := fmt.Sprintf("%03dx{252}", i)
		if cost, compiled, _ := regexrules.Admission(pattern); cost != 65536 || compiled == nil {
			t.Fatalf("%q costs %d (admitted %v), the fixture needs exactly 65536", pattern, cost, compiled != nil)
		}
		rules = append(rules, bldBlockRule(pattern))
	}
	if db, admitted := dnsblCompileRegexRules(rules, false); admitted != 300 || db.len() != 300 || out.Len() != 0 {
		t.Errorf("admitted %d, log %q", admitted, out)
	}
	out.Reset()
	rules = nil
	for i := range 1500 {
		rules = append(rules, bldBlockRule(fmt.Sprintf("host%05d", i)))
	}
	if cost, _, _ := regexrules.Admission(rules[0].pattern); cost != 2304 {
		t.Fatalf("an unanchored 9-character literal costs %d, want 2304", cost)
	}
	if _, admitted := dnsblCompileRegexRules(rules, false); admitted != 1500 || out.Len() != 0 {
		t.Errorf("admitted %d, log %q", admitted, out)
	}
}

func TestRefusalLogLinesAreCappedPerListAndTheRestCountedOnce(t *testing.T) {
	for _, tc := range []struct {
		count, suppressed int
	}{{50, 30}, {REGEX_REFUSAL_LOG_MAX, 0}, {REGEX_REFUSAL_LOG_MAX + 1, 1}} {
		out := bldCaptureLog(t)
		var rules []regexRule
		for i := range tc.count {
			rules = append(rules, bldAllowRule(fmt.Sprintf("(a+)+x%d", i)))
		}
		db, admitted := dnsblCompileRegexRules(rules, false)
		lines := bldLogLines(out)
		wantLines := REGEX_REFUSAL_LOG_MAX
		if tc.suppressed > 0 {
			wantLines++
		}
		if db.len() != 0 || admitted != 0 || len(lines) != wantLines {
			t.Fatalf("count %d: %d rules, %d admitted, %d log lines, want 0, 0 and %d: %q", tc.count, db.len(), admitted, len(lines), wantLines, lines)
		}
		if tc.suppressed > 0 && !strings.HasSuffix(lines[len(lines)-1], fmt.Sprintf("%d more refused allow regex rules not logged", tc.suppressed)) {
			t.Errorf("count %d: summary = %q", tc.count, lines[len(lines)-1])
		}
	}
}

func TestGateRefusalsLengthCapDropsAndCompileErrorsShareOneRefusalLogBudget(t *testing.T) {
	out := bldCaptureLog(t)
	real := compileRegexText
	compileRegexText = func(text string) (*regexp.Regexp, error) {
		if strings.HasPrefix(text, "^boom") {
			return nil, fmt.Errorf("cannot compile")
		}
		return real(text)
	}
	t.Cleanup(func() { compileRegexText = real })
	var rules []regexRule
	for i := range 10 {
		rules = append(rules, bldBlockRule(fmt.Sprintf("(a+)+x%d", i))) // refused by the gate
	}
	for i := range 10 {
		rules = append(rules, bldBlockRule("^"+strings.Repeat("a", 210)+fmt.Sprintf("%02d$", i))) // over the opt-in length cap
	}
	for i := range 5 {
		rules = append(rules, bldBlockRule(fmt.Sprintf("^boom%d$", i))) // admitted, then the compile fails
	}
	db, admitted := dnsblCompileRegexRules(rules, true)
	lines := bldLogLines(out)
	if db.len() != 0 || admitted != 0 || len(lines) != REGEX_REFUSAL_LOG_MAX+1 || !strings.HasSuffix(lines[len(lines)-1], "5 more refused block regex rules not logged") {
		t.Errorf("%d rules, %d admitted, %d log lines, last %q", db.len(), admitted, len(lines), lines[len(lines)-1])
	}
}

func TestWideClassRulesAreRefusedWithoutACompileAttempt(t *testing.T) {
	out := bldCaptureLog(t)
	real := compileRegexText
	compiled := 0
	compileRegexText = func(text string) (*regexp.Regexp, error) { compiled++; return real(text) }
	t.Cleanup(func() { compileRegexText = real })
	var rules []regexRule
	for i := range 1000 {
		rules = append(rules, bldBlockRule("^"+strings.Repeat("[!-~]", 49)+fmt.Sprintf("x%04d", i)))
	}
	db, admitted := dnsblCompileRegexRules(rules, false)
	lines := bldLogLines(out)
	if db.len() != 0 || admitted != 0 || compiled != 0 || len(lines) != REGEX_REFUSAL_LOG_MAX+1 {
		t.Fatalf("%d rules, %d admitted, %d compile attempts, %d log lines", db.len(), admitted, compiled, len(lines))
	}
	for _, line := range lines[:REGEX_REFUSAL_LOG_MAX] {
		if !strings.Contains(line, "character classes too wide") {
			t.Errorf("line %q does not carry the gate's reason", line)
		}
	}
	if !strings.HasSuffix(lines[len(lines)-1], fmt.Sprintf("%d more refused block regex rules not logged", 1000-REGEX_REFUSAL_LOG_MAX)) {
		t.Errorf("summary = %q", lines[len(lines)-1])
	}
}

func TestRefusalsDoNotStopTheRestOfTheListLoading(t *testing.T) {
	out := bldCaptureLog(t)
	var rules []regexRule
	for i := range REGEX_REFUSAL_LOG_MAX + 30 {
		rules = append(rules, bldBlockRule(fmt.Sprintf("(a+)+x%d", i)))
	}
	for i := range 1100 {
		rules = append(rules, bldBlockRule(fmt.Sprintf(`^r%d\.example$`, i)))
	}
	if _, admitted := dnsblCompileRegexRules(rules, false); admitted != 1100 {
		t.Errorf("admitted %d, want 1100", admitted)
	}
	lines := bldLogLines(out)
	if len(lines) != REGEX_REFUSAL_LOG_MAX+1 || !strings.HasSuffix(lines[len(lines)-1], "30 more refused block regex rules not logged") {
		t.Errorf("%d log lines, last %q", len(lines), lines[len(lines)-1])
	}
}

func TestBuildLoadsEveryAdmittedFeedBlockAndAllowRegexRule(t *testing.T) {
	var lines []string
	for i := range 1500 {
		lines = append(lines, fmt.Sprintf(`/^b[0-9]+x%d\.example$/`, i))
	}
	for i := range 1200 {
		lines = append(lines, fmt.Sprintf(`@@/^a[0-9]+x%d\.example$/`, i))
	}
	result := bldRegexBuild(t, false, nil, bldList{"F", lines})
	if result.regexDB.len() != 1500 || result.allowRegexDB.len() != 1200 || result.regexCount != 2700 {
		t.Errorf("regexDB %d, allowRegexDB %d, regex_count %d, want 1500, 1200 and 2700", result.regexDB.len(), result.allowRegexDB.len(), result.regexCount)
	}
}

func TestRefusedPatternsAreLoggedAsAShortExcerpt(t *testing.T) {
	// refused by every gate generation: only its log form differs
	long := "(a+)+" + strings.Repeat("a", 285) + "TAILMARKER"
	out := bldCaptureLog(t)
	if _, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(long), bldBlockRule(`^ok\.example$`)}, false); admitted != 1 {
		t.Errorf("admitted %d, want 1", admitted)
	}
	if text := out.String(); !strings.Contains(text, regexrules.Excerpt(long)) || !strings.Contains(text, "over 256 characters") || strings.Contains(text, "TAILMARKER") {
		t.Errorf("log = %q", text)
	}

	// dropped by the length cap
	capped := "^" + strings.Repeat("a", 228) + "TAILMARKER$"
	out = bldCaptureLog(t)
	if _, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(capped)}, true); admitted != 0 {
		t.Errorf("admitted %d, want 0", admitted)
	}
	if text := out.String(); !strings.Contains(text, regexrules.Excerpt(capped)) || strings.Contains(text, "TAILMARKER") || !strings.Contains(text, "static length cap") {
		t.Errorf("log = %q", text)
	}

	// a compile failure whose message quotes the whole pattern
	failing := "^" + strings.Repeat("a", 150) + "TAILMARKER$"
	real := compileRegexText
	compileRegexText = func(text string) (*regexp.Regexp, error) {
		if text == failing {
			return nil, fmt.Errorf("cannot compile %s", failing)
		}
		return real(text)
	}
	t.Cleanup(func() { compileRegexText = real })
	out = bldCaptureLog(t)
	if _, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(failing), bldBlockRule(`^ok\.example$`)}, false); admitted != 1 {
		t.Errorf("admitted %d, want 1", admitted)
	}
	if text := out.String(); !strings.Contains(text, regexrules.Excerpt(failing)) || strings.Contains(text, "TAILMARKER$") && !strings.Contains(text, "...") {
		t.Errorf("log = %q", text)
	}
}

func TestControlCharactersInARefusedPatternNeverReachTheLogRaw(t *testing.T) {
	out := bldCaptureLog(t)
	pattern := "(a+)+\x00b\x1bc\rd"
	if _, admitted := dnsblCompileRegexRules([]regexRule{bldBlockRule(pattern)}, false); admitted != 0 {
		t.Errorf("admitted %d", admitted)
	}
	text := out.String()
	if strings.ContainsAny(strings.TrimSuffix(text, "\n"), "\x00\x1b\r\n") || !strings.Contains(text, `'(a+)+\x00b\x1bc\rd'`) {
		t.Errorf("log = %q", text)
	}
}

func TestUserRegexLoader(t *testing.T) {
	t.Run("log lines number every row starting at one", func(t *testing.T) {
		out := bldCaptureLog(t)
		entries := []userRegexEntry{{"one", "(a+)+x"}, {"two", "(a+)+y"}, {"three", `^fine\.example$`}, {"four", "(b+)+z"}}
		db := dnsblCompileUserRegex(entries, false)
		lines := bldLogLines(out)
		if db.len() != 1 || len(lines) != 3 {
			t.Fatalf("%d rules, log %q", db.len(), lines)
		}
		for i, row := range []string{"1", "2", "4"} {
			if !strings.Contains(lines[i], "on line #"+row) {
				t.Errorf("line %d = %q, want row #%s", i, lines[i], row)
			}
		}
	})
	t.Run("a user pattern whose compile fails is dropped alone", func(t *testing.T) {
		out := bldCaptureLog(t)
		real := compileRegexText
		compileRegexText = func(text string) (*regexp.Regexp, error) {
			if text == `^middle\.example$` {
				return nil, fmt.Errorf("simulated")
			}
			return real(text)
		}
		t.Cleanup(func() { compileRegexText = real })
		db := dnsblCompileUserRegex([]userRegexEntry{{"first", `^first\.example$`}, {"middle", `^middle\.example$`}, {"last", `^last\.example$`}}, false)
		names, _ := bldPatterns(db)
		if !slices.Equal(names, []string{"first", "last"}) {
			t.Errorf("names = %q", names)
		}
		if lines := bldLogLines(out); len(lines) != 1 || !strings.Contains(lines[0], "Regex [ middle ] compile error pattern [ '^middle\\\\.example$' ] on line #2: error 'simulated'") {
			t.Errorf("log = %q", lines)
		}
	})
	t.Run("refusals share one budget and the rest of the list still loads", func(t *testing.T) {
		out := bldCaptureLog(t)
		var entries []userRegexEntry
		for i := range REGEX_REFUSAL_LOG_MAX + 10 {
			entries = append(entries, userRegexEntry{fmt.Sprintf("row%d", i), fmt.Sprintf("(a+)+x%d", i)})
		}
		for i := range 1100 {
			entries = append(entries, userRegexEntry{fmt.Sprintf("keep%d", i), fmt.Sprintf(`^r%d\.example$`, i)})
		}
		if db := dnsblCompileUserRegex(entries, false); db.len() != 1100 {
			t.Errorf("%d rules loaded, want 1100", db.len())
		}
		lines := bldLogLines(out)
		if len(lines) != REGEX_REFUSAL_LOG_MAX+1 || !strings.HasSuffix(lines[len(lines)-1], "10 more refused user regex rules not logged") {
			t.Errorf("%d log lines, last %q", len(lines), lines[len(lines)-1])
		}
	})
	t.Run("the length cap logs a short excerpt with the row", func(t *testing.T) {
		out := bldCaptureLog(t)
		pattern := "^" + strings.Repeat("a", 228) + "TAILMARKER$"
		if db := dnsblCompileUserRegex([]userRegexEntry{{"long", pattern}}, true); db.len() != 0 {
			t.Error("an over-length user pattern loaded")
		}
		if text := out.String(); !strings.Contains(text, regexrules.Excerpt(pattern)) || strings.Contains(text, "TAILMARKER") || !strings.Contains(text, "on line #1 (static length cap)") {
			t.Errorf("log = %q", text)
		}
	})
	t.Run("rows are user blocks: band 5, not important", func(t *testing.T) {
		db := dnsblCompileUserRegex([]userRegexEntry{{"a", `^a\.example$`}}, false)
		if entry, _ := db.get("a"); entry == nil || entry.band != PRIO_USER_BLOCK || entry.important {
			t.Errorf("entry = %+v", entry)
		}
	})
	t.Run("a repeated name keeps its first position and the last payload", func(t *testing.T) {
		db := dnsblCompileUserRegex([]userRegexEntry{{"dup", `^a\.example$`}, {"x", `^x\.example$`}, {"dup", `^b\.example$`}}, false)
		bldWantRegexDB(t, "db", db, []string{"dup", "x"}, []string{`^b\.example$`, `^x\.example$`})
	})
}

// ---------------------------------------------------------------------------------------------------------------
// the stdlib emulations

func TestPyOSErrorIsPythonsStrOfAnOSError(t *testing.T) {
	_, err := os.Open("/no/such/file")
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatal("not a PathError")
	}
	if got := pyOSError(pathErr.Err, "/no/such/file"); got != "[Errno 2] No such file or directory: '/no/such/file'" {
		t.Errorf("pyOSError = %q", got)
	}
	if got := pyOSError(fmt.Errorf("boom"), "x"); got != "boom" {
		t.Errorf("pyOSError(non-errno) = %q", got)
	}
}

func TestDecodeReplaceKnownRows(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"abc", "abc"},
		{"\xe2\x82", "\uFFFD"},                 // one maximal subpart, not two bytes
		{"\xe2\x82a", "\uFFFDa"},               // the subpart ends at a byte that cannot continue it
		{"\xf0\x90\x80", "\uFFFD"},             // a truncated four-byte sequence
		{"\xff\xfe", "\uFFFD\uFFFD"},           // two invalid lead bytes
		{"\xed\xa0\x80", "\uFFFD\uFFFD\uFFFD"}, // an encoded surrogate: each byte its own
		{"\xc0\x80", "\uFFFD\uFFFD"},           // overlong
		{"a\x00b", "a\x00b"},
	} {
		if got := decodeReplace([]byte(tc.in)); got != tc.want {
			t.Errorf("decodeReplace(% x) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
