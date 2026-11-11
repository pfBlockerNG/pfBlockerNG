// Manifest-compatibility tests of pfb_unbound_build.go: the retired inline config.top1m_list of a pre-#1542 manifest
// (issue #1841, ported from the deleted tests/test_issue1841_legacy_manifest_top1m.py) and the feeds[].top1m shape
// check (issue #3648). The package upgrade must never take DNSBL down because the manifest schema moved, and a corrupt
// Group flag must fail the generation rather than be read as "unticked".
package decider

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const retiredTop1mKeyWarning = "config.top1m_list"

// bldAbsent leaves a manifest key out; nil is a JSON null.
type bldAbsentKey struct{}

var bldAbsent = bldAbsentKey{}

// bldStageTop1mManifest writes one raw feed and a manifest/v1 whose feed row carries `feedTop1m` and whose config
// carries top1m_enabled plus `top1mList` (bldAbsent: key left out, the post-#1542 vintage for the list).
func bldStageTop1mManifest(t *testing.T, top1mEnabled bool, top1mList, feedTop1m any) (dir, manifestPath string) {
	t.Helper()
	dir = t.TempDir()
	bldWriteFile(t, filepath.Join(dir, "feed.raw"),
		"blocked.example\npopularcdn.com\nwww.popularcdn.com\nsidecar.example\nlegacy.example\nwww.legacy.example\n")
	config := map[string]any{"user_whitelist": []any{}, "top1m_enabled": top1mEnabled}
	if top1mList != bldAbsent {
		config["top1m_list"] = top1mList
	}
	feed := map[string]any{"raw": "feed.raw", "feed": "feed", "group": "g", "log_flag": "1"}
	if feedTop1m != bldAbsent {
		feed["top1m"] = feedTop1m
	}
	manifestPath = filepath.Join(dir, "pfb_py_sources.json")
	bldWriteManifest(t, manifestPath, map[string]any{"version": 1, "config": config, "feeds": []any{feed}})
	return dir, manifestPath
}

func bldSortedNames(result *buildResult) []string {
	return slices.Sorted(maps.Keys(result.dataDB))
}

var (
	bldAllFeedNames  = []string{"blocked.example", "legacy.example", "popularcdn.com", "sidecar.example", "www.legacy.example", "www.popularcdn.com"}
	bldNonCdnNames   = []string{"blocked.example", "legacy.example", "sidecar.example", "www.legacy.example"}
	bldSidecarFilter = []string{"blocked.example", "legacy.example", "popularcdn.com", "www.legacy.example", "www.popularcdn.com"}
)

func TestLegacyManifestWithTop1mDisabledStillBuildsItsFeeds(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, false, []any{"popularcdn.com"}, true)
	logs := bldCaptureLog(t)

	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

	if result == nil {
		t.Fatal("the retired config.top1m_list failed the whole generation")
	}
	if got := bldSortedNames(result); !slices.Equal(got, bldAllFeedNames) {
		t.Errorf("dataDB = %v, want every feed name %v (TOP1M is off)", got, bldAllFeedNames)
	}
	if len(result.zoneDB) != 0 || len(result.whiteDB) != 0 {
		t.Errorf("zoneDB = %v, whiteDB = %v, want both empty", result.zoneDB, result.whiteDB)
	}
	if got := logs.String(); !strings.Contains(got, retiredTop1mKeyWarning) || !strings.Contains(got, "ignoring it (TOP1M is disabled)") {
		t.Errorf("log = %q, want the retired-key warning saying the list was ignored", got)
	}
}

func TestLegacyManifestWithTop1mEnabledFiltersItsOptedInFeedFromTheInlineList(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, true, []any{"popularcdn.com"}, true)
	bldCaptureLog(t)
	if _, err := os.Stat(filepath.Join(dir, "pfb_py_top1m.txt")); err == nil {
		t.Fatal("a pre-#1542 manifest predates the sidecar, yet one exists")
	}

	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

	if result == nil {
		t.Fatal("did not build")
	}
	if got := bldSortedNames(result); !slices.Equal(got, bldNonCdnNames) {
		t.Errorf("dataDB = %v, want %v (the listed name and its www form removed)", got, bldNonCdnNames)
	}
	if len(result.zoneDB) != 0 || len(result.whiteDB) != 0 {
		t.Errorf("zoneDB = %v, whiteDB = %v, want both empty: TOP1M is never a global whitelist", result.zoneDB, result.whiteDB)
	}
}

func TestLegacyManifestInlineListFiltersNothingForAFeedThatDidNotOptIn(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, true, []any{"popularcdn.com"}, bldAbsent)
	bldCaptureLog(t)

	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

	if result == nil {
		t.Fatal("did not build")
	}
	if got := bldSortedNames(result); !slices.Equal(got, bldAllFeedNames) {
		t.Errorf("dataDB = %v, want %v: the Group's TOP1M box is cleared", got, bldAllFeedNames)
	}
}

func TestLegacyCommaFramedRecordsStayInertWhileAValidCompanionStillFilters(t *testing.T) {
	for name, framed := range map[string]string{
		"wildcard-record": ".legacy.example,,",
		"exact-record":    ",legacy.example,,",
		"www-record":      ",www.legacy.example,,",
	} {
		t.Run(name, func(t *testing.T) {
			dir, manifestPath := bldStageTop1mManifest(t, true, []any{framed, "popularcdn.com"}, true)
			logs := bldCaptureLog(t)

			result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

			if result == nil {
				t.Fatal("a real legacy manifest must still load its feeds")
			}
			if got := bldSortedNames(result); !slices.Equal(got, bldNonCdnNames) {
				t.Errorf("dataDB = %v, want %v: the framed record filters nothing, the companion does", got, bldNonCdnNames)
			}
			if len(result.zoneDB) != 0 || len(result.whiteDB) != 0 {
				t.Errorf("zoneDB = %v, whiteDB = %v, want both empty", result.zoneDB, result.whiteDB)
			}
			if !strings.Contains(logs.String(), retiredTop1mKeyWarning) {
				t.Errorf("log = %q, want the retired-key warning", logs.String())
			}
		})
	}
}

func TestLegacyManifestWarnsOnceAboutTheRetiredKey(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, true, []any{"popularcdn.com"}, true)
	logs := bldCaptureLog(t)

	if bldModuleIn(dir).dnsblBuildFromManifest(manifestPath) == nil {
		t.Fatal("did not build")
	}

	got := logs.String()
	if n := strings.Count(got, retiredTop1mKeyWarning); n != 1 {
		t.Errorf("the warning appears %d times in %q, want once", n, got)
	}
	if !strings.Contains(got, "reading TOP1M from it") {
		t.Errorf("log = %q, want the warning saying the inline list is read", got)
	}
}

func TestCurrentManifestReadsTheSidecarAndWarnsAboutNothing(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, true, bldAbsent, true)
	bldWriteFile(t, filepath.Join(dir, "pfb_py_top1m.txt"), "sidecar.example\n")
	logs := bldCaptureLog(t)

	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

	if result == nil {
		t.Fatal("did not build")
	}
	if got := bldSortedNames(result); !slices.Equal(got, bldSidecarFilter) {
		t.Errorf("dataDB = %v, want %v (sidecar.example filtered)", got, bldSidecarFilter)
	}
	if strings.Contains(logs.String(), retiredTop1mKeyWarning) {
		t.Errorf("log = %q, want no retired-key warning", logs.String())
	}
}

func TestLegacyManifestPrefersItsOwnInlineListOverAStraySidecar(t *testing.T) {
	dir, manifestPath := bldStageTop1mManifest(t, true, []any{"popularcdn.com"}, true)
	bldWriteFile(t, filepath.Join(dir, "pfb_py_top1m.txt"), "sidecar.example\n")
	bldCaptureLog(t)

	result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

	if result == nil {
		t.Fatal("did not build")
	}
	if got := bldSortedNames(result); !slices.Equal(got, bldNonCdnNames) {
		t.Errorf("dataDB = %v, want %v: the manifest's own vintage of TOP1M wins over the sidecar", got, bldNonCdnNames)
	}
}

func TestMalformedLegacyTop1mListStillFailsTheGeneration(t *testing.T) {
	for name, malformed := range map[string]any{
		"non-string-entry": []any{"popularcdn.com", float64(42)},
		"bare-string":      "popularcdn.com",
		"object":           map[string]any{"popularcdn.com": true},
	} {
		t.Run(name, func(t *testing.T) {
			dir, manifestPath := bldStageTop1mManifest(t, true, malformed, true)
			bldCaptureLog(t)

			if bldModuleIn(dir).dnsblBuildFromManifest(manifestPath) != nil {
				t.Fatal("built: tolerating the retired key must not tolerate a corrupt one")
			}
			entries := bldLedgerEntries(t, dir)
			if len(entries) == 0 || !strings.Contains(entries[len(entries)-1]["message"].(string), "config.top1m_list must be list[str]") {
				t.Errorf("ledger = %v, want the list[str] refusal", entries)
			}
		})
	}
}

func TestFeedTop1mThatIsNotABoolFailsTheGeneration(t *testing.T) {
	for name, value := range map[string]any{
		"string": "true",
		"number": float64(1),
		"null":   nil,
		"list":   []any{true},
	} {
		t.Run(name, func(t *testing.T) {
			dir, manifestPath := bldStageTop1mManifest(t, true, bldAbsent, value)
			bldCaptureLog(t)

			if bldModuleIn(dir).dnsblBuildFromManifest(manifestPath) != nil {
				t.Fatal("built: a non-bool feeds[].top1m was accepted")
			}
			entries := bldLedgerEntries(t, dir)
			if len(entries) == 0 || !strings.Contains(entries[len(entries)-1]["message"].(string), "DNSBL manifest/v1 feeds[0].top1m must be bool") {
				t.Errorf("ledger = %v, want the feeds[0].top1m refusal", entries)
			}
		})
	}
}

func TestFeedTop1mBoolIsAcceptedEitherWay(t *testing.T) {
	for _, value := range []bool{true, false} {
		dir, manifestPath := bldStageTop1mManifest(t, true, bldAbsent, value)
		bldWriteFile(t, filepath.Join(dir, "pfb_py_top1m.txt"), "popularcdn.com\n")
		bldCaptureLog(t)

		result := bldModuleIn(dir).dnsblBuildFromManifest(manifestPath)

		if result == nil {
			t.Fatalf("top1m=%v: did not build", value)
		}
		_, kept := result.dataDB["popularcdn.com"]
		if kept == value {
			t.Errorf("top1m=%v: popularcdn.com kept=%v, want it dropped only for a ticked Group", value, kept)
		}
	}
}
