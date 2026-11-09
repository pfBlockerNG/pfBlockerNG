// Tests for the BuildResult / Snapshot half of pfb_unbound_model.go (Python 4525-4677).
package decider

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func mwSameMap[K comparable, V any](a, b map[K]V) bool {
	return reflect.ValueOf(a).UnsafePointer() == reflect.ValueOf(b).UnsafePointer()
}

// Python dataclass defaults: BuildResult(...) and Snapshot(...) leave these fields at the values below, and every
// built dict is fresh (a builder writes into them without a nil-map panic).
func TestNewBuildResultDefaults(t *testing.T) {
	r := newBuildResult()
	if r.builtinLogFlag != "0" {
		t.Errorf("builtinLogFlag = %q, want \"0\" (issue #3539: Null Blocking, logged)", r.builtinLogFlag)
	}
	if r.importantRules || r.counts != 0 || r.regexCount != 0 {
		t.Errorf("importantRules=%v counts=%d regexCount=%d, want false 0 0", r.importantRules, r.counts, r.regexCount)
	}
	if r.dataDB == nil || r.zoneDB == nil || r.whiteDB == nil || r.feedGroupIndexDB == nil || r.rejects == nil {
		t.Error("a built dict is nil; BuildResult dicts must be fresh and writable")
	}
	if r.regexDB == nil || r.allowRegexDB == nil || r.userRegexDB == nil || r.userAllowRegexDB == nil {
		t.Error("a regex DB is nil; BuildResult regex DBs must be fresh and writable")
	}
	r.dataDB["a.example"] = &blockEntry{log: "1", band: PRIO_FEED_BLOCK}
	r.rejects[[2]string{"feed", "group"}] = map[string]int{"shape": 1}
	r.regexDB.set("r", &regexEntry{})
	if other := newBuildResult(); len(other.dataDB) != 0 || len(other.rejects) != 0 || other.regexDB.len() != 0 {
		t.Error("two BuildResults share state")
	}
}

func TestNewSnapshotDefaults(t *testing.T) {
	s := newSnapshot()
	if !s.pslIncludePrivate || s.pslAllowPrivate {
		t.Errorf("pslIncludePrivate=%v pslAllowPrivate=%v, want true false", s.pslIncludePrivate, s.pslAllowPrivate)
	}
	if s.pslFeedPrivatePolicy != "honor" || s.pslFeedIcannPolicy != "honor" {
		t.Errorf("feed policies = %q, %q, want honor, honor (hand-built legacy fixtures stay decision-identical)", s.pslFeedPrivatePolicy, s.pslFeedIcannPolicy)
	}
	if s.builtinLogFlag != "0" {
		t.Errorf("builtinLogFlag = %q, want \"0\"", s.builtinLogFlag)
	}
	if s.hasTldAllowRoots || s.importantRules || s.counts != 0 || s.regexCount != 0 {
		t.Errorf("hasTldAllowRoots=%v importantRules=%v counts=%d regexCount=%d, want false false 0 0", s.hasTldAllowRoots, s.importantRules, s.counts, s.regexCount)
	}
	if s.dataDB == nil || s.zoneDB == nil || s.whiteDB == nil || s.feedGroupIndexDB == nil || s.hstsDB == nil || s.rejects == nil || s.groupEpochs == nil {
		t.Error("a snapshot dict is nil; Snapshot dicts must be writable until the snapshot is published")
	}
	if s.regexDB == nil || s.allowRegexDB == nil || s.userRegexDB == nil || s.userAllowRegexDB == nil {
		t.Error("a snapshot regex DB is nil")
	}
	if s.noAAAADB == nil || s.safeSearchDB == nil || s.gpListDB == nil {
		t.Error("an operate()-level dict is nil")
	}
}

// pfb_unbound.py _snapshot_gen = itertools.count(1): every built Snapshot gets a unique, monotonically advancing
// generation, from 1 (issue #1074; test_stale_generation_write_cannot_extend_a_live_memo: 0 < stale < replacement).
func TestSnapshotGenIsMonotonicAndUnique(t *testing.T) {
	prev := newSnapshot().gen
	if prev <= 0 {
		t.Fatalf("gen = %d, want > 0 (0 is the \"no real generation\" memo stamp)", prev)
	}
	for range 100 {
		if next := newSnapshot().gen; next <= prev {
			t.Fatalf("gen %d after %d: not strictly increasing", next, prev)
		}
		prev = snapshotGen.Load()
	}
	const workers, each = 8, 200
	gens := make([][]int64, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				gens[w] = append(gens[w], newSnapshot().gen)
			}
		}()
	}
	wg.Wait()
	seen := map[int64]bool{}
	for w, list := range gens {
		if !slices.IsSorted(list) {
			t.Errorf("worker %d saw non-monotonic generations", w)
		}
		for _, g := range list {
			if seen[g] {
				t.Fatalf("generation %d handed to two snapshots", g)
			}
			seen[g] = true
		}
	}
}

// test_adr10_snapshot_equivalence.py TestSnapshotType.test_containers_covers_every_legacy_key: the containers are
// views of the snapshot (the same objects), never copies; tld_allow_roots falls back to an empty tuple.
func TestSnapshotContainers(t *testing.T) {
	s := newSnapshot()
	s.dataDB["a"] = &blockEntry{log: "1"}
	s.pslIncludePrivate, s.pslAllowPrivate = false, true
	s.pslFeedPrivatePolicy, s.pslFeedIcannPolicy = "apex", "ignore"
	c := s.containers()
	if !mwSameMap(c.dataDB, s.dataDB) || !mwSameMap(c.zoneDB, s.zoneDB) || !mwSameMap(c.whiteDB, s.whiteDB) ||
		!mwSameMap(c.feedGroupIndexDB, s.feedGroupIndexDB) || !mwSameMap(c.hstsDB, s.hstsDB) {
		t.Error("a container map is a copy, want the snapshot's own map")
	}
	if c.regexDB != s.regexDB || c.allowRegexDB != s.allowRegexDB || c.userRegexDB != s.userRegexDB || c.userAllowRegexDB != s.userAllowRegexDB {
		t.Error("a container regex DB is a copy, want the snapshot's own DB")
	}
	if !reflect.DeepEqual(c.pslRules, s.pslRules) {
		t.Errorf("pslRules = %+v, want %+v", c.pslRules, s.pslRules)
	}
	if c.pslIncludePrivate || !c.pslAllowPrivate || c.pslFeedPrivatePolicy != "apex" || c.pslFeedIcannPolicy != "ignore" {
		t.Errorf("psl flags = %v %v %q %q, want false true apex ignore", c.pslIncludePrivate, c.pslAllowPrivate, c.pslFeedPrivatePolicy, c.pslFeedIcannPolicy)
	}
	// A hand-built legacy fixture carries no roots (None): the container reads them as the empty tuple.
	if len(c.tldAllowRoots) != 0 {
		t.Errorf("tldAllowRoots = %q, want empty", c.tldAllowRoots)
	}
	s.tldAllowRoots, s.hasTldAllowRoots = []string{"com", "net"}, true
	if got := s.containers().tldAllowRoots; !slices.Equal(got, []string{"com", "net"}) {
		t.Errorf("tldAllowRoots = %q, want [com net]", got)
	}
	s.tldAllowRoots = []string{} // a runtime swap captures a tuple, empty included
	if got := s.containers().tldAllowRoots; len(got) != 0 {
		t.Errorf("empty captured tldAllowRoots = %q, want empty", got)
	}
}

func mwSnapshot(tag int) *snapshot {
	s := newSnapshot()
	s.dataDB["evil.example"] = &blockEntry{log: "1", index: tag, band: PRIO_FEED_BLOCK}
	s.zoneDB["zone.example"] = &blockEntry{log: "1", index: tag, band: PRIO_FEED_BLOCK}
	s.whiteDB["white.example"] = mwBand(true, true, PRIO_USER_ALLOW)
	s.feedGroupIndexDB[tag] = feedGroup{feed: fmt.Sprint("feed", tag), group: fmt.Sprint("group", tag)}
	s.hstsDB["evil.example"] = struct{}{}
	s.regexDB.set("r", &regexEntry{band: PRIO_FEED_BLOCK})
	s.noAAAADB["v6.example"] = true
	s.safeSearchDB["search.example"] = safeSearchEntry{a: fmt.Sprint(tag), aaaa: "", v4: "192.0.2.1"}
	s.gpListDB["192.0.2.7"] = 0
	s.gpNetDB = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	s.settings = &pfbSettings{decisiondbMax: int64(tag)}
	return s
}

// Owner rule (2026-11-09): a decision reads ONE immutable snapshot published through atomic.Pointer; nothing in it
// is mutated after the Store; the decisionDB memo is keyed by generation. Readers resolve each query against the
// snapshot they loaded while another goroutine keeps swapping in new ones; run under -race.
func TestSnapshotSwapRace(t *testing.T) {
	var live atomic.Pointer[snapshot]
	live.Store(mwSnapshot(0))
	memo := newLruCache[*decision](3)
	names := []string{"evil.example", "zone.example", "a.zone.example", "white.example", "other.example"}
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				snap := live.Load()
				tag := snap.dataDB["evil.example"].index
				feed, group := resolveFeedGroup(tag, snap.feedGroupIndexDB)
				if feed != fmt.Sprint("feed", tag) || group != fmt.Sprint("group", tag) {
					t.Errorf("torn read: dataDB index %d but feed/group (%q, %q)", tag, feed, group)
					return
				}
				if key, entry := findZoneMatch("a.zone.example", snap.zoneDB); key != "zone.example" || entry.index != tag {
					t.Errorf("torn read: zone entry (%q, %+v) not from snapshot %d", key, entry, tag)
					return
				}
				if snap.settings.decisiondbMax != int64(tag) || snap.safeSearchDB["search.example"].a != fmt.Sprint(tag) {
					t.Errorf("torn read: settings/safeSearchDB not from snapshot %d", tag)
					return
				}
				if band := whitelistLookupBand("www.white.example", snap.whiteDB, 1); band != PRIO_USER_ALLOW {
					t.Errorf("whitelistLookupBand = %d, want %d", band, PRIO_USER_ALLOW)
					return
				}
				if !evaluateNoaaaa("v6.example", snap.noAAAADB) || snap.regexDB.len() != 1 || len(snap.gpNetDB) != 1 {
					t.Error("snapshot lost an entry it was published with")
					return
				}
				if _, ok := snap.containers().hstsDB["evil.example"]; !ok {
					t.Error("containers() lost hstsDB")
					return
				}
				dec := decisionFor(memo, names[(w+i)%len(names)], snap.gen)
				if dec.snapGen != snap.gen {
					t.Errorf("memo stamped gen %d for a query on snapshot gen %d", dec.snapGen, snap.gen)
					return
				}
				dec.setDnsbl(&dnsblDecision{isFound: true, feed: feed, group: group})
				if got, ok := dec.getDnsbl().(*dnsblDecision); !ok || got.feed != feed {
					t.Errorf("memo of generation %d holds a verdict from another generation: %v", snap.gen, dec.getDnsbl())
					return
				}
			}
		}()
	}
	for tag := 1; tag <= 300; tag++ {
		live.Store(mwSnapshot(tag))
		memo.clear() // rebuild_and_swap clears the memo after the Store
	}
	stop.Store(true)
	wg.Wait()
}
