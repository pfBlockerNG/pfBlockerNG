package resources_test

import (
	"maps"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// A consumer reports the generation of each resource it serves (ReportApplied); the Core Updater, the store's one writer,
// folds that report into the applied baselines (spec section 7: retention is the current generation and the applied
// baseline; a resource that left the configuration stays until its consumer no longer serves it).

func fold(t *testing.T, s *resources.Store, report map[string]resources.Cursor) {
	t.Helper()
	if err := s.FoldApplied("dnsbl/", report); err != nil {
		t.Fatalf("FoldApplied(%v): %v", report, err)
	}
}

func TestAFoldedReportLeavesTheCurrentGenerationAndTheBaselineOnly(t *testing.T) {
	s, dir := newStore(t)
	// Given the consumer applied generation 1, and two more were published since
	publish(t, s, id, 1, nil, "a")
	fold(t, s, map[string]resources.Cursor{id: {Generation: 1, Digest: dg("a")}})
	publish(t, s, id, 2, nil, "a", "b")
	publish(t, s, id, 3, nil, "b", "c")
	wantNames(t, dir, "index.json", bn(id, 1), bn(id, 3), dn(id, 3, 1, "add"), dn(id, 3, 1, "remove"))
	if r := mustGet(t, s, id, &resources.Cursor{Generation: 1, Digest: dg("a")}); r.Kind != resources.KindDelta {
		t.Fatalf("before the report, generation 1 is answered %s, want delta", r.Kind)
	}

	// When it reports generation 3 applied
	fold(t, s, map[string]resources.Cursor{id: {Generation: 3, Digest: dg("b", "c")}})

	// Then generation 3 is both the current generation and the baseline: its body alone is kept
	wantNames(t, dir, "index.json", bn(id, 3))
	if r := mustGet(t, s, id, &resources.Cursor{Generation: 3, Digest: dg("b", "c")}); r.Kind != resources.KindUnchanged {
		t.Errorf("after the report, generation 3 is answered %s, want unchanged", r.Kind)
	}
	// And the next publish carries the delta from it
	publish(t, s, id, 4, nil, "c")
	wantNames(t, dir, "index.json", bn(id, 3), bn(id, 4), dn(id, 4, 3, "add"), dn(id, 4, 3, "remove"))
}

func TestAReportOfAGenerationTheStoreNeverHadChangesNothing(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "a")
	fold(t, s, map[string]resources.Cursor{id: {Generation: 1, Digest: dg("a")}})
	publish(t, s, id, 2, nil, "b")
	before := snapshot(t, dir)
	for name, report := range map[string]map[string]resources.Cursor{
		"a generation never published":       {id: {Generation: 99, Digest: dg("b")}},
		"the current generation, other body": {id: {Generation: 2, Digest: dg("z")}},
		"the baseline, other body":           {id: {Generation: 1, Digest: dg("z")}},
		"the baseline as it is":              {id: {Generation: 1, Digest: dg("a")}},
		"a resource never published":         {id: {Generation: 1, Digest: dg("a")}, "dnsbl/never": {Generation: 1, Digest: dg("a")}},
	} {
		fold(t, s, report)
		if after := snapshot(t, dir); !maps.Equal(after, before) {
			t.Errorf("%s: the store changed:\n before %v\n after  %v", name, before, after)
		}
	}
	if r := mustGet(t, s, id, &resources.Cursor{Generation: 1, Digest: dg("a")}); r.Kind != resources.KindDelta {
		t.Errorf("the baseline is answered %s, want delta", r.Kind)
	}
}

func TestAResourceThatLeftTheConfigurationGoesOnceTheReportNoLongerListsIt(t *testing.T) {
	const other, ipSet = "dnsbl/y", "ip-set/g/ipv4"
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "a")
	publish(t, s, other, 1, nil, "b")
	publish(t, s, ipSet, 1, nil, "10.0.0.0/8")
	both := map[string]resources.Cursor{id: {Generation: 1, Digest: dg("a")}, other: {Generation: 1, Digest: dg("b")}}
	fold(t, s, both)
	// Given both left the configuration: the store answers not found at once
	for _, gone := range []string{other, ipSet} {
		if err := s.Remove(gone); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.Get(other, nil)
	wantErr(t, "Get of a removed resource", err, resources.ErrNotFound)

	// While the consumer still reports serving it, its body stays
	fold(t, s, both)
	wantNames(t, dir, "index.json", bn(id, 1), bn(other, 1), bn(ipSet, 1))

	// Once the report no longer lists it, it goes; a removed id outside the consumer's prefix is not its to settle
	fold(t, s, map[string]resources.Cursor{id: {Generation: 1, Digest: dg("a")}})
	wantNames(t, dir, "index.json", bn(id, 1), bn(ipSet, 1))
	held := readIndex(t, dir)["resources"].(map[string]any)
	if _, ok := held[other]; ok {
		t.Errorf("the index still holds %s: %v", other, held)
	}
	if _, ok := held[ipSet]; !ok {
		t.Errorf("the index lost %s, which another consumer settles: %v", ipSet, held)
	}
}

func TestNoReportChangesNothingAndAReportOfNothingSettlesEveryRemovedResource(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "a")
	fold(t, s, map[string]resources.Cursor{id: {Generation: 1, Digest: dg("a")}})
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)

	// No report (nil: the consumer never reported) is not a report that it serves nothing
	fold(t, s, nil)
	if after := snapshot(t, dir); !maps.Equal(after, before) {
		t.Errorf("folding no report changed the store:\n before %v\n after  %v", before, after)
	}

	// A report of nothing (empty, not nil) settles the removed resource
	fold(t, s, map[string]resources.Cursor{})
	wantNames(t, dir, "index.json")
	if _, ok := readIndex(t, dir)["resources"].(map[string]any)[id]; ok {
		t.Errorf("the index still holds %s after a report of nothing", id)
	}
}
