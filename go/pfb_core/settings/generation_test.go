package settings

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

// The generations of Production's dns values: sha256 of their JSON with sorted keys, the first 8 bytes big-endian, shifted
// right by 11 (53 bits). Computed outside Go, so that the formula cannot drift unseen.
const (
	defaultsGeneration  uint64 = 7555500541304996
	controlOnGeneration uint64 = 6318479188123327
)

// A generation comes from a projection's values alone: equal values give it in any store (a restarted Core, another
// backend), the revision does not enter it, and a change of value moves it.
func TestAGenerationIsDerivedFromTheValuesAndFromNothingElse(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 7, nil))
	if got := projection(t, get(t, loadFake(t, f, 0)), "dns").Generation; got != defaultsGeneration {
		t.Errorf("generation of the production defaults = %d, want %d", got, defaultsGeneration)
	}
	if got := projection(t, get(t, loadFake(t, f, 0)), "dns").Generation; got != defaultsGeneration {
		t.Errorf("generation after a second Load (a restart) = %d, want the same %d", got, defaultsGeneration)
	}
	f.reply(readReply(t, 9, nil))
	if got := projection(t, get(t, loadFake(t, f, 0)), "dns").Generation; got != defaultsGeneration {
		t.Errorf("generation of the same values at revision 9 = %d, want %d: the revision is not part of it", got, defaultsGeneration)
	}
	f.reply(readReply(t, 9, map[string]any{"control": true}))
	if got := projection(t, get(t, loadFake(t, f, 0)), "dns").Generation; got != controlOnGeneration {
		t.Errorf("generation with control on = %d, want %d", got, controlOnGeneration)
	}
}

// settings.json holds the format, the revision and each projection's values: no generation, which is computed on read.
func TestAFileStoreKeepsNoGenerationAndEqualValuesGiveTheSameOneAgain(t *testing.T) {
	dir := t.TempDir()
	st := open(t, dir)
	if _, err := st.Initialize(nil); err != nil {
		t.Fatal(err)
	}
	dns := func(st *Store) uint64 { return projection(t, get(t, st), "dns").Generation }
	if got := dns(st); got != defaultsGeneration {
		t.Errorf("generation after Initialize with the defaults = %d, want %d", got, defaultsGeneration)
	}
	if _, err := st.Save(1, changes(t, `{"dns": {"control": true}}`)); err != nil {
		t.Fatal(err)
	}
	if got := dns(st); got != controlOnGeneration {
		t.Errorf("generation after control on = %d, want %d", got, controlOnGeneration)
	}
	if _, err := st.Save(2, changes(t, `{"dns": {"control": false}}`)); err != nil {
		t.Fatal(err)
	}
	if got := dns(st); got != defaultsGeneration || get(t, st).Revision != 3 {
		t.Errorf("after control on and off again: generation %d, revision %d, want %d at revision 3: a counter would be 3, content is not",
			got, get(t, st).Revision, defaultsGeneration)
	}
	if got := dns(open(t, dir)); got != defaultsGeneration {
		t.Errorf("generation after a restart = %d, want %d", got, defaultsGeneration)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(storeBytes(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(doc)); !slices.Equal(got, []string{"format", "projections", "revision"}) {
		t.Errorf("settings.json keys = %v, want format, projections, revision", got)
	}
	var projections map[string]map[string]json.RawMessage
	if err := json.Unmarshal(doc["projections"], &projections); err != nil {
		t.Fatal(err)
	}
	if len(projections) != len(testSchema().Projections) { // the loop below must have something to check
		t.Fatalf("settings.json holds %d projections, want every one of the schema's", len(projections))
	}
	for id, p := range projections {
		if got := slices.Sorted(maps.Keys(p)); !slices.Equal(got, []string{"values"}) {
			t.Errorf("settings.json projection %s keys = %v, want only values", id, got)
		}
	}
}
