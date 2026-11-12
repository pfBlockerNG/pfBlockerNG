package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Core's defaults are what today's PHP gives with nothing stored: the parity fixture's defaults case, field for field,
// and the fixture names every dns field the schema has.
func TestCoreDefaultsAreTheParityFixturesDefaults(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_dns_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			ID     string                     `json:"id"`
			Native map[string]json.RawMessage `json:"native"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(doc.Cases, func(c struct {
		ID     string                     `json:"id"`
		Native map[string]json.RawMessage `json:"native"`
	}) bool {
		return c.ID == "defaults"
	})
	if i < 0 {
		t.Fatal("the fixture has no defaults case")
	}
	want := doc.Cases[i].Native
	st := open(t, t.TempDir())
	if _, err := st.Initialize(nil); err != nil {
		t.Fatal(err)
	}
	value := projection(t, get(t, st, "dns"), "dns").Value
	if len(value) != len(want) {
		t.Errorf("the schema has %d dns fields, the fixture's defaults case %d: every field needs its PHP default", len(value), len(want))
	}
	for field, w := range want {
		if have := jsonOf(t, value[field]); have != string(w) {
			t.Errorf("default %s = %s, PHP gives %s", field, have, w)
		}
	}
}

func TestConcurrentSavesAtOneRevisionAcceptExactlyOne(t *testing.T) {
	st, _ := initialized(t)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			_, err := st.Save(1, changes(t, `{"dns": {"decisionCacheMax": `+jsonOf(t, i+1)+`}}`))
			results <- err
		})
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case !isConflict(err):
			t.Errorf("a concurrent save failed with %v, want success or a conflict", err)
		}
	}
	if snap := get(t, st); accepted != 1 || snap.Revision != 2 {
		t.Errorf("%d of %d saves at revision 1 accepted, store at revision %d; want exactly one, revision 2", accepted, n, snap.Revision)
	}
}

func writeStore(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenRefusesAStoreWithDataAfterItsDocument(t *testing.T) {
	_, dir := initialized(t)
	raw, err := os.ReadFile(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(writeStore(t, string(raw)+"garbage"), testSchema()); err == nil {
		t.Error("Open took a store with data after its JSON document")
	}
}

func TestOpenRefusesAStoreHoldingAProjectionThisCoreDoesNotKnow(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":4,"projections":{"dns":{"generation":2,"values":{}},
		"feedauth":{"generation":1,"values":{}},"retired":{"generation":1,"values":{}}}}`)
	if _, err := Open(dir, testSchema()); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Errorf("Open = %v, want a refusal naming the unknown projection", err)
	}
}

// A Core whose schema grew reads the store an older Core wrote: a field or projection it does not hold is its default,
// the projection at generation 1, and the revision is unchanged.
func TestOpenFillsWhatAnOlderStoreDoesNotHoldWithDefaults(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":4,"projections":{"dns":{"generation":3,"values":{"control":true}}}}`)
	st, err := Open(dir, testSchema())
	if err != nil {
		t.Fatalf("Open of an older store: %v", err)
	}
	snap := get(t, st)
	dns, auth := projection(t, snap, "dns"), projection(t, snap, "feedauth")
	if snap.Revision != 4 || dns.Generation != 3 || dns.Value["control"] != true || dns.Value["replyLogging"] != true ||
		auth.Generation != 1 || auth.Value["user"] != "" {
		t.Errorf("older store read as %s, want revision 4, dns generation 3 with control on and defaults, feedauth generation 1",
			jsonOf(t, snap))
	}
	if _, err := st.Save(4, changes(t, `{"feedauth": {"user": "u"}}`)); err != nil {
		t.Errorf("the grown store takes a save: %v", err)
	}
}

func TestAOneSidedBoundIsCheckedWithoutPanicking(t *testing.T) {
	floor := Field{Name: "n", Type: TypeInt, Default: int64(0), Min: new(int64(0))}
	ceiling := Field{Name: "n", Type: TypeInt, Default: int64(0), Max: new(int64(9))}
	if _, err := decode(floor, json.RawMessage(`-1`)); err == nil || !strings.Contains(err.Error(), "0") {
		t.Errorf("below a lone minimum = %v, want an error naming 0", err)
	}
	if _, err := decode(ceiling, json.RawMessage(`10`)); err == nil || !strings.Contains(err.Error(), "9") {
		t.Errorf("above a lone maximum = %v, want an error naming 9", err)
	}
}

// Once the new store is renamed into place it is the store: a failed directory sync after it still fails the call, but
// the next read serves what is on disk, never the revision before it.
func TestAFailedDirectorySyncAfterTheRenameServesWhatIsOnDisk(t *testing.T) {
	st, dir := initialized(t)
	syncDir = func(*os.File) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDir = (*os.File).Sync })
	if _, err := st.Save(1, changes(t, `{"dns": {"control": true}}`)); err == nil {
		t.Error("Save hid the failed directory sync")
	}
	mem := get(t, st)
	_ = st.Close()
	disk := get(t, open(t, dir))
	if jsonOf(t, mem) != jsonOf(t, disk) || mem.Revision != 2 {
		t.Errorf("memory %s, disk %s: want both at revision 2", jsonOf(t, mem), jsonOf(t, disk))
	}
}
