package settings

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// refreshBackend is a Backend a test steers. Its fields are plain on purpose: a Store calls a backend one call at a time,
// so any overlap of two calls is a data race the detector must see.
type refreshBackend struct {
	revision      uint64
	values        map[string]map[string]any // what Read reports; nil is an uninitialized backend
	readErr       error                     // fails Read
	writeErr      error                     // refuses Write: nothing is written
	onWrite       func()                    // runs inside Write, before it decides
	afterWrite    func(*refreshBackend)     // the backend rewrites what it took, as an adapter that normalizes
	reads, writes int
}

func newRefreshBackend(revision uint64, values map[string]map[string]any) *refreshBackend {
	return &refreshBackend{revision: revision, values: values}
}

func (b *refreshBackend) Read() (Stored, error) {
	b.reads++
	if b.readErr != nil {
		return Stored{}, b.readErr
	}
	projections := make(map[string]map[string]json.RawMessage, len(b.values))
	for id, fields := range b.values {
		projections[id] = make(map[string]json.RawMessage, len(fields))
		for name, v := range fields {
			raw, err := json.Marshal(v)
			if err != nil {
				return Stored{}, err
			}
			projections[id][name] = raw
		}
	}
	return Stored{Initialized: b.values != nil, Revision: b.revision, Projections: projections}, nil
}

func (b *refreshBackend) Write(expected uint64, values map[string]map[string]any) (uint64, error) {
	b.writes++
	if b.onWrite != nil {
		b.onWrite()
	}
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	b.revision++
	written := b.revision
	b.values = make(map[string]map[string]any, len(values))
	for id, fields := range values {
		b.values[id] = make(map[string]any, len(fields))
		for name, v := range fields {
			b.values[id][name] = v
		}
	}
	if b.afterWrite != nil {
		b.afterWrite(b)
	}
	return written, nil
}

// storeOver loads a Store over b.
func storeOver(t *testing.T, b *refreshBackend) *Store {
	t.Helper()
	st, err := Load(b, testSchema())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return st
}

// movedUnderCore puts b at revision 5 with values a store at revision 1 does not hold (a restore or an HA receive wrote
// config.xml behind Core's back), and has it refuse the next write as the adapter does.
func movedUnderCore(b *refreshBackend) {
	b.revision = 5
	b.values = map[string]map[string]any{"dns": {"decisionCacheMax": int64(900), "control": true}}
	b.writeErr = &ConflictError{Field: "expectedRevision", Message: "the backend is at revision 5, not 1"}
}

func decisionCacheMax(t *testing.T, st *Store) any {
	t.Helper()
	return projection(t, get(t, st, "dns"), "dns").Value["decisionCacheMax"]
}

// An API client that gets a conflict reads at once and must see the revision that moved, not wait for the next tick.
func TestSaveRereadsTheBackendWhenItsWriteConflicts(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	if snap := get(t, st, "dns"); snap.Revision != 1 || decisionCacheMax(t, st) != int64(500) {
		t.Fatalf("before the save: %s, want revision 1 and decisionCacheMax 500", jsonOf(t, snap))
	}
	movedUnderCore(b)

	if _, err := st.Save(1, changes(t, `{"dns": {"cnameValidation": true}}`)); !isConflict(err) {
		t.Fatalf("Save over a moved backend = %v, want a conflict", err)
	}
	snap := get(t, st, "dns")
	dns := projection(t, snap, "dns")
	if snap.Revision != 5 || dns.Value["decisionCacheMax"] != int64(900) || dns.Value["control"] != true {
		t.Errorf("after the conflict: %s, want the backend's revision 5 with decisionCacheMax 900 and control true", jsonOf(t, snap))
	}
}

func TestInitializeRereadsTheBackendWhenItsWriteConflicts(t *testing.T) {
	b := newRefreshBackend(0, nil)
	st := storeOver(t, b)
	if get(t, st).Initialized {
		t.Fatal("the store is initialized before Initialize")
	}
	b.revision = 5
	b.values = map[string]map[string]any{"dns": {"decisionCacheMax": int64(900)}}
	b.writeErr = &ConflictError{Field: "expectedRevision", Message: "the backend is at revision 5, not 0"}

	if _, err := st.Initialize(nil); !isConflict(err) {
		t.Fatalf("Initialize over a moved backend = %v, want a conflict", err)
	}
	if snap := get(t, st, "dns"); !snap.Initialized || snap.Revision != 5 || decisionCacheMax(t, st) != int64(900) {
		t.Errorf("after the conflict: %s, want initialized at the backend's revision 5 with decisionCacheMax 900", jsonOf(t, snap))
	}
}

func TestSaveKeepsItsStateWhenTheRereadAfterAConflictFails(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	movedUnderCore(b)
	b.readErr = errString("the backend is gone")
	reads := b.reads

	if _, err := st.Save(1, changes(t, `{"dns": {"cnameValidation": true}}`)); !isConflict(err) {
		t.Fatalf("Save = %v, want the conflict, not the failed re-read", err)
	}
	if b.reads != reads+1 {
		t.Errorf("the backend was read %d times after the conflict, want 1 re-read attempt", b.reads-reads)
	}
	if snap := get(t, st, "dns"); snap.Revision != 1 || decisionCacheMax(t, st) != int64(500) {
		t.Errorf("after the failed re-read: %s, want the state as it was: revision 1, decisionCacheMax 500", jsonOf(t, snap))
	}
}

func TestSaveDoesNotRereadWhenTheBackendRefusesAValidationError(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	b.writeErr = &ValidationError{Fields: []FieldError{{Field: "dns.cnameValidation", Message: "the adapter refuses it"}}}
	reads := b.reads

	_, err := st.Save(1, changes(t, `{"dns": {"cnameValidation": true}}`))
	if got := strings.Join(validationFields(err), ","); got != "dns.cnameValidation" {
		t.Fatalf("Save = %v, want the backend's validation error", err)
	}
	if b.writes != 1 || b.reads != reads {
		t.Errorf("backend calls after the refusal: %d writes, %d reads since the write, want 1 and 0", b.writes, b.reads-reads)
	}
	if snap := get(t, st, "dns"); snap.Revision != 1 || projection(t, snap, "dns").Value["cnameValidation"] != false {
		t.Errorf("after the refusal: %s, want the state as it was", jsonOf(t, snap))
	}
}

func TestSaveDoesNotRereadOrCallTheBackendOnItsOwnStaleRevisionConflict(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	reads := b.reads

	if _, err := st.Save(7, changes(t, `{"dns": {"cnameValidation": true}}`)); !isConflict(err) {
		t.Fatalf("Save at a stale revision = %v, want a conflict", err)
	}
	if b.writes != 0 || b.reads != reads {
		t.Errorf("backend calls: %d writes, %d reads, want none: the store refused it before asking", b.writes, b.reads-reads)
	}
}

// lowerUser is an adapter that stores a feed user in lower case.
func lowerUser(b *refreshBackend) {
	b.values["feedauth"]["user"] = strings.ToLower(b.values["feedauth"]["user"].(string))
}

// Core holds what the adapter stored, and the result shows exactly the projections that differ from before, as stored.
func TestSaveRereadShowsWhatTheBackendNormalized(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	b.afterWrite = lowerUser
	st := storeOver(t, b)

	res, err := st.Save(1, changes(t, `{"dns": {"control": true}, "feedauth": {"user": "Alice"}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	snap := get(t, st)
	if got := projection(t, snap, "feedauth").Value["user"]; got != "alice" {
		t.Errorf("feedauth.user after Save = %v, want the backend's form \"alice\"", got)
	}
	if res.Revision != snap.Revision {
		t.Errorf("Result.Revision = %d, Get's revision = %d, want them equal", res.Revision, snap.Revision)
	}
	var shown []string
	for _, p := range res.Projections {
		shown = append(shown, p.ResourceID)
		if want := jsonOf(t, projection(t, snap, strings.TrimPrefix(p.ResourceID, "settings/"))); jsonOf(t, p) != want {
			t.Errorf("Result shows %s, Get shows %s: the result must come from the values the backend stored", jsonOf(t, p), want)
		}
	}
	if got := strings.Join(shown, ","); got != "settings/dns,settings/feedauth" {
		t.Errorf("Result.Projections = %s, want the two that differ from before: settings/dns,settings/feedauth", got)
	}
}

// A change the backend normalizes back to what Core held is no change: the result must not list it.
func TestSaveRereadOmitsAProjectionTheBackendNormalizedBackToWhatItWas(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}, "feedauth": {"user": "alice"}})
	b.afterWrite = lowerUser
	st := storeOver(t, b)

	res, err := st.Save(1, changes(t, `{"dns": {"control": true}, "feedauth": {"user": "ALICE"}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	var shown []string
	for _, p := range res.Projections {
		shown = append(shown, p.ResourceID)
	}
	if got := strings.Join(shown, ","); got != "settings/dns" {
		t.Errorf("Result.Projections = %s, want only settings/dns: feedauth is \"alice\" before and after", got)
	}
}

// The result carries the revision the store holds after the re-read, not the one the write answered.
func TestSaveRereadReportsTheRevisionTheStoreHolds(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	b.afterWrite = func(b *refreshBackend) { b.revision++ } // another writer slipped in after this one
	st := storeOver(t, b)

	res, err := st.Save(1, changes(t, `{"dns": {"control": true}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if snap := get(t, st); res.Revision != 3 || snap.Revision != 3 {
		t.Errorf("Result.Revision = %d, Get's revision = %d, want both 3 (the write answered 2)", res.Revision, snap.Revision)
	}
}

func TestSaveKeepsTheWrittenValuesWhenTheRereadAfterItFails(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	b.readErr = errString("the backend is gone")
	reads := b.reads

	res, err := st.Save(1, changes(t, `{"dns": {"control": true}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if b.reads != reads+1 {
		t.Errorf("the backend was read %d times after the write, want 1 re-read attempt", b.reads-reads)
	}
	snap := get(t, st, "dns")
	if res.Revision != 2 || snap.Revision != 2 || projection(t, snap, "dns").Value["control"] != true {
		t.Errorf("Result.Revision = %d, Get = %s, want the written values at the written revision 2", res.Revision, jsonOf(t, snap))
	}
	if len(res.Projections) != 1 || res.Projections[0].ResourceID != "settings/dns" {
		t.Errorf("Result.Projections = %s, want settings/dns, the one that changed", jsonOf(t, res.Projections))
	}
}

// Reload and Save both hold wmu across their backend call. The backend is deliberately not synchronized, so a Reload that
// does not wait for a Save in flight reads and writes it unordered, which -race reports; with wmu it reads the saved revision.
func TestSaveRaceWithAReloadIsSerializedByTheWriteLock(t *testing.T) {
	b := newRefreshBackend(1, map[string]map[string]any{"dns": {"decisionCacheMax": int64(500)}})
	st := storeOver(t, b)
	entered, release := make(chan struct{}), make(chan struct{})
	b.onWrite = func() {
		close(entered)
		<-release
	}
	var (
		wg        sync.WaitGroup
		saved     Result
		saveErr   error
		reloaded  Snapshot
		reloadErr error
	)
	wg.Go(func() { saved, saveErr = st.Save(1, changes(t, `{"dns": {"control": true}}`)) })
	<-entered // the Save holds wmu and is inside the backend's Write
	wg.Go(func() { reloaded, reloadErr = st.Reload() })
	close(release)
	wg.Wait()

	if saveErr != nil || reloadErr != nil {
		t.Fatalf("Save = %v, Reload = %v, want both to succeed", saveErr, reloadErr)
	}
	if saved.Revision != 2 || reloaded.Revision != 2 || get(t, st).Revision != 2 {
		t.Errorf("revisions: Save %d, Reload %d, Get %d, want 2 everywhere: the Reload runs after the Save", saved.Revision, reloaded.Revision, get(t, st).Revision)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
