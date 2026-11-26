package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// issue #4264 (owner, 2026-11-24, https://github.com/pfBlockerNG/pfBlockerNG/issues/3977#issuecomment-7145862780): Core holds
// the temporary unlocks. The Alerts page's Lock and Unlock send the whole set of unlocked domains to SetTemporaryUnlocks, and
// Core republishes dnsbl/manifest with them as its unlock rows, without running a whole Update; pfB-DNS takes them through
// its poll. The next DNSBL build re-locks them.

// startUnlockCore is a Core with Updates (a fake program) and a resource store holding a DNSBL publication.
func startUnlockCore(t *testing.T) (*runningCore, *fakeUpdate, *resources.Store) {
	t.Helper()
	holdQuarters(t)
	f := newFakeUpdate(t)
	dir := scratchDir(t)
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := resources.Open(storeDir)
	if _, err := dnsbl.Publish(store, dnsbl.Set{Whitelist: []string{"w.example"}}); err != nil {
		t.Fatal(err)
	}
	return startCore(t, dir, "--update-cmd", f.path, "--resource-dir", storeDir), f, store
}

// manifestUnlocks are the domains of the manifest's unlock rows, in byte order, and its generation.
func manifestUnlocks(t *testing.T, store *resources.Store) ([]string, uint64) {
	t.Helper()
	cur, err := store.Current(dnsbl.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := store.Body(dnsbl.ManifestID, cur.Generation, resources.PartMembers, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	dec := json.NewDecoder(f)
	for dec.More() {
		var r struct{ Kind, Domain string }
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if r.Kind == "unlock" {
			out = append(out, r.Domain)
		}
	}
	slices.Sort(out)
	return out, cur.Generation
}

func TestSetTemporaryUnlocksRepublishesTheManifestWithTheUnlockedDomains(t *testing.T) {
	c, _, store := startUnlockCore(t)

	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","domains":["b.example","a.example"]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Fatalf("after an Unlock the manifest unlocks %v", got)
	}

	// a Lock sends the set without the domain
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u2","domains":["a.example"]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("after a Lock the manifest unlocks %v, want a.example only", got)
	}
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u3","domains":[]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); len(got) != 0 {
		t.Errorf("after the last Lock the manifest unlocks %v, want none", got)
	}
}

func TestSetTemporaryUnlocksRefusesADomainThatIsNoneAndChangesNothing(t *testing.T) {
	c, _, store := startUnlockCore(t)
	_, before := manifestUnlocks(t, store)

	for body, fields := range map[string][]string{
		`{"requestId":"u1","domains":["a.example","not a domain"]}`: {"domains[1]"},
		`{"requestId":"u2","domains":[""]}`:                         {"domains[0]"},
		`{"requestId":"u3"}`:                                        {"domains"},
		`{"requestId":"u4","domains":"a.example"}`:                  {"domains"},
	} {
		wantError(t, c.post("SetTemporaryUnlocks", body), http.StatusBadRequest, codeInvalidArgument, fields...)
	}
	if got, after := manifestUnlocks(t, store); len(got) != 0 || after != before {
		t.Errorf("after refused requests the manifest unlocks %v at generation %d, want none at %d", got, after, before)
	}
}

func TestSetTemporaryUnlocksWhileAnUpdateRunsIsAConflict(t *testing.T) {
	c, f, store := startUnlockCore(t)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"s1","trigger":"manual"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")

	// the Update is the store's writer, and its end re-locks every unlock anyway
	wantError(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","domains":["a.example"]}`), http.StatusConflict, codeConflict)
	if got, _ := manifestUnlocks(t, store); len(got) != 0 {
		t.Errorf("the manifest unlocks %v, want none", got)
	}
	f.release()
	c.waitFinished("manual")
}

func TestSetTemporaryUnlocksWithoutAPublicationWritesNothing(t *testing.T) {
	holdQuarters(t)
	f := newFakeUpdate(t)
	dir := scratchDir(t)
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := startCore(t, dir, "--update-cmd", f.path, "--resource-dir", storeDir)

	// before the cutover PHP publishes the manifest pfB-DNS reads, and Core's store holds no dnsbl/*
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","domains":["a.example"]}`), http.StatusOK, `{}`)
	if ids, err := resources.Open(storeDir).IDs("dnsbl/"); err != nil || len(ids) != 0 {
		t.Errorf("the store holds %v (%v), want nothing", ids, err)
	}
}

func TestSetTemporaryUnlocksIsUnavailableWithoutAStore(t *testing.T) {
	c := startCore(t, scratchDir(t), "--update-cmd", newFakeUpdate(t).path)
	wantError(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","domains":["a.example"]}`), http.StatusServiceUnavailable, codeUnavailable)
}

// Without Updates nothing else writes the store, so the unlocks are published without waiting on one.
func TestSetTemporaryUnlocksWithoutUpdatesStillRepublishesTheManifest(t *testing.T) {
	dir := scratchDir(t)
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := resources.Open(storeDir)
	if _, err := dnsbl.Publish(store, dnsbl.Set{}); err != nil {
		t.Fatal(err)
	}
	c := startCore(t, dir, "--resource-dir", storeDir)

	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","domains":["a.example"]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("the manifest unlocks %v, want a.example", got)
	}
}

func TestSetTemporaryUnlocksIsForRootAlone(t *testing.T) {
	m, ok := coreMethods(t.TempDir(), nil, nil, nil, nil)["SetTemporaryUnlocks"]
	if !ok || !m.mutating || m.client {
		t.Errorf("SetTemporaryUnlocks = %+v (served %v), want a mutating method no client may call", m, ok)
	}
}
