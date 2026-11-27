package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"b.example","type":"DNSBL"},{"domain":"a.example","type":"DNSBL"}]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Fatalf("after an Unlock the manifest unlocks %v", got)
	}

	// a Lock sends the set without the domain
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u2","unlocks":[{"domain":"a.example","type":"DNSBL"}]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("after a Lock the manifest unlocks %v, want a.example only", got)
	}
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u3","unlocks":[]}`), http.StatusOK, `{}`)
	if got, _ := manifestUnlocks(t, store); len(got) != 0 {
		t.Errorf("after the last Lock the manifest unlocks %v, want none", got)
	}
}

func TestSetTemporaryUnlocksRefusesADomainThatIsNoneAndChangesNothing(t *testing.T) {
	c, _, store := startUnlockCore(t)
	_, before := manifestUnlocks(t, store)

	for body, fields := range map[string][]string{
		`{"requestId":"u1","unlocks":[{"domain":"a.example","type":"DNSBL"},{"domain":"not a domain","type":"DNSBL"}]}`: {"unlocks[1].domain"},
		`{"requestId":"u2","unlocks":[{"domain":"","type":"DNSBL"}]}`:                                                   {"unlocks[0].domain"},
		`{"requestId":"u3"}`:                       {"unlocks"},
		`{"requestId":"u4","unlocks":"a.example"}`: {"unlocks"},
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
	wantError(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"a.example","type":"DNSBL"}]}`), http.StatusConflict, codeConflict)
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
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"a.example","type":"DNSBL"}]}`), http.StatusOK, `{}`)
	if ids, err := resources.Open(storeDir).IDs("dnsbl/"); err != nil || len(ids) != 0 {
		t.Errorf("the store holds %v (%v), want nothing", ids, err)
	}
}

func TestSetTemporaryUnlocksRefusesMoreThanItsCap(t *testing.T) {
	c, _, store := startUnlockCore(t)
	_, before := manifestUnlocks(t, store)
	domains := make([]string, maxUnlocks+1)
	for i := range domains {
		domains[i] = fmt.Sprintf(`{"domain":"d%d.example","type":"DNSBL"}`, i)
	}
	wantError(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[`+strings.Join(domains, ",")+`]}`),
		http.StatusBadRequest, codeInvalidArgument, "unlocks")
	if got, after := manifestUnlocks(t, store); len(got) != 0 || after != before {
		t.Errorf("after a refused request the manifest unlocks %d domains at generation %d, want none at %d", len(got), after, before)
	}
}

func TestSetTemporaryUnlocksIsUnavailableWithoutAStore(t *testing.T) {
	c := startCore(t, scratchDir(t), "--update-cmd", newFakeUpdate(t).path)
	wantError(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"a.example","type":"DNSBL"}]}`), http.StatusServiceUnavailable, codeUnavailable)
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

	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"a.example","type":"DNSBL"}]}`), http.StatusOK, `{}`)
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

// Two clicks at once (two tabs, a double click) are no Update: both are taken, one after the other.
func TestConcurrentSetTemporaryUnlocksAreAllTaken(t *testing.T) {
	c, _, store := startUnlockCore(t)
	const n = 16
	got := make(chan reply, n)
	for i := range n {
		go func() {
			got <- c.post("SetTemporaryUnlocks", fmt.Sprintf(`{"requestId":"c%d","unlocks":[{"domain":"d%d.example","type":"DNSBL"}]}`, i, i))
		}()
	}
	for range n {
		wantJSON(t, <-got, http.StatusOK, `{}`)
	}
	if got, _ := manifestUnlocks(t, store); len(got) != 1 {
		t.Errorf("the manifest unlocks %v, want the one set the last request sent", got)
	}
}

// #3977 (owner, 2026-11-27): the Alerts page reads Core's set, with each domain's type.
func TestGetTemporaryUnlocksAnswersTheSetWithItsTypes(t *testing.T) {
	c, _, _ := startUnlockCore(t)
	wantJSON(t, c.post("GetTemporaryUnlocks", `{}`), http.StatusOK, `{"unlocks":[]}`)
	wantJSON(t, c.post("SetTemporaryUnlocks", `{"requestId":"u1","unlocks":[{"domain":"b.example","type":"Python"},{"domain":"a.example","type":"DNSBL"}]}`),
		http.StatusOK, `{}`)
	wantJSON(t, c.post("GetTemporaryUnlocks", `{}`), http.StatusOK,
		`{"unlocks":[{"domain":"a.example","type":"DNSBL"},{"domain":"b.example","type":"Python"}]}`) // in domain order
}

func TestGetTemporaryUnlocksIsAReadForRootAlone(t *testing.T) {
	m, ok := coreMethods(t.TempDir(), nil, nil, nil, nil)["GetTemporaryUnlocks"]
	if !ok || m.mutating || m.client {
		t.Errorf("GetTemporaryUnlocks = %+v (served %v), want a read no client may call", m, ok)
	}
}

func TestSetTemporaryUnlocksRefusesATypeThatIsNoWord(t *testing.T) {
	c, _, store := startUnlockCore(t)
	_, before := manifestUnlocks(t, store)
	for body, field := range map[string]string{
		`{"requestId":"u1","unlocks":[{"domain":"a.example"}]}`:                   "unlocks[0].type",
		`{"requestId":"u2","unlocks":[{"domain":"a.example","type":"a b"}]}`:      "unlocks[0].type",
		`{"requestId":"u3","unlocks":[{"domain":"a.example","type":"<script>"}]}`: "unlocks[0].type",
	} {
		wantError(t, c.post("SetTemporaryUnlocks", body), http.StatusBadRequest, codeInvalidArgument, field)
	}
	if got, after := manifestUnlocks(t, store); len(got) != 0 || after != before {
		t.Errorf("after refused requests the manifest unlocks %v at generation %d, want none at %d", got, after, before)
	}
}
