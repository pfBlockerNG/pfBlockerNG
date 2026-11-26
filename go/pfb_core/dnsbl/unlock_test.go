package dnsbl_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// unlockRows are the domains of the manifest's unlock rows, in byte order.
func unlockRows(t *testing.T, store *resources.Store) []string {
	t.Helper()
	var out []string
	for _, row := range body(t, store, dnsbl.ManifestID) {
		var r struct{ Kind, Domain string }
		if err := json.Unmarshal([]byte(row), &r); err != nil {
			t.Fatalf("manifest row %q: %v", row, err)
		}
		if r.Kind == "unlock" {
			out = append(out, r.Domain)
		}
	}
	slices.Sort(out)
	return out
}

func withoutUnlocks(rows []string) []string {
	return slices.DeleteFunc(slices.Clone(rows), func(r string) bool { return strings.Contains(r, `"kind":"unlock"`) })
}

// issue #4264 (owner, 2026-11-24): Core holds the Alerts page's temporary unlocks as the manifest's unlock rows, set by
// republishing the manifest alone, without a whole Update.
func TestSetUnlocksRepublishesTheManifestWithOnlyItsUnlockRowsChanged(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{Whitelist: []string{"w.example"}, Unlock: []string{"old.example"}}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Current(dnsbl.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	rowsBefore := body(t, store, dnsbl.ManifestID)

	generation, ok, err := dnsbl.SetUnlocks(store, []string{"b.example", "a.example"})
	if err != nil || !ok {
		t.Fatalf("SetUnlocks = %v, %v", ok, err)
	}

	after, err := store.Current(dnsbl.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	if generation != after.Generation || after.Generation <= before.Generation {
		t.Errorf("generation %d, the manifest's %d, before %d: want a new one, answered", generation, after.Generation, before.Generation)
	}
	if got := unlockRows(t, store); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Errorf("unlock rows %v, want the domains given, and the earlier one gone", got)
	}
	if got, want := withoutUnlocks(body(t, store, dnsbl.ManifestID)), withoutUnlocks(rowsBefore); !slices.Equal(got, want) {
		t.Errorf("the other rows changed:\n got %v\nwant %v", got, want)
	}
	if string(after.Metadata) != string(before.Metadata) {
		t.Errorf("metadata %s, want %s", after.Metadata, before.Metadata)
	}
}

func TestSetUnlocksWithTheSameDomainsAdvancesNoGeneration(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{}); err != nil {
		t.Fatal(err)
	}
	first, _, err := dnsbl.SetUnlocks(store, []string{"a.example"})
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := dnsbl.SetUnlocks(store, []string{"a.example"})
	if err != nil || again != first {
		t.Errorf("the same unlocks again: generation %d (%v), want %d", again, err, first)
	}
}

func TestSetUnlocksWithNoDomainsLocksEveryOne(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{Unlock: []string{"a.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dnsbl.SetUnlocks(store, nil); err != nil {
		t.Fatal(err)
	}
	if got := unlockRows(t, store); len(got) != 0 {
		t.Errorf("unlock rows %v, want none", got)
	}
}

// A publication's metadata is kept byte for byte: a call that changes no unlock row advances no generation either.
func TestSetUnlocksKeepsTheMetadataOfAPublicationWithFeeds(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{Feeds: []dnsbl.Feed{{Name: "F", Group: "G", Rows: []string{"d.example"}}}}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Current(dnsbl.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	generation, _, err := dnsbl.SetUnlocks(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Current(dnsbl.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	if generation != before.Generation || string(after.Metadata) != string(before.Metadata) {
		t.Errorf("generation %d, metadata %s; want %d, %s", generation, after.Metadata, before.Generation, before.Metadata)
	}
}

func TestSetUnlocksWithoutAManifestWritesNothing(t *testing.T) {
	store := resources.Open(t.TempDir())

	_, ok, err := dnsbl.SetUnlocks(store, []string{"a.example"})

	if err != nil || ok {
		t.Fatalf("SetUnlocks over no manifest = %v, %v; want nothing to unlock in", ok, err)
	}
	if ids, err := store.IDs("dnsbl/"); err != nil || len(ids) != 0 {
		t.Errorf("the store holds %v (%v), want nothing", ids, err)
	}
}

// The next DNSBL build re-locks: its set carries no unlock (owner, 2026-11-24: the re-lock at an Update's end is Core's).
func TestTheNextPublicationReLocks(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dnsbl.SetUnlocks(store, []string{"a.example"}); err != nil {
		t.Fatal(err)
	}

	if _, err := dnsbl.Publish(store, dnsbl.Set{}); err != nil {
		t.Fatal(err)
	}

	if got := unlockRows(t, store); len(got) != 0 {
		t.Errorf("unlock rows after the next publication %v, want none", got)
	}
}
