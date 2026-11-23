package resources_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// IDs lists what the store holds under a prefix, in byte order, leaving out an id marked removed; a store with no index
// holds nothing, and an index that cannot be read is cleared as by any write.
func TestIDsListsWhatTheStoreHoldsUnderAPrefix(t *testing.T) {
	dir := t.TempDir()
	s := resources.Open(dir)
	if ids, err := s.IDs("dnsbl/"); err != nil || ids != nil {
		t.Fatalf("empty store: IDs = %q, %v; want none", ids, err)
	}
	for _, id := range []string{"dnsbl/b", "dnsbl/a", "geo-catalog", "dnsbl/gone", "ip-set/dnsbl/ipv4"} {
		if _, err := s.Publish(id, []string{"m"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Remove("dnsbl/gone"); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.IDs("dnsbl/"); err != nil || !slices.Equal(ids, []string{"dnsbl/a", "dnsbl/b"}) {
		t.Errorf("IDs(dnsbl/) = %q, %v; want dnsbl/a, dnsbl/b", ids, err)
	}

	index, err := filepath.Glob(filepath.Join(dir, "index*"))
	if err != nil || len(index) == 0 {
		t.Fatalf("index files %q, %v", index, err)
	}
	if err := os.WriteFile(index[0], []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.IDs("dnsbl/"); err != nil || ids != nil {
		t.Errorf("unreadable index: IDs = %q, %v; want none, cleared", ids, err)
	}
}

// An index entry that is null is no resource, as Get reads it: IDs leaves it out instead of failing on it.
func TestIDsLeavesOutANullIndexEntry(t *testing.T) {
	dir := t.TempDir()
	s := resources.Open(dir)
	if _, err := s.Publish("dnsbl/a", []string{"m"}, nil); err != nil {
		t.Fatal(err)
	}
	index, err := filepath.Glob(filepath.Join(dir, "index*"))
	if err != nil || len(index) != 1 {
		t.Fatalf("index files %q, %v", index, err)
	}
	raw, err := os.ReadFile(index[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["resources"].(map[string]any)["dnsbl/orphan"] = nil
	if raw, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index[0], raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("dnsbl/orphan", nil); !errors.Is(err, resources.ErrNotFound) {
		t.Fatalf("Get(dnsbl/orphan) = %v, want ErrNotFound: the index must load with the null entry", err)
	}
	if ids, err := s.IDs("dnsbl/"); err != nil || !slices.Equal(ids, []string{"dnsbl/a"}) {
		t.Errorf("IDs(dnsbl/) = %q, %v; want dnsbl/a", ids, err)
	}
}

// RemovedIDs lists, under a prefix, the ids marked removed and not yet deleted, in byte order; a current id, an id under
// another prefix and an id whose removal was applied are left out, and a store with no index holds none.
func TestRemovedIDsListsTheRemovedIDsUnderAPrefix(t *testing.T) {
	s := resources.Open(t.TempDir())
	if ids, err := s.RemovedIDs("ip-set/"); err != nil || ids != nil {
		t.Fatalf("empty store: RemovedIDs = %q, %v; want none", ids, err)
	}
	for _, id := range []string{"ip-set/B/ipv4", "ip-set/A/ipv6", "ip-set/A/ipv4", "ip-set/C/ipv4", "ip-aggregate/deny/ipv4"} {
		if _, err := s.Publish(id, []string{"192.0.2.1"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"ip-set/B/ipv4", "ip-set/A/ipv6", "ip-set/C/ipv4", "ip-aggregate/deny/ipv4"} {
		if err := s.Remove(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RemovalApplied("ip-set/C/ipv4"); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.RemovedIDs("ip-set/"); err != nil || !slices.Equal(ids, []string{"ip-set/A/ipv6", "ip-set/B/ipv4"}) {
		t.Errorf("RemovedIDs(ip-set/) = %q, %v; want ip-set/A/ipv6, ip-set/B/ipv4", ids, err)
	}
	if ids, err := s.IDs("ip-set/"); err != nil || !slices.Equal(ids, []string{"ip-set/A/ipv4"}) {
		t.Errorf("IDs(ip-set/) = %q, %v; want only the current ip-set/A/ipv4", ids, err)
	}
}
