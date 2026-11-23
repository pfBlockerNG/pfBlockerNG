package resources_test

import (
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
