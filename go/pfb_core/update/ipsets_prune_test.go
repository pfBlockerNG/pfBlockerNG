package update

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// WHEN the GeoIP stage supplies no continent set (GeoIP failed, no country data, or off) THEN the prune keeps a continent's
// list: it is the GeoIP stage's to remove.
func TestThePruneKeepsAContinentListWithoutItsGeoSet(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	continent := filepath.Join(s.Folders["deny"], "pfB_Africa_v4.txt")
	touch(t, continent, "198.51.100.0/24\n")
	build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)})
	if b, err := os.ReadFile(continent); err != nil || string(b) != "198.51.100.0/24\n" {
		t.Errorf("pfB_Africa_v4.txt = %q (%v), want it kept", b, err)
	}
}

// WHEN DNSBLIP is supplied in a class other than deny with CIDR Aggregation on THEN its list is aggregated as a feed's of
// that class is, and written to the class folder as today's pass writes it; the set publishes the aggregate.
func TestDNSBLIPIsAggregatedOutsideDenyAndWrittenToItsClassFolder(t *testing.T) {
	s := ipTree(t)
	source := filepath.Join(filepath.Dir(s.StateDir), "DNSBLIP_v4.source")
	touch(t, source, "203.0.113.0/25\n203.0.113.128/25\n")
	settings := ipSettings(nil, nil)
	settings["policy/ip"] = map[string]any{"aggregate": true}
	build(t, s, IPInput{Settings: settings,
		DNSBLIP: []GeoSet{{Alias: "DNSBLIP_v4", Group: "DNSBLIP", Family: "ipv4", Action: "Alias_Native", ListClass: "native", Path: source, Changed: true}}})
	if b, err := os.ReadFile(filepath.Join(s.Folders["native"], "DNSBLIP_v4.txt")); err != nil || string(b) != "203.0.113.0/24\n" {
		t.Errorf("native/DNSBLIP_v4.txt = %q (%v), want the aggregated list", b, err)
	}
	if got := body(t, s.Store, "ip-set/DNSBLIP/ipv4"); !slices.Equal(got, []string{"203.0.113.0/24"}) {
		t.Errorf("DNSBLIP = %q", got)
	}
}

// WHEN an id removed in this Update sorts before an id removed earlier THEN the removed list is in id order.
func TestTheRemovedListIsInIDOrder(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	parsed(t, s, "Z_v4", "198.51.100.1\n")
	a, z := group("A", "Deny_Both", "deny", "A"), group("Z", "Deny_Both", "deny", "Z")
	build(t, s, IPInput{Settings: ipSettings([]any{a, z}, nil)})
	build(t, s, IPInput{Settings: ipSettings([]any{a}, nil)})
	out := build(t, s, IPInput{Settings: ipSettings(nil, nil)})
	if want := []string{"ip-set/A/ipv4", "ip-set/Z/ipv4"}; !slices.Equal(out.Removed, want) {
		t.Errorf("removed = %q, want %q", out.Removed, want)
	}
}
