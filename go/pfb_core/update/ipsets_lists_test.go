package update

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// WHEN CIDR Aggregation is on THEN an IPv4 list of a class other than deny is aggregated (today's cidr_aggregate after the
// parse) and so is a continent's list in any class (today's GeoIP block), in the set and in the list the Outpost reads.
func TestCIDRAggregationReachesOtherClassesAndContinents(t *testing.T) {
	s := ipTree(t)
	halves := "203.0.113.0/25\n203.0.113.128/25\n"
	parsed(t, s, "P_v4", halves)
	continent := filepath.Join(s.Folders["deny"], "pfB_Asia_v4.txt")
	touch(t, continent, "198.51.100.0/25\n198.51.100.128/25\n")
	settings := ipSettings([]any{group("Pass", "Permit_Both", "permit", "P")}, nil)
	settings["policy/ip"] = map[string]any{"aggregate": true}
	build(t, s, IPInput{Settings: settings,
		GeoSets: []GeoSet{{Alias: "pfB_Asia_v4", Group: "Asia", Family: "ipv4", Action: "Deny_Both", ListClass: "deny", Path: continent, Changed: true}}})
	for id, want := range map[string][]string{"ip-set/Pass/ipv4": {"203.0.113.0/24"}, "ip-set/Asia/ipv4": {"198.51.100.0/24"}} {
		if got := body(t, s.Store, id); !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(s.Folders["permit"], "P_v4.txt")); string(b) != "203.0.113.0/24\n" {
		t.Errorf("P_v4.txt = %q", b)
	}
}

// WHEN a group holds a disabled feed whose list is still on disk THEN the set leaves that list out.
func TestADisabledFeedIsLeftOut(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "On_v4", "192.0.2.1\n")
	parsed(t, s, "Off_v4", "198.51.100.1\n")
	g := group("A", "Deny_Both", "deny", "On", "Off")
	g["feeds"].([]any)[1].(map[string]any)["state"] = "disabled"
	build(t, s, IPInput{Settings: ipSettings([]any{g}, nil)})
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("A = %q, want the disabled feed left out", got)
	}
}

// WHEN a group's action is Both THEN its set carries both directions, egress then ingress, as the Outpost sorts them.
func TestABothActionCarriesBothDirections(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Match_Both", "match", "A")}, nil)})
	if r, _ := resourceOf(out, "ip-set/A/ipv4"); r.Action != "match" || !reflect.DeepEqual(r.Direction, []string{"egress", "ingress"}) {
		t.Errorf("A = %+v, want match, egress and ingress", r)
	}
}

// WHEN nothing changed since the last Update THEN a feed is not run through its per-feed stage again: its snapshot from the
// state stands, though the country lookup it was first built with is gone (Reputation Max keeps a CN /24 the lookup names).
func TestAnUnchangedFeedKeepsTheSnapshotItsStateHolds(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4\n")
	settings := ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)
	settings["policy/ip"] = map[string]any{"max": true, "maxLimit": int64(3), "countryWhitelist": []any{map[string]any{"code": "CN"}},
		"countryBlacklistAction": "block"}
	s.Geo = func(string) string { return "CN" }
	build(t, s, IPInput{Settings: settings})
	kept := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, kept) {
		t.Fatalf("before: A = %q, want the CN rows kept", got)
	}
	s.Geo = nil
	build(t, s, IPInput{Settings: settings})
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, kept) {
		t.Errorf("after an Update with nothing changed: A = %q, want the snapshot's rows", got)
	}
}
