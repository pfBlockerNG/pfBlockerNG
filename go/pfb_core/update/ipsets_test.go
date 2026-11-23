package update

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

func parsed(t *testing.T, s IPSets, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.FeedDirs["ipv4"], name+".parsed.ip"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func group(name, action, class string, headers ...string) map[string]any {
	var feeds []any
	for _, h := range headers {
		feeds = append(feeds, map[string]any{"header": h, "state": "enabled", "url": "https://example.org/" + h})
	}
	return map[string]any{"name": name, "action": action, "listClass": class, "feeds": feeds}
}

func ipSettings(v4 []any, v6 []any) map[string]map[string]any {
	return map[string]map[string]any{"policy/ip": {}, "ingest": {"suppression": true}, "feeds/ipv4": {"groups": v4},
		"feeds/ipv6": {"groups": v6}}
}

func build(t *testing.T, s IPSets, in IPInput) IPOut {
	t.Helper()
	out, err := s.Build(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func resourceOf(out IPOut, id string) (apply.Resource, bool) {
	i := slices.IndexFunc(out.Resources, func(r apply.Resource) bool { return r.ID == id })
	if i < 0 {
		return apply.Resource{}, false
	}
	return out.Resources[i], true
}

// WHEN groups of every action family are published THEN each id carries the group action's resource action and direction
// as the Outpost reads config.xml, and its member count; WHEN the next Update finds nothing changed THEN no generation
// moves; WHEN one feed changes THEN only its set's generation moves.
func TestTheIPSetsCarryActionDirectionAndPublishNothingForAnUnchangedBody(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "D_v4", "192.0.2.1\n192.0.2.2\n")
	parsed(t, s, "P_v4", "198.51.100.1\n")
	parsed(t, s, "N_v4", "203.0.113.1\n")
	in := IPInput{Settings: ipSettings([]any{group("Deny", "Deny_Inbound", "deny", "D"), group("Pass", "Permit_Outbound", "permit", "P"),
		group("Nat", "Alias_Native", "native", "N")}, nil), Changed: map[string]bool{"D_v4": true, "P_v4": true, "N_v4": true}}
	first := build(t, s, in)
	want := []apply.Resource{
		{ID: "ip-set/Deny/ipv4", Generation: 1, Action: "deny", Direction: []string{"ingress"}, Entries: 2},
		{ID: "ip-set/Nat/ipv4", Generation: 1, Action: "alias_only", Entries: 1},
		{ID: "ip-set/Pass/ipv4", Generation: 1, Action: "permit", Direction: []string{"egress"}, Entries: 1},
	}
	if !reflect.DeepEqual(first.Resources, want) {
		t.Fatalf("first Update:\n have %+v\n want %+v", first.Resources, want)
	}
	in.Changed = nil
	second := build(t, s, in)
	if !reflect.DeepEqual(second.Resources, want) {
		t.Errorf("unchanged Update: resources %+v; want the same generations", second.Resources)
	}
	parsed(t, s, "P_v4", "198.51.100.2\n")
	in.Changed = map[string]bool{"P_v4": true}
	third := build(t, s, in)
	want[2].Generation = 2
	if !reflect.DeepEqual(third.Resources, want) {
		t.Errorf("one feed changed: resources %+v; want Pass alone at generation 2", third.Resources)
	}
}

// WHEN a group leaves the settings THEN its ids are removed from the store and listed as removed, and an Uber aggregate
// no longer selected is removed the same way.
func TestAGroupThatLeftIsRemoved(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	parsed(t, s, "B_v4", "198.51.100.1\n")
	in := IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A"), group("B", "Deny_Both", "deny", "B")}, nil)}
	in.Settings["policy/ip"] = map[string]any{"aggregates": []any{map[string]any{"class": "deny"}}}
	build(t, s, in)
	in.Settings = ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)
	out := build(t, s, in)
	if want := []string{"ip-aggregate/deny/ipv4", "ip-aggregate/deny/ipv6", "ip-set/B/ipv4"}; !slices.Equal(out.Removed, want) {
		t.Errorf("removed = %q, want %q", out.Removed, want)
	}
	if _, ok := resourceOf(out, "ip-set/B/ipv4"); ok || len(out.Resources) != 1 {
		t.Errorf("resources = %+v, want only A's", out.Resources)
	}
	if removed, err := s.Store.RemovedIDs("ip-set/"); err != nil || !slices.Equal(removed, []string{"ip-set/B/ipv4"}) {
		t.Errorf("the store holds %q as removed (%v), want B's id", removed, err)
	}
}

// WHEN a list holds a row the address guard refuses and rows in another spelling THEN the body holds each network once
// in Core's spelling, the refused row is left out, and the set carries one issue naming it.
func TestABodyIsPublishedInCoresSpellingWithTheGuard(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "0.1.2.3\n192.0.2.1/32\n192.0.2.1\n")
	parsed(t, s, "A_v6", "2001:DB8::1\n")
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, []any{group("A", "Deny_Both", "deny", "A")})})
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("ipv4 body = %q", got)
	}
	if got := body(t, s.Store, "ip-set/A/ipv6"); !slices.Equal(got, []string{"2001:db8::1"}) {
		t.Errorf("ipv6 body = %q", got)
	}
	if len(out.Issues) != 1 || out.Issues[0].Resource != "ip-set/A/ipv4" || out.Issues[0].Code != "member_refused" ||
		!strings.Contains(out.Issues[0].Message, `"0.1.2.3"`) {
		t.Errorf("issues = %+v, want one member_refused for ip-set/A/ipv4 naming 0.1.2.3", out.Issues)
	}
}

// WHEN a feed parsed to nothing (no list on its first run) THEN its group is published empty, with no placeholder, and the
// list the Outpost's pages read is an empty file; a feed with rows has its list written in its class's folder.
func TestAnEmptySetIsPublishedEmptyAndItsListIsEmpty(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "P_v4", "198.51.100.1\n")
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("E", "Deny_Both", "deny", "E"), group("P", "Permit_Both", "permit", "P")}, nil)})
	if r, ok := resourceOf(out, "ip-set/E/ipv4"); !ok || r.Entries != 0 || len(body(t, s.Store, "ip-set/E/ipv4")) != 0 {
		t.Errorf("E: %+v (published %v), want an empty set", r, ok)
	}
	for path, want := range map[string]string{filepath.Join(s.Folders["deny"], "E_v4.txt"): "",
		filepath.Join(s.Folders["permit"], "P_v4.txt"): "198.51.100.1\n"} {
		if b, err := os.ReadFile(path); err != nil || string(b) != want {
			t.Errorf("%s = %q (%v), want %q", path, b, err, want)
		}
	}
}

// WHEN a configured group takes the id of a continent set the loop builds THEN the continent's body is published under it
// and the group gets an issue; a group whose name maps to no alias gets an issue and no id.
func TestOneBodyPerIDAndAGeneratedSetWins(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "Mine_v4", "192.0.2.1\n")
	parsed(t, s, "Long_v4", "192.0.2.2\n")
	continent := filepath.Join(s.Folders["deny"], "pfB_Africa_v4.txt")
	touch(t, continent, "198.51.100.0/24\n")
	long := strings.Repeat("L", 25)
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("Africa", "Deny_Both", "deny", "Mine"), group(long, "Deny_Both", "deny", "Long")}, nil),
		GeoSets: []GeoSet{{Alias: "pfB_Africa_v4", Group: "Africa", Family: "ipv4", Action: "Deny_Inbound", ListClass: "deny", Path: continent}}})
	if got := body(t, s.Store, "ip-set/Africa/ipv4"); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("ip-set/Africa/ipv4 = %q, want the continent's", got)
	}
	codes := map[string]string{}
	for _, i := range out.Issues {
		codes[i.Resource] = i.Code
	}
	if want := map[string]string{"ip-set/Africa/ipv4": "set_id_taken", "ip-set/" + long + "/ipv4": "set_unpublishable"}; !reflect.DeepEqual(codes, want) {
		t.Errorf("issues = %v, want %v", codes, want)
	}
	if b, _ := os.ReadFile(continent); string(b) != "198.51.100.0/24\n" {
		t.Errorf("the continent's list = %q, want the GeoIP stage's, untouched", b)
	}
}

// WHEN a folder of the IP sets is not given THEN Build refuses to run and publishes nothing, rather than write a relative path.
func TestTheIPSetsRefuseAFolderNotGiven(t *testing.T) {
	s := ipTree(t)
	delete(s.Folders, "match")
	parsed(t, s, "A_v4", "192.0.2.1\n")
	if _, err := s.Build(context.Background(), IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)}); err == nil {
		t.Fatal("Build ran without the match folder")
	}
	if cur, _ := s.Store.IDs(""); cur != nil {
		t.Errorf("the store holds %q", cur)
	}
}

// WHEN the country lookup is asked for a /24 THEN it answers the ISO code the database gives the /24's ".1" address, as
// today's mmdblookup of "country iso_code" does, and "" for an address the database does not hold or a bad key.
func TestCountryLookupAnswersTheCountryOfTheSlash24sFirstHost(t *testing.T) {
	look, db, err := CountryLookup("../../pfb_dns_gateway/decider/testdata/GeoLite2-Country-Test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for octets, want := range map[string]string{"202.196.224": "PH", "111.235.160": "CN", "81.2.69": "", "300.1.2": "", "2001:db8": ""} {
		if got := look(octets); got != want {
			t.Errorf("%s: %q, want %q", octets, got, want)
		}
	}
	if _, _, err := CountryLookup(filepath.Join(t.TempDir(), "none.mmdb")); err == nil {
		t.Error("a missing database opened")
	}
}

// WHEN dedup is on and the feed that owned a shared row leaves THEN the feed after it gets the row back in the same
// Update, though its own list did not change: the recompute's ownership follows the member order.
func TestAMemberThatLeftHandsItsRowsToTheNextOwner(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	parsed(t, s, "B_v4", "192.0.2.1\n198.51.100.1\n")
	policy := map[string]any{"dedup": true}
	settings := ipSettings([]any{group("A", "Deny_Both", "deny", "A"), group("B", "Deny_Both", "deny", "B")}, nil)
	settings["policy/ip"] = policy
	build(t, s, IPInput{Settings: settings, Changed: map[string]bool{"A_v4": true, "B_v4": true}})
	if got := body(t, s.Store, "ip-set/B/ipv4"); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Fatalf("before: B = %q, want the shared row left to A", got)
	}
	settings = ipSettings([]any{group("B", "Deny_Both", "deny", "B")}, nil)
	settings["policy/ip"] = policy
	build(t, s, IPInput{Settings: settings})
	if got := body(t, s.Store, "ip-set/B/ipv4"); !slices.Equal(got, []string{"192.0.2.1", "198.51.100.1"}) {
		t.Errorf("after A left: B = %q, want the shared row back", got)
	}
}

// WHEN suppression covers an address that a feed row, the group's custom list and a deny continent all hold THEN only
// the feed row loses it: today's alias loop reads the custom list and the continent beside the suppression pass.
func TestTheCustomListAndAContinentAreNotSuppressed(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n198.51.100.1\n")
	parsed(t, s, "C_custom_v4", "192.0.2.1\n")
	continent := filepath.Join(s.Folders["deny"], "pfB_Asia_v4.txt")
	touch(t, continent, "192.0.2.1\n")
	g := group("C", "Deny_Both", "deny", "A")
	g["customList"] = "192.0.2.1"
	settings := ipSettings([]any{g}, nil)
	settings["policy/ip"] = map[string]any{"suppressionV4": []any{map[string]any{"cidr": "192.0.2.0/24"}}}
	build(t, s, IPInput{Settings: settings, Changed: map[string]bool{"A_v4": true},
		GeoSets: []GeoSet{{Alias: "pfB_Asia_v4", Group: "Asia", Family: "ipv4", Action: "Deny_Both", ListClass: "deny", Path: continent, Changed: true}}})
	for path, want := range map[string]string{filepath.Join(s.Folders["deny"], "A_v4.txt"): "198.51.100.1\n",
		filepath.Join(s.Folders["deny"], "C_custom_v4.txt"): "192.0.2.1\n"} {
		if b, _ := os.ReadFile(path); string(b) != want {
			t.Errorf("%s = %q, want %q", filepath.Base(path), b, want)
		}
	}
	if got := body(t, s.Store, "ip-set/Asia/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("Asia = %q, want its address kept", got)
	}
}
