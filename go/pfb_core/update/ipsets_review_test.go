package update

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The review of sub-slice 9h (#4038): the IP sets heal themselves from their own state, follow the policy, take the Uber
// selection from the settings, and never let one list or id overwrite another.

// WHEN a published body is damaged on disk THEN the next Update still builds, and the store holds the body again.
func TestADamagedBodyIsRepublishedByTheNextUpdate(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	in := IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)}
	build(t, s, in)
	bodies, err := filepath.Glob(filepath.Join(filepath.Dir(s.StateDir), "store", "*.body"))
	if err != nil || len(bodies) != 1 {
		t.Fatalf("bodies %q, %v; want one", bodies, err)
	}
	touch(t, bodies[0], "garbage\n")
	if _, err := s.Build(context.Background(), in); err != nil {
		t.Fatalf("the Update after the damage failed: %v", err)
	}
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("A = %q, want its body back", got)
	}
}

// WHEN only the IP policy changes (a suppression entry added), with no feed change THEN the deny sets are built again
// under the new policy. Today's pass waits for a feed change or a Force Reload: Core is stricter.
func TestAPolicyChangeAloneRebuildsTheDenySets(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n198.51.100.1\n")
	in := IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)}
	build(t, s, in)
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"192.0.2.1", "198.51.100.1"}) {
		t.Fatalf("before: A = %q", got)
	}
	in.Settings["policy/ip"] = map[string]any{"suppressionV4": []any{map[string]any{"cidr": "192.0.2.0/24"}}}
	build(t, s, in)
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Errorf("after the suppression entry: A = %q, want 192.0.2.1 suppressed", got)
	}
}

// WHEN a feed's parsed list changed but the caller did not name it changed (an Update that failed before its state was
// saved lost the news) THEN the next Update finds the change from its own state and publishes it.
func TestAFeedChangeTheCallerDidNotNameIsFoundFromTheState(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	in := IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)}
	build(t, s, in)
	parsed(t, s, "A_v4", "192.0.2.2\n")
	build(t, s, in)
	if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("A = %q, want the new list", got)
	}
}

// WHEN Reputation Max is on with a limit unlike dMax's THEN a feed's own reputation stage uses the Max limit, as today's
// pass hands pfblockerng.sh $pfb['max'] (rep/p24_max_var): the ipset corpus row pre_rep_unknown_block (max 3, no country
// data) collapses the /24 holding four rows; with Max at 50 and dMax at 3 nothing collapses.
func TestAFeedsReputationStageUsesTheMaxLimitNotDMaxs(t *testing.T) {
	for _, tc := range []struct {
		max, dmax int64
		dmaxOn    bool
		want      []string
	}{
		{3, 50, true, []string{"192.0.2.9", "203.0.113.0/24"}},
		{50, 3, false, []string{"192.0.2.9", "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}},
	} {
		s := ipTree(t)
		parsed(t, s, "A_v4", "203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4\n192.0.2.9\n")
		settings := ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)
		settings["policy/ip"] = map[string]any{"max": true, "maxLimit": tc.max, "dMax": tc.dmaxOn, "dMaxLimit": tc.dmax,
			"countryWhitelist": []any{map[string]any{"code": "CN"}}, "countryWhitelistAction": "ignore", "countryBlacklistAction": "block"}
		build(t, s, IPInput{Settings: settings})
		if got := body(t, s.Store, "ip-set/A/ipv4"); !slices.Equal(got, tc.want) {
			t.Errorf("Max %d, dMax %d: A = %q, want %q", tc.max, tc.dmax, got, tc.want)
		}
	}
}

// WHEN policy/ip selects the deny class for the Uber aggregates THEN the deny aggregate of each family is published,
// and no other class's.
func TestTheUberSelectionComesFromTheSettings(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	settings := ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)
	settings["policy/ip"] = map[string]any{"aggregates": []any{map[string]any{"class": "deny"}}}
	out := build(t, s, IPInput{Settings: settings})
	var ids []string
	for _, r := range out.Resources {
		ids = append(ids, r.ID)
	}
	if want := []string{"ip-aggregate/deny/ipv4", "ip-aggregate/deny/ipv6", "ip-set/A/ipv4"}; !slices.Equal(ids, want) {
		t.Fatalf("resources %q, want %q", ids, want)
	}
	if got := body(t, s.Store, "ip-aggregate/deny/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("the deny aggregate = %q", got)
	}
}

// WHEN group B leaves the settings THEN its list deny/B_v4.txt is deleted, as today's orphan prune deletes a class folder's
// list that no configured list names; A's stays.
func TestTheListOfADepartedGroupIsDeleted(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	parsed(t, s, "B_v4", "198.51.100.1\n")
	build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A"), group("B", "Deny_Both", "deny", "B")}, nil)})
	gone := filepath.Join(s.Folders["deny"], "B_v4.txt")
	if _, err := os.Stat(gone); err != nil {
		t.Fatalf("before: %v", err)
	}
	build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)})
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Errorf("B_v4.txt is still there (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(s.Folders["deny"], "A_v4.txt")); err != nil {
		t.Errorf("A_v4.txt: %v", err)
	}
}

// WHEN a feed's list name is the name of a set the loop builds (a header pfB_Africa beside the continent pfB_Africa_v4)
// THEN the feed is refused with an issue, the continent's list is never overwritten, and the continent's set is published.
func TestAFeedNamedAsAGeneratedListIsRefused(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "pfB_Africa_v4", "192.0.2.1\n")
	continent := filepath.Join(s.Folders["deny"], "pfB_Africa_v4.txt")
	touch(t, continent, "198.51.100.0/24\n")
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("Mine", "Deny_Both", "deny", "pfB_Africa")}, nil),
		GeoSets: []GeoSet{{Alias: "pfB_Africa_v4", Group: "Africa", Family: "ipv4", Action: "Deny_Both", ListClass: "deny", Path: continent, Changed: true}}})
	if b, _ := os.ReadFile(continent); string(b) != "198.51.100.0/24\n" {
		t.Errorf("the continent's list = %q, overwritten", b)
	}
	if got := body(t, s.Store, "ip-set/Africa/ipv4"); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("Africa = %q, want the continent's", got)
	}
	if got := body(t, s.Store, "ip-set/Mine/ipv4"); len(got) != 0 {
		t.Errorf("Mine = %q, want the refused feed left out", got)
	}
	found := false
	for _, i := range out.Issues {
		found = found || strings.Contains(i.Resource, "pfB_Africa_v4") && i.Code == "list_name_taken"
	}
	if !found {
		t.Errorf("issues = %+v, want list_name_taken for pfB_Africa_v4", out.Issues)
	}
}

// WHEN two configured groups map to one id THEN the second gets an issue that says a configured group holds the id, not
// that the Core Updater built it.
func TestTheIDTakenIssueNamesWhoTookTheID(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	parsed(t, s, "B_v4", "198.51.100.1\n")
	out := build(t, s, IPInput{Settings: ipSettings([]any{group("Same", "Deny_Both", "deny", "A"), group("Same", "Deny_Both", "deny", "B")}, nil)})
	if len(out.Issues) != 1 || out.Issues[0].Code != "set_id_taken" || strings.Contains(out.Issues[0].Message, "builds itself") ||
		!strings.Contains(out.Issues[0].Message, "group") {
		t.Errorf("issues = %+v, want one set_id_taken naming another configured group", out.Issues)
	}
}
