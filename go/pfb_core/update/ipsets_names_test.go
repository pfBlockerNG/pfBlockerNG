package update

import (
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// Parity quirk (#4220 review, kept on purpose): with dedup on, a row a group's feed and its custom list both hold belongs to
// the feed, which comes first in the recompute's member order (today's custom row is appended after the group's rows,
// pfblockerng_apply.inc:1828), and the suppression list then removes it from the feed, while the custom list, read beside
// the suppression pass, no longer holds it (pfblockerng_apply.inc:4473-4520). The address ends in no list, as today.
func TestASharedRowSuppressedFromItsFeedIsLostFromTheCustomListAsToday(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n198.51.100.1\n")
	parsed(t, s, "G_custom_v4", "192.0.2.1\n")
	g := group("G", "Deny_Both", "deny", "A")
	g["customList"] = "192.0.2.1"
	settings := ipSettings([]any{g}, nil)
	settings["policy/ip"] = map[string]any{"dedup": true, "suppressionV4": []any{map[string]any{"cidr": "192.0.2.0/24"}}}
	build(t, s, IPInput{Settings: settings})
	if got := body(t, s.Store, "ip-set/G/ipv4"); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Errorf("G = %q, want only 198.51.100.1: the shared row is lost, as today", got)
	}
}

// WHEN a deny member keeps its name and its list but becomes a group's custom list (no longer suppressed) THEN the change
// counts as a changed member, and the set holds the row suppression took from it before.
func TestAMemberThatBecomesACustomListIsBuiltAgainUnsuppressed(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "X_custom_v4", "192.0.2.1\n")
	policy := map[string]any{"suppressionV4": []any{map[string]any{"cidr": "192.0.2.0/24"}}}
	before := ipSettings([]any{group("X", "Deny_Both", "deny", "X_custom")}, nil)
	before["policy/ip"] = policy
	build(t, s, IPInput{Settings: before})
	if got := body(t, s.Store, "ip-set/X/ipv4"); len(got) != 0 {
		t.Fatalf("before: X = %q, want the feed's row suppressed", got)
	}
	custom := map[string]any{"name": "X", "action": "Deny_Both", "listClass": "deny", "customList": "192.0.2.1"}
	after := ipSettings([]any{custom}, nil)
	after["policy/ip"] = policy
	build(t, s, IPInput{Settings: after})
	if got := body(t, s.Store, "ip-set/X/ipv4"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("after: X = %q, want the custom list's row, unsuppressed", got)
	}
}

// WHEN a feed takes the list name of DNSBLIP or of a continent, of either family, though the caller supplies no DNSBLIP and
// no continent set THEN the feed is still left out with list_name_taken: those names are reserved whatever is supplied.
func TestTheGeneratedListNamesAreReservedWhetherOrNotTheirSetsAreSupplied(t *testing.T) {
	for _, header := range []string{"DNSBLIP", "pfB_Africa", "pfB_Top"} {
		for _, family := range []string{"ipv4", "ipv6"} {
			s := ipTree(t)
			name := header + "_" + short(family)
			parsed(t, s, name, map[string]string{"ipv4": "192.0.2.1\n", "ipv6": "2001:db8::1\n"}[family])
			groups := []any{group("Mine", "Deny_Both", "deny", header)}
			var settings map[string]map[string]any
			if family == "ipv4" {
				settings = ipSettings(groups, nil)
			} else {
				settings = ipSettings(nil, groups)
			}
			out := build(t, s, IPInput{Settings: settings})
			if got := body(t, s.Store, "ip-set/Mine/"+family); len(got) != 0 {
				t.Errorf("%s: Mine = %q, want the feed left out", name, got)
			}
			if !slices.ContainsFunc(out.Issues, func(i apply.Issue) bool {
				return i.Code == "list_name_taken" && i.Resource == "feed/"+family+":"+name
			}) {
				t.Errorf("%s: issues = %+v, want list_name_taken", name, out.Issues)
			}
		}
	}
}
