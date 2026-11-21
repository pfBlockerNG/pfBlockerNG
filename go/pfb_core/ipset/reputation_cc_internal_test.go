package ipset

import (
	"slices"
	"testing"
)

// The country list is matched entry by entry (#4149): an entry that only contains the offender's country, such as a proxy
// list "A1_US", does not exempt it.
var ccCases = []struct {
	cc     string
	exempt bool
}{
	{"US", true},
	{"DE,US", true},
	{"A1_US", false},
	{"DE,A2_US", false},
	{"DE", false},
}

func usGeo(string) string { return "US" }

func TestTheFeedStageMatchesWholeCountryEntries(t *testing.T) {
	rows := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for _, tc := range ccCases {
		got, _ := feedReputation(rows, PrepIn{Reputation: Reputation{Max: 2, CC: tc.cc, CCBlack: "block", Geo: usGeo}})
		want := []string{"198.51.100.0/24"}
		if tc.exempt {
			want = rows
		}
		if !slices.Equal(got, want) {
			t.Errorf("CC %q: members %q, want %q", tc.cc, got, want)
		}
	}
}

func TestTheRecomputeMatchesWholeCountryEntries(t *testing.T) {
	for _, tc := range ccCases {
		out := Recompute(RecomputeIn{Family: V4, Mode: RepDMax,
			Feeds: []Feed{{Name: "feed_v4", Text: "198.51.100.1\n198.51.100.2\n198.51.100.3\n"}},
			Rep:   Reputation{Max: 2, CC: tc.cc, CCBlack: "block", Geo: usGeo}})
		want := []string{"198.51.100.0/24"}
		if tc.exempt {
			want = []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
		}
		if got := out.Lists[0].Lines; !slices.Equal(got, want) {
			t.Errorf("CC %q: feed_v4 %q, want %q", tc.cc, got, want)
		}
	}
}
