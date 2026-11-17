package ipset

import (
	"slices"
	"testing"
)

// A later feed's /24 survives two earlier /25 halves, while a host inside them is pruned: a row is covered only by ONE
// earlier network at least as wide as itself (pfb_cidr_dedup with grepcidr 2.0, issue #3606), never by a union of narrower ones.
func TestRecomputeKeepsARowItsEarlierHalvesOnlyCoverTogether(t *testing.T) {
	out := Recompute(RecomputeIn{Family: V4, Dedup: true, Feeds: []Feed{
		{"X_v4", "1.2.3.0/25\n1.2.3.128/25\n"},
		{"Y_v4", "1.2.3.0/24\n1.2.3.7\n1.2.4.0/24\n"},
	}})
	if want, got := []string{"1.2.3.0/24", "1.2.4.0/24"}, out.Lists[1].Lines; !slices.Equal(want, got) {
		t.Errorf("Y_v4: expected %q, actual %q", want, got)
	}
}
