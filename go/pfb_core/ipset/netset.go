package ipset

import (
	"net/netip"

	"go4.org/netipx"
)

// addrSet is a set of addresses of one family built from inclusive spans. It is the only place the package names netipx.
type addrSet struct {
	b   netipx.IPSetBuilder
	set *netipx.IPSet // what freeze last built
}

// span is an inclusive address range.
type span struct{ lo, hi netip.Addr }

func (s *addrSet) add(lo, hi netip.Addr) { s.b.AddRange(netipx.IPRangeFrom(lo, hi)) }

// remove takes effect on what was added before it.
func (s *addrSet) remove(lo, hi netip.Addr) { s.b.RemoveRange(netipx.IPRangeFrom(lo, hi)) }

// prefixes is the least list of prefixes, in address order, whose union is exactly the set.
func (s *addrSet) prefixes() []netip.Prefix {
	// The spans are valid by construction, so building cannot fail.
	set, _ := s.b.IPSet()
	return set.Prefixes()
}

// freeze fixes the set as it stands for contains.
func (s *addrSet) freeze() { s.set, _ = s.b.IPSet() }

// contains reports whether the frozen set holds a.
func (s *addrSet) contains(a netip.Addr) bool { return s.set != nil && s.set.Contains(a) }

// prefixSpan is the addresses of a prefix, host bits cleared.
func prefixSpan(p netip.Prefix) span {
	r := netipx.RangeOfPrefix(p)
	return span{r.From(), r.To()}
}

// spans is the set as sorted, disjoint spans that touch nothing.
func (s *addrSet) spans() []span {
	set, _ := s.b.IPSet()
	ranges := set.Ranges()
	out := make([]span, len(ranges))
	for i, r := range ranges {
		out[i] = span{r.From(), r.To()}
	}
	return out
}
