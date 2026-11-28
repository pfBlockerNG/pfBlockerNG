package spoa

import (
	"net/netip"

	"github.com/gaissmai/bart"
)

// RadixTree is an immutable IPv4/IPv6 longest-prefix-match routing table backed by github.com/gaissmai/bart.
// Build via RadixBuilder and publish atomically with atomic.Pointer[RadixTree[T]].
type RadixTree[T any] struct {
	tbl *bart.Table[T]
}

// RadixBuilder accumulates prefixes and produces an immutable RadixTree.
type RadixBuilder[T any] struct {
	tbl *bart.Table[T]
}

// NewRadixBuilder returns an empty builder.
func NewRadixBuilder[T any]() *RadixBuilder[T] {
	return &RadixBuilder[T]{tbl: new(bart.Table[T])}
}

// Insert adds prefix -> val. If the exact prefix already exists, the first inserted value is kept unless overwrite is true.
func (b *RadixBuilder[T]) Insert(p netip.Prefix, val T, overwrite bool) {
	if !p.IsValid() {
		return
	}
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a = a.Unmap()
		bits -= 96
	}
	p = netip.PrefixFrom(a, bits).Masked()
	if !overwrite {
		if _, exists := b.tbl.Get(p); exists {
			return
		}
	}
	b.tbl.Insert(p, val)
}

// Build finalizes the immutable RadixTree. The builder must not be used after Build.
func (b *RadixBuilder[T]) Build() *RadixTree[T] {
	return &RadixTree[T]{tbl: b.tbl}
}

// Counts returns the number of distinct IPv4 and IPv6 prefixes stored in the tree.
func (t *RadixTree[T]) Counts() (v4, v6 int) {
	if t == nil || t.tbl == nil {
		return 0, 0
	}
	return t.tbl.Size4(), t.tbl.Size6()
}

// Lookup returns the longest-prefix match for addr, or the zero value and false if none matches.
func (t *RadixTree[T]) Lookup(addr netip.Addr) (T, bool) {
	var zero T
	if t == nil || t.tbl == nil || !addr.IsValid() {
		return zero, false
	}
	return t.tbl.Lookup(addr.Unmap())
}
