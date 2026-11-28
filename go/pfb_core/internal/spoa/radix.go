package spoa

import "net/netip"

// RadixTree is an immutable IPv4/IPv6 binary trie supporting zero-allocation longest-prefix match.
// Build via RadixBuilder and publish atomically with atomic.Pointer[RadixTree[T]].
type RadixTree[T any] struct {
	v4      []radixNode[T]
	v6      []radixNode[T]
	countV4 int
	countV6 int
}

type radixNode[T any] struct {
	child [2]int32 // 0 = no child; root is index 0
	has   bool
	val   T
}

// RadixBuilder accumulates prefixes and produces an immutable RadixTree.
type RadixBuilder[T any] struct {
	v4      []radixNode[T]
	v6      []radixNode[T]
	countV4 int
	countV6 int
}

// NewRadixBuilder returns an empty builder.
func NewRadixBuilder[T any]() *RadixBuilder[T] {
	return &RadixBuilder[T]{
		v4: make([]radixNode[T], 1),
		v6: make([]radixNode[T], 1),
	}
}

// Insert adds prefix -> val. If the exact prefix already exists, the first inserted value is kept unless overwrite is true.
func (b *RadixBuilder[T]) Insert(p netip.Prefix, val T, overwrite bool) {
	if !p.IsValid() {
		return
	}
	a := p.Addr()
	bits := p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			// A v6 prefix shorter than /96 that contains ::ffff:0:0/96 stays in the v6 trie.
		} else {
			a = a.Unmap()
			bits -= 96
		}
	}
	p = netip.PrefixFrom(a, bits).Masked()
	if p.Addr().Is4() {
		b4 := p.Addr().As4()
		if insertBits(&b.v4, b4[:], p.Bits(), val, overwrite) {
			b.countV4++
		}
		return
	}
	b16 := p.Addr().As16()
	if insertBits(&b.v6, b16[:], p.Bits(), val, overwrite) {
		b.countV6++
	}
}

func insertBits[T any](nodes *[]radixNode[T], addr []byte, bits int, val T, overwrite bool) bool {
	cur := int32(0)
	for i := range bits {
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		next := (*nodes)[cur].child[bit]
		if next == 0 {
			next = int32(len(*nodes))
			*nodes = append(*nodes, radixNode[T]{})
			(*nodes)[cur].child[bit] = next
		}
		cur = next
	}
	node := &(*nodes)[cur]
	if node.has {
		if overwrite {
			node.val = val
		}
		return false
	}
	node.has = true
	node.val = val
	return true
}

// Build finalizes the immutable RadixTree. The builder must not be used after Build.
func (b *RadixBuilder[T]) Build() *RadixTree[T] {
	return &RadixTree[T]{
		v4:      b.v4,
		v6:      b.v6,
		countV4: b.countV4,
		countV6: b.countV6,
	}
}

// Counts returns the number of distinct IPv4 and IPv6 prefixes stored in the tree.
func (t *RadixTree[T]) Counts() (v4, v6 int) {
	if t == nil {
		return 0, 0
	}
	return t.countV4, t.countV6
}

// Lookup returns the longest-prefix match for addr, or the zero value and false if none matches.
func (t *RadixTree[T]) Lookup(addr netip.Addr) (T, bool) {
	var zero T
	if t == nil || !addr.IsValid() {
		return zero, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b4 := addr.As4()
		return lookupBits(t.v4, b4[:], 32)
	}
	b16 := addr.As16()
	return lookupBits(t.v6, b16[:], 128)
}

func lookupBits[T any](nodes []radixNode[T], addr []byte, maxBits int) (T, bool) {
	var best T
	found := false
	if len(nodes) == 0 {
		return best, false
	}
	cur := int32(0)
	if nodes[0].has {
		best = nodes[0].val
		found = true
	}
	for i := range maxBits {
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		next := nodes[cur].child[bit]
		if next == 0 {
			break
		}
		cur = next
		if nodes[cur].has {
			best = nodes[cur].val
			found = true
		}
	}
	return best, found
}
