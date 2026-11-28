package spoa

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRadixTreeIPv4AndIPv6LPM(t *testing.T) {
	b := NewRadixBuilder[string]()
	b.Insert(netip.MustParsePrefix("0.0.0.0/0"), "default-v4", false)
	b.Insert(netip.MustParsePrefix("10.0.0.0/8"), "rfc1918", false)
	b.Insert(netip.MustParsePrefix("10.1.2.0/24"), "subnet", false)
	b.Insert(netip.MustParsePrefix("10.1.2.3/32"), "host", false)
	// Duplicate without overwrite keeps first; with overwrite replaces.
	b.Insert(netip.MustParsePrefix("10.1.2.3/32"), "ignored", false)
	b.Insert(netip.MustParsePrefix("192.0.2.0/24"), "first", false)
	b.Insert(netip.MustParsePrefix("192.0.2.0/24"), "replaced", true)

	b.Insert(netip.MustParsePrefix("2001:db8::/32"), "doc-v6", false)
	b.Insert(netip.MustParsePrefix("2001:db8:1::/48"), "sub-v6", false)
	b.Insert(netip.MustParsePrefix("2001:db8:1::42/128"), "host-v6", false)
	// 4-in-6 prefix maps into v4 trie.
	b.Insert(netip.MustParsePrefix("::ffff:198.51.100.0/120"), "mapped-v4", false)

	tree := b.Build()
	v4, v6 := tree.Counts()
	if v4 != 6 || v6 != 3 {
		t.Fatalf("Counts() = (%d, %d), want (6, 3)", v4, v6)
	}

	cases := []struct {
		ip   string
		want string
		ok   bool
	}{
		{"1.2.3.4", "default-v4", true},
		{"10.9.9.9", "rfc1918", true},
		{"10.1.2.99", "subnet", true},
		{"10.1.2.3", "host", true},
		{"192.0.2.5", "replaced", true},
		{"198.51.100.7", "mapped-v4", true},
		{"::ffff:10.1.2.3", "host", true},
		{"2001:db8::1", "doc-v6", true},
		{"2001:db8:1::1", "sub-v6", true},
		{"2001:db8:1::42", "host-v6", true},
		{"2606:4700::1", "", false},
	}
	for _, tc := range cases {
		got, ok := tree.Lookup(netip.MustParseAddr(tc.ip))
		if ok != tc.ok || got != tc.want {
			t.Errorf("Lookup(%s) = (%q, %v), want (%q, %v)", tc.ip, got, ok, tc.want, tc.ok)
		}
	}

	var nilTree *RadixTree[string]
	if _, ok := nilTree.Lookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Fatal("nil tree matched")
	}
	if gotV4, gotV6 := nilTree.Counts(); gotV4 != 0 || gotV6 != 0 {
		t.Fatalf("nil Counts() = (%d, %d), want (0, 0)", gotV4, gotV6)
	}
}

func TestRadixTreeConcurrentAtomicSwap(t *testing.T) {
	var ptr atomic.Pointer[RadixTree[int]]
	build := func(gen int) *RadixTree[int] {
		b := NewRadixBuilder[int]()
		b.Insert(netip.MustParsePrefix("203.0.113.0/24"), gen, false)
		return b.Build()
	}
	ptr.Store(build(1))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("203.0.113.42")
			for {
				select {
				case <-stop:
					return
				default:
					v, ok := ptr.Load().Lookup(ip)
					if !ok || v < 1 {
						t.Errorf("unexpected lookup result (%d, %v)", v, ok)
						return
					}
				}
			}
		}()
	}
	for gen := 2; gen <= 20; gen++ {
		ptr.Store(build(gen))
	}
	close(stop)
	wg.Wait()
}
