package dnsbl

import "context"

// SafeSearchPolicy is policy/dnsbl's SafeSearch fields.
type SafeSearchPolicy struct {
	Enable  bool
	YouTube string
	DoH     bool
	DoHList []string
}

// Resolver answers a CNAME target's first A and AAAA address, "" for none.
type Resolver func(ctx context.Context, target string) (v4, v6 string)

// SafeSearchTable is a stub: sub-slice 9g's RED commit.
func SafeSearchTable(ctx context.Context, dir string, p SafeSearchPolicy, resolve Resolver) (rows []SafeSearch, refused []string) {
	return nil, nil
}
