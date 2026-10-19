package main

import "testing"

// hasTCPKeepalive finds option 11 in an OPT record, and says no for another option, for no OPT at all and for a
// message it cannot parse (the decider has its own checks for those).
func TestHasTCPKeepalive(t *testing.T) {
	plain := buildQuery(t, 0, "example.", true)
	for _, c := range []struct {
		name string
		wire []byte
		want bool
	}{
		{"no OPT", plain, false},
		{"keepalive", ednsQuery(t, "example.", ednsTCPKeepalive), true},
		{"padding", ednsQuery(t, "example.", ednsPadding), false},
		{"truncated after the question", plain[:len(plain)-1], false},
		{"not a DNS message", []byte{1, 2, 3}, false},
	} {
		if got := hasTCPKeepalive(c.wire); got != c.want {
			t.Errorf("%s: hasTCPKeepalive = %v, want %v", c.name, got, c.want)
		}
	}
}
