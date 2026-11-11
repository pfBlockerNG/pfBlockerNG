package main

import "testing"

// devel's readiness check takes at most five port digits (pfb_dns_proxy_listener_port: strlen <= 5) however many leading zeros
// they carry, so a longer spelling is not a supported upstream and the status omits it.
func TestStatusWireOmitsUpstreamPortLongerThanFiveDigits(t *testing.T) {
	for _, upstream := range []string{
		"127.0.0.1:000053", "127.0.0.1:000005353", "[::1]:0000065535", "127.0.0.1:0000000000000000000000001",
	} {
		t.Run(upstream, func(t *testing.T) {
			got := cliStatusObject(t, upstream)
			requireSnapshot(t, got)
			if v, ok := got["upstream"]; ok {
				t.Fatalf("upstream %v must be absent", v)
			}
		})
	}
}

// Five digits is the longest supported port spelling; its leading zeros are normalized.
func TestStatusWireNormalizesFivePortDigitSpellings(t *testing.T) {
	for upstream, applied := range map[string]string{
		"127.0.0.1:00053": "127.0.0.1:53",
		"127.0.0.1:05353": "127.0.0.1:5353",
		"[::1]:00001":     "[::1]:1",
	} {
		t.Run(upstream, func(t *testing.T) {
			got := cliStatusObject(t, upstream)
			requireSnapshot(t, got)
			if got["upstream"] != applied {
				t.Fatalf("applied upstream %v want %s", got["upstream"], applied)
			}
		})
	}
}
