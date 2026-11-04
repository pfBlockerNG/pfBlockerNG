package main

import (
	"io"
	"strings"
	"testing"
)

func TestStandardPortFlagsEnableOnlyTheirOwnTransportWithoutOrdinaryAddresses(t *testing.T) {
	for _, flag := range []string{"listen-53", "dot-listen-853", "doh-listen-443", "doq-listen-853"} {
		for _, host := range []string{"192.0.2.53", "2001:db8::53", "::ffff:192.0.2.53"} {
			t.Run(flag+"/"+host, func(t *testing.T) {
				args := []string{"--" + flag, host, "--" + flag, host}
				if flag != "listen-53" {
					args = append(args, "--listen", "127.0.0.1")
				}
				if _, err := parseConfig(append(args, "--", "decider"), io.Discard); err != nil {
					t.Fatalf("valid standard-port listener --%s %s rejected: %v", flag, host, err)
				}
			})
		}
	}
}

func TestStandardPortFlagsRejectMalformedAddressesAtTheCliBoundary(t *testing.T) {
	for _, flag := range []string{"listen-53", "dot-listen-853", "doh-listen-443", "doq-listen-853"} {
		for _, host := range []string{"", "resolver.example", "fe80::1%em0", "192.0.2.53:853", "192.0.2.53,192.0.2.54", "192.0.2.53 ", "192.0.2.53\t", "'$(touch nope)'"} {
			t.Run(flag+"/"+host, func(t *testing.T) {
				_, err := parseConfig([]string{"--listen", "127.0.0.1", "--" + flag, host, "--", "decider"}, io.Discard)
				if err == nil || !strings.Contains(err.Error(), "--"+flag) {
					t.Fatalf("--%s %q: error %v, want a flag-specific invalid-address error", flag, host, err)
				}
			})
		}
	}
}
