package main

import (
	"slices"
	"strings"
	"testing"
)

// issue #3694: --ddr-doh-443 ADDR (repeatable) is an address DDR advertises DoH on without a port, and --doh-listen-443 ADDR
// (repeatable) is an address DoH is also served on, on port 443. The per-family bool flags are gone. PHP is the primary trust
// boundary; these are the gateway's own checks, so a bad flag is a usage error and never a wrong record.

func TestConfigRejectsBadDoH443Usage(t *testing.T) {
	ddr := []string{"--dns-name", "fw.example.lan", "--ddr"}
	with := func(flags ...string) []string { return append(slices.Clone(ddr), flags...) }
	cases := map[string]struct {
		flags []string
		want  string // what the error says
	}{
		"--ddr-doh-443 without --ddr":                   {[]string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443 needs --ddr"},
		"--ddr-doh-443 with no name and no --ddr":       {[]string{"--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443 needs --ddr"},
		"--ddr-doh-443 with no address (the old bool)":  {with("--ddr-doh-443"), "ddr-doh-443"},
		"--ddr-doh-443 with an empty address":           {with("--ddr-doh-443", ""), `--ddr-doh-443 "`},
		"--ddr-doh-443 with a zone":                     {with("--ddr-doh-443", "fe80::1%em0"), `--ddr-doh-443 "`},
		"--ddr-doh-443 with a port":                     {with("--ddr-doh-443", "192.0.2.1:443"), `--ddr-doh-443 "`},
		"--ddr-doh-443 with a name":                     {with("--ddr-doh-443", "fw.example.lan"), `--ddr-doh-443 "`},
		"--ddr-doh-443 with two addresses in one value": {with("--ddr-doh-443", "192.0.2.1,192.0.2.2"), `--ddr-doh-443 "`},
		"--ddr-doh-443 with a space after the address":  {with("--ddr-doh-443", "192.0.2.1 "), `--ddr-doh-443 "`},
		"a good --ddr-doh-443 then a bad one":           {with("--ddr-doh-443", "192.0.2.1", "--ddr-doh-443", "192.0.2.1:443"), `--ddr-doh-443 "`},
		"--ddr-doh-4436, the retired IPv6 flag":         {with("--ddr-doh-4436"), "ddr-doh-4436"},
		"--doh-listen-443 with no address":              {[]string{"--doh-listen", "192.0.2.1", "--doh-listen-443"}, "doh-listen-443"},
		"--doh-listen-443 with an empty address":        {[]string{"--doh-listen", "192.0.2.1", "--doh-listen-443", ""}, "--doh-listen-443 must not be empty"},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}

func TestConfigAcceptsDoH443Flags(t *testing.T) {
	ddr := []string{"--dns-name", "fw.example.lan", "--ddr"}
	with := func(flags ...string) []string { return append(slices.Clone(ddr), flags...) }
	cases := map[string][]string{
		"one address":                              with("--ddr-doh-443", "192.0.2.1"),
		"an IPv6 address":                          with("--ddr-doh-443", "2001:db8::1"),
		"the IPv4-mapped spelling":                 with("--ddr-doh-443", "::ffff:192.0.2.1"),
		"several addresses":                        with("--ddr-doh-443", "192.0.2.1", "--ddr-doh-443", "2001:db8::1"),
		"the same address twice is harmless":       with("--ddr-doh-443", "192.0.2.1", "--ddr-doh-443", "192.0.2.1"),
		"--ddr-doh-443 before --ddr":               {"--ddr-doh-443", "192.0.2.1", "--dns-name", "fw.example.lan", "--ddr"},
		"--doh-listen-443 without ordinary DoH":    {"--doh-listen-443", "192.0.2.53"},
		"--doh-listen-443 beside another TLS kind": {"--dot-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53"},
		"--doh-listen-443 with --doh-listen":       {"--doh-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53"},
		"--doh-listen-443 before --doh-listen":     {"--doh-listen-443", "192.0.2.53", "--doh-listen", "192.0.2.1"},
		"several --doh-listen-443 addresses":       {"--doh-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53", "--doh-listen-443", "fd00:53:53:53:53:53:53:1"},
		"both flags":                               with("--doh-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53", "--ddr-doh-443", "192.0.2.1"),
	}
	for label, flags := range cases {
		t.Run(label, func(t *testing.T) {
			if cfg, err := parse(t, append(slices.Clone(flags), "--", "decider")...); err != nil {
				t.Fatalf("got cfg=%+v err=%v, want the flags accepted", cfg, err)
			}
		})
	}
}
