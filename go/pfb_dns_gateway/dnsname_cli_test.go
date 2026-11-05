package main

import (
	"slices"
	"strings"
	"testing"
)

// issue #3694: --dns-name NAME is DDR's target and the one name the gateway answers A and AAAA for; --ddr is a bool that needs
// it; --dns-name-answer LOCAL=ADDR[,ADDR] says what a query that reached LOCAL is answered. PHP is the primary trust
// boundary; these are the gateway's own checks, so a bad flag is a usage error and never a wrong answer.

// badNameValues are LOCAL=ADDR[,ADDR] values that are errors, wherever the syntax is read: the flag, and a line of the
// address table verb.
var badNameValues = map[string]string{
	"no LOCAL":           "=1.2.3.4",
	"no equals sign":     "10.0.0.1",
	"empty":              "",
	"two IPv4 addresses": "1.2.3.4=1.2.3.4,5.6.7.8",
	"two IPv6 addresses": "10.0.0.1=2001:db8::1,2001:db8::2",
	"two addresses of one family, one of them IPv4-mapped": "10.0.0.1=1.2.3.4,::ffff:5.6.7.8",
	"a zone on LOCAL":                 "fe80::1%em0=1.2.3.4",
	"a zone on an address":            "10.0.0.1=fe80::1%em0",
	"a space before LOCAL":            " 10.0.0.1=1.2.3.4",
	"spaces around the equals sign":   "10.0.0.1 = 1.2.3.4",
	"a space after the comma":         "10.0.0.1=1.2.3.4, 2001:db8::1",
	"a trailing comma":                "10.0.0.1=1.2.3.4,",
	"an empty address between commas": "10.0.0.1=1.2.3.4,,2001:db8::1",
	"a name instead of an address":    "10.0.0.1=example.lan",
	"a prefix as LOCAL":               "10.0.0.0/24=1.2.3.4",
	"a second equals sign":            "10.0.0.1=1.2.3.4=5.6.7.8",
	"a carriage return at the end":    "10.0.0.1=1.2.3.4\r",
	"a tab":                           "10.0.0.1=1.2.3.4\t",
	"a leading zero":                  "10.0.0.1=01.2.3.4",
}

func TestConfigRejectsBadDNSNameUsage(t *testing.T) {
	const answer = "10.0.0.1=10.0.0.1"
	cases := map[string]struct {
		flags []string
		want  string // what the error says
	}{
		"--ddr without a name":                                 {[]string{"--ddr"}, "--ddr needs --dns-name"},
		"--ddr with an empty name":                             {[]string{"--dns-name", "", "--ddr"}, "--ddr needs --dns-name"},
		"an answer without a name":                             {[]string{"--dns-name-answer", answer}, "--dns-name-answer needs --dns-name"},
		"an answer with an empty name":                         {[]string{"--dns-name", "", "--dns-name-answer", answer}, "--dns-name-answer needs --dns-name"},
		"--ddr-doh-443 without --ddr":                          {[]string{"--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443 needs --ddr"},
		"--ddr-doh-443 with a name, without --ddr":             {[]string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443 needs --ddr"},
		"--ddr NAME, the old form, is not a flag with a value": {[]string{"--ddr", "fw.example.lan", "--dns-name", "fw.example.lan"}, "unexpected argument"},
		"name with an empty label":                             {[]string{"--dns-name", "fw..lan"}, `--dns-name "`},
		"name with a leading dot":                              {[]string{"--dns-name", ".fw.lan"}, `--dns-name "`},
		"name with two trailing dots":                          {[]string{"--dns-name", "fw.lan.."}, `--dns-name "`},
		"the root as the name":                                 {[]string{"--dns-name", "."}, `--dns-name "`},
		"name with a label over 63 bytes":                      {[]string{"--dns-name", strings.Repeat("a", 64) + ".lan"}, `--dns-name "`},
		"name over 253 characters":                             {[]string{"--dns-name", strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example.lan"}, `--dns-name "`},
		"the same LOCAL twice":                                 {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", "10.0.0.1=10.0.0.1", "--dns-name-answer", "10.0.0.1=10.0.0.2"}, `--dns-name-answer "`},
		"the same LOCAL twice, once IPv4-mapped":               {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", "::ffff:10.0.0.1=10.0.0.1", "--dns-name-answer", "10.0.0.1=10.0.0.2"}, `--dns-name-answer "`},
		"a good answer then a bad one":                         {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", answer, "--dns-name-answer", "10.0.0.2=bad"}, `--dns-name-answer "`},
	}
	for label, value := range badNameValues {
		cases["answer value: "+label] = struct {
			flags []string
			want  string
		}{[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", value}, `--dns-name-answer "`}
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}
