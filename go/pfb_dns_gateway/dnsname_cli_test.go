package main

import (
	"slices"
	"strings"
	"testing"
)

// issue #3694: --dns-name NAME is DDR's target and the one name the gateway answers A and AAAA for; --ddr is a bool that needs
// it; --dns-name-answer LOCAL=ADDR[,ADDR] says what a query that reached LOCAL is answered. PHP is the primary trust
// boundary; the gateway's own checks never give a wrong answer: what it cannot use is served without (issue #3848).

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

// issue #3848: a DNS name flag that cannot be built is no usage error. parseConfig takes it as given; start serves without the name
// (and without DDR) and the status names the loss (TestADNSNameOrDDRFlagThatCannotBeBuiltStartsTheGatewayWithoutIt).
func TestConfigAcceptsDNSNameFlagsThatCannotBeBuiltAndLeavesTheOutcomeToStart(t *testing.T) {
	const answer = "10.0.0.1=10.0.0.1"
	longName := strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example.lan"
	cases := map[string]struct {
		flags   []string
		dnsName string
		answers []string
	}{
		"--ddr without a name":                     {[]string{"--ddr"}, "", nil},
		"--ddr with an empty name":                 {[]string{"--dns-name", "", "--ddr"}, "", nil},
		"an answer without a name":                 {[]string{"--dns-name-answer", answer}, "", []string{answer}},
		"an answer with an empty name":             {[]string{"--dns-name", "", "--dns-name-answer", answer}, "", []string{answer}},
		"--ddr-doh-443 without --ddr":              {[]string{"--ddr-doh-443", "192.0.2.1"}, "", nil},
		"--ddr-doh-443 with a name, without --ddr": {[]string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"}, "fw.example.lan", nil},
		"name with an empty label":                 {[]string{"--dns-name", "fw..lan"}, "fw..lan", nil},
		"name with a leading dot":                  {[]string{"--dns-name", ".fw.lan"}, ".fw.lan", nil},
		"name with two trailing dots":              {[]string{"--dns-name", "fw.lan.."}, "fw.lan..", nil},
		"the root as the name":                     {[]string{"--dns-name", "."}, ".", nil},
		"name with a label over 63 bytes":          {[]string{"--dns-name", strings.Repeat("a", 64) + ".lan"}, strings.Repeat("a", 64) + ".lan", nil},
		"name over 253 characters":                 {[]string{"--dns-name", longName}, longName, nil},
		"the same LOCAL twice":                     {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", "10.0.0.1=10.0.0.1", "--dns-name-answer", "10.0.0.1=10.0.0.2"}, "fw.example.lan", []string{"10.0.0.1=10.0.0.1", "10.0.0.1=10.0.0.2"}},
		"the same LOCAL twice, once IPv4-mapped":   {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", "::ffff:10.0.0.1=10.0.0.1", "--dns-name-answer", "10.0.0.1=10.0.0.2"}, "fw.example.lan", []string{"::ffff:10.0.0.1=10.0.0.1", "10.0.0.1=10.0.0.2"}},
		"a good answer then a bad one":             {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", answer, "--dns-name-answer", "10.0.0.2=bad"}, "fw.example.lan", []string{answer, "10.0.0.2=bad"}},
	}
	for label, value := range badNameValues {
		cases["answer value: "+label] = struct {
			flags   []string
			dnsName string
			answers []string
		}{[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", value}, "fw.example.lan", []string{value}}
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			cfg, err := parse(t, slices.Clone(c.flags)...)
			if err != nil {
				t.Fatalf("got err=%v, want the flags accepted", err)
			}
			if cfg.dnsName != c.dnsName || !slices.Equal(cfg.nameAnswers, c.answers) {
				t.Fatalf("got dnsName=%q answers=%q, want %q %q", cfg.dnsName, cfg.nameAnswers, c.dnsName, c.answers)
			}
		})
	}
}

// The old `--ddr NAME` form is not a flag with a value: the name is a stray argument, which stays a usage error.
func TestConfigRejectsTheOldDDRNameForm(t *testing.T) {
	if cfg, err := parse(t, "--ddr", "fw.example.lan", "--dns-name", "fw.example.lan"); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("got cfg=%+v err=%v, want an error mentioning an unexpected argument", cfg, err)
	}
}
