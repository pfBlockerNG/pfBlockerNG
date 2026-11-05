package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: what the flags are parsed to, and what a LOCAL=ADDR[,ADDR] value means: the one syntax of --dns-name-answer
// and of a line of the address table verb.

func TestConfigDNSNameFlagsAreParsedAndOffByDefault(t *testing.T) {
	longest := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61) // 253 characters
	cases := map[string]struct {
		flags   []string
		name    string
		ddr     bool
		doh443  bool
		answers []string
	}{
		"off by default":                     {nil, "", false, false, nil},
		"an empty name is off, not an error": {[]string{"--dns-name", ""}, "", false, false, nil},
		"name without a trailing dot":        {[]string{"--dns-name", "fw.example.lan"}, "fw.example.lan", false, false, nil},
		"name with a trailing dot":           {[]string{"--dns-name", "fw.example.lan."}, "fw.example.lan.", false, false, nil},
		"name in mixed case":                 {[]string{"--dns-name", "FW.Example.Lan"}, "FW.Example.Lan", false, false, nil},
		"the longest name (253 characters)":  {[]string{"--dns-name", longest}, longest, false, false, nil},
		"--ddr with the name":                {[]string{"--dns-name", "fw.example.lan", "--ddr"}, "fw.example.lan", true, false, nil},
		"--ddr before the name":              {[]string{"--ddr", "--dns-name", "fw.example.lan"}, "fw.example.lan", true, false, nil},
		"--ddr and --ddr-doh-443":            {[]string{"--dns-name", "fw.example.lan", "--ddr", "--ddr-doh-443", "192.0.2.1"}, "fw.example.lan", true, true, nil},
		"--ddr-doh-443 before --ddr":         {[]string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1", "--ddr"}, "fw.example.lan", true, true, nil},
		"answers, each flag its own value":   {[]string{"--dns-name", "fw.example.lan", "--dns-name-answer", "10.0.0.1=10.0.0.1,2001:db8::1", "--dns-name-answer", "10.0.0.53=10.0.0.53"}, "fw.example.lan", false, false, []string{"10.0.0.1=10.0.0.1,2001:db8::1", "10.0.0.53=10.0.0.53"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...)
			if err != nil {
				t.Fatal(err)
			}
			if has443 := len(cfg.ddrDoH443) > 0; cfg.dnsName != c.name || cfg.ddr != c.ddr || has443 != c.doh443 || !slices.Equal(cfg.nameAnswers, c.answers) {
				t.Fatalf("got dnsName=%q ddr=%v ddrDoH443=%q answers=%q, want %q %v with --ddr-doh-443 %v and %q", cfg.dnsName, cfg.ddr, cfg.ddrDoH443, cfg.nameAnswers, c.name, c.ddr, c.doh443, c.answers)
			}
		})
	}
}

// goodNameValue is one LOCAL=ADDR[,ADDR] value and what a query for the name is answered when it reached `at` (A, AAAA); an
// empty address is local NODATA for that family.
type goodNameValue struct{ value, at, a, aaaa string }

var goodNameValues = map[string]goodNameValue{
	"both families":                          {"10.0.0.1=10.0.0.1,2001:db8:1::1", "10.0.0.1", "10.0.0.1", "2001:db8:1::1"},
	"IPv6 first":                             {"10.0.0.1=2001:db8:1::1,10.0.0.9", "10.0.0.1", "10.0.0.9", "2001:db8:1::1"},
	"IPv4 only":                              {"10.0.0.1=10.0.0.9", "10.0.0.1", "10.0.0.9", ""},
	"IPv6 only on an IPv6 LOCAL":             {"2001:db8::53=2001:db8::54", "2001:db8::53", "", "2001:db8::54"},
	"LOCAL need not be among the addresses":  {"10.0.0.1=192.0.2.5,2001:db8::5", "10.0.0.1", "192.0.2.5", "2001:db8::5"},
	"an IPv4-mapped LOCAL is the IPv4 one":   {"::ffff:10.0.0.1=10.0.0.1", "10.0.0.1", "10.0.0.1", ""},
	"an IPv4-mapped address is the IPv4 one": {"10.0.0.1=::ffff:192.0.2.5", "10.0.0.1", "192.0.2.5", ""},
	"a link-local LOCAL without a zone":      {"fe80::1=10.0.0.1", "fe80::1", "10.0.0.1", ""},
}

// requireValueAnswers asks the name, A and AAAA, as ask would be asked of a query that reached v.at, and requires v's answers; an
// address the value does not name is never answered. ask returns nil for a query that is the decider's.
func requireValueAnswers(t *testing.T, ask func(local string, wire []byte) []byte, v goodNameValue) {
	t.Helper()
	for _, c := range []struct {
		typ  dnsmessage.Type
		want string
	}{{dnsmessage.TypeA, v.a}, {dnsmessage.TypeAAAA, v.aaaa}} {
		query := nameQuery(t, nameFQDN, c.typ)
		reply := ask(v.at, query)
		if c.want == "" {
			requireNameNODATA(t, query, reply)
		} else if reply == nil {
			t.Fatalf("%s: %v on %s got no reply, want %s", v.value, c.typ, v.at, c.want)
		} else {
			requireNameAnswer(t, query, reply, nameFQDN, c.want)
		}
		if reply := ask("10.99.99.99", query); reply != nil {
			t.Fatalf("%s: %v on an address the value does not name got the reply %x", v.value, c.typ, reply)
		}
	}
}

func TestNameAnswerValuesOfTheFlagMeanWhatTheContractSays(t *testing.T) {
	for label, v := range goodNameValues {
		t.Run(label, func(t *testing.T) {
			names := mustNames(t, "fw.example.lan", v.value)
			requireValueAnswers(t, func(local string, wire []byte) []byte {
				return names.answer(wire, netip.MustParseAddr(local), true)
			}, v)
		})
	}
	t.Run("several flags are several entries", func(t *testing.T) {
		names := mustNames(t, "fw.example.lan", "10.0.0.1=10.0.0.1", "10.0.0.2=10.0.0.2")
		for local, want := range map[string]string{"10.0.0.1": "10.0.0.1", "10.0.0.2": "10.0.0.2"} {
			query := nameQuery(t, nameFQDN, dnsmessage.TypeA)
			requireNameAnswer(t, query, names.answer(query, netip.MustParseAddr(local), true), nameFQDN, want)
		}
	})
}
