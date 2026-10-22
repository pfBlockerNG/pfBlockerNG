package main

import (
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// parse runs parseConfig. --listen is required, so a test that does not care about it is given one.
func parse(t *testing.T, args ...string) (config, error) {
	t.Helper()
	if !slices.ContainsFunc(args, func(a string) bool { return a == "--listen" || a == "-listen" }) {
		args = append([]string{"--listen", "127.0.0.1"}, args...)
	}
	return parseConfig(args, io.Discard)
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := parse(t, "--", "/usr/local/pkg/pfblockerng/pfb_python.sh", "-u", "pfb_dns_proxy.py")
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		listen: []string{"127.0.0.1"}, port: 53, upstream: "127.0.0.1:5353", timeout: 5 * time.Second,
		unboundConf: "/var/unbound/unbound.conf", decider: []string{"/usr/local/pkg/pfblockerng/pfb_python.sh", "-u", "pfb_dns_proxy.py"},
		tlsPEM: "/var/etc/pfb_dns/tls.pem", ctlSocket: "/var/run/pfb_dns/ctl.sock", dotPort: 853, dohPort: 4443, doqPort: 853,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("defaults:\n got  %+v\n want %+v", cfg, want)
	}
}

func TestConfigEveryFlag(t *testing.T) {
	cfg, err := parse(t,
		"--listen", "192.0.2.1", "--listen", "::1", "--port", "5300", "--upstream", "[::1]:5454",
		"--timeout", "2500ms", "--unbound-conf", "/tmp/unbound.conf", "--user", "unbound",
		"--", "/usr/bin/python3", "-u", "decider.py", "--decision-fd", "3", "--module-dir", "/var/unbound")
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		listen: []string{"192.0.2.1", "::1"}, port: 5300, upstream: "[::1]:5454", timeout: 2500 * time.Millisecond,
		unboundConf: "/tmp/unbound.conf", user: "unbound", tlsPEM: "/var/etc/pfb_dns/tls.pem", ctlSocket: "/var/run/pfb_dns/ctl.sock", dotPort: 853, dohPort: 4443, doqPort: 853,
		// everything after `--` is the decider's, flags and all
		decider: []string{"/usr/bin/python3", "-u", "decider.py", "--decision-fd", "3", "--module-dir", "/var/unbound"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("flags:\n got  %+v\n want %+v", cfg, want)
	}
}

func TestConfigPortZeroAndSingleDashFlags(t *testing.T) {
	cfg, err := parse(t, "-port", "0", "-listen", "127.0.0.1", "--", "decider")
	if err != nil || cfg.port != 0 || !reflect.DeepEqual(cfg.listen, []string{"127.0.0.1"}) {
		t.Fatalf("got port=%d listen=%v err=%v, want port 0 (one port per address) and one listener", cfg.port, cfg.listen, err)
	}
}

// Usage errors (exit 2): the decider argv is required, and every value is checked before anything is bound.
func TestConfigRejectsBadUsage(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"no separator":                    {[]string{"--port", "53", "decider"}, "--"},
		"nothing after the separator":     {[]string{"--port", "53", "--"}, "decider"},
		"no arguments at all":             {nil, "--"},
		"positional before the separator": {[]string{"extra", "--", "decider"}, "extra"},
		"unknown flag":                    {[]string{"--frobnicate", "--", "decider"}, "frobnicate"},
		"port too large":                  {[]string{"--port", "65536", "--", "decider"}, "port"},
		"negative port":                   {[]string{"--port", "-1", "--", "decider"}, "port"},
		"port not a number":               {[]string{"--port", "http", "--", "decider"}, "port"},
		"upstream without a port":         {[]string{"--upstream", "127.0.0.1", "--", "decider"}, "upstream"},
		"upstream without a host":         {[]string{"--upstream", ":5353", "--", "decider"}, "upstream"},
		"upstream port 0":                 {[]string{"--upstream", "127.0.0.1:0", "--", "decider"}, "upstream"},
		"upstream port too large":         {[]string{"--upstream", "127.0.0.1:65536", "--", "decider"}, "upstream"},
		"zero timeout":                    {[]string{"--timeout", "0s", "--", "decider"}, "timeout"},
		"negative timeout":                {[]string{"--timeout", "-1s", "--", "decider"}, "timeout"},
		"timeout not a duration":          {[]string{"--timeout", "five", "--", "decider"}, "timeout"},
		"empty listen address":            {[]string{"--listen", "", "--", "decider"}, "listen"},
		"empty unbound conf":              {[]string{"--unbound-conf", "", "--", "decider"}, "unbound-conf"},
		"empty decider program":           {[]string{"--", ""}, "decider"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if cfg, err := parse(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}

// pfB-DNS's modes (issue #3513): the gateway takes the flags of the Python proxy that decide what its decider does, and
// hands them on, so the rc line has one set of mode flags whichever process serves.
func TestConfigHandsTheModeFlagsToTheDecider(t *testing.T) {
	base := []string{"/usr/bin/python3", "-u", "decider.py", "--decision-fd", "3", "--module-dir", "/var/unbound"}
	cases := map[string]struct {
		flags []string
		want  []string
	}{
		"no flags leave the decider argv as it was": {nil, nil},
		"DNSBL off":                          {[]string{"--no-module"}, []string{"--no-module"}},
		"DNSBL off, replies logged":          {[]string{"--no-module", "--reply-log"}, []string{"--no-module", "--reply-log"}},
		"DNSBL on, upstream blocks reported": {[]string{"--observer"}, []string{"--observer"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := parse(t, append(append(slices.Clone(c.flags), "--"), base...)...)
			if err != nil {
				t.Fatal(err)
			}
			if want := append(slices.Clone(base), c.want...); !slices.Equal(cfg.decider, want) {
				t.Fatalf("decider argv:\n got  %q\n want %q", cfg.decider, want)
			}
		})
	}
}

func TestConfigRejectsModeFlagsThatContradictEachOther(t *testing.T) {
	cases := map[string]struct {
		flags []string
		want  string
	}{
		"the observer needs the module":           {[]string{"--no-module", "--observer"}, "--observer"},
		"the reply log is for the no-module mode": {[]string{"--reply-log"}, "--reply-log"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}

// issue #3583: --ddr NAME turns DDR on; --ddr-doh-443 leaves the port out of the DoH record and needs --ddr. PHP is the
// primary trust boundary; these are the gateway's own checks, so a bad flag is a usage error and never a broken record.
func TestConfigDDRFlagsAreParsedAndOffByDefault(t *testing.T) {
	cases := map[string]struct {
		flags  []string
		ddr    string
		doh443 bool
	}{
		"off by default":                     {nil, "", false},
		"name without a trailing dot":        {[]string{"--ddr", "fw.example.lan"}, "fw.example.lan", false},
		"name with a trailing dot":           {[]string{"--ddr", "fw.example.lan."}, "fw.example.lan.", false},
		"name and --ddr-doh-443":             {[]string{"--ddr", "fw.example.lan", "--ddr-doh-443"}, "fw.example.lan", true},
		"--ddr-doh-443 before the name":      {[]string{"--ddr-doh-443", "--ddr", "fw.example.lan"}, "fw.example.lan", true},
		"the longest name (253 characters)":  {[]string{"--ddr", strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61)}, strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61), false},
		"an empty name is off, not an error": {[]string{"--ddr", ""}, "", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ddr != c.ddr || cfg.ddrDoH443 != c.doh443 {
				t.Fatalf("got ddr=%q doh443=%v, want ddr=%q doh443=%v", cfg.ddr, cfg.ddrDoH443, c.ddr, c.doh443)
			}
		})
	}
}

func TestConfigRejectsBadDDRUsage(t *testing.T) {
	cases := map[string]struct {
		flags []string
		want  string // the flag the error names
	}{
		"--ddr-doh-443 without --ddr":       {[]string{"--ddr-doh-443"}, "--ddr-doh-443"},
		"--ddr-doh-443 with an empty --ddr": {[]string{"--ddr", "", "--ddr-doh-443"}, "--ddr-doh-443"},
		"name with an empty label":          {[]string{"--ddr", "fw..lan"}, `--ddr "`},
		"name with a leading dot":           {[]string{"--ddr", ".fw.lan"}, `--ddr "`},
		"name with two trailing dots":       {[]string{"--ddr", "fw.lan.."}, `--ddr "`},
		"the root as the name":              {[]string{"--ddr", "."}, `--ddr "`},
		"name with a label over 63 bytes":   {[]string{"--ddr", strings.Repeat("a", 64) + ".lan"}, `--ddr "`},
		"name over 253 characters":          {[]string{"--ddr", strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example.lan"}, `--ddr "`},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}
