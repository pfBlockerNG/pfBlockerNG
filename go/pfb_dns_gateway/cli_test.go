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
	cfg, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		listen: []string{"127.0.0.1"}, port: 53, upstream: "127.0.0.1:5353", timeout: 5 * time.Second,
		unboundConf: "/var/unbound/unbound.conf", moduleDir: "/var/unbound", logDir: "/var/log/pfblockerng",
		tlsPEM: "/var/etc/pfb_dns/tls.pem", ctlSocket: "/var/run/pfb_dns/ctl.sock", dotPort: 853, dohPort: 4443, doqPort: 853,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("defaults:\n got  %+v\n want %+v", cfg, want)
	}
}

func TestConfigEveryFlag(t *testing.T) {
	cfg, err := parse(t,
		"--listen", "192.0.2.1", "--listen", "::1", "--port", "5300", "--upstream", "[::1]:5454",
		"--timeout", "2500ms", "--unbound-conf", "/tmp/unbound.conf", "--user", "unbound", "--module-dir", "/tmp/module", "--log-dir", "/tmp/logs")
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		listen: []string{"192.0.2.1", "::1"}, port: 5300, upstream: "[::1]:5454", timeout: 2500 * time.Millisecond,
		unboundConf: "/tmp/unbound.conf", user: "unbound", moduleDir: "/tmp/module", logDir: "/tmp/logs",
		tlsPEM: "/var/etc/pfb_dns/tls.pem", ctlSocket: "/var/run/pfb_dns/ctl.sock", dotPort: 853, dohPort: 4443, doqPort: 853,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("flags:\n got  %+v\n want %+v", cfg, want)
	}
}

func TestConfigPortZeroAndSingleDashFlags(t *testing.T) {
	cfg, err := parse(t, "-port", "0", "-listen", "127.0.0.1")
	if err != nil || cfg.port != 0 || !reflect.DeepEqual(cfg.listen, []string{"127.0.0.1"}) {
		t.Fatalf("got port=%d listen=%v err=%v, want port 0 (one port per address) and one listener", cfg.port, cfg.listen, err)
	}
}

// Usage errors (exit 2): there is no argument but flags, and every value is checked before anything is bound.
func TestConfigRejectsBadUsage(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"a positional argument":           {[]string{"extra"}, `unexpected argument "extra"`},
		"a retired decider command":       {[]string{"--port", "53", "--", "/bin/true"}, `unexpected argument "/bin/true"`},
		"a retired decider command, bare": {[]string{"--", "decider", "--no-module"}, `unexpected argument "decider"`},
		"unknown flag":                    {[]string{"--frobnicate"}, "frobnicate"},
		"the retired decision fd flag":    {[]string{"--decision-fd", "3"}, "decision-fd"},
		"port too large":                  {[]string{"--port", "65536"}, "port"},
		"negative port":                   {[]string{"--port", "-1"}, "port"},
		"port not a number":               {[]string{"--port", "http"}, "port"},
		"upstream without a port":         {[]string{"--upstream", "127.0.0.1"}, "upstream"},
		"upstream without a host":         {[]string{"--upstream", ":5353"}, "upstream"},
		"upstream port 0":                 {[]string{"--upstream", "127.0.0.1:0"}, "upstream"},
		"upstream port too large":         {[]string{"--upstream", "127.0.0.1:65536"}, "upstream"},
		"zero timeout":                    {[]string{"--timeout", "0s"}, "timeout"},
		"negative timeout":                {[]string{"--timeout", "-1s"}, "timeout"},
		"timeout not a duration":          {[]string{"--timeout", "five"}, "timeout"},
		"empty listen address":            {[]string{"--listen", ""}, "listen"},
		"empty unbound conf":              {[]string{"--unbound-conf", ""}, "unbound-conf"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if cfg, err := parse(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}

// pfB-DNS's modes (issue #3513): the gateway takes the flags of the Python proxy that decide what its decider does; they are
// the options the decider boots with.
func TestConfigTakesTheModeFlagsAndTheModuleDir(t *testing.T) {
	cases := map[string]struct {
		flags                        []string
		noModule, observer, replyLog bool
	}{
		"no flags: the module, no observer":  {nil, false, false, false},
		"DNSBL off":                          {[]string{"--no-module"}, true, false, false},
		"DNSBL off, replies logged":          {[]string{"--no-module", "--reply-log"}, true, false, true},
		"DNSBL on, upstream blocks reported": {[]string{"--observer"}, false, true, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := parse(t, append(slices.Clone(c.flags), "--module-dir", "/some/dir")...)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.moduleDir != "/some/dir" || cfg.noModule != c.noModule || cfg.observer != c.observer || cfg.replyLog != c.replyLog {
				t.Fatalf("got moduleDir=%q noModule=%v observer=%v replyLog=%v, want /some/dir %v %v %v", cfg.moduleDir, cfg.noModule, cfg.observer, cfg.replyLog, c.noModule, c.observer, c.replyLog)
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
			if cfg, err := parse(t, c.flags...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}

// issue #3583, as issue #3694 changed it: --ddr turns DDR on and names --dns-name; --ddr-doh-443 leaves the port out of the DoH
// record and needs --ddr. PHP is the primary trust boundary; these are the gateway's own checks, so a bad flag is a usage
// error and never a broken record.
func TestConfigDDRFlagsAreParsedAndOffByDefault(t *testing.T) {
	cases := map[string]struct {
		flags  []string
		name   string
		ddr    bool
		doh443 bool
	}{
		"off by default":                    {nil, "", false, false},
		"--ddr and the name":                {[]string{"--dns-name", "fw.example.lan", "--ddr"}, "fw.example.lan", true, false},
		"the name with a trailing dot":      {[]string{"--dns-name", "fw.example.lan.", "--ddr"}, "fw.example.lan.", true, false},
		"--ddr, the name and --ddr-doh-443": {[]string{"--dns-name", "fw.example.lan", "--ddr", "--ddr-doh-443", "192.0.2.1"}, "fw.example.lan", true, true},
		"--ddr-doh-443 before --ddr":        {[]string{"--ddr-doh-443", "192.0.2.1", "--ddr", "--dns-name", "fw.example.lan"}, "fw.example.lan", true, true},
		"the name alone is not DDR":         {[]string{"--dns-name", "fw.example.lan"}, "fw.example.lan", false, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := parse(t, slices.Clone(c.flags)...)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(cfg.ddrDoH443) > 0; cfg.dnsName != c.name || cfg.ddr != c.ddr || got != c.doh443 {
				t.Fatalf("got dnsName=%q ddr=%v ddrDoH443=%q, want dnsName=%q ddr=%v with --ddr-doh-443 %v", cfg.dnsName, cfg.ddr, cfg.ddrDoH443, c.name, c.ddr, c.doh443)
			}
		})
	}
}

func TestConfigRejectsBadDDRUsage(t *testing.T) {
	cases := map[string]struct {
		flags []string
		want  string // the flag the error names
	}{
		"--ddr-doh-443 without --ddr":      {[]string{"--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443"},
		"--ddr-doh-443 with an empty name": {[]string{"--dns-name", "", "--ddr-doh-443", "192.0.2.1"}, "--ddr-doh-443"},
		"--ddr without a name":             {[]string{"--ddr"}, "--ddr needs --dns-name"},
		"name with an empty label":         {[]string{"--dns-name", "fw..lan", "--ddr"}, `--dns-name "`},
		"name with a leading dot":          {[]string{"--dns-name", ".fw.lan", "--ddr"}, `--dns-name "`},
		"name with two trailing dots":      {[]string{"--dns-name", "fw.lan..", "--ddr"}, `--dns-name "`},
		"the root as the name":             {[]string{"--dns-name", ".", "--ddr"}, `--dns-name "`},
		"name with a label over 63 bytes":  {[]string{"--dns-name", strings.Repeat("a", 64) + ".lan", "--ddr"}, `--dns-name "`},
		"name over 253 characters":         {[]string{"--dns-name", strings.Repeat(strings.Repeat("a", 60)+".", 4) + "example.lan", "--ddr"}, `--dns-name "`},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if cfg, err := parse(t, slices.Clone(c.flags)...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got cfg=%+v err=%v, want an error mentioning %q", cfg, err, c.want)
			}
		})
	}
}
