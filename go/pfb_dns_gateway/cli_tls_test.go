package main

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestConfigTLSDefaults(t *testing.T) {
	cfg, err := parse(t, "--", "decider")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.dot || cfg.tlsPEM != "/var/unbound/pfb_dns_cert.pem" || cfg.dotPort != 853 || cfg.dohPort != 4443 || cfg.doqPort != 853 ||
		len(cfg.dohListen) != 0 || len(cfg.dohTrusted) != 0 || len(cfg.doqListen) != 0 {
		t.Fatalf("defaults: got dot=%v tls-pem=%q dot-port=%d doh-port=%d doq-port=%d doh-listen=%v doh-trusted=%v doq-listen=%v",
			cfg.dot, cfg.tlsPEM, cfg.dotPort, cfg.dohPort, cfg.doqPort, cfg.dohListen, cfg.dohTrusted, cfg.doqListen)
	}
}

func TestConfigTLSEveryFlag(t *testing.T) {
	cfg, err := parse(t,
		"--dot", "--dot-port", "8530", "--tls-pem", "/tmp/cert.pem",
		"--doh-listen", "192.0.2.1", "--doh-listen", "::1", "--doh-port", "8443",
		"--doh-trusted", "192.0.2.0/24", "--doh-trusted", "2001:db8::1",
		"--doq-listen", "192.0.2.2", "--doq-port", "8853",
		"--", "decider")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.dot || cfg.tlsPEM != "/tmp/cert.pem" || cfg.dotPort != 8530 || cfg.dohPort != 8443 || cfg.doqPort != 8853 ||
		!reflect.DeepEqual(cfg.dohListen, []string{"192.0.2.1", "::1"}) ||
		!reflect.DeepEqual(cfg.dohTrusted, []string{"192.0.2.0/24", "2001:db8::1"}) ||
		!reflect.DeepEqual(cfg.doqListen, []string{"192.0.2.2"}) {
		t.Fatalf("got %+v", cfg)
	}
}

func TestConfigTLSPortZeroPicksOne(t *testing.T) {
	cfg, err := parse(t, "--dot-port", "0", "--doh-port", "0", "--doq-port", "0", "--", "decider")
	if err != nil || cfg.dotPort != 0 || cfg.dohPort != 0 || cfg.doqPort != 0 {
		t.Fatalf("got dot-port=%d doh-port=%d doq-port=%d err=%v, want 0, 0 and 0 (a port picked per address)", cfg.dotPort, cfg.dohPort, cfg.doqPort, err)
	}
}

func TestConfigRejectsBadTLSUsage(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"dot port above 65535": {[]string{"--dot-port", "70000"}, "--dot-port"},
		"dot port negative":    {[]string{"--dot-port", "-1"}, "--dot-port"},
		"doh port above 65535": {[]string{"--doh-port", "70000"}, "--doh-port"},
		"doh port negative":    {[]string{"--doh-port", "-1"}, "--doh-port"},
		"doq port above 65535": {[]string{"--doq-port", "70000"}, "--doq-port"},
		"doq port negative":    {[]string{"--doq-port", "-1"}, "--doq-port"},
		"doh listen empty":     {[]string{"--doh-listen", ""}, "--doh-listen"},
		"doq listen empty":     {[]string{"--doq-listen", ""}, "--doq-listen"},
		"tls pem empty":        {[]string{"--tls-pem", ""}, "--tls-pem"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, append(c.args, "--", "decider")...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got err=%v, want a usage error naming %s", err, c.want)
			}
		})
	}
}

// --doh-trusted takes a prefix (host bits masked) or a bare address (/32, /128); the PHP side emits addr/len with
// no leading zeros. A value that is neither is logged and ignored, never fatal: a stored value must not
// crash-loop the only :53 listener under `daemon -r`.
func TestTrustedPrefixes(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" = ignored
	}{
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"198.51.100.7/24", "198.51.100.0/24"},
		{"192.0.2.7", "192.0.2.7/32"},
		{"192.0.2.7/32", "192.0.2.7/32"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:db8::1/32", "2001:db8::/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"::1/128", "::1/128"},
		{"junk", ""},
		{"", ""},
		{"192.0.2.0/33", ""},
		{"192.0.2.0/", ""},
		{"192.0.2.300", ""},
		{"010.0.0.1", ""},
		{"010.0.0.0/8", ""},
		{"2001:db8::/129", ""},
		{"192.0.2.0/24 extra", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			logs := &capturedLog{}
			got := parseTrusted([]string{c.in}, logs.logf)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("%q must be ignored, got %v", c.in, got)
				}
				if n := logs.count(); n != 1 || !strings.Contains(logs.joined(), "--doh-trusted") || !strings.Contains(logs.joined(), c.in) {
					t.Fatalf("an ignored value is logged once and named, got %d lines: %s", n, logs.joined())
				}
				return
			}
			if len(got) != 1 || got[0] != netip.MustParsePrefix(c.want) {
				t.Fatalf("%q: got %v, want %s", c.in, got, c.want)
			}
			if logs.count() != 0 {
				t.Fatalf("a good value logs nothing, got: %s", logs.joined())
			}
		})
	}
}

func TestTrustedPrefixesKeepTheGoodOnesBesideABadOne(t *testing.T) {
	logs := &capturedLog{}
	got := parseTrusted([]string{"192.0.2.0/24", "junk", "2001:db8::1"}, logs.logf)
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128")}
	if !reflect.DeepEqual(got, want) || logs.count() != 1 {
		t.Fatalf("got %v (%d log lines), want %v and one line for `junk`", got, logs.count(), want)
	}
}
