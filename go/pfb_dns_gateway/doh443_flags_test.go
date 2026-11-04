package main

import (
	"slices"
	"testing"
)

// issue #3694: what --ddr-doh-443 and --doh-listen-443 are parsed to: each flag is one value, in the order given; their syntax
// is checked at parse time and the set is made from them at start.

func TestConfigDoH443FlagsAreParsedAsLists(t *testing.T) {
	cases := map[string]struct {
		flags     []string
		ddrDoH443 []string
		dohListen []string
	}{
		"off by default": {nil, nil, nil},
		"--ddr-doh-443, each flag its own value, in order": {
			[]string{"--dns-name", "fw.example.lan", "--ddr", "--ddr-doh-443", "192.0.2.1", "--ddr-doh-443", "2001:db8::1", "--ddr-doh-443", "192.0.2.1"},
			[]string{"192.0.2.1", "2001:db8::1", "192.0.2.1"}, nil,
		},
		"--doh-listen-443, each flag its own value, in order": {
			[]string{"--doh-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53", "--doh-listen-443", "fd00:53:53:53:53:53:53:1"},
			nil, []string{"192.0.2.53", "fd00:53:53:53:53:53:53:1"},
		},
		"the flags are independent": {
			[]string{"--dns-name", "fw.example.lan", "--ddr", "--doh-listen", "192.0.2.1", "--doh-listen-443", "192.0.2.53", "--ddr-doh-443", "192.0.2.1"},
			[]string{"192.0.2.1"}, []string{"192.0.2.53"},
		},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			cfg, err := parse(t, append(slices.Clone(c.flags), "--", "decider")...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.ddrDoH443, c.ddrDoH443) || !slices.Equal(cfg.dohListen443, c.dohListen) {
				t.Fatalf("got ddrDoH443=%q dohListen443=%q, want %q and %q", cfg.ddrDoH443, cfg.dohListen443, c.ddrDoH443, c.dohListen)
			}
		})
	}
}
