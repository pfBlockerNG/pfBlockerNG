package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
)

func TestIPv6TransportPortsBindIndependently(t *testing.T) {
	for _, kind := range []string{"dot", "doh", "doq"} {
		t.Run(kind, func(t *testing.T) {
			v4, v6 := freePort(t), freePort(t)
			args := []string{"--listen", "127.0.0.1", "--" + kind + "-listen", "127.0.0.1", "--" + kind + "-listen", "::1", "--" + kind + "-port", fmt.Sprint(v4), "--" + kind + "-port6", fmt.Sprint(v6), "--", "decider"}
			cfg, err := parseConfig(args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			secure := bindTLS(cfg, t.Logf, map[string]string{})
			defer secure.close()
			var got []netip.AddrPort
			switch kind {
			case "dot":
				for _, ln := range secure.dot {
					got = append(got, ln.Addr().(*net.TCPAddr).AddrPort())
				}
			case "doh":
				for _, ln := range secure.doh {
					got = append(got, ln.Addr().(*net.TCPAddr).AddrPort())
				}
			case "doq":
				for _, ln := range secure.doq {
					got = append(got, ln.LocalAddr().(*net.UDPAddr).AddrPort())
				}
			}
			if len(got) != 2 || got[0].Port() != uint16(v4) || got[1].Port() != uint16(v6) {
				t.Fatalf("%s listeners %v, want IPv4 :%d and IPv6 :%d", kind, got, v4, v6)
			}
		})
	}
}
