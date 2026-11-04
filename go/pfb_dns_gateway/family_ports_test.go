package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
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

func TestDDRDoH443AdvertisementIsPerFamily(t *testing.T) {
	m := newTLSMaterial(t)
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			flag := "--ddr-doh-443"
			if family == "6" {
				flag += "6"
			}
			cfg, err := parseConfig([]string{"--listen", "127.0.0.1", "--dns-name", "fw.example.lan", "--ddr", flag, "--", "decider"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			v4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer v4.Close()
			v6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
			if err != nil {
				t.Fatal(err)
			}
			defer v6.Close()
			d, err := ddrOnListeners(cfg, &tlsListeners{certs: m.certs, doh: []*net.TCPListener{v4, v6}})
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ host, family string }{{"127.0.0.1", "4"}, {"::1", "6"}} {
				answers, _ := d.designate(dnsmessage.MustNewName(ddrAsk), netip.MustParseAddr(tc.host))
				if len(answers) != 1 {
					t.Fatalf("%s: got %v", tc.host, answers)
				}
				hasPort := false
				for _, p := range answers[0].Body.(*dnsmessage.SVCBResource).Params {
					hasPort = hasPort || p.Key == dnsmessage.SVCParamPort
				}
				if hasPort != (tc.family != family) {
					t.Fatalf("advertise family %s, query family %s: port present %v", family, tc.family, hasPort)
				}
			}
		})
	}
}
