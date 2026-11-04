package main

import (
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The existing DoH-443 seam and its 53/853 siblings keep tests off shared privileged ports.
func liveStandardPorts(host string, fixedOnly bool) liveOpt {
	return func(t *testing.T, cfg *config) {
		liveDDR(t, cfg)
		for {
			ports := liveFreePorts(t, 3)
			taken := []int{cfg.port, cfg.dotPort, cfg.dohPort, cfg.doqPort, cfg.dotPort6, cfg.dohPort6, cfg.doqPort6}
			if !slices.ContainsFunc(ports, func(p int) bool { return slices.Contains(taken, p) }) {
				cfg.plain53Port, cfg.tls853Port, cfg.doh443Port = ports[0], ports[1], ports[2]
				break
			}
		}
		cfg.listen53, cfg.dotListen853, cfg.dohListen443, cfg.doqListen853 = []string{host}, []string{host}, []string{host}, []string{host}
		if fixedOnly {
			cfg.dotListen, cfg.dohListen, cfg.doqListen = nil, nil, nil
		}
	}
}

func standardAt(cfg config, kind, host string) netip.AddrPort {
	port := cfg.port53()
	switch kind {
	case "dot", "doq":
		port = cfg.port853()
	case "doh":
		port = cfg.port443()
	}
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func requireStandardDDR(t *testing.T, r *liveRig, host string, kinds ...string) {
	t.Helper()
	want := ddrWant{additional: []string{ddrAddrRR(ddrFQDN, host)}}
	if slices.Contains(kinds, "doh") {
		want.svcb = append(want.svcb, ddrDoHRec(ddrFQDN, 0, host, ddrDoHPath))
	}
	if slices.Contains(kinds, "dot") {
		want.svcb = append(want.svcb, ddrDoTRec(ddrFQDN, uint16(r.cfg.port853()), host))
	}
	if slices.Contains(kinds, "doq") {
		want.svcb = append(want.svcb, ddrDoQRec(ddrFQDN, uint16(r.cfg.port853()), host))
	}
	if len(want.svcb) == 0 {
		want = ddrNODATA
	}
	query := ddrQuery(t, 0x3699, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, liveUDPQuery(t, standardAt(r.cfg, "udp+tcp", host), query), want)
}

func TestStandardListenersColdAndLiveHaveIdenticalEndpointsAndActualDDR(t *testing.T) {
	for _, host := range []string{"127.0.0.2", "::1"} {
		t.Run(host, func(t *testing.T) {
			liveNeedAddr(t, host)
			r := newLiveRig(t, liveV6Ports(), liveStandardPorts(host, true))
			keys := []string{liveKey("udp+tcp", r.at("udp+tcp", "127.0.0.1"))}
			for _, kind := range listenerKinds {
				ap := standardAt(r.cfg, kind, host)
				keys = append(keys, liveKey(kind, ap))
				r.ask(kind, ap)
				configured := netip.AddrPortFrom(ap.Addr(), uint16(r.cfg.transportPort(kind, host)))
				r.requireGone(kind, configured)
			}
			if got, want := r.list(), listReply(keys, nil); got != want {
				t.Fatalf("cold list %q, want %q", got, want)
			}
			requireStandardDDR(t, r, host, "dot", "doh", "doq")
			for _, kind := range []string{"dot", "doh", "doq"} {
				ap := standardAt(r.cfg, kind, host)
				r.remove(kind, ap)
				r.requireGone(kind, ap)
				remaining := slices.DeleteFunc([]string{"dot", "doh", "doq"}, func(k string) bool { return k == kind })
				requireStandardDDR(t, r, host, remaining...)
				r.add(kind, ap)
				r.ask(kind, ap)
				requireStandardDDR(t, r, host, "dot", "doh", "doq")
			}
			plain := standardAt(r.cfg, "udp+tcp", host)
			r.remove("udp+tcp", plain)
			r.requireGone("udp+tcp", plain)
			r.add("udp+tcp", plain)
			r.ask("udp+tcp", plain)
			if got, want := r.list(), listReply(keys, nil); got != want {
				t.Fatalf("live list %q, want cold list %q", got, want)
			}
			if got := r.countLines("starting pid "); got != 1 {
				t.Fatalf("gateway starts %d, want 1; logs:\n%s", got, r.logs.text())
			}
		})
	}
}

func TestStandardListenersKeepOrdinaryCustomPortsAndDeduplicateDefaults(t *testing.T) {
	for _, samePort := range []bool{false, true} {
		t.Run(map[bool]string{false: "custom", true: "default"}[samePort], func(t *testing.T) {
			r := newLiveRig(t, liveStandardPorts("127.0.0.1", false), func(_ *testing.T, cfg *config) {
				if samePort {
					cfg.port, cfg.dotPort, cfg.dohPort, cfg.doqPort = cfg.port53(), cfg.port853(), cfg.port443(), cfg.port853()
				}
			})
			want := []string{}
			for _, kind := range listenerKinds {
				ap := standardAt(r.cfg, kind, "127.0.0.1")
				want = append(want, liveKey(kind, ap))
				r.ask(kind, ap)
				if !samePort {
					configured := r.at(kind, "127.0.0.1")
					want = append(want, liveKey(kind, configured))
					r.ask(kind, configured)
				}
			}
			if got := r.list(); got != listReply(want, nil) {
				t.Fatalf("list %q, want %q", got, listReply(want, nil))
			}
		})
	}
}

func TestStandardListenerRefusalsAreRealAndLiveRecoveryClearsThem(t *testing.T) {
	for _, host := range []string{"127.0.0.2", "::1"} {
		for _, kind := range listenerKinds {
			t.Run(host+"/"+kind, func(t *testing.T) {
				liveNeedAddr(t, host)
				var held interface{ Close() error }
				r := newLiveRig(t, liveStandardPorts(host, true), func(t *testing.T, cfg *config) {
					ap := standardAt(*cfg, kind, host)
					if kind == "doq" {
						c, err := net.ListenUDP(liveNet("udp", ap), net.UDPAddrFromAddrPort(ap))
						if err != nil {
							t.Fatal(err)
						}
						held = c
					} else {
						held = liveHoldTCP(t, host, int(ap.Port()))
					}
					t.Cleanup(func() { _ = held.Close() })
				})
				ap := standardAt(r.cfg, kind, host)
				if !strings.Contains(r.list(), "refused "+liveKey(kind, ap)+" "+liveInUse) {
					t.Fatalf("missing refused %s %s in %q", kind, ap, r.list())
				}
				if kind != "udp+tcp" {
					remaining := slices.DeleteFunc([]string{"dot", "doh", "doq"}, func(k string) bool { return k == kind })
					requireStandardDDR(t, r, host, remaining...)
				}
				_ = held.Close()
				r.add(kind, ap)
				r.ask(kind, ap)
				if strings.Contains(r.list(), "refused "+liveKey(kind, ap)) {
					t.Fatalf("recovered %s %s remains refused: %s", kind, ap, r.list())
				}
				requireStandardDDR(t, r, host, "dot", "doh", "doq")
			})
		}
	}
}

func TestStandardLiveAdmissionPreservesPortsDescriptorsAndTransportGates(t *testing.T) {
	r := newLiveRig(t, liveStandardPorts("127.0.0.1", true))
	const host = "127.0.0.2"
	for _, kind := range listenerKinds {
		ap := standardAt(r.cfg, kind, host)
		wrong := netip.AddrPortFrom(ap.Addr(), uint16(r.stranger))
		r.refuse(kind+" wrong port", false, func() []livePart {
			return []livePart{{r.addFrame(kind, wrong), liveSockets(t, kind, wrong)}}
		})
		r.refuse(kind+" descriptor bound elsewhere", false, func() []livePart {
			return []livePart{{r.addFrame(kind, ap), liveSockets(t, kind, wrong)}}
		})
		r.refuse(kind+" wrong socket protocol", false, func() []livePart {
			if kind == "doq" {
				return []livePart{{r.addFrame(kind, ap), []int{liveTCP(t, ap)}}}
			}
			if kind == "udp+tcp" {
				return []livePart{{r.addFrame(kind, ap), []int{liveTCP(t, ap), liveUDP(t, ap)}}}
			}
			return []livePart{{r.addFrame(kind, ap), []int{liveUDP(t, ap)}}}
		})
		other := standardAt(r.cfg, "udp+tcp", host)
		if kind == "udp+tcp" {
			other = standardAt(r.cfg, "dot", host)
		}
		r.refuse(kind+" another transport's standard port", false, func() []livePart {
			return []livePart{{r.addFrame(kind, other), liveSockets(t, kind, other)}}
		})
	}
	for _, kind := range []string{"dot", "doh", "doq"} {
		t.Run("disabled/"+kind, func(t *testing.T) {
			r := newLiveRig(t, liveStandardPorts("127.0.0.1", true), func(_ *testing.T, cfg *config) {
				switch kind {
				case "dot":
					cfg.dotListen853 = nil
				case "doh":
					cfg.dohListen443 = nil
				case "doq":
					cfg.doqListen853 = nil
				}
			})
			ap := standardAt(r.cfg, kind, host)
			r.refuse("disabled "+kind+" standard listener", false, func() []livePart {
				return []livePart{{r.addFrame(kind, ap), liveSockets(t, kind, ap)}}
			})
		})
	}
}

func TestStandardPortCliFlagsBindOnlyTheirNamedTransport(t *testing.T) {
	for _, host := range []string{"127.0.0.2", "::1"} {
		for kind, flag := range map[string]string{"udp+tcp": "listen-53", "dot": "dot-listen-853", "doh": "doh-listen-443", "doq": "doq-listen-853"} {
			t.Run(host+"/"+flag, func(t *testing.T) {
				liveNeedAddr(t, host)
				parsed, err := parseConfig([]string{"--listen", "127.0.0.1", "--" + flag, host, "--", "decider"}, io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				r := newLiveRig(t, liveStandardPorts(host, true), func(_ *testing.T, cfg *config) {
					cfg.listen, cfg.listen53 = parsed.listen, parsed.listen53
					cfg.dotListen, cfg.dotListen853 = parsed.dotListen, parsed.dotListen853
					cfg.dohListen, cfg.dohListen443 = parsed.dohListen, parsed.dohListen443
					cfg.doqListen, cfg.doqListen853 = parsed.doqListen, parsed.doqListen853
				})
				ap := standardAt(r.cfg, kind, host)
				want := listReply([]string{liveKey("udp+tcp", r.at("udp+tcp", "127.0.0.1")), liveKey(kind, ap)}, nil)
				if got := r.list(); got != want {
					t.Fatalf("--%s bound %q, want only its named transport in %q", flag, got, want)
				}
				r.ask(kind, ap)
			})
		}
	}
}
