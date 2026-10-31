package main

import (
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Root asks the running gateway what it serves with `FF FF FF FC` and nothing after it. The reply is `listening <kind>
// <host:port>` for each listener served, then `refused <kind> <host:port> <reason>` for each start-time bind refused and
// not served since, each group in key order, then `ok`. Linux only, as the rig.

const (
	liveNoAddr = "bind: cannot assign requested address"
	liveInUse  = "bind: address already in use"
)

var liveList = []byte{0xff, 0xff, 0xff, 0xfc}

// liveKey is `<kind> <host:port>` for ap, the key the list reply spells.
func liveKey(kind string, ap netip.AddrPort) string { return kind + " " + ap.String() }

// listReply is the reply the verb must give: `listening` for each served key, then `refused <key> <reason>` for each
// refusal, each group in key order, then ok.
func listReply(served []string, refused map[string]string) string {
	slices.Sort(served)
	var b strings.Builder
	for _, k := range served {
		b.WriteString("listening " + k + "\n")
	}
	for _, k := range slices.Sorted(maps.Keys(refused)) {
		b.WriteString("refused " + k + " " + refused[k] + "\n")
	}
	b.WriteString("ok\n")
	return b.String()
}

// liveAlso gives kind more addresses to bind at start, on the port kind has.
func liveAlso(kind string, hosts ...string) liveOpt {
	return func(_ *testing.T, cfg *config) {
		switch kind {
		case "udp+tcp":
			cfg.listen = append(cfg.listen, hosts...)
		case "dot":
			cfg.dotListen = append(cfg.dotListen, hosts...)
		case "doh":
			cfg.dohListen = append(cfg.dohListen, hosts...)
		case "doq":
			cfg.doqListen = append(cfg.doqListen, hosts...)
		}
	}
}

// liveHoldTCP listens on host:port, so that a start's bind of that port on host is refused until the listener is closed.
func liveHoldTCP(t *testing.T, host string, port int) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// refusedAtStart starts a rig whose start binds kind on host, while the test holds the TCP port there, so the start
// refuses it. The holder is returned for the test to close when it wants the port back.
func refusedAtStart(t *testing.T, kind, host string) (*liveRig, net.Listener) {
	t.Helper()
	var held net.Listener
	r := newLiveRig(t, liveAlso(kind, host), func(t *testing.T, cfg *config) {
		port := cfg.port
		if kind == "dot" {
			port = cfg.dotPort
		}
		held = liveHoldTCP(t, host, port)
	})
	return r, held
}

// defaultKeys are the keys of the listeners newLiveRig starts: every kind on 127.0.0.1.
func (r *liveRig) defaultKeys() []string {
	var keys []string
	for _, kind := range liveKinds {
		keys = append(keys, liveKey(kind, r.at(kind, "127.0.0.1")))
	}
	return keys
}

// list sends the verb on a connection of its own and returns the whole reply, read to the gateway's close.
func (r *liveRig) list() string {
	t := r.t
	t.Helper()
	c := dialCtl(t, r.sock)
	_, _ = c.Write(liveList) // a gateway that refuses the peer has closed already: the reply is what tells
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	reply, err := io.ReadAll(c)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("STUCK/ENVIRONMENT: the control socket neither finished the list reply nor closed within the watchdog (read so far: %q)", reply)
	}
	if err != nil && !isClosed(err) {
		t.Fatalf("reading the list reply: %q, %v", reply, err)
	}
	return string(reply)
}

// L1-L4: every listener the start serves is listed, once each, in key order.
func TestListReportsEveryListenerTheStartServes(t *testing.T) {
	r := newLiveRig(t)
	want := listReply(r.defaultKeys(), nil)
	if got := r.list(); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
}

// R1-R4: a bind the start refuses is listed with its reason, and the listeners that did bind are still listed.
func TestListReportsEachStartBindThatIsRefused(t *testing.T) {
	for _, kind := range liveKinds {
		t.Run(kind, func(t *testing.T) {
			r := newLiveRig(t, liveAlso(kind, "192.0.2.1"))
			want := listReply(r.defaultKeys(), map[string]string{liveKey(kind, r.at(kind, "192.0.2.1")): liveNoAddr})
			if got := r.list(); got != want {
				t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
			}
		})
	}
}

// R5: DoQ (UDP) refused on the port DoT (TCP) binds, where the test holds the UDP port; DoT is still listed.
func TestListReportsADoQBindRefusedOnTheDoTPort(t *testing.T) {
	r := newLiveRig(t, func(t *testing.T, cfg *config) {
		cfg.doqPort = cfg.dotPort
		held, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.dotPort)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Close() })
	})
	doqAt := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(r.cfg.dotPort))
	served := []string{
		liveKey("udp+tcp", r.at("udp+tcp", "127.0.0.1")),
		liveKey("doh", r.at("doh", "127.0.0.1")),
		liveKey("dot", r.at("dot", "127.0.0.1")),
	}
	want := listReply(served, map[string]string{liveKey("doq", doqAt): liveInUse})
	if got := r.list(); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
}

// E1: with no TLS address given, only plain DNS is listed: no TLS kind is served or refused.
func TestListReportsOnlyPlainDNSWhenNoTLSKindIsGiven(t *testing.T) {
	r := newLiveRig(t, liveOnly())
	want := listReply([]string{liveKey("udp+tcp", r.at("udp+tcp", "127.0.0.1"))}, nil)
	if got := r.list(); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
}

// A1: a start refusal is listed until the address is added live; after the add it is listed as served, not refused.
func TestAStartRefusalIsClearedWhenTheListenerIsAddedLive(t *testing.T) {
	for _, kind := range []string{"udp+tcp", "dot"} {
		t.Run(kind, func(t *testing.T) {
			r, held := refusedAtStart(t, kind, "127.0.0.2")
			ap := r.at(kind, "127.0.0.2")
			if got, want := r.list(), listReply(r.defaultKeys(), map[string]string{liveKey(kind, ap): liveInUse}); got != want {
				t.Fatalf("before the add: list reply %q, want %q; log:\n%s", got, want, r.logs.text())
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			r.add(kind, ap)
			if got, want := r.list(), listReply(append(r.defaultKeys(), liveKey(kind, ap)), nil); got != want {
				t.Fatalf("after the add: list reply %q, want %q; log:\n%s", got, want, r.logs.text())
			}
		})
	}
}

// D1: a removed listener is neither listed nor refused, and a remove does not bring back a refusal the start made.
func TestARemovedListenerIsNeitherListedNorRefused(t *testing.T) {
	for _, kind := range liveKinds {
		t.Run(kind, func(t *testing.T) {
			r := newLiveRig(t)
			r.remove(kind, r.at(kind, "127.0.0.1"))
			var served []string
			for _, k := range liveKinds {
				if k != kind {
					served = append(served, liveKey(k, r.at(k, "127.0.0.1")))
				}
			}
			if got, want := r.list(), listReply(served, nil); got != want {
				t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
			}
		})
	}
	for _, kind := range []string{"udp+tcp", "dot"} {
		t.Run(kind+" refused at start", func(t *testing.T) {
			r, held := refusedAtStart(t, kind, "127.0.0.2")
			ap := r.at(kind, "127.0.0.2")
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			r.add(kind, ap)
			r.remove(kind, ap)
			if got, want := r.list(), listReply(r.defaultKeys(), nil); got != want {
				t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
			}
		})
	}
}

// DUP: an address given twice is bound once; the second bind's refusal is not listed, the first's listener is.
func TestAListenerGivenTwiceAtStartIsListedOnceAndNotRefused(t *testing.T) {
	r := newLiveRig(t, liveAlso("udp+tcp", "127.0.0.1"))
	if got, want := r.list(), listReply(r.defaultKeys(), nil); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
}

// N1: a peer that is not root is closed on without the verb being read from it: no reply.
func TestAPeerThatIsNotRootGetsNoListReply(t *testing.T) {
	r := newLiveRig(t, liveStranger())
	if got := r.list(); got != "" {
		t.Fatalf("list from a peer that is not root: reply %q, want none", got)
	}
}

// V6: IPv6 listeners and refusals are spelled in brackets, as their keys are.
func TestListSpellsIPv6ListenersAndRefusalsWithBrackets(t *testing.T) {
	liveNeedAddr(t, "::1")
	r := newLiveRig(t, liveAlso("udp+tcp", "::1", "2001:db8::1"))
	served := append(r.defaultKeys(), liveKey("udp+tcp", r.at("udp+tcp", "::1")))
	want := listReply(served, map[string]string{liveKey("udp+tcp", r.at("udp+tcp", "2001:db8::1")): liveNoAddr})
	if got := r.list(); got != want {
		t.Fatalf("list reply %q, want %q; log:\n%s", got, want, r.logs.text())
	}
}
