package main

import (
	"net/netip"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Issue #3849: a listener is its address and port, not the text that names it. The gateway parses the frame once, unmaps an
// IPv4-mapped address, and keys the listener by the parsed value, so an add, a remove or a refusal may spell it any way
// netip reads. Zones, names, port 0, ports out of range and malformed text stay refused.

const (
	liveDottedV6 = "[::192.0.2.1]:53" // PHP: pfb_dns_proxy_host_port('::c000:201', '53') prints this, pinned in the PHP tests
	liveNetipV6  = "[::c000:201]:53"  // the spelling netip gives the same address and port
)

// liveV6On53 is the address and port both spellings name: plain DNS on its standard port, which the rig does not move.
func liveV6On53() netip.AddrPort { return netip.MustParseAddrPort(liveNetipV6) }

// freebindSockets are the sockets of an add of udp+tcp on ap: UDP, then a listening TCP socket. ap may be an address this
// host does not own; the gateway checks only what each socket is bound to.
func freebindSockets(t *testing.T, ap netip.AddrPort) []int {
	t.Helper()
	return []int{freebindSocket(t, syscall.SOCK_DGRAM, ap, false), freebindSocket(t, syscall.SOCK_STREAM, ap, true)}
}

// freebindSocket is liveSocket for ap, with IPV6_FREEBIND set before the bind so that an address this host does not own
// can be bound. Only this file's sockets carry it: the refused-bind rows need an unassigned address to fail.
func freebindSocket(t *testing.T, typ int, ap netip.AddrPort, listen bool) int {
	t.Helper()
	family, sa := liveSockaddr(ap)
	fd, err := syscall.Socket(family, typ|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []int{syscall.SO_REUSEADDR, unix.SO_REUSEPORT} {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, opt, 1); err != nil {
			t.Fatal(err)
		}
	}
	if ap.Addr().Is6() { // IPv6 only: an address this host does not own binds only with the option set before the bind
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Bind(fd, sa); err != nil {
		t.Fatalf("bind %s: %v", ap, err)
	}
	if listen {
		if err := syscall.Listen(fd, 16); err != nil {
			t.Fatal(err)
		}
	}
	return fd
}

// requireListed requires the list to be the rig's own listeners and these extra keys, no refusals.
func (r *liveRig) requireListed(when string, extra ...string) {
	t := r.t
	t.Helper()
	if got, want := r.list(), listReply(append(r.defaultKeys(), extra...), nil); got != want {
		t.Fatalf("list %s: reply %q, want %q", when, got, want)
	}
}

// addSpelled sends fds for udp+tcp, named by body, and requires the gateway to serve exactly ap.
func (r *liveRig) addSpelled(body string, ap netip.AddrPort, fds []int) {
	t := r.t
	t.Helper()
	if got := r.send(liveFrame(liveAdd, "udp+tcp "+body), fds...); got != "ok" {
		t.Fatalf("add udp+tcp %s: reply %q, want ok; log:\n%s", body, got, r.logs.text())
	}
	r.requireListed("after the add of "+body, liveKey("udp+tcp", ap))
}

// removeSpelled sends a remove of udp+tcp named by body, and requires the gateway to have stopped ap and nothing else.
func (r *liveRig) removeSpelled(body string) {
	t := r.t
	t.Helper()
	if got := r.send(liveFrame(liveRemove, "udp+tcp "+body)); got != "ok" {
		t.Fatalf("remove udp+tcp %s: reply %q, want ok; log:\n%s", body, got, r.logs.text())
	}
	r.requireListed("after the remove of " + body)
}

// An add in one spelling is removed in the other, and in the same one: the list names the key of the parsed value.
func TestAnIPv6AddAndRemoveNameOneListenerInEitherSpelling(t *testing.T) {
	for _, row := range []struct{ name, add, remove string }{
		{"add dotted, remove dotted", liveDottedV6, liveDottedV6},
		{"add netip, remove dotted", liveNetipV6, liveDottedV6},
		{"add dotted, remove netip", liveDottedV6, liveNetipV6},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := newLiveRig(t)
			ap := liveV6On53()
			r.addSpelled(row.add, ap, freebindSockets(t, ap))
			r.removeSpelled(row.remove)
		})
	}
}

// One listener is one key whichever spelling names it: a remove of an unserved one names the key, and an add in the
// other spelling of a served one is refused with that key, its descriptors closed, and the first keeps serving.
func TestOneIPv6ListenerIsOneKeyWhateverSpellingNamesIt(t *testing.T) {
	r := newLiveRig(t)
	ap := liveV6On53()
	key := liveKey("udp+tcp", ap)
	if got, want := r.send(liveFrame(liveRemove, "udp+tcp "+liveDottedV6)), "error: "+key+" is not served"; got != want {
		t.Fatalf("remove of an unserved %s: reply %q, want %q", liveDottedV6, got, want)
	}
	r.addSpelled(liveDottedV6, ap, freebindSockets(t, ap))
	reply := r.refuse("add of "+liveNetipV6+" while "+liveDottedV6+" is served", false, func() []livePart {
		return []livePart{{liveFrame(liveAdd, "udp+tcp "+liveNetipV6), freebindSockets(t, ap)}}
	})
	if want := "error: " + key + " is served already"; reply != want {
		t.Fatalf("add of %s while served: reply %q, want %q", liveNetipV6, reply, want)
	}
	r.requireListed("after the refused add", key)
	r.removeSpelled(liveDottedV6)
}

// An IPv4-mapped IPv6 address is the IPv4 address: the sockets are the IPv4 ones, the key is the IPv4 key.
func TestAnIPv4MappedSpellingIsServedAndRemovedAsTheIPv4Listener(t *testing.T) {
	for _, row := range []struct{ name, host string }{
		{"dotted", "[::ffff:127.0.0.2]:"},
		{"hex", "[::ffff:7f00:2]:"},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := newLiveRig(t)
			ap := r.at("udp+tcp", "127.0.0.2")
			body := row.host + strconv.Itoa(int(ap.Port()))
			r.addSpelled(body, ap, liveSockets(t, "udp+tcp", ap))
			r.removeSpelled(body)
		})
	}
}

// Zero-padded IPv6 text is the address its digits give: served as [::1]:p, removed in the same spelling.
func TestAZeroPaddedIPv6AddressIsItsCanonicalListener(t *testing.T) {
	liveNeedAddr(t, "::1")
	for _, host := range []string{"[0:0::1]:", "[0000:0000:0000:0000:0000:0000:0000:0001]:", "[::0001]:"} {
		t.Run(host, func(t *testing.T) {
			r := newLiveRig(t)
			ap := r.at("udp+tcp", "::1")
			body := host + strconv.Itoa(int(ap.Port()))
			r.addSpelled(body, ap, liveSockets(t, "udp+tcp", ap))
			r.removeSpelled(body)
		})
	}
}

// A port spelled with leading zeros is the port its digits give: the add is served under the port's own key.
func TestAPortSpelledWithLeadingZerosIsItsPort(t *testing.T) {
	r := newLiveRig(t)
	ap := r.at("udp+tcp", "127.0.0.2")
	body := "127.0.0.2:0" + strconv.Itoa(int(ap.Port()))
	r.addSpelled(body, ap, liveSockets(t, "udp+tcp", ap))
	r.removeSpelled(body)
}

// Text that is not a numeric address and a port in range stays refused, adds and removes alike, with the descriptors an
// add carries closed and nothing served.
func TestSpellingsThatAreNotAListenerKeepTheirRefusal(t *testing.T) {
	r := newLiveRig(t)
	v6, v4 := liveV6On53(), r.at("udp+tcp", "127.0.0.2")
	p := strconv.Itoa(int(v4.Port()))
	for _, row := range []struct {
		name, body string
		ap         netip.AddrPort // what the sockets of the add are bound to
	}{
		{"a zone", "[fe80::192.0.2.1%lo]:53", v6},
		{"port 0", "[::192.0.2.1]:0", v6},
		{"port 65536", "[::192.0.2.1]:65536", v6},
		{"an IPv4 part out of range", "[::192.0.2.256]:53", v6},
		{"no port", "[::192.0.2.1]", v6},
		{"IPv6 without brackets", "::192.0.2.1:53", v6},
		{"a space inside the brackets", "[::192.0.2.1 ]:53", v6},
		{"a name in brackets", "[localhost]:53", v6},
		{"a name", "localhost:53", v4},
		{"IPv4 in brackets", "[127.0.0.2]:" + p, v4},
		{"IPv4 with zero-padded octets", "127.000.000.002:" + p, v4},
		{"an IPv4-mapped address with a zone", "[::ffff:127.0.0.2%lo]:" + p, v4},
	} {
		r.refuse("add of "+row.name, false, func() []livePart {
			return []livePart{{liveFrame(liveAdd, "udp+tcp "+row.body), freebindSockets(t, row.ap)}}
		})
		r.refuse("remove of "+row.name, false, func() []livePart {
			return []livePart{{liveFrame(liveRemove, "udp+tcp "+row.body), nil}}
		})
	}
	r.requireListed("after the refusals")
}
