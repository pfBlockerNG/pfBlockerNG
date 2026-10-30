package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// What the gateway does not take it refuses with `error: <reason>`, closes every descriptor that came with the request,
// and serves nothing new. A gateway older than the verbs answers all of these with the certificate length's error, which
// liveRefused does not accept.

// G4: a remove names a listener that is served; anything else is an error naming it.
func TestRemovingAListenerThatIsNotServedIsAnError(t *testing.T) {
	r := newLiveRig(t)
	rows := []struct {
		kind string
		ap   netip.AddrPort
	}{
		{"udp+tcp", r.at("udp+tcp", "127.0.0.2")}, // never added
		{"dot", r.at("dot", "127.0.0.9")},
		{"doh", r.at("doh", "::1")},
		{"doq", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(r.stranger))}, // a port no kind is on
		{"dot", r.at("doh", "127.0.0.1")},                                                 // another kind's port
	}
	for _, row := range rows {
		want := "error: " + row.kind + " " + row.ap.String() + " is not served"
		if got := r.send(r.removeFrame(row.kind, row.ap)); got != want {
			t.Fatalf("remove of %s %s: reply %q, want %q", row.kind, row.ap, got, want)
		}
	}
	added := r.at("doq", "127.0.0.2")
	r.add("doq", added)
	r.remove("doq", added)
	if got, want := r.send(r.removeFrame("doq", added)), "error: doq "+added.String()+" is not served"; got != want {
		t.Fatalf("second remove of the same listener: reply %q, want %q", got, want)
	}
	for _, kind := range liveKinds {
		r.ask(kind, r.at(kind, "127.0.0.1"))
	}
}

// A remove whose text is not the canonical spelling of what is served does not take it down.
func TestARemoveThatSpellsTheListenerAnotherWayLeavesItServing(t *testing.T) {
	r := newLiveRig(t)
	ap := r.at("dot", "127.0.0.2")
	r.add("dot", ap)
	for _, body := range []string{"dot " + ap.String() + " ", "dot " + ap.String() + "\n", "DOT " + ap.String(), "dot  " + ap.String(), "dot"} {
		liveRefused(t, r.send(liveFrame(liveRemove, body)), "remove "+strconv.Quote(body))
		r.ask("dot", ap)
	}
}

// G5: an add for a kind that is served on that address already is refused and the first keeps serving. A listener of the
// start cannot be offered twice this way: the kernel does not let the test bind its address.
func TestAddingAServedListenerAgainIsRefusedAndItsDescriptorsAreClosed(t *testing.T) {
	for _, kind := range liveKinds {
		t.Run(kind, func(t *testing.T) {
			r := newLiveRig(t)
			ap := r.at(kind, "127.0.0.2")
			r.add(kind, ap)
			r.refuse(kind+" added twice", false, func() []livePart {
				return []livePart{{r.addFrame(kind, ap), liveSockets(t, kind, ap)}}
			})
			r.ask(kind, ap)
			r.remove(kind, ap)
			r.requireGone(kind, ap) // sockets of the test's share the port: the old listener must be closed before a new one is taken
			r.add(kind, ap)         // the remove freed the name
			r.ask(kind, ap)
		})
	}
}

// G6: the descriptor count is the kind's, and a control message with more descriptors than the gateway has room for is
// refused whole.
func TestAnAddWithTheWrongNumberOfDescriptorsIsRefused(t *testing.T) {
	r := newLiveRig(t)
	at := func(kind string) netip.AddrPort { return r.at(kind, "127.0.0.2") }
	extra := func() int { return liveSocket(t, syscall.SOCK_STREAM, netip.AddrPort{}, false) }
	rows := []struct {
		name, kind string
		sockets    func() []int
	}{
		{"udp+tcp with none", "udp+tcp", func() []int { return nil }},
		{"udp+tcp with the UDP socket only", "udp+tcp", func() []int { return []int{liveUDP(t, at("udp+tcp"))} }},
		{"udp+tcp with three", "udp+tcp", func() []int { return append(liveSockets(t, "udp+tcp", at("udp+tcp")), extra()) }},
		{"dot with none", "dot", func() []int { return nil }},
		{"dot with two", "dot", func() []int { return append(liveSockets(t, "dot", at("dot")), extra()) }},
		{"doh with none", "doh", func() []int { return nil }},
		{"doh with two", "doh", func() []int { return append(liveSockets(t, "doh", at("doh")), extra()) }},
		{"doq with none", "doq", func() []int { return nil }},
		{"doq with two", "doq", func() []int { return append(liveSockets(t, "doq", at("doq")), extra()) }},
		{"udp+tcp with 202 descriptors", "udp+tcp", func() []int {
			fds := liveSockets(t, "udp+tcp", at("udp+tcp"))
			for range 200 {
				fds = append(fds, liveDevNull(t))
			}
			return fds
		}},
	}
	for _, row := range rows {
		r.refuse(row.name, false, func() []livePart {
			return []livePart{{r.addFrame(row.kind, at(row.kind)), row.sockets()}}
		})
	}
	r.add("udp+tcp", at("udp+tcp")) // the refusals left the address free
	r.ask("udp+tcp", at("udp+tcp"))
}

// G7: every descriptor is a socket of the type, the state and the address the frame names.
func TestAnAddWithDescriptorsThatAreNotWhatTheFrameNamesIsRefused(t *testing.T) {
	r := newLiveRig(t)
	plain, dot, doh, doq := r.at("udp+tcp", "127.0.0.2"), r.at("dot", "127.0.0.2"), r.at("doh", "127.0.0.2"), r.at("doq", "127.0.0.2")
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.2"), plain.Port())
	otherPort := netip.AddrPortFrom(plain.Addr(), uint16(r.stranger))
	elsewhere := r.at("udp+tcp", "127.0.0.3")
	unbound := netip.AddrPort{}
	rows := []struct {
		name, kind string
		frame      netip.AddrPort
		sockets    func() []int
	}{
		{"two stream sockets for udp+tcp", "udp+tcp", plain, func() []int { return []int{liveTCP(t, plain), liveTCP(t, plain)} }},
		{"udp+tcp in the wrong order", "udp+tcp", plain, func() []int { return []int{liveTCP(t, plain), liveUDP(t, plain)} }},
		{"two datagram sockets for udp+tcp", "udp+tcp", plain, func() []int { return []int{liveUDP(t, plain), liveUDP(t, plain)} }},
		{"a datagram socket for dot", "dot", dot, func() []int { return []int{liveUDP(t, dot)} }},
		{"a datagram socket for doh", "doh", doh, func() []int { return []int{liveUDP(t, doh)} }},
		{"a stream socket for doq", "doq", doq, func() []int { return []int{liveTCP(t, doq)} }},
		{"IPv6 sockets for an IPv4 frame", "udp+tcp", plain, func() []int { return []int{liveUDP(t, mapped), liveTCP(t, mapped)} }},
		{"unbound sockets for udp+tcp", "udp+tcp", plain, func() []int {
			return []int{liveSocket(t, syscall.SOCK_DGRAM, unbound, false), liveSocket(t, syscall.SOCK_STREAM, unbound, false)}
		}},
		{"an unbound stream socket for dot", "dot", dot, func() []int { return []int{liveSocket(t, syscall.SOCK_STREAM, unbound, false)} }},
		{"an unbound datagram socket for doq", "doq", doq, func() []int { return []int{liveUDP(t, unbound)} }},
		{"a stream socket that is bound and not listening", "udp+tcp", plain, func() []int {
			return []int{liveUDP(t, plain), liveSocket(t, syscall.SOCK_STREAM, plain, false)}
		}},
		{"a stream socket that is bound and not listening for doh", "doh", doh, func() []int {
			return []int{liveSocket(t, syscall.SOCK_STREAM, doh, false)}
		}},
		{"sockets bound to another address", "udp+tcp", plain, func() []int { return []int{liveUDP(t, elsewhere), liveTCP(t, elsewhere)} }},
		{"only the TCP socket bound to another address", "udp+tcp", plain, func() []int {
			return []int{liveUDP(t, plain), liveTCP(t, elsewhere)}
		}},
		{"sockets bound to another port", "udp+tcp", plain, func() []int { return []int{liveUDP(t, otherPort), liveTCP(t, otherPort)} }},
		{"sockets of another address for a frame naming a start address", "udp+tcp", r.at("udp+tcp", "127.0.0.1"), func() []int {
			return []int{liveUDP(t, plain), liveTCP(t, plain)}
		}},
		{"a pipe for dot", "dot", dot, func() []int {
			p := livePipe(t)
			liveClose(p[1]) // the write end stays here: only the read end is sent
			return p[:1]
		}},
		{"two pipes for udp+tcp", "udp+tcp", plain, func() []int { return livePipe(t) }},
		{"a character device for doq", "doq", doq, func() []int { return []int{liveDevNull(t)} }},
		{"a listening Unix socket for dot", "dot", dot, func() []int { return []int{liveUnixListener(t)} }},
	}
	for _, row := range rows {
		r.refuse(row.name, false, func() []livePart {
			return []livePart{{r.addFrame(row.kind, row.frame), row.sockets()}}
		})
	}
	r.add("udp+tcp", plain) // none of the refusals took the address
	r.ask("udp+tcp", plain)
}

// G8: the port is the kind's configured one.
func TestAnAddForAPortThatIsNotTheKindsIsRefused(t *testing.T) {
	r := newLiveRig(t)
	for i, kind := range liveKinds {
		own := r.at(kind, "127.0.0.2")
		stranger := netip.AddrPortFrom(own.Addr(), uint16(r.stranger))
		next := netip.AddrPortFrom(own.Addr(), uint16(r.port[liveKinds[(i+1)%len(liveKinds)]]))
		for name, ap := range map[string]netip.AddrPort{"a port no kind is on": stranger, "another kind's port": next} {
			r.refuse(kind+" on "+name, false, func() []livePart {
				return []livePart{{r.addFrame(kind, ap), liveSockets(t, kind, ap)}}
			})
		}
		r.add(kind, own) // its own port is taken
		r.remove(kind, own)
	}
}

// G8: a TLS kind is served only when the start was given its listen address; plain DNS always is.
func TestAnAddForATLSKindThatTheStartDidNotServeIsRefused(t *testing.T) {
	for _, row := range []struct {
		name string
		only []string
	}{{"only DoH", []string{"doh"}}, {"no TLS kind", nil}} {
		t.Run(row.name, func(t *testing.T) {
			r := newLiveRig(t, liveOnly(row.only...))
			for _, kind := range []string{"dot", "doh", "doq"} {
				if ap := r.at(kind, "127.0.0.2"); !slices.Contains(row.only, kind) {
					r.refuse(kind+" that this gateway does not serve", false, func() []livePart {
						return []livePart{{r.addFrame(kind, ap), liveSockets(t, kind, ap)}}
					})
				}
			}
			for _, kind := range append([]string{"udp+tcp"}, row.only...) { // served: refusals above left the address free
				r.add(kind, r.at(kind, "127.0.0.2"))
				r.ask(kind, r.at(kind, "127.0.0.2"))
			}
		})
	}
}

// G9: descriptors that come with a restart, a certificate or a remove are closed and the frame does what it does without
// them. The test keeps the other end of each socket it sends: it reads EOF once the gateway has closed its copy.
func TestDescriptorsSentWithAnyOtherFrameAreClosedAndTheFrameIsHandledAsWithoutThem(t *testing.T) {
	r := newLiveRig(t)
	pem, err := os.ReadFile(r.cfg.tlsPEM)
	if err != nil {
		t.Fatal(err)
	}
	ap := r.at("dot", "127.0.0.2")
	r.add("dot", ap)
	rows := []struct {
		name  string
		frame []byte
		want  func(reply string) bool
	}{
		{"a certificate push", ctlFrame(pem), func(s string) bool { return s == "ok" }},
		{"a push that is not a certificate", ctlFrame([]byte("x")), func(s string) bool {
			return strings.HasPrefix(s, "error: ") && !strings.Contains(s, "not between")
		}},
		{"a remove of a served listener", r.removeFrame("dot", ap), func(s string) bool { return s == "ok" }},
		{"a remove of one that is not served", r.removeFrame("dot", ap), func(s string) bool {
			return s == "error: dot "+ap.String()+" is not served"
		}},
		{"a restart", ctlRestartFrame, func(s string) bool { return s == "ok" }},
	}
	for _, row := range rows {
		kept, sent := livePair(t)
		if got := r.send(row.frame, sent); !row.want(got) {
			t.Fatalf("%s with a descriptor: reply %q", row.name, got)
		}
		liveRequireEOF(t, kept, row.name)
	}
	r.requireGone("dot", ap)
	r.ask("udp+tcp", r.at("udp+tcp", "127.0.0.1")) // the restarted decider answers
}

// A descriptor on a byte after the frame is never read by the gateway: the kernel disposes of it when the connection ends.
func TestADescriptorOnAByteAfterTheFrameIsNotLeftInTheGateway(t *testing.T) {
	r := newLiveRig(t)
	base := liveOpenFDs(t)
	kept, sent := livePair(t)
	frame := r.removeFrame("dot", r.at("dot", "127.0.0.2"))
	got := r.exchange(false, livePart{data: frame}, livePart{data: []byte{0}, fds: []int{sent}})
	liveRefused(t, got, "a remove with a byte and a descriptor after it")
	liveRequireEOF(t, kept, "a descriptor after the frame")
	liveRequireFDs(t, base+1, "after the exchange") // the kept end
}

// An add that comes once the gateway has begun to stop is refused: stop() has taken its list of what to close.
func TestAnAddOnceTheGatewayIsStoppingIsRefused(t *testing.T) {
	r := newLiveRig(t)
	ap := r.at("udp+tcp", "127.0.0.2")
	r.srv.g.cancel() // what stop() does first
	r.refuse("an add while stopping", false, func() []livePart {
		return []livePart{{r.addFrame("udp+tcp", ap), liveSockets(t, "udp+tcp", ap)}}
	})
}

// G10: a peer that is not root is closed on unread: no descriptor reaches the gateway and nothing is served.
func TestAPeerThatIsNotRootGetsNoDescriptorIntoTheGateway(t *testing.T) {
	r := newLiveRig(t, liveStranger())
	for _, kind := range liveKinds {
		ap := r.at(kind, "127.0.0.2")
		base := liveOpenFDs(t)
		kept, sent := livePair(t)
		if got := r.send(r.addFrame(kind, ap), append(liveSockets(t, kind, ap), sent)...); got != "" {
			t.Fatalf("%s add from a peer that is not root: reply %q, want none", kind, got)
		}
		liveRequireEOF(t, kept, kind+" add from a peer that is not root")
		liveRequireFDs(t, base+1, kind+" add from a peer that is not root") // the kept end
		r.requireGone(kind, ap)
		if r.hasLine("listening " + kind + " " + ap.String()) {
			t.Fatalf("%s add from a peer that is not root was served:\n%s", kind, r.logs.text())
		}
	}
}

// The hostile rows of the spec: a frame whose length or text is not what an add or a remove is.
func TestAnAddOrRemoveWithAMalformedFrameIsRefusedAndItsDescriptorsAreClosed(t *testing.T) {
	r := newLiveRig(t)
	p := strconv.Itoa(r.port["udp+tcp"])
	v4 := r.at("udp+tcp", "127.0.0.2")
	sockets := func(verb []byte, head []byte, eof bool, row, reason string) {
		reply := r.refuse(row, eof, func() []livePart {
			return []livePart{{append(slices.Clone(verb), head...), liveSockets(t, "udp+tcp", v4)}}
		})
		if !strings.Contains(reply, reason) {
			t.Fatalf("%s: reply %q, want one that says %q", row, reply, reason)
		}
	}
	for _, v := range []struct {
		name string
		verb []byte
	}{{"add", liveAdd}, {"remove", liveRemove}} {
		// No body follows these lengths and the connection stays open: only a length judged before the body is read is answered.
		sockets(v.verb, []byte{0, 0, 0, 0}, false, v.name+" of length 0", "between 1 and 256")
		sockets(v.verb, binary.BigEndian.AppendUint32(nil, 257), false, v.name+" of length 257", "between 1 and 256")
		sockets(v.verb, append(binary.BigEndian.AppendUint32(nil, 40), "udp+tcp 127"...), true, v.name+" whose body is shorter than its length", "the message ended after 11 of 40 bytes")
	}
	rows := []struct{ name, body string }{
		{"an unknown kind", "tls 127.0.0.2:" + p},
		{"an empty kind", " 127.0.0.2:" + p},
		{"no kind", "127.0.0.2:" + p},
		{"a kind and nothing else", "udp+tcp"},
		{"the kind in capitals", "UDP+TCP 127.0.0.2:" + p},
		{"the kind in mixed case", "Udp+Tcp 127.0.0.2:" + p},
		{"no port", "udp+tcp 127.0.0.2"},
		{"an empty port", "udp+tcp 127.0.0.2:"},
		{"unbracketed IPv6", "udp+tcp ::1:" + p},
		{"a name", "udp+tcp localhost:" + p},
		{"a zone", "udp+tcp [fe80::1%lo]:" + p},
		{"IPv4-mapped IPv6", "udp+tcp [::ffff:127.0.0.2]:" + p},
		{"port 0", "udp+tcp 127.0.0.2:0"},
		{"port 65536", "udp+tcp 127.0.0.2:65536"},
		{"a port with a leading zero", "udp+tcp 127.0.0.2:0" + p},
		{"an address with leading zeros", "udp+tcp 127.000.000.002:" + p},
		{"a trailing space", "udp+tcp 127.0.0.2:" + p + " "},
		{"a trailing newline", "udp+tcp 127.0.0.2:" + p + "\n"},
		{"a trailing carriage return and newline", "udp+tcp 127.0.0.2:" + p + "\r\n"},
		{"a leading space", " udp+tcp 127.0.0.2:" + p},
		{"two spaces", "udp+tcp  127.0.0.2:" + p},
		{"a tab", "udp+tcp\t127.0.0.2:" + p},
		{"a NUL byte", "udp+tcp 127.0.0.2:" + p + "\x00"},
		{"bytes above 0x7f", "udp+tcp 127.0.0.2:" + p + "\xc3\xa9"},
		{"a second address", "udp+tcp 127.0.0.2:" + p + " 127.0.0.3:" + p},
	}
	for _, row := range rows {
		r.refuse("add of "+row.name, false, func() []livePart {
			return []livePart{{liveFrame(liveAdd, row.body), liveSockets(t, "udp+tcp", v4)}}
		})
		r.refuse("remove of "+row.name, false, func() []livePart { return []livePart{{liveFrame(liveRemove, row.body), nil}} })
	}
	// The sockets of this row are bound to the mapped address itself: only the spelling of the frame is wrong.
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.2"), v4.Port())
	r.refuse("add of IPv4-mapped IPv6 with sockets bound to that very address", false, func() []livePart {
		return []livePart{{liveFrame(liveAdd, "udp+tcp "+mapped.String()), liveSockets(t, "udp+tcp", mapped)}}
	})
	r.add("udp+tcp", v4) // none of the refusals took the address
	r.ask("udp+tcp", v4)
}

// A spelling of an IPv6 address that is not its canonical one is refused although the sockets are exactly right.
func TestAnAddWithANonCanonicalIPv6SpellingIsRefused(t *testing.T) {
	liveNeedAddr(t, "::1")
	r := newLiveRig(t)
	v6 := r.at("udp+tcp", "::1")
	p := strconv.Itoa(r.port["udp+tcp"])
	for _, spelling := range []string{"[0:0::1]:", "[0000:0000:0000:0000:0000:0000:0000:0001]:", "[::0001]:", "[::1 ]:"} {
		r.refuse("add of "+spelling, false, func() []livePart {
			return []livePart{{liveFrame(liveAdd, "udp+tcp "+spelling+p), liveSockets(t, "udp+tcp", v6)}}
		})
	}
	r.add("udp+tcp", v6)
	r.ask("udp+tcp", v6)
}
