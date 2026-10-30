package main

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A listener added over the control socket is served exactly as a start-bound one of its kind, logs the line a start
// logs, and a remove closes it with the others untouched.

var liveKinds = []string{"udp+tcp", "dot", "doh", "doq"}

// G1: UDP and TCP on an added address, IPv4 and IPv6.
func TestAnAddedPlainListenerAnswersOverUDPAndTCPAndIsLogged(t *testing.T) {
	for _, host := range []string{"127.0.0.2", "::1"} {
		t.Run(host, func(t *testing.T) {
			liveNeedAddr(t, host)
			r := newLiveRig(t)
			ap := r.at("udp+tcp", host)
			r.requireGone("udp+tcp", ap) // before: nothing answers there
			r.add("udp+tcp", ap)
			r.ask("udp+tcp", ap)
			r.ask("udp+tcp", r.at("udp+tcp", "127.0.0.1"))
		})
	}
}

// G2: DoT, DoH and DoQ on an added address, IPv4 and IPv6, with the certificate the store holds.
func TestAnAddedTLSListenerServesWithTheStoresCertificate(t *testing.T) {
	for _, kind := range []string{"dot", "doh", "doq"} {
		for _, host := range []string{"127.0.0.2", "::1"} {
			t.Run(kind+" "+host, func(t *testing.T) {
				liveNeedAddr(t, host)
				r := newLiveRig(t)
				ap := r.at(kind, host)
				r.requireGone(kind, ap)
				r.add(kind, ap)
				r.ask(kind, ap)
			})
		}
	}
}

// G2: an added DoH listener trusts the front ends the start was given: the client an X-Forwarded-For names is believed
// from the front end and not from anyone else, as on the listener the start bound. The ACL refuses 203.0.113.9.
func TestAnAddedDoHListenerTrustsTheFrontEndsOfTheStart(t *testing.T) {
	r := newLiveRig(t)
	added := r.at("doh", "127.0.0.2")
	r.add("doh", added)
	const named = "203.0.113.9"
	refused := func(ap, source string) byte {
		c := r.doh(r.at("doh", ap), source)
		resp, body := c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", named))
		if resp.StatusCode != 200 || len(body) < 12 {
			t.Fatalf("DoH on %s as %s: status %d body %x", ap, source, resp.StatusCode, body)
		}
		return body[3] & 0x0f
	}
	for _, ap := range []string{"127.0.0.1", "127.0.0.2"} { // the start's own listener is the control
		if got := refused(ap, liveFront); got != 5 {
			t.Fatalf("DoH on %s from the trusted front end naming %s: rcode %d, want 5 (REFUSED): the header was not believed", ap, named, got)
		}
		if got := refused(ap, "127.0.0.3"); got != 0 {
			t.Fatalf("DoH on %s from a client that is not trusted naming %s: rcode %d, want 0: the header was believed", ap, named, got)
		}
	}
}

// G3: a remove closes that listener, bound by the start or added, logs it, and leaves every other listener serving.
func TestARemovedListenerStopsAndTheOthersKeepServing(t *testing.T) {
	for _, kind := range liveKinds {
		t.Run(kind, func(t *testing.T) {
			r := newLiveRig(t)
			bound, added := r.at(kind, "127.0.0.1"), r.at(kind, "127.0.0.2")
			r.add(kind, added)
			r.ask(kind, bound)
			r.ask(kind, added)

			r.remove(kind, bound)
			r.requireGone(kind, bound)
			r.ask(kind, added)
			for _, other := range liveKinds {
				if other != kind {
					r.ask(other, r.at(other, "127.0.0.1"))
				}
			}

			r.remove(kind, added)
			r.requireGone(kind, added)
		})
	}
}

// G3: a removed listener gives its descriptors back, and add and remove cycles leave nothing registered for the stop.
func TestRemovingAnAddedListenerReleasesItsDescriptorsAndLeavesNoCloserBehind(t *testing.T) {
	r := newLiveRig(t)
	base, closers := liveOpenFDs(t), r.closers()
	held := map[string]int{"udp+tcp": 2, "dot": 1, "doh": 1, "doq": 1}
	for _, kind := range liveKinds {
		ap := r.at(kind, "127.0.0.2")
		for round := range 3 {
			when := kind + " round " + strconv.Itoa(round)
			r.add(kind, ap)
			liveRequireFDs(t, base+held[kind], when+" added")
			r.remove(kind, ap)
			liveRequireFDs(t, base, when+" removed")
		}
	}
	if got := r.closers(); got != closers {
		t.Fatalf("the gateway holds %d closers after the cycles, %d before: a removed listener stays registered", got, closers)
	}
}

// G11: a shutdown closes every added listener, and one that was removed is not closed again: DoQ's closer counts its runs.
func TestShutdownClosesEveryAddedListenerAndNotARemovedOneAgain(t *testing.T) {
	r := newLiveRig(t)
	doqClosed := r.countDoQClosers()
	for _, kind := range liveKinds {
		r.add(kind, r.at(kind, "127.0.0.2"))
	}
	r.remove("doq", r.at("doq", "127.0.0.2"))
	eventually(t, "the removed DoQ listener's closer to run", func() bool { return doqClosed.Load() == 1 })

	done := make(chan struct{})
	go func() { r.srv.shutdown(); close(done) }()
	waitClosed(t, done, "the shutdown to end")

	if text := r.logs.text(); strings.Contains(text, "still running") {
		t.Fatalf("a serving goroutine outlived the shutdown:\n%s", text)
	}
	for _, kind := range liveKinds {
		r.requireGone(kind, r.at(kind, "127.0.0.2"))
	}
	if got := doqClosed.Load(); got != 2 {
		t.Fatalf("DoQ's closer ran %d times, want 2: the start's listener at the shutdown and the removed one at its remove, not again", got)
	}
}

// The sockets may ride with any byte of the frame: the gateway reads rights from every read, so it takes them from
// whichever part carries them.
func TestTheSocketsMayRideWithAnyPartOfTheFrame(t *testing.T) {
	r := newLiveRig(t)
	ap := r.at("udp+tcp", "127.0.0.2")
	frame := r.addFrame("udp+tcp", ap)
	for _, row := range []struct {
		name  string
		cuts  []int // where the frame is cut into sendmsg calls
		carry int   // the call whose sendmsg carries the sockets
	}{
		{"the first four bytes", []int{4}, 0},
		{"the length", []int{4, 8}, 1},
		{"the body", []int{8}, 1},
		{"the last byte", []int{len(frame) - 1}, 1},
		{"every byte alone, the sockets on the fifth", everyByte(frame), 4},
	} {
		sockets := liveSockets(t, "udp+tcp", ap)
		var parts []livePart
		from := 0
		for _, to := range append(row.cuts, len(frame)) {
			parts = append(parts, livePart{data: frame[from:to]})
			from = to
		}
		parts[row.carry].fds = sockets
		if got := r.exchange(false, parts...); got != "ok" {
			t.Fatalf("sockets with %s: reply %q, want ok", row.name, got)
		}
		r.waitLine("listening udp+tcp " + ap.String())
		r.ask("udp+tcp", ap)
		r.remove("udp+tcp", ap)
		r.requireGone("udp+tcp", ap)
	}
}

func everyByte(frame []byte) []int {
	cuts := make([]int, 0, len(frame)-1)
	for i := 1; i < len(frame); i++ {
		cuts = append(cuts, i)
	}
	return cuts
}

// livePair is two connected stream sockets: the test sends one and keeps the other, which reads EOF once the last copy of
// the sent one is closed. After the test closes its own, that is the gateway's.
func livePair(t *testing.T) (kept *os.File, sent int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	kept = os.NewFile(uintptr(fds[0]), "kept")
	t.Cleanup(func() { _ = kept.Close() })
	return kept, fds[1]
}

func liveRequireEOF(t *testing.T, kept *os.File, row string) {
	t.Helper()
	_ = kept.SetReadDeadline(time.Now().Add(watchdog))
	if n, err := kept.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: reading the other end of the socket sent got %d bytes and %v, want EOF: the gateway still holds its copy", row, n, err)
	}
}
