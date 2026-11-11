package main

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// A panic inside the decider is a SERVFAIL, as an exception of the Python decider was (its resolve wrapper turned it into
// MODULE_ERROR, a SERVFAIL, and logged one line per 30 seconds): it must not take the process down, and the next query is
// answered as usual. The two panics here come inside one window, so one line is logged, with the panic value.
func TestADeciderPanicIsAServfailLoggedOncePerWindowAndTheGatewayKeepsServing(t *testing.T) {
	client, wire := netip.MustParseAddr(clientAllowed), buildQuery(t, 0x0042, "boom.example.", true)
	var mu sync.Mutex
	var lines []string
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	calls := 0
	decide := func([]byte, string, func([]byte) []byte, string, string, string) []byte {
		calls++
		if calls <= 2 {
			panic(fmt.Sprintf("decider broke on call %d", calls))
		}
		return []byte("fine")
	}
	g := newGateway(nil, decide, nil, 3600e9, logf)
	ask := func(what string) []byte {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s: resolve panicked with %v: the panic reached the process", what, r)
			}
		}()
		return g.resolve(context.Background(), client, netip.Addr{}, clientUDP, wire, noForward(t))
	}
	for i := 1; i <= 2; i++ {
		if got, want := ask(fmt.Sprintf("panicking query %d", i)), buildServfail(wire); !bytes.Equal(got, want) {
			t.Fatalf("panicking query %d: reply %x, want SERVFAIL %x", i, got, want)
		}
	}
	mu.Lock()
	logged := append([]string(nil), lines...)
	mu.Unlock()
	if len(logged) != 1 || !strings.Contains(logged[0], "decider broke on call 1") {
		t.Fatalf("two panics in one window logged %q, want one line with the first panic's value", logged)
	}
	if got := ask("the next query"); string(got) != "fine" {
		t.Fatalf("the query after the panics got %q, want the decider's answer", got)
	}
}

// The log of a decider that keeps failing is rearmed once the window has passed: a panic just inside the window is not
// logged, one at the window's end is, and the window then starts again from that line. The gateway's clock is the test's.
func TestADeciderPanicIsLoggedAgainOnceTheWindowHasPassed(t *testing.T) {
	client, wire := netip.MustParseAddr(clientAllowed), buildQuery(t, 0x0042, "boom.example.", true)
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	calls := 0
	decide := func([]byte, string, func([]byte) []byte, string, string, string) []byte {
		calls++
		panic(fmt.Sprintf("decider broke on call %d", calls))
	}
	g := newGateway(nil, decide, nil, 3600e9, logf)
	now := time.Unix(1_000_000, 0)
	g.now = func() time.Time { return now }
	ask := func() { g.resolve(context.Background(), client, netip.Addr{}, clientUDP, wire, noForward(t)) }

	ask() // call 1: the first failure is logged
	now = now.Add(deciderFailureLogInterval - time.Nanosecond)
	ask() // call 2: just inside the window
	if len(lines) != 1 {
		t.Fatalf("a failure just inside the window logged %q, want only the first line", lines)
	}
	now = now.Add(time.Nanosecond)
	ask() // call 3: the window's end
	if len(lines) != 2 || !strings.Contains(lines[1], "decider broke on call 3") {
		t.Fatalf("a failure at the window's end logged %q, want a second line, with call 3's value", lines)
	}
	now = now.Add(deciderFailureLogInterval - time.Nanosecond)
	ask() // call 4: inside the window that line started
	if len(lines) != 2 {
		t.Fatalf("a failure inside the second window logged %q, want no third line", lines)
	}
}
