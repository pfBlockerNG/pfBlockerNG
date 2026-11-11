package main

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

// What the rc stop gives the gateway after TERM before it sends KILL: the `5)` tick of the stop script that
// pfb_dns_proxy_service() writes (pfblockerng.inc), pinned there by DnsProxyServiceTest
// (testAProcessIgnoringTermIsKilledAfterFiveTicksAndItsStalePidfilesAreRemoved). A KILL leaves the ready file behind.
const rcStopKillAfter = 5 * time.Second

// The default budget has to end the shutdown before the rc stop's KILL: the transports' stop and the decider's close share it.
func TestTheDefaultShutdownBudgetEndsBeforeTheRcStopSendsKill(t *testing.T) {
	if defaultShutdownBudget >= rcStopKillAfter {
		t.Fatalf("the shutdown budget is %v, the rc stop sends KILL %v after TERM: a slow shutdown would be killed with its ready file in place", defaultShutdownBudget, rcStopKillAfter)
	}
}

// stuckFrontend is a decider whose Close does not return until the test lets it.
type stuckFrontend struct {
	echoFrontend
	release chan struct{}
}

func (f stuckFrontend) Close() { <-f.release }

// A decider that cannot be closed does not hold the shutdown past its budget: the gateway says so and returns, and the process
// exit takes the decider with it. The ready file goes first, so that even this shutdown leaves none behind.
func TestShutdownEndsInsideItsBudgetWhenTheDeciderCannotBeClosed(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	stuck := stuckFrontend{release: make(chan struct{})}
	t.Cleanup(sync.OnceFunc(func() { close(stuck.release) }))
	cfg.open = func(decider.Options) (frontend, error) { return stuck, nil }
	cfg.shutdownBudget = 50 * time.Millisecond
	cfg.readyFile = t.TempDir() + "/ready"
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end inside its budget")
	if text := logs.text(); !strings.Contains(text, "the decider did not close within") {
		t.Fatalf("the log must say that the decider was left:\n%s", text)
	}
	if _, err := os.Stat(cfg.readyFile); err == nil {
		t.Fatal("the ready file is still there after the shutdown")
	}
}

// heldFrontend is a decider that ignores the cancelling of a query: Resolve says it has the query, then holds it until
// release. Close, when closeGate is set, does not return until the gate is closed; closed says it was called.
type heldFrontend struct {
	entered   chan struct{}
	release   chan struct{}
	closeGate chan struct{}
	closing   chan struct{} // receives once when Close has begun, when set
	closed    atomic.Bool
}

func (f *heldFrontend) Resolve([]byte, string, func([]byte) []byte, string, string, string) []byte {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.release
	return nil
}

func (f *heldFrontend) Close() {
	f.closed.Store(true)
	if f.closing != nil {
		select {
		case f.closing <- struct{}{}:
		default:
		}
	}
	if f.closeGate != nil {
		<-f.closeGate
	}
}

// startHeldQuery starts a server whose decider is fe, sends it a TCP query and returns once the decider holds it.
func startHeldQuery(t *testing.T, fe *heldFrontend, stopBound, budget time.Duration, tweaks ...func(*config)) (*server, net.Conn, *capture) {
	t.Helper()
	cfg, logs := lifecycleConfig(t)
	cfg.open = func(decider.Options) (frontend, error) { return fe, nil }
	cfg.shutdownBudget = budget
	for _, tweak := range tweaks {
		tweak(&cfg)
	}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	srv.g.stopBound = stopBound
	var addr netip.AddrPort
	for _, l := range strings.Split(logs.text(), "\n") {
		if strings.HasPrefix(l, "listening udp+tcp ") {
			addr = listenAddr(t, l)
		}
	}
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	tcpSend(t, c, buildQuery(t, 1, "held.example.", true))
	waitClosed(t, fe.entered, "the decider to hold the query")
	return srv, c, logs
}

// A query that never finishes does not keep the decider open: once the transports have stopped and the drain bound has
// passed, the decider is closed all the same, so its watchers stop and its observer socket goes. Close is safe for the query
// still inside it (decider.Frontend.Close).
func TestShutdownClosesTheDeciderWhileAQueryIsStillInIt(t *testing.T) {
	fe := &heldFrontend{entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(sync.OnceFunc(func() { close(fe.release) }))
	srv, _, logs := startHeldQuery(t, fe, 20*time.Millisecond, 10*time.Second)
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end")
	if !fe.closed.Load() {
		t.Fatal("the decider was not closed while a query was still running in it")
	}
	if text := logs.text(); !strings.Contains(text, "queries are still running in the decider: closing it anyway") {
		t.Fatalf("the log must say that the decider is closed with a query in it:\n%s", text)
	}
}

// The close on that path shares the shutdown budget like the normal one: a Close that never returns ends the shutdown at
// the budget, with the query still held.
func TestShutdownEndsWhenTheDeciderCannotBeClosedWhileAQueryIsStillInIt(t *testing.T) {
	fe := &heldFrontend{entered: make(chan struct{}, 1), release: make(chan struct{}), closeGate: make(chan struct{})}
	t.Cleanup(sync.OnceFunc(func() { close(fe.release) }))
	t.Cleanup(sync.OnceFunc(func() { close(fe.closeGate) }))
	srv, _, logs := startHeldQuery(t, fe, 20*time.Millisecond, 100*time.Millisecond)
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end although the decider cannot be closed")
	if text := logs.text(); !strings.Contains(text, "the decider did not close within") {
		t.Fatalf("the log must say that the decider was left:\n%s", text)
	}
}

// fakeBudgetClock is the time of a shutdown under test: now is moved by the test, and a timer is asked for once and fires
// when the test says. No duration is waited for.
type fakeBudgetClock struct {
	mu      sync.Mutex
	t       time.Time
	asked   chan time.Duration // what each timer was asked for
	expired chan time.Time     // a timer fires when the test sends on it
}

func newFakeBudgetClock() *fakeBudgetClock {
	return &fakeBudgetClock{t: time.Unix(1_000_000, 0), asked: make(chan time.Duration, 4), expired: make(chan time.Time, 1)}
}

func (f *fakeBudgetClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeBudgetClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func (f *fakeBudgetClock) timer(d time.Duration) (<-chan time.Time, func() bool) {
	f.asked <- d
	return f.expired, func() bool { return true }
}

func (f *fakeBudgetClock) config(cfg *config) { cfg.clock = budgetClock{now: f.now, timer: f.timer} }

// The stop of the transports and the close of the decider share one budget: a stop that took some of it leaves the decider
// only what is left, and a Close that never returns ends the shutdown when that runs out. The fake time moves by 150 ms from
// inside stop(), once it has closed the client connections (clientsClosed), so the advance is before stop() returns and
// no goroutine races it. The held query is never let go: stop() gives up on it after its second bound, as production does,
// and the decider is given the budget less the 150 ms.
func TestShutdownGivesTheDeciderOnlyWhatTheStopLeftOfTheBudget(t *testing.T) {
	const budget, stopTook = 800 * time.Millisecond, 150 * time.Millisecond
	clock := newFakeBudgetClock()
	fe := &heldFrontend{entered: make(chan struct{}, 1), release: make(chan struct{}), closeGate: make(chan struct{}), closing: make(chan struct{}, 1)}
	t.Cleanup(sync.OnceFunc(func() { close(fe.release) }))
	t.Cleanup(sync.OnceFunc(func() { close(fe.closeGate) }))
	srv, _, logs := startHeldQuery(t, fe, 20*time.Millisecond, budget, clock.config)
	srv.g.clientsClosed = func() { clock.advance(stopTook) }
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()

	select {
	case asked := <-clock.asked:
		if want := budget - stopTook; asked != want {
			t.Fatalf("the decider was given %v to close in, want what the stop left of the budget: %v", asked, want)
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: shutdown never started its timer for the decider's close")
	}
	waitClosed(t, fe.closing, "the decider's Close to begin")
	select {
	case <-done:
		t.Fatal("shutdown ended before the budget ran out, with the decider's Close still running")
	default:
	}
	clock.expired <- time.Time{}
	waitClosed(t, done, "shutdown to end once the budget ran out")
	if !fe.closed.Load() {
		t.Fatal("the decider was not closed although the stop drained")
	}
	if text := logs.text(); !strings.Contains(text, "the decider did not close within") {
		t.Fatalf("the log must say that the decider was left:\n%s", text)
	}
}
