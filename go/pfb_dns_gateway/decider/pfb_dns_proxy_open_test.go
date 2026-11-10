// Tests of the decider's in-process surface (#3791 step A): Open, Resolve and Close, which the gateway calls in place of the
// Python decision protocol. The behaviour they pin is serve_decisions and Frontend.resolve of
// src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py, tests/dns_proxy/test_no_module.py and test_decider_cli.py.
package decider

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

// lockedLog is a log several goroutines write (the observer's, a log writer's) and a test reads.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// captureLockedLog is captureLog for a log that goroutines write.
func captureLockedLog(t *testing.T) *lockedLog {
	t.Helper()
	out := &lockedLog{}
	previous := logOutput
	logOutput = out
	t.Cleanup(func() { logOutput = previous })
	return out
}

// moduleDir is a module directory the module boots from.
func moduleDir(t *testing.T) string { return modIniDir(t, "[MAIN]\npython_enable = true\n") }

// openOK is Open that must succeed, closed when the test ends.
func openOK(t *testing.T, opts Options) *Frontend {
	t.Helper()
	f, err := Open(opts)
	if err != nil || f == nil {
		t.Fatalf("Open(%+v) = (%v, %v), want a decider and no error", opts, f, err)
	}
	t.Cleanup(f.Close)
	return f
}

// --- Open ----------------------------------------------------------------------------------------

func TestOpenBootsTheModuleAndResolveAsksIt(t *testing.T) {
	rlQuietLog(t)
	f := openOK(t, Options{ModuleDir: moduleDir(t)})
	if f.module == nil {
		t.Fatal("Open booted no module")
	}
	reply := f.Resolve(queryWire(t, allowed, dnswire.RD), testClient, unboundAnswering192_0_2_77(t), "UDP", "", "")
	if got := raceAddresses(t, reply); got != "192.0.2.77" {
		t.Errorf("the answer carries %q, want Unbound's 192.0.2.77", got)
	}
}

func TestOpenReturnsTheBootErrorAndLeavesNothingRunning(t *testing.T) {
	dir := modIniDir(t, "[MAIN]\npython_enable = banana\n")
	f, err := Open(Options{ModuleDir: dir, Observer: true})
	if err == nil || f != nil || !strings.Contains(err.Error(), "python_enable") {
		t.Fatalf("Open with a module that cannot initialise = (%v, %v), want (nil, an error naming python_enable)", f, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "pfb_upstream.sock")); !os.IsNotExist(err) {
		t.Errorf("the observer socket exists after a failed boot (lstat: %v), want nothing left running", err)
	}
}

func TestOpenWithNoModuleBootsNoModuleAndNeedsNoModuleDir(t *testing.T) {
	f := openOK(t, Options{NoModule: true})
	if f.module != nil || f.replyLog != nil || f.observer != nil {
		t.Errorf("Open(NoModule) = module %v, reply log %v, observer %v, want none of them", f.module, f.replyLog, f.observer)
	}
}

// argparse's two rules of pfb_dns_proxy.py: --reply-log needs --no-module, --observer excludes it.
func TestOpenRejectsTheFlagCombinationsTheCLIRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		opts Options
		want string
	}{
		"the reply log without NoModule": {Options{ModuleDir: "unused", ReplyLog: true}, "--reply-log needs --no-module"},
		"the observer with NoModule":     {Options{NoModule: true, Observer: true}, "--observer cannot be used with --no-module"},
	} {
		f, err := Open(tc.opts)
		if err == nil || f != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Open = (%v, %v), want (nil, an error holding %q)", name, f, err, tc.want)
		}
	}
}

// --- Resolve without the module -------------------------------------------------------------------

// Python's resolve with no module: after the header checks, the query is forwarded and Unbound's reply relayed; no reply
// is the proxy's SERVFAIL. Everything before that is the module path's, so each case is asked of both and must agree.
func TestNoModuleAnswersWhatTheModulePathAnswersWhereNoModuleDecides(t *testing.T) {
	rlQuietLog(t)
	bare := openOK(t, Options{NoModule: true})
	withModule := openOK(t, Options{ModuleDir: moduleDir(t)})
	twoQuestions := encode(t, &dnswire.Message{ID: 7, Flags: dnswire.RD, Questions: append(question(allowed, dnswire.CLASS_IN), question("other.example.", dnswire.CLASS_IN)...)})
	chaos := encode(t, &dnswire.Message{ID: 8, Flags: dnswire.RD, Questions: question(allowed, 3)})
	good := queryWire(t, allowed, dnswire.RD)
	for _, c := range []struct {
		name       string
		wire       []byte
		answers    bool // Unbound has an answer for it
		wantAsked  int
		wantNilOut bool
	}{
		{"a query Unbound answers", good, true, 1, false},
		{"a query Unbound does not answer", good, false, 1, false},
		{"a response", append(header(1, dnswire.QR, 1, 0, 0, 0), qtc...), true, 0, true},
		{"an opcode other than QUERY", append(header(2, 4<<11, 1, 0, 0, 0), qtc...), true, 1, false},
		{"two questions", twoQuestions, true, 0, false},
		{"TC set", queryWire(t, allowed, dnswire.RD|dnswire.TC), true, 1, false},
		{"a malformed question", header(3, dnswire.RD, 1, 0, 0, 0), true, 0, false},
		{"a class Unbound answers itself", chaos, true, 1, false},
		{"a header alone", header(4, dnswire.RD, 0, 0, 0, 0), true, 0, false},
	} {
		var got [2][]byte
		for i, f := range []*Frontend{bare, withModule} {
			r := &recorder{}
			if c.answers {
				r.answer = func(wire []byte) []byte {
					if _, err := dnswire.Parse(wire); err != nil {
						return []byte("not a DNS message") // relayed as it is by both
					}
					return replyTo(t, wire, 0, aRecord(allowed, 300, 77))
				}
			}
			got[i] = f.Resolve(c.wire, testClient, r.forward, "UDP", "", "")
			if len(r.wires) != c.wantAsked {
				t.Errorf("%s (module=%v): Unbound was asked %d times, want %d", c.name, i == 1, len(r.wires), c.wantAsked)
			}
		}
		if !bytes.Equal(got[0], got[1]) {
			t.Errorf("%s: without the module %x, with it %x, want the same", c.name, got[0], got[1])
		}
		if (got[0] == nil) != c.wantNilOut {
			t.Errorf("%s: reply %x, dropped = %v, want dropped = %v", c.name, got[0], got[0] == nil, c.wantNilOut)
		}
	}
}

func TestNoModuleRelaysUnboundsReplyAsItIs(t *testing.T) {
	f := openOK(t, Options{NoModule: true})
	wire := queryWire(t, allowed, dnswire.RD)
	reply := replyTo(t, wire, 0, aRecord(allowed, 300, 77))
	if got := f.Resolve(wire, testClient, answering(reply).forward, "UDP", "", ""); !bytes.Equal(got, reply) {
		t.Errorf("reply = %x, want Unbound's %x unchanged", got, reply)
	}
}

func TestNoModuleAnswersServfailWhenUnboundIsSilentAndSaysSoOnce(t *testing.T) {
	log := captureLog(t)
	f := openOK(t, Options{NoModule: true})
	wire := queryWire(t, allowed, dnswire.RD)
	for range 3 {
		reply := f.Resolve(wire, testClient, (&recorder{}).forward, "UDP", "", "")
		wantBare(t, "silence", reply, 0x4242, dnswire.QR|dnswire.RD|dnswire.RA|RCODE_SERVFAIL, RCODE_SERVFAIL, question(allowed, dnswire.CLASS_IN))
	}
	if got := logLines(log); len(got) != 1 || got[0] != "pfb_dns_proxy warning: no reply from Unbound for allowed.example. A" {
		t.Errorf("log = %q, want the one silence line inside the interval", got)
	}
}

// --- Resolve under concurrency ---------------------------------------------------------------------

// Every goroutine asks the same Frontend: the latches (silence, oversized chase, the malformed-report warning) are the only
// shared state a Resolve writes. Under -race this fails on an unguarded one, and every answer must be its own query's.
func TestResolveIsSafeForConcurrentUseWithAndWithoutTheModule(t *testing.T) {
	rlQuietLog(t)
	for name, opts := range map[string]Options{
		"with the module": {ModuleDir: moduleDir(t)},
		"no module":       {NoModule: true},
	} {
		f := openOK(t, opts)
		var wg sync.WaitGroup
		start := make(chan struct{}) // every goroutine at the latches at once
		for g := range 32 {
			wg.Go(func() {
				<-start
				for i := range 20 {
					id := uint16(g*100 + i)
					wire := raceQuery(t, id, fmt.Sprintf("host%d.example.", g))
					if i%2 == 0 { // Unbound says nothing: the proxy's SERVFAIL, and the silence latch
						reply := f.Resolve(wire, testClient, func([]byte) []byte { return nil }, "UDP", "", "")
						if m, err := dnswire.Parse(reply); err != nil || m.ID != id || m.Rcode() != RCODE_SERVFAIL {
							t.Errorf("%s: silent upstream for id %d: reply %x (%v), want SERVFAIL for that id", name, id, reply, err)
						}
						continue
					}
					reply := f.Resolve(wire, testClient, unboundAnswering192_0_2_77(t), "UDP", "", "")
					if m, err := dnswire.Parse(reply); err != nil || m.ID != id || raceAddresses(t, reply) != "192.0.2.77" {
						t.Errorf("%s: id %d: reply %x (%v), want its own 192.0.2.77 answer", name, id, reply, err)
					}
				}
			})
		}
		close(start)
		wg.Wait()
	}
}

// The oversized-chase latch needs a 64 KiB chase to be reached through Resolve, and the malformed-report latch an observer:
// both are taken here directly, from many goroutines at once, as the silence latch is by the test above. Inside one
// interval a latch lets one line through however many ask.
func TestTheFrontendsOtherLatchesAreSafeForConcurrentUseAndLetOneLineThrough(t *testing.T) {
	log := captureLockedLog(t)
	f := newFrontend(nil)
	var chase, silence atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			for range 50 {
				if f.due(&f.oversizedChase) {
					chase.Add(1)
				}
				if f.due(&f.silence) {
					silence.Add(1)
				}
				f.relayUpstreamResponse([]byte("not json")) // malformed: the module is not reached
			}
		})
	}
	close(start)
	wg.Wait()
	if chase.Load() != 1 || silence.Load() != 1 {
		t.Errorf("lines let through inside one interval: chase %d, silence %d, want 1 each", chase.Load(), silence.Load())
	}
	if got := strings.Count(log.String(), "malformed upstream report from the observer"); got != 1 {
		t.Errorf("the malformed-report warning was logged %d times, want once; log = %q", got, log.String())
	}
}

// --- Close -----------------------------------------------------------------------------------------

func TestCloseDeinitsTheModuleOnceAndASecondCloseDoesNothing(t *testing.T) {
	log := captureLockedLog(t)
	f, err := Open(Options{ModuleDir: moduleDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	f.Close()
	if got := strings.Count(log.String(), "pfb_unbound.py script exiting"); got != 1 {
		t.Errorf("the module's exit line was logged %d times over two Close calls, want 1; log = %q", got, log.String())
	}
	if f.module.reloadStop != nil || f.module.logs != nil || f.module.maxmind != nil {
		t.Errorf("after Close: reload watcher %v, log writer %v, GeoIP reader %v, want all stopped", f.module.reloadStop != nil, f.module.logs != nil, f.module.maxmind != nil)
	}
}

func TestCloseOfADeciderWithNoModuleIsANoOp(t *testing.T) {
	f, err := Open(Options{NoModule: true})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	f.Close()
}
