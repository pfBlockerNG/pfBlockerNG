// Tests for the Go translation of pfb_unbound.py's live DNSBL update (ADR-10): _reload_read_generation,
// _reload_ram_gate_ok, _reload_run_swap, _reload_write_applied, _build_swap_snapshot and pfb_reload_watcher, plus the
// runtime state a swap carries (the module globals gpListDB, gpNetDB, noAAAADB and safeSearchDB that Python's swap never
// touches). They mirror tests/test_adr10_watcher.py (TestRamGate, TestGenerationReader, TestRunSwap, TestWatcherLoop,
// TestAppliedMarker) and tests/test_adr10_swap.py. Python waits on a kqueue or a poll and its tests wait on the daemon
// thread; here the watcher's tick is a channel the test sends on and a build that must block waits on a channel, so no
// test sleeps or waits on a clock.
package decider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// rlDeclineMillion is the line Python logs (log_info) when the gate declines a reload whose live snapshot holds
// 1,000,000 entries: (2 * 1000000 * 276) // (1024 * 1024) == 526.
const rlDeclineMillion = "pfb_dns_proxy info: [pfBlockerNG]: DNSBL reload DECLINED -- RAM-constrained box (projected ~526 MiB for 1000000 " +
	"entries would not fit total RAM); keeping current lists, the update needs the restart fallback\n"

const rlReloaded = "pfb_dns_proxy info: [pfBlockerNG]: DNSBL lists reloaded with no restart (zero-downtime swap)\n"

// rlQuietLog discards the log (it is written from several goroutines in the race tests); a test that reads the log
// captures it again afterwards.
func rlQuietLog(t *testing.T) {
	t.Helper()
	previous := logOutput
	logOutput = io.Discard
	t.Cleanup(func() { logOutput = previous })
}

// rlModule is a booted module whose reload watcher does not run, with plenty of RAM for a reload.
func rlModule(t *testing.T) *pfbUnbound {
	t.Helper()
	rlQuietLog(t)
	m := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\n"))
	m.stopReloadWatcher()
	m.totalRAM = func() (uint64, bool) { return 8 << 30, true }
	return m
}

// rlManifestModule is rlModule over a module directory holding a manifest and its feeds (opManifestModule).
func rlManifestModule(t *testing.T, main []string, feeds map[string][]string) (*pfbUnbound, string) {
	t.Helper()
	rlQuietLog(t)
	dir := opManifestModule(t, main, feeds)
	m := modMust(t, dir)
	m.stopReloadWatcher()
	m.totalRAM = func() (uint64, bool) { return 8 << 30, true }
	return m, dir
}

// rlWriteFeeds rewrites the manifest and the raw feed files of a module directory.
func rlWriteFeeds(t *testing.T, dir string, feeds map[string][]string) {
	t.Helper()
	rows := []map[string]string{}
	for name, lines := range feeds {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, map[string]string{"raw": name, "feed": name, "group": name, "log_flag": "1", "provenance": "feed"})
	}
	manifest, err := json.Marshal(map[string]any{"version": 1, "config": map[string]any{}, "feeds": rows})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
}

func rlPublish(t *testing.T, m *pfbUnbound, gen int) {
	t.Helper()
	if err := os.WriteFile(m.pfb.pfbPyReload, []byte(fmt.Sprintf("%d\n", gen)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rlApplied is the applied marker's text, "" if there is none.
func rlApplied(t *testing.T, m *pfbUnbound) string {
	t.Helper()
	data, err := os.ReadFile(m.pfb.pfbPyReloadApplied)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func rlWantApplied(t *testing.T, what string, m *pfbUnbound, want string) {
	t.Helper()
	if got := rlApplied(t, m); got != want {
		t.Errorf("%s: applied marker = %q, want %q", what, got, want)
	}
}

// rlBuilds is the reload builder under the test's hand: it records the generation each build observed and can fail or
// block. A build that has a gate waits for one receive on it, after announcing itself on entered.
type rlBuilds struct {
	m       *pfbUnbound
	mu      sync.Mutex
	gens    []int64
	errs    []error // the next builds fail with these, in order
	empty   bool    // a build returns no snapshot (Python's None)
	entered chan struct{}
	gate    chan struct{}
}

func newRlBuilds(m *pfbUnbound) *rlBuilds {
	b := &rlBuilds{m: m}
	m.reloadBuilder = b.build
	return b
}

func (b *rlBuilds) build() (*snapshot, error) {
	gen, _ := reloadReadGeneration(b.m.pfb.pfbPyReload)
	b.mu.Lock()
	b.gens = append(b.gens, gen)
	var err error
	if len(b.errs) > 0 {
		err, b.errs = b.errs[0], b.errs[1:]
	}
	empty := b.empty
	b.mu.Unlock()
	if b.gate != nil {
		b.entered <- struct{}{}
		<-b.gate
	}
	if err != nil {
		return nil, err
	}
	if empty {
		return nil, nil
	}
	s := newSnapshot()
	opBlockData(s, fmt.Sprintf("gen%d.example", gen), "1", 0)
	opFeed(s, 0, "F", "G")
	s.counts = int(gen)
	return s, nil
}

func (b *rlBuilds) built() []int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.gens)
}

func rlWantBuilds(t *testing.T, what string, b *rlBuilds, want ...int64) {
	t.Helper()
	if got := b.built(); !slices.Equal(got, want) {
		t.Errorf("%s: builds observed generations %v, want %v", what, got, want)
	}
}

func rlDomains(m *pfbUnbound) []string {
	var out []string
	for name := range m.snapshot.Load().dataDB {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func rlWantDomains(t *testing.T, what string, m *pfbUnbound, want ...string) {
	t.Helper()
	if got := rlDomains(m); !slices.Equal(got, want) {
		t.Errorf("%s: live dataDB = %v, want %v", what, got, want)
	}
}

// rlLoop runs the watcher's loop on a goroutine fed by a tick channel the test sends on. The loop takes a tick only when
// its previous drain is over, so the second send of a pair is the barrier that the first tick's drain finished.
type rlLoop struct {
	stop chan struct{}
	tick chan time.Time
	done chan struct{}
}

func startRlLoop(w *reloadWatcher) *rlLoop {
	l := &rlLoop{stop: make(chan struct{}), tick: make(chan time.Time), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		w.run(l.stop, l.tick)
	}()
	return l
}

// poll is two ticks: the first drains, the second returns once that drain is over.
func (l *rlLoop) poll() {
	l.tick <- time.Time{}
	l.tick <- time.Time{}
}

func (l *rlLoop) end(t *testing.T) {
	t.Helper()
	close(l.stop)
	chWait(t, "the loop to end after stop", l.done)
}

// rlHostileLog is a stderr whose every write fails (the Python tests' _RaisingStderr).
type rlHostileLog struct{}

func (rlHostileLog) Write([]byte) (int, error) { return 0, errors.New("stderr is closed") }

// --- a. the generation reader ---

func TestReloadReadGenerationFollowsPythonsIntParse(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       int64
		ok         bool
	}{
		{"an integer", "42\n", 42, true},
		{"zero", "0\n", 0, true},
		{"a leading plus", "+5\n", 5, true},
		{"a leading minus", "-3\n", -3, true},
		{"surrounding whitespace", "  9 \t\n", 9, true},
		{"digit underscores", "1_0\n", 10, true},
		{"no trailing newline", "11", 11, true},
		{"only the first line", "7\nignored second line\n", 7, true},
		{"a carriage return ends the first line", "7\r8\n", 7, true},
		// int() takes every Unicode decimal digit (category Nd), mixed with ASCII ones, and refuses past 4300 digits.
		{"an Arabic-Indic digit", "\u0663", 3, true},
		{"two Arabic-Indic digits", "\u0663\u0664", 34, true},
		{"Arabic-Indic digits and a newline", "\u0661\u0662\u0663\n", 123, true},
		{"an ASCII and an Arabic-Indic digit", "5\u0663", 53, true},
		{"Arabic-Indic digits around an underscore", "\u0663_\u0664", 34, true},
		{"a sign before Arabic-Indic digits", "-\u0663", -3, true},
		{"4300 digits (past int64: saturates)", strings.Repeat("1", 4300), math.MaxInt64, true},
		{"4301 digits (Python's int() limit)", strings.Repeat("1", 4301), 0, false},
		{"a superscript is a digit but no decimal", "\u00b2", 0, false},
		{"empty", "", 0, false},
		{"a blank first line", "\n8\n", 0, false},
		{"not a number", "not-a-number\n", 0, false},
		{"a number followed by text", "12abc\n", 0, false},
		{"a decimal", "1.5\n", 0, false},
	} {
		path := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(path, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		got, ok := reloadReadGeneration(path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s (%q): reloadReadGeneration = (%d, %v), want (%d, %v)", tc.name, tc.text, got, ok, tc.want, tc.ok)
		}
	}
}

func TestReloadReadGenerationOfAnAbsentFileOrADirectoryIsNone(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{"absent": filepath.Join(dir, "nope"), "a directory": dir} {
		if got, ok := reloadReadGeneration(path); ok {
			t.Errorf("%s: reloadReadGeneration = (%d, true), want none", name, got)
		}
	}
}

// --- b. the RAM gate ---

func ramOf(total uint64) func() (uint64, bool) { return func() (uint64, bool) { return total, true } }

func TestReloadRAMGateAdmitsAReloadThatFits(t *testing.T) {
	if !reloadRAMGateOK(1000, ramOf(4<<30)) {
		t.Errorf("1000 entries on 4 GiB: declined, want admitted")
	}
}

func TestReloadRAMGateDeclinesAReloadThatDoesNotFit(t *testing.T) {
	// 1.5M entries project to ~786 MiB of transient; 200 MiB cannot hold it.
	if reloadRAMGateOK(1_500_000, ramOf(200<<20)) {
		t.Errorf("1.5M entries on 200 MiB: admitted, want declined")
	}
}

// The projection is 2 x entries x 276 bytes plus 64 MiB of headroom: exactly that fits, one byte short does not. The
// numbers are Python's constants, written out so that a changed constant fails here.
func TestReloadRAMGateBoundaryIsExactlyTheProjectionPlusHeadroom(t *testing.T) {
	const entries = 10
	projected := uint64(2*entries*276 + 64*1024*1024)
	if !reloadRAMGateOK(entries, ramOf(projected)) {
		t.Errorf("total RAM = projected (%d): declined, want admitted", projected)
	}
	if reloadRAMGateOK(entries, ramOf(projected-1)) {
		t.Errorf("total RAM = projected-1 (%d): admitted, want declined", projected-1)
	}
}

func TestReloadRAMGateDeclinesWhenTotalRAMIsUnknown(t *testing.T) {
	if reloadRAMGateOK(1000, func() (uint64, bool) { return 1 << 40, false }) {
		t.Errorf("unknown total RAM: admitted, want declined (fail closed)")
	}
}

// The gate projects the LIVE snapshot's counts + regex_count, not the build's size and not counts alone.
func TestReloadRunSwapProjectsTheLiveSnapshotsCountsPlusRegexCount(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { s.counts, s.regexCount = 1, 1_000_000 })
	m.totalRAM = ramOf(uint64(2*1_000_001*276+64*1024*1024) - 1)
	if m.reloadRunSwap(b.build) {
		t.Errorf("one byte short of counts + regex_count: swapped, want declined")
	}
	m.totalRAM = ramOf(uint64(2*1_000_001*276 + 64*1024*1024))
	if !m.reloadRunSwap(b.build) {
		t.Errorf("exactly counts + regex_count: declined, want swapped")
	}
}

func TestReloadDeclineLogLineIsPythonsByteForByte(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { s.counts = 1_000_000 })
	m.totalRAM = ramOf(1 << 20)
	log := modCaptureLog(t)
	if m.reloadRunSwap(b.build) {
		t.Fatalf("reloadRunSwap = true, want a decline")
	}
	if got := log.String(); got != rlDeclineMillion {
		t.Errorf("decline log = %q, want %q", got, rlDeclineMillion)
	}
}

// rlStopAfterDeclines is a log that closes stop at its limit-th decline line: a loop that retries a declined generation
// is then ended by the log, so that it is the count that fails and the test does not hang.
type rlStopAfterDeclines struct {
	declines, limit int
	stop            chan struct{}
}

func (l *rlStopAfterDeclines) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "DNSBL reload DECLINED") {
		l.declines++
		if l.declines == l.limit {
			close(l.stop)
		}
	}
	return len(p), nil
}

// Python advances its last generation before the gate, so a declined generation is not retried and logs once; the next
// generation logs its own line.
func TestReloadDeclineIsLoggedOncePerDeclinedGeneration(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { s.counts = 1_000_000 })
	m.totalRAM = ramOf(1 << 20)
	w := m.newReloadWatcher()
	stop := make(chan struct{})
	log := &rlStopAfterDeclines{limit: 3, stop: stop}
	previous := logOutput
	logOutput = log
	t.Cleanup(func() { logOutput = previous })

	rlPublish(t, m, 1)
	w.drainAndSwap(stop)
	w.drainAndSwap(stop)
	if log.declines != 1 {
		t.Errorf("declines logged for generation 1 after two polls = %d, want 1", log.declines)
	}
	rlPublish(t, m, 2)
	w.drainAndSwap(stop)
	if log.declines != 2 {
		t.Errorf("declines logged after generation 2 = %d, want 2", log.declines)
	}
	rlWantBuilds(t, "declined generations", b)
}

func TestReloadDeclineKeepsTheOldSnapshotServingSkipsTheBuilderAndLeavesTheMarker(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { s.counts = 1_000_000; opBlockData(s, "old.example", "1", 0) })
	m.totalRAM = ramOf(1 << 20)
	rlPublish(t, m, 5)
	w := m.newReloadWatcher() // adopts 5 as the baseline and publishes it
	old := m.snapshot.Load()
	rlWantApplied(t, "before the advance", m, "5\n")

	rlPublish(t, m, 6)
	w.drainAndSwap(make(chan struct{}))

	if m.snapshot.Load() != old {
		t.Errorf("a declined reload replaced the live snapshot")
	}
	rlWantDomains(t, "after the decline", m, "old.example")
	rlWantBuilds(t, "after the decline", b)
	rlWantApplied(t, "after the decline", m, "5\n")
}

// --- c. the run-swap ---

func TestReloadRunSwapSwapsWhenTheGateAdmits(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0) })
	log := modCaptureLog(t)
	old := m.snapshot.Load()
	rlWantDomains(t, "before", m, "old.example")

	if !m.reloadRunSwap(b.build) {
		t.Fatalf("reloadRunSwap = false, want the swap reported")
	}
	if m.snapshot.Load() == old {
		t.Errorf("the live snapshot was not replaced")
	}
	rlWantDomains(t, "after", m, "gen0.example")
	if got := log.String(); !strings.Contains(got, rlReloaded) {
		t.Errorf("log = %q, want it to hold %q", got, rlReloaded)
	}
}

func TestReloadRunSwapKeepsTheOldSnapshotWhenTheBuildFails(t *testing.T) {
	for name, fail := range map[string]func(*rlBuilds){
		"the builder reports an error":                                func(b *rlBuilds) { b.errs = []error{errors.New("build blew up")} },
		"the builder returns no snapshot (a missing or bad manifest)": func(b *rlBuilds) { b.empty = true },
	} {
		m := rlModule(t)
		b := newRlBuilds(m)
		opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0) })
		fail(b)
		old := m.snapshot.Load()
		if m.reloadRunSwap(b.build) {
			t.Errorf("%s: reloadRunSwap = true, want false", name)
		}
		if m.snapshot.Load() != old {
			t.Errorf("%s: the live snapshot was replaced", name)
		}
		rlWantBuilds(t, name, b, 0)
	}
}

// --- d. the watcher ---

func TestReloadWatcherAdoptsTheBaselineWithoutABuildAndPublishesIt(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	rlPublish(t, m, 5)
	rlWantApplied(t, "before the watcher", m, "")

	w := m.newReloadWatcher()
	w.drainAndSwap(make(chan struct{}))

	rlWantApplied(t, "after the baseline", m, "5\n")
	rlWantBuilds(t, "the baseline generation", b)

	rlPublish(t, m, 6)
	w.drainAndSwap(make(chan struct{}))
	rlWantBuilds(t, "a genuine advance past the baseline", b, 6)
}

func TestReloadWatcherWithoutASentinelPublishesNoBaselineAndBuildsForTheFirstGeneration(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	w := m.newReloadWatcher()
	stop := make(chan struct{})
	w.drainAndSwap(stop)
	rlWantApplied(t, "no sentinel", m, "")
	rlWantBuilds(t, "no sentinel", b)

	rlPublish(t, m, 1) // None -> 1 is an advance
	w.drainAndSwap(stop)
	rlWantBuilds(t, "the first generation", b, 1)
}

func TestReloadWatcherAdvanceTriggersExactlyOneSwap(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0) })
	w := m.newReloadWatcher()
	stop := make(chan struct{})
	rlWantDomains(t, "before the advance", m, "old.example")

	rlPublish(t, m, 1)
	w.drainAndSwap(stop)
	w.drainAndSwap(stop)

	rlWantBuilds(t, "one advance, two polls", b, 1)
	rlWantDomains(t, "after the advance", m, "gen1.example")
}

func TestReloadWatcherDoesNotSwapWithoutAnAdvance(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	w := m.newReloadWatcher()
	stop := make(chan struct{})
	rlPublish(t, m, 5)
	w.drainAndSwap(stop)
	rlWantBuilds(t, "the first advance", b, 5)

	rlPublish(t, m, 5) // the same generation again: a duplicate event
	w.drainAndSwap(stop)
	rlPublish(t, m, 3) // a generation that went backwards is no advance either
	w.drainAndSwap(stop)
	rlWantBuilds(t, "the same and a lower generation", b, 5)
}

// A trigger that lands during a build is folded into one more build for the latest generation, never a parallel build:
// the build for generation 2 blocks while 3, 4 and 5 are published, and one build for 5 follows.
func TestReloadWatcherCoalescesAdvancesThatLandDuringABuild(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	b.gate, b.entered = make(chan struct{}), make(chan struct{}, 8)
	w := m.newReloadWatcher()
	stop, done := make(chan struct{}), make(chan struct{})

	rlPublish(t, m, 2)
	go func() {
		defer close(done)
		w.drainAndSwap(stop)
	}()
	chWait(t, "the generation 2 build to start", b.entered)
	for gen := 3; gen <= 5; gen++ {
		rlPublish(t, m, gen)
	}
	rlWantBuilds(t, "advances published during the build", b, 2) // the one goroutine that builds is blocked in it

	b.gate <- struct{}{} // release generation 2; the drain re-reads the sentinel and builds once more
	chWait(t, "the coalesced build to start", b.entered)
	b.gate <- struct{}{}
	chWait(t, "the drain to end", done)

	rlWantBuilds(t, "after the coalesced build", b, 2, 5)
	rlWantDomains(t, "after the coalesced build", m, "gen5.example")
	rlWantApplied(t, "after the coalesced build", m, "5\n")
}

func TestReloadWatcherKeepsTheOldSnapshotAndTheMarkerWhenABuildFailsAndDoesNotRetryTheGeneration(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0) })
	rlPublish(t, m, 8)
	w := m.newReloadWatcher()
	old := m.snapshot.Load()
	b.empty = true
	rlWantApplied(t, "before", m, "8\n")

	rlPublish(t, m, 9)
	stop := make(chan struct{})
	w.drainAndSwap(stop)
	w.drainAndSwap(stop)

	if m.snapshot.Load() != old {
		t.Errorf("a failed build replaced the live snapshot")
	}
	rlWantApplied(t, "after the failed build", m, "8\n")
	rlWantBuilds(t, "a failed generation", b, 9) // last_gen advanced before the build: it is not retried
}

// Python catches a builder's exception inside rebuild_and_swap, with a stderr that may be none or raise, and the watcher
// lives for the next generation. The Go builder's failure is its error; the log it writes may fail.
func TestReloadWatcherLivesAfterABuilderFailureForTheNextGeneration(t *testing.T) {
	for name, hostile := range map[string]bool{"stderr writes": false, "stderr write fails": true} {
		func() {
			m := rlModule(t)
			b := newRlBuilds(m)
			b.errs = []error{errors.New("build blew up")}
			opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0) })
			if hostile {
				previous := logOutput
				logOutput = rlHostileLog{}
				defer func() { logOutput = previous }()
			}
			loop := startRlLoop(m.newReloadWatcher())
			loop.poll() // the startup drain is over

			rlPublish(t, m, 1)
			loop.poll()
			rlWantDomains(t, name+": after the failed generation", m, "old.example")
			rlWantApplied(t, name+": after the failed generation", m, "")
			select {
			case <-loop.done:
				t.Errorf("%s: the watcher ended after a builder failure", name)
				return
			default:
			}

			rlPublish(t, m, 2)
			loop.poll()
			rlWantDomains(t, name+": after the next generation", m, "gen2.example")
			rlWantApplied(t, name+": after the next generation", m, "2\n")
			loop.end(t)
		}()
	}
}

func TestReloadWatcherLoopPollsOnEveryTickUntilStopped(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	loop := startRlLoop(m.newReloadWatcher())
	loop.poll()
	rlWantBuilds(t, "the startup drain with no sentinel", b)

	rlPublish(t, m, 1)
	loop.poll()
	rlWantBuilds(t, "after the first tick pair", b, 1)
	rlPublish(t, m, 2)
	loop.poll()
	rlWantBuilds(t, "after the second tick pair", b, 1, 2)
	loop.end(t)
}

func TestReloadWatcherDoesNotSwapOnceStopped(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	w := m.newReloadWatcher()
	stop := make(chan struct{})
	close(stop)
	rlPublish(t, m, 1)
	w.drainAndSwap(stop)
	rlWantBuilds(t, "a drain after stop", b)

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(stop, make(chan time.Time))
	}()
	chWait(t, "the loop to end at once", done)
	rlWantBuilds(t, "a loop already stopped", b)
}

// Python's uncaught exception in the watcher ends only the watcher thread (pfb_unbound.py:966-972): it writes
// "[pfBlockerNG]: reload watcher error: ..." and the thread is gone while pfb["reload_watcher"] stays True. A panic in the
// loop body ends only the watcher goroutine the same way; the module goes on answering.
func TestAPanicInTheReloadLoopEndsOnlyTheWatcherAndIsLogged(t *testing.T) {
	m := rlModule(t)
	opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0); opFeed(s, 0, "F", "G") })
	m.totalRAM = func() (uint64, bool) { panic("ram probe blew up") }
	log := modCaptureLog(t)
	tick, ended := make(chan time.Time), make(chan struct{})
	m.reloadTick = func() (<-chan time.Time, func()) { return tick, func() { close(ended) } }
	m.startReloadWatcher()

	// The loop's startup drain may already see the generation, and then it panics before it takes a tick.
	rlPublish(t, m, 1)
	select {
	case tick <- time.Time{}:
	case <-ended:
	}
	chWait(t, "the watcher goroutine to end after the panic", ended)

	if want := "[pfBlockerNG]: reload watcher error: ram probe blew up\n"; !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to hold %q", log.String(), want)
	}
	if m.reloadStop == nil {
		t.Errorf("the watcher is marked stopped after a panic; Python leaves reload_watcher True")
	}
	rlWantDomains(t, "after the watcher died", m, "old.example")
	m.stopReloadWatcher() // a stop of a watcher that has already ended returns
	if m.reloadStop != nil {
		t.Errorf("stopReloadWatcher left the watcher marked running")
	}
}

// rlTicks is the module's poll tick under the test's hand: it counts the watchers started (each takes one tick source)
// and holds the release of the tick source's cleanup, which runs when a watcher's goroutine ends.
type rlTicks struct {
	mu      sync.Mutex
	started int
	entered chan struct{}
	release chan struct{}
}

func rlInjectTicks(m *pfbUnbound, blockCleanup bool) *rlTicks {
	c := &rlTicks{entered: make(chan struct{}), release: make(chan struct{})}
	m.reloadTick = func() (<-chan time.Time, func()) {
		c.mu.Lock()
		c.started++
		c.mu.Unlock()
		return make(chan time.Time), func() {
			if blockCleanup {
				close(c.entered)
				<-c.release
			}
		}
	}
	return c
}

func (c *rlTicks) watchers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func TestStartReloadWatcherDoesNotStartASecondWatcherWhileOneRuns(t *testing.T) {
	m := rlModule(t)
	ticks := rlInjectTicks(m, false)
	t.Cleanup(m.stopReloadWatcher)
	m.startReloadWatcher()
	m.startReloadWatcher()
	if got := ticks.watchers(); got != 1 {
		t.Errorf("watchers started = %d after two starts, want 1", got)
	}
	m.stopReloadWatcher()
	m.startReloadWatcher()
	if got := ticks.watchers(); got != 2 {
		t.Errorf("watchers started = %d after a stop and a start, want 2", got)
	}
}

// stopReloadWatcher returns only once the watcher's goroutine has ended: its cleanup, which runs last, is still blocked
// here, so a stop that has returned did not wait.
func TestStopReloadWatcherWaitsForTheWatcherToEnd(t *testing.T) {
	m := rlModule(t)
	ticks := rlInjectTicks(m, true)
	m.startReloadWatcher()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		m.stopReloadWatcher()
	}()
	chWait(t, "the watcher to reach its cleanup after stop", ticks.entered)
	for range 10000 {
		select {
		case <-returned:
			t.Fatalf("stopReloadWatcher returned while the watcher's goroutine had not ended")
		default:
			runtime.Gosched()
		}
	}
	close(ticks.release)
	chWait(t, "stopReloadWatcher to return once the watcher ended", returned)
	if m.reloadStop != nil {
		t.Errorf("the watcher is still marked running after stopReloadWatcher")
	}
}

// Python starts the watcher in init_standard whatever python_enable says, after the init swap; the generation on disk at
// that moment is its baseline, adopted and published, never built.
func TestInitStandardStartsTheReloadWatcherAndPublishesTheBaseline(t *testing.T) {
	for name, ini := range map[string]string{
		"python_enable on":  "[MAIN]\npython_enable = true\n",
		"python_enable off": "[MAIN]\npython_enable = false\n",
		"no ini":            "",
	} {
		dir := t.TempDir()
		if ini != "" {
			if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "pfb_py_reload"), []byte("4\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m := modMust(t, dir)
		t.Cleanup(m.stopReloadWatcher)
		if m.reloadStop == nil {
			t.Errorf("%s: the reload watcher is not running after init", name)
		}
		rlWantApplied(t, name, m, "4\n")
		m.stopReloadWatcher()
		if m.reloadStop != nil {
			t.Errorf("%s: the watcher is still marked running after stopReloadWatcher", name)
		}
		m.startReloadWatcher()
		if m.reloadStop == nil {
			t.Errorf("%s: the watcher did not start again", name)
		}
		m.stopReloadWatcher()
	}
}

// --- e. the applied marker ---

func TestReloadWriteAppliedRoundTripsAndOverwrites(t *testing.T) {
	m := rlModule(t)
	m.reloadWriteApplied(5)
	if got, ok := reloadReadGeneration(m.pfb.pfbPyReloadApplied); !ok || got != 5 {
		t.Errorf("marker after 5 = (%d, %v), want (5, true)", got, ok)
	}
	m.reloadWriteApplied(9)
	if got, ok := reloadReadGeneration(m.pfb.pfbPyReloadApplied); !ok || got != 9 {
		t.Errorf("marker after 9 = (%d, %v), want (9, true)", got, ok)
	}
	rlWantApplied(t, "the file", m, "9\n")
	if _, err := os.Stat(m.pfb.pfbPyReloadApplied + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a stale temp file is left (stat error %v)", err)
	}
}

func TestReloadWriteAppliedWithoutAPathWritesNothing(t *testing.T) {
	m := rlModule(t)
	dir := filepath.Dir(m.pfb.pfbPyReloadApplied)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.pfb.pfbPyReloadApplied = ""
	m.reloadWriteApplied(3)
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("directory entries after a write with no path = %d, want the %d it had", len(after), len(before))
	}
}

func TestReloadWriteAppliedFailureIsLoggedAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	asDirectory := filepath.Join(dir, "marker-dir")
	if err := os.Mkdir(asDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"the directory is missing":  filepath.Join(dir, "missing", "pfb_py_reload.applied"),
		"the marker is a directory": asDirectory,
	} {
		m := rlModule(t)
		m.pfb.pfbPyReloadApplied = path
		log := modCaptureLog(t)
		m.reloadWriteApplied(7)
		want := "[pfBlockerNG]: failed to write applied-generation marker [ " + path + " ]: "
		if !strings.Contains(log.String(), want) {
			t.Errorf("%s: log = %q, want it to hold %q", name, log.String(), want)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("%s: a temp file is left (stat error %v)", name, err)
		}
	}
}

func TestReloadMarkerAdvancesOnlyOnASuccessfulSwap(t *testing.T) {
	m := rlModule(t)
	newRlBuilds(m)
	rlPublish(t, m, 5)
	w := m.newReloadWatcher()
	rlWantApplied(t, "before: the baseline", m, "5\n")

	rlPublish(t, m, 6)
	w.drainAndSwap(make(chan struct{}))
	rlWantApplied(t, "after the swap", m, "6\n")
}

func TestReloadMarkerIsNotAdvancedOnARAMDecline(t *testing.T) {
	m := rlModule(t)
	newRlBuilds(m)
	opInstall(t, m, nil, func(s *snapshot) { s.counts = 1_000_000 })
	m.totalRAM = ramOf(1 << 20)
	rlPublish(t, m, 5)
	w := m.newReloadWatcher()
	rlWantApplied(t, "before: the baseline", m, "5\n")

	rlPublish(t, m, 7)
	w.drainAndSwap(make(chan struct{}))
	rlWantApplied(t, "after the decline", m, "5\n")
}

func TestReloadMarkerIsNotAdvancedOnAFailedBuild(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	b.empty = true
	rlPublish(t, m, 2)
	w := m.newReloadWatcher()
	rlWantApplied(t, "before: the baseline", m, "2\n")

	rlPublish(t, m, 3)
	w.drainAndSwap(make(chan struct{}))
	rlWantApplied(t, "after the failed build", m, "2\n")
}

// A marker that cannot be written is logged and the swap stands (PHP's wait then times out); the watcher goes on.
func TestReloadWatcherKeepsTheSwapWhenTheMarkerWriteFailsAndGoesOn(t *testing.T) {
	m := rlModule(t)
	b := newRlBuilds(m)
	m.pfb.pfbPyReloadApplied = filepath.Join(t.TempDir(), "missing", "pfb_py_reload.applied")
	log := modCaptureLog(t)
	w := m.newReloadWatcher()
	stop := make(chan struct{})

	rlPublish(t, m, 1)
	w.drainAndSwap(stop)
	rlWantDomains(t, "after the failed marker write", m, "gen1.example")
	if !strings.Contains(log.String(), "failed to write applied-generation marker") {
		t.Errorf("log = %q, want the marker failure", log.String())
	}
	rlPublish(t, m, 2)
	w.drainAndSwap(stop)
	rlWantBuilds(t, "the generation after a marker failure", b, 1, 2)
}

// --- f. the reload builder ---

func TestReloadBuildSnapshotBuildsEveryStratumFromTheManifestOffToTheSide(t *testing.T) {
	m, dir := rlManifestModule(t, nil, map[string][]string{"feed.txt": {"evil.example", `/^bad[0-9]+\.example$/`}})
	live := m.snapshot.Load()
	rlWantDomains(t, "the init load", m, "evil.example")
	if live.regexDB.len() != 1 {
		t.Fatalf("init regexDB = %d, want 1", live.regexDB.len())
	}

	rlWriteFeeds(t, dir, map[string][]string{"feed.txt": {"new.example", "other.example"}})
	next, err := m.reloadBuildSnapshot()
	if err != nil || next == nil {
		t.Fatalf("reloadBuildSnapshot = (%v, %v), want a snapshot", next, err)
	}
	var got []string
	for name := range next.dataDB {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"new.example", "other.example"}) {
		t.Errorf("built dataDB = %v, want the rewritten feed", got)
	}
	if next.counts != 2 || next.regexDB.len() != 0 || next.regexCount != 0 || next.importantRules {
		t.Errorf("(counts, regexDB, regexCount, importantRules) = (%d, %d, %d, %v), want (2, 0, 0, false)", next.counts, next.regexDB.len(), next.regexCount, next.importantRules)
	}
	if next.gen <= live.gen {
		t.Errorf("built generation = %d, want one past the live %d", next.gen, live.gen)
	}
	if next.settings != nil {
		t.Errorf("the builder set settings; a reload leaves them to the swap, which takes the live ones")
	}
	if m.snapshot.Load() != live {
		t.Errorf("the build replaced the live snapshot")
	}
	rlWantDomains(t, "after the build, nothing live written", m, "evil.example")
}

func TestReloadBuildSnapshotRereadsTheUserRegexListFromTheIni(t *testing.T) {
	m, dir := rlManifestModule(t, []string{opRegexList(`^one[0-9]+\.example$`)}, map[string][]string{})
	live := m.snapshot.Load()
	if live.userRegexDB.len() != 1 {
		t.Fatalf("init userRegexDB = %d, want 1", live.userRegexDB.len())
	}
	ini := "[MAIN]\npython_enable = true\n" + opRegexList(`^two\.example$`, `^three\.example$`) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}

	next, err := m.reloadBuildSnapshot()
	if err != nil || next == nil {
		t.Fatalf("reloadBuildSnapshot = (%v, %v), want a snapshot", next, err)
	}
	if next.userRegexDB.len() != 2 || next.regexCount != 2 || !next.importantRules {
		t.Errorf("(userRegexDB, regexCount, importantRules) = (%d, %d, %v), want (2, 2, true)", next.userRegexDB.len(), next.regexCount, next.importantRules)
	}
	if slices.Equal(next.userRegexDB.names, live.userRegexDB.names) {
		t.Errorf("user regex names %v are the init list's, want the re-read ones", next.userRegexDB.names)
	}
}

// Python re-reads the ini for [MAIN] regex_list and nothing else: every other setting a swap uses is the module's, from
// init. Here the ini changes a setting of each kind the builder and the swap touch; none of them takes effect.
func TestReloadReadsOnlyTheRegexListFromTheIni(t *testing.T) {
	m, dir := rlManifestModule(t, []string{opRegexList(`^one\.example$`), "psl_feed_private_policy = honor"}, map[string][]string{"feed.txt": {"a.example"}})
	ini := "[MAIN]\npython_enable = true\n" + opRegexList(`^one\.example$`) + "\npsl_feed_private_policy = apex\nregex_cap = true\n" +
		"python_hsts = true\ntld_allow = true\ntld_allow_list = com\npython_tld_seg = 3\ndecisiondb_max = 7\n"
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_hsts.txt"), []byte("hsts.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatalf("reloadRunSwap = false, want a swap")
	}
	snap := m.snapshot.Load()
	if snap.pslFeedPrivatePolicy != "honor" || len(snap.tldAllowRoots) != 0 || len(snap.hstsDB) != 0 {
		t.Errorf("(pslFeedPrivatePolicy, tldAllowRoots, hstsDB) = (%q, %v, %v), want the init values (honor, none, none)", snap.pslFeedPrivatePolicy, snap.tldAllowRoots, snap.hstsDB)
	}
	s := snap.settings
	if s.regexCap || s.pythonHsts || s.tldAllow || s.pythonTldSeg != 0 || s.decisiondbMax != 10000 {
		t.Errorf("settings (regexCap, pythonHsts, tldAllow, pythonTldSeg, decisiondbMax) = (%v, %v, %v, %d, %d), want the init values", s.regexCap, s.pythonHsts, s.tldAllow, s.pythonTldSeg, s.decisiondbMax)
	}
}

func TestReloadBuildSnapshotTakesTldAllowRootsAndPslPoliciesFromTheLiveSettings(t *testing.T) {
	m, dir := rlManifestModule(t, []string{
		"tld_allow = true", "tld_allow_list = com, .ORG.", "psl_include_private = false", "psl_allow_private = true",
		"psl_feed_private_policy = apex", "psl_feed_icann_policy = ignore",
	}, map[string][]string{})
	// A non-default PSL policy needs the authority file in the build.
	bldWriteFile(t, filepath.Join(dir, "dnsbl_psl"), bldAuthority([]string{"com", "org"}))
	ini := "[MAIN]\npython_enable = true\ntld_allow = false\npsl_include_private = true\npsl_allow_private = false\n" +
		"psl_feed_private_policy = honor\npsl_feed_icann_policy = honor\n"
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}

	next, err := m.reloadBuildSnapshot()
	if err != nil || next == nil {
		t.Fatalf("reloadBuildSnapshot = (%v, %v), want a snapshot", next, err)
	}
	if !slices.Equal(next.tldAllowRoots, []string{"com", "org"}) || !next.hasTldAllowRoots {
		t.Errorf("(tldAllowRoots, hasTldAllowRoots) = (%v, %v), want ([com org], true)", next.tldAllowRoots, next.hasTldAllowRoots)
	}
	if next.pslIncludePrivate || !next.pslAllowPrivate || next.pslFeedPrivatePolicy != "apex" || next.pslFeedIcannPolicy != "ignore" {
		t.Errorf("PSL (includePrivate, allowPrivate, private, icann) = (%v, %v, %q, %q), want (false, true, apex, ignore)",
			next.pslIncludePrivate, next.pslAllowPrivate, next.pslFeedPrivatePolicy, next.pslFeedIcannPolicy)
	}
}

// hstsDB is no part of the manifest: the builder reads pfb_py_hsts.txt itself, when python_hsts is on.
func TestReloadBuildSnapshotReloadsHstsFromTheFileOnlyWhenPythonHstsIsOn(t *testing.T) {
	const file = "# a comment\nexample.test\n\n  other.test  \n"
	for _, tc := range []struct {
		name string
		main []string
		want []string
	}{
		{"python_hsts on", []string{"python_hsts = true"}, []string{"example.test", "other.test"}},
		{"python_hsts off", nil, nil},
	} {
		m, dir := rlManifestModule(t, tc.main, map[string][]string{})
		if len(m.snapshot.Load().hstsDB) != 0 {
			t.Fatalf("%s: init hstsDB is not empty", tc.name)
		}
		if err := os.WriteFile(filepath.Join(dir, "pfb_py_hsts.txt"), []byte(file), 0o644); err != nil {
			t.Fatal(err)
		}
		next, err := m.reloadBuildSnapshot()
		if err != nil || next == nil {
			t.Fatalf("%s: reloadBuildSnapshot = (%v, %v), want a snapshot", tc.name, next, err)
		}
		var got []string
		for name := range next.hstsDB {
			got = append(got, name)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: hstsDB = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReloadBuildSnapshotLogsAnUnreadableHstsFileAndStillBuilds(t *testing.T) {
	m, dir := rlManifestModule(t, []string{"python_hsts = true"}, map[string][]string{"feed.txt": {"a.example"}})
	hsts := filepath.Join(dir, "pfb_py_hsts.txt")
	if err := os.WriteFile(hsts, []byte("example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.readFile = func(name string) ([]byte, error) { return nil, errors.New("read failed") }
	log := modCaptureLog(t)

	next, err := m.reloadBuildSnapshot()
	if err != nil || next == nil {
		t.Fatalf("reloadBuildSnapshot = (%v, %v), want a snapshot", next, err)
	}
	if len(next.hstsDB) != 0 || len(next.dataDB) != 1 {
		t.Errorf("(hstsDB, dataDB) = (%d, %d), want (0, 1)", len(next.hstsDB), len(next.dataDB))
	}
	if want := "reload: failed to load " + hsts + ": read failed"; !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to hold %q", log.String(), want)
	}
}

// The group epochs are the counter authority of a snapshot: a reload reads them from the DNSBL database when it builds.
func TestReloadBuildSnapshotReadsTheGroupEpochsFromTheDatabase(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(0, "First")})
	r.m.stopReloadWatcher()
	rlWriteFeeds(t, r.dir, map[string][]string{"feed.txt": {"a.example"}})
	key := [2]string{"Second", "custom"}
	if _, ok := r.m.snapshot.Load().groupEpochs[key]; ok {
		t.Fatalf("the init snapshot already holds the epoch of a group created after it")
	}
	sqlExec(t, r.path(dbDnsbl), fmt.Sprintf("INSERT INTO dnsbl_group_epochs VALUES ('Second', 'custom', '%032x')", 9))

	next, err := r.m.reloadBuildSnapshot()
	if err != nil || next == nil {
		t.Fatalf("reloadBuildSnapshot = (%v, %v), want a snapshot", next, err)
	}
	if next.groupEpochs[key] != fmt.Sprintf("%032x", 9) || next.groupEpochs[[2]string{"First", "custom"}] == "" {
		t.Errorf("built groupEpochs = %v, want both groups' epochs", next.groupEpochs)
	}
}

func TestReloadBuildSnapshotFailsClosedOnAMissingOrBadManifest(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, dir string){
		"the manifest is missing": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "pfb_py_sources.json")); err != nil {
				t.Fatal(err)
			}
		},
		"the manifest is not JSON": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), []byte("{not json"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		m, dir := rlManifestModule(t, nil, map[string][]string{"feed.txt": {"evil.example"}})
		prepare(t, dir)
		modCaptureLog(t)
		if next, _ := m.reloadBuildSnapshot(); next != nil {
			t.Errorf("%s: reloadBuildSnapshot returned a snapshot, want none", name)
		}
		live := m.snapshot.Load()
		if m.reloadRunSwap(m.reloadBuildSnapshot) {
			t.Errorf("%s: the swap reported success, want a no-op", name)
		}
		if m.snapshot.Load() != live {
			t.Errorf("%s: the live snapshot was replaced", name)
		}
		rlWantDomains(t, name, m, "evil.example")
	}
}

// --- g. the runtime state a swap carries ---

// Python keeps gpListDB, gpNetDB, noAAAADB and safeSearchDB as module globals that a swap never touches; here a reload
// takes the live snapshot's tables at publish time. The entries are asserted, not only the settings flags.
func TestAReloadSwapCarriesTheRuntimeBypassNetworkNoAAAAAndSafeSearchTables(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_blocking = true"}, map[string][]string{"feed.txt": {"evil.example"}})
	opInstall(t, m, func(s *pfbSettings) { s.gpListDB, s.noAAAADB, s.safeSearchDB = true, true, true }, func(s *snapshot) {
		s.gpListDB["10.0.0.4"] = 0
		s.noAAAADB["v6.example"] = true
		s.safeSearchDB["search.example"] = safeSearchEntry{a: "192.0.2.1"}
		s.gpNetDB = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	})
	if applied, msg := ctlApply(m, "python_control", "addbypass", "10-0-0-5"); !applied {
		t.Fatalf("addbypass: %q", msg)
	}
	rlWantDomains(t, "before the reload", m)

	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatalf("reloadRunSwap = false, want a swap")
	}
	live := m.snapshot.Load()
	rlWantDomains(t, "after the reload", m, "evil.example")
	if _, ok := live.gpListDB["10.0.0.4"]; !ok {
		t.Errorf("gpListDB lost the entry the module had: %v", live.gpListDB)
	}
	if _, ok := live.gpListDB["10.0.0.5"]; !ok {
		t.Errorf("gpListDB lost the runtime addbypass entry: %v", live.gpListDB)
	}
	if _, ok := live.noAAAADB["v6.example"]; !ok {
		t.Errorf("noAAAADB lost its entry: %v", live.noAAAADB)
	}
	if got := live.safeSearchDB["search.example"]; got.a != "192.0.2.1" {
		t.Errorf("safeSearchDB lost its entry: %v", live.safeSearchDB)
	}
	if !slices.Equal(live.gpNetDB, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}) {
		t.Errorf("gpNetDB = %v, want the carried prefix", live.gpNetDB)
	}
	s := live.settings
	if !s.gpListDB || !s.noAAAADB || !s.safeSearchDB || !s.pythonBlacklist {
		t.Errorf("settings (gpListDB, noAAAADB, safeSearchDB, pythonBlacklist) = (%v, %v, %v, %v), want all true", s.gpListDB, s.noAAAADB, s.safeSearchDB, s.pythonBlacklist)
	}
}

// A control write that lands while the reload builds is carried: the tables are taken from the live snapshot when the swap
// stores, not when the build began or ended. The three writes land before the build starts, after it returns and before
// the swap stores, so that a carry taken at any earlier moment loses the last one.
func TestAControlWriteDuringAReloadBuildIsCarriedByTheSwap(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_blocking = true"}, map[string][]string{"feed.txt": {"evil.example"}})
	build := func() (*snapshot, error) {
		ctlApply(m, "python_control", "addbypass", "10-0-0-6")
		next, err := m.reloadBuildSnapshot()
		ctlApply(m, "python_control", "addbypass", "10-0-0-7") // after the build returned, before rebuildAndSwap stores
		return next, err
	}
	if !m.reloadRunSwap(build) {
		t.Fatalf("reloadRunSwap = false, want a swap")
	}
	live := m.snapshot.Load()
	for _, ip := range []string{"10.0.0.6", "10.0.0.7"} {
		if _, ok := live.gpListDB[ip]; !ok {
			t.Errorf("gpListDB lost the addbypass of %s: %v", ip, live.gpListDB)
		}
	}
	if !live.settings.gpListDB {
		t.Errorf("the Group Policy gate a control write turned on is off after the swap")
	}
	rlWantDomains(t, "after the reload", m, "evil.example")
}

// A control command copies the live snapshot to publish it; the copy is a control edit, not a reload's build, so it does
// not ask the next swap to carry from itself.
func TestAControlEditAfterAReloadSwapIsNotMarkedForCarry(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_blocking = true"}, map[string][]string{"feed.txt": {"evil.example"}})
	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatalf("reloadRunSwap = false, want a swap")
	}
	before := m.snapshot.Load()
	ctlApply(m, "python_control", "addbypass", "10-0-0-8")
	live := m.snapshot.Load()
	if live == before {
		t.Fatalf("the control command published nothing")
	}
	if live.carryRuntime {
		t.Errorf("a snapshot a control command published is still marked carryRuntime")
	}
}

// Python's swap sets python_blacklist when the new snapshot has any list, which re-enables a runtime disable (map section
// 6, recorded on #3511): the Go reload keeps that.
func TestAReloadThatLoadsListsSwitchesTheBlacklistGateBackOn(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_blocking = true"}, map[string][]string{"feed.txt": {"evil.example"}})
	ctlApply(m, "python_control", "disable")
	if ctlBlacklist(m) {
		t.Fatalf("python_blacklist is still on after a disable")
	}
	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatalf("reloadRunSwap = false, want a swap")
	}
	if !ctlBlacklist(m) {
		t.Errorf("python_blacklist = false after a reload that loaded lists, want true as in Python")
	}
}

// --- h. the swap race ---

// A control addbypass racing a reload swap loses neither: every IP added in a round is in the final table, and the last
// swap's lists are live. Run it with -race.
func TestControlAddbypassRacingAReloadSwapLosesNeither(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_blocking = true"}, map[string][]string{"feed.txt": {"evil.example"}})
	for round := range 5 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 20 {
				m.reloadRunSwap(m.reloadBuildSnapshot)
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 20 {
				ctlApply(m, "python_control", "addbypass", fmt.Sprintf("10-%d-0-%d", round, i))
			}
		}()
		wg.Wait()
		live := m.snapshot.Load()
		for i := range 20 {
			if _, ok := live.gpListDB[fmt.Sprintf("10.%d.0.%d", round, i)]; !ok {
				t.Fatalf("round %d: the addbypass of 10.%d.0.%d was lost by a reload swap", round, round, i)
			}
		}
		if len(live.dataDB) != 1 {
			t.Fatalf("round %d: dataDB = %d entries, want the reload's list", round, len(live.dataDB))
		}
	}
}

// Queries run through Frontend.resolve in several goroutines while the watcher drains one generation after another and
// control commands run alongside. The odd generations block n.example and t.example, the even ones m.example, with
// different sinkholes, so each answer must be exactly one generation's verdict (a torn mix matches neither). The applied
// marker must end at the last generation. Run it with -race.
func TestReloadSwapRaceEveryAnswerIsOneGenerationsVerdict(t *testing.T) {
	m := modMust(t, t.TempDir())
	m.stopReloadWatcher()
	m.totalRAM = func() (uint64, bool) { return 8 << 30, true }
	m.reloadBuilder = func() (*snapshot, error) {
		gen, _ := reloadReadGeneration(m.pfb.pfbPyReload)
		side := raceA
		if gen%2 == 0 {
			side = raceB
		}
		return raceSnapshot(t, side)()
	}
	w := m.newReloadWatcher()
	stopDrain := make(chan struct{})
	published := 0
	reload := func() {
		published++
		rlPublish(t, m, published)
		w.drainAndSwap(stopDrain)
	}
	want := map[string]map[string]string{
		"n.example.": {"A": "192.0.2.1", "B": "192.0.2.99"},
		"m.example.": {"A": "192.0.2.99", "B": "192.0.2.2"},
		"c.example.": {"A": "192.0.2.1", "B": "CNAME,192.0.2.99"},
		"u.example.": {"A": "192.0.2.99", "B": "192.0.2.99"},
	}
	names := []string{"n.example.", "m.example.", "c.example.", "u.example."}
	upstream := raceUpstream(t)

	// Settled generations first: each reload answers as its own list says.
	for _, side := range []string{"A", "B"} {
		reload()
		f := newFrontend(m)
		for i, name := range names {
			got := raceAddresses(t, f.resolve(raceQuery(t, uint16(i+1), name), "192.0.2.10", upstream, "UDP", "", ""))
			if got != want[name][side] {
				t.Errorf("settled generation %s: %s answered %q, want %q", side, name, got, want[name][side])
			}
		}
	}

	const queriers, rounds = 6, 400
	var wg, background sync.WaitGroup
	stop := make(chan struct{})
	background.Add(2)
	go func() {
		defer background.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			reload()
		}
	}()
	go func() {
		defer background.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctlApply(m, "python_control", "addbypass", "192.0.2.55")
			ctlApply(m, "python_control", "removebypass", "192.0.2.55")
		}
	}()
	for g := range queriers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := newFrontend(m)
			for i := range rounds {
				name := names[(g+i)%len(names)]
				got := raceAddresses(t, f.resolve(raceQuery(t, uint16(g*rounds+i), name), "192.0.2.10", upstream, "UDP", "", ""))
				if got != want[name]["A"] && got != want[name]["B"] {
					t.Errorf("%s answered %q, want one generation's verdict: %q (A) or %q (B)", name, got, want[name]["A"], want[name]["B"])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	background.Wait()

	rlWantApplied(t, "after the last reload", m, fmt.Sprintf("%d\n", published))
}
