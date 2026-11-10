// Tests of the two carry-forwards of the reload and control watchers (#3791 step A): a panic of the reload builder fails
// that swap and not the watcher (Python's rebuild_and_swap catches the builder's exception, and the thread lives), and a
// watcher's stop waits at most watcherStopWait for its goroutine (deinit's join(timeout=5)) and then goes on.
package decider

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// shortStopWait is the bound a test gives a stuck watcher, so that it does not wait the five seconds of production.
func shortStopWait(t *testing.T) {
	t.Helper()
	previous := watcherStopWait
	watcherStopWait = 50 * time.Millisecond
	t.Cleanup(func() { watcherStopWait = previous })
}

// A builder that panics on generation N is a failed swap: N is logged and not applied, the old snapshot serves, and the
// watcher takes generation N+1.
func TestReloadWatcherSurvivesABuilderPanicAndTakesTheNextGeneration(t *testing.T) {
	m := rlModule(t)
	opInstall(t, m, nil, func(s *snapshot) { opBlockData(s, "old.example", "1", 0); opFeed(s, 0, "F", "G") })
	m.reloadBuilder = func() (*snapshot, error) {
		gen, _ := reloadReadGeneration(m.pfb.pfbPyReload)
		if gen == 1 {
			panic("builder blew up")
		}
		s := newSnapshot()
		opBlockData(s, fmt.Sprintf("gen%d.example", gen), "1", 0)
		opFeed(s, 0, "F", "G")
		s.counts = int(gen)
		return s, nil
	}
	log := modCaptureLog(t)
	tick, ended := make(chan time.Time), make(chan struct{})
	m.reloadTick = func() (<-chan time.Time, func()) { return tick, func() { close(ended) } }
	m.startReloadWatcher()

	// The loop takes a tick only when its previous drain is over, so the second send of a pair is the barrier that the
	// first tick's drain finished. A watcher that ended is the failure this test is for.
	poll := func(what string) {
		t.Helper()
		for range 2 {
			select {
			case tick <- time.Time{}:
			case <-ended:
				t.Fatalf("%s: the watcher ended; log = %q", what, log.String())
			}
		}
	}

	rlPublish(t, m, 1)
	poll("after the generation whose build panicked")
	if want := "[pfBlockerNG]: DNSBL rebuild failed, keeping current snapshot: builder blew up\n"; !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to hold %q", log.String(), want)
	}
	rlWantDomains(t, "after the panicked generation", m, "old.example")
	rlWantApplied(t, "after the panicked generation", m, "")

	rlPublish(t, m, 2)
	poll("after the next generation")
	rlWantDomains(t, "after the next generation", m, "gen2.example")
	rlWantApplied(t, "after the next generation", m, "2\n")
}

// A stop of a watcher whose goroutine is stuck in a build returns after the bound, with one line saying so, and the
// stuck goroutine is left to finish by itself.
func TestStopReloadWatcherGivesUpOnAStuckDrainAfterTheBound(t *testing.T) {
	m := rlModule(t)
	shortStopWait(t)
	entered, release := make(chan struct{}), make(chan struct{})
	m.reloadBuilder = func() (*snapshot, error) {
		close(entered)
		<-release
		return nil, nil
	}
	tick := make(chan time.Time)
	m.reloadTick = func() (<-chan time.Time, func()) { return tick, func() {} }
	m.startReloadWatcher()
	rlPublish(t, m, 1)
	select { // the loop's own drain may already have seen the generation, and then it never takes a tick
	case tick <- time.Time{}:
	case <-entered:
	}
	chWait(t, "the build to start", entered)
	log := modCaptureLog(t)
	t.Cleanup(func() { close(release) }) // runs before stopModule's stop: the stuck build ends first

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		m.stopReloadWatcher()
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatalf("stopReloadWatcher is still waiting for a stuck watcher: the wait is not bounded")
	}
	if m.reloadStop != nil {
		t.Errorf("the watcher is still marked running after stopReloadWatcher gave up on it")
	}
	if got := strings.Count(log.String(), "reload watcher did not stop"); got != 1 {
		t.Errorf("stop logged %d lines about the stuck watcher, want 1; log = %q", got, log.String())
	}
}

func TestStopControlWatcherGivesUpOnAStuckWatcherAfterTheBound(t *testing.T) {
	m := chModule(t)
	shortStopWait(t)
	ticks := chInjectTicks(m, true) // the watcher's goroutine cannot end: its tick source's release is held
	m.startControlWatcher()
	log := modCaptureLog(t)
	t.Cleanup(func() { close(ticks.release) })

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		m.stopControlWatcher()
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatalf("stopControlWatcher is still waiting for a stuck watcher: the wait is not bounded")
	}
	if m.controlStop != nil {
		t.Errorf("the watcher is still marked running after stopControlWatcher gave up on it")
	}
	if got := strings.Count(log.String(), "control watcher did not stop"); got != 1 {
		t.Errorf("stop logged %d lines about the stuck watcher, want 1; log = %q", got, log.String())
	}
}

// A reload still building when Close runs outlives the bounded stop (the watcher's goroutine is abandoned after
// watcherStopWait). It must not act on a closed module when it finishes: no snapshot is published, no stats database is
// opened again (its connections stay released), and the applied marker is not advanced for a generation that was never
// served. Nothing is left open once the late build has ended.
func TestAReloadThatOutlivesCloseNeitherPublishesNorReopensAnything(t *testing.T) {
	m, _ := rlManifestModule(t, []string{"python_hsts = true"}, map[string][]string{"feed.txt": {"late.example"}})
	shortStopWait(t)
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ticks := make(chan time.Time)
	if err := os.WriteFile(m.pfb.pfbPyHsts, []byte("example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalRead := m.readFile
	m.readFile = func(path string) ([]byte, error) {
		if path == m.pfb.pfbPyHsts {
			close(entered)
			<-release
		}
		return originalRead(path)
	}
	m.reloadTick = func() (<-chan time.Time, func()) { return ticks, func() { close(ended) } }
	rlPublish(t, m, 1)
	m.startReloadWatcher()
	rlPublish(t, m, 2)
	select { // the loop's own drain may already have seen the generation, and then it never takes a tick
	case ticks <- time.Time{}:
	case <-entered:
	}
	chWait(t, "the build to start", entered)
	appliedAtClose := rlApplied(t, m)

	newFrontend(m).Close()
	connections := func() int {
		m.dbMu.Lock()
		defer m.dbMu.Unlock()
		return len(m.dbConns)
	}
	if got := connections(); got != 0 {
		t.Fatalf("Close left %d database connections open", got)
	}
	snapshotAtClose := m.snapshot.Load()

	close(release)
	chWait(t, "the late build to end", ended)
	if got := connections(); got != 0 {
		t.Errorf("the late reload reopened the stats database: %d connections after Close returned", got)
	}
	if m.snapshot.Load() != snapshotAtClose {
		t.Errorf("the late reload published a snapshot after Close returned")
	}
	rlWantApplied(t, "after the late reload ended", m, appliedAtClose)
}

// The applied marker is a publication too: a swap that landed just before Close must not have its generation announced
// to PHP's wait once the module is closing.
func TestTheAppliedMarkerIsNotWrittenOnceTheModuleIsClosing(t *testing.T) {
	m := rlModule(t)
	m.reloadWriteApplied(1)
	rlWantApplied(t, "before deinit", m, "1\n")
	m.deinit()
	m.reloadWriteApplied(2)
	rlWantApplied(t, "after deinit", m, "1\n")
}
