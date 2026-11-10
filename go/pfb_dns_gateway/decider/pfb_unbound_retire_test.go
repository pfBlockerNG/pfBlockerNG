// Tests of what a module that is closing no longer does (#3791 step A): deinit retires it before it stops anything, so a
// reload or a control record that outlives the bounded stop of its watcher publishes, writes and opens nothing, and the
// stop does not wait on a write that never returns.
package decider

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// releaseFifo opens fifo for reading without blocking, so that a writer stuck in its open goes on; it is closed when the
// test ends.
func releaseFifo(t *testing.T, fifo string) {
	t.Helper()
	fd, err := syscall.Open(fifo, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
}

// A reload that has swapped in its snapshot and is blocked writing its count file (a FIFO nobody reads) holds nothing
// that Close needs: Close returns within its bound instead of waiting behind the write.
func TestACloseDoesNotWaitBehindAReloadBlockedWritingItsCountFile(t *testing.T) {
	m, _ := rlManifestModule(t, nil, map[string][]string{"feed.txt": {"late.example"}})
	shortStopWait(t)
	fifo := filepath.Join(t.TempDir(), "pfb_py_count")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	opInstall(t, m, func(s *pfbSettings) { s.pfbPyCount = fifo }, nil)
	ticks, ended := make(chan time.Time), make(chan struct{})
	m.reloadTick = func() (<-chan time.Time, func()) { return ticks, func() { close(ended) } }
	rlPublish(t, m, 1)
	m.startReloadWatcher()
	before := m.snapshot.Load() // taken ahead of the publish: the watcher's first drain may already take generation 2
	rlPublish(t, m, 2)
	for deadline := time.Now().Add(10 * time.Second); m.snapshot.Load() == before; time.Sleep(5 * time.Millisecond) {
		select {
		case ticks <- time.Time{}:
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the reload never swapped its snapshot in")
		}
	}
	time.Sleep(200 * time.Millisecond) // the swap is stored: the reload is now in its count write

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		m.deinit()
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		releaseFifo(t, fifo) // let the blocked write go, so that Close ends before the test's own cleanup stops the module
		<-closed
		<-ended
		t.Fatal("Close is still waiting for a reload blocked writing its count file")
	}
	releaseFifo(t, fifo) // the abandoned reload's write goes on and ends
	chWait(t, "the abandoned reload to end", ended)
}

// A control record that is read after Close (the watcher was blocked reading its channel when Close gave up on it) is not
// applied: no command runs, nothing is logged, and the applied marker keeps the baseline.
func TestAControlRecordReadAfterCloseIsNotApplied(t *testing.T) {
	m := chModule(t)
	shortStopWait(t)
	timers := &ctlTimers{}
	m.afterFunc = timers.afterFunc
	chPublish(t, m, `{"seq":1,"cmd":"enable"}`)
	tick, ended := make(chan time.Time), make(chan struct{})
	m.controlTick = func() (<-chan time.Time, func()) { return tick, func() { close(ended) } }
	m.startControlWatcher()
	if got := chApplied(t, m); got != "1\n" {
		t.Fatalf("baseline marker = %q, want 1", got)
	}
	// the channel becomes a FIFO nobody writes: the watcher's next read blocks
	if err := os.Remove(m.pfb.pfbPyControl); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(m.pfb.pfbPyControl, 0o600); err != nil {
		t.Fatal(err)
	}
	var writer int
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		select {
		case tick <- time.Time{}:
		default:
		}
		fd, err := syscall.Open(m.pfb.pfbPyControl, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil { // a reader is waiting in its open: the watcher is in its read
			writer = fd
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the control watcher never blocked reading its channel")
		}
	}
	log := captureLockedLog(t)
	before := m.snapshot.Load()
	m.deinit() // gives up on the watcher after the bound

	if _, err := syscall.Write(writer, []byte(`{"seq":5,"cmd":"disable"}`)); err != nil {
		t.Fatal(err)
	}
	syscall.Close(writer)
	chWait(t, "the control watcher to end", ended)

	if got := chApplied(t, m); got != "1\n" {
		t.Errorf("applied marker = %q after a record read in a closed module, want the baseline 1", got)
	}
	if strings.Contains(log.String(), "Python_control") {
		t.Errorf("a command ran in a closed module; log = %q", log.String())
	}
	if m.snapshot.Load() != before || len(timers.all()) != 0 {
		t.Errorf("a closed module published a snapshot or started a timer")
	}
}

// The control publishers do nothing once the module is closed: a command applied by hand, a timer that expires and a
// bypass that lapses leave the snapshot as it was, and start no timer.
func TestControlPublishersDoNothingOnceTheModuleIsClosed(t *testing.T) {
	m := chModule(t)
	timers := &ctlTimers{}
	m.afterFunc = timers.afterFunc
	m.deinit()
	before := m.snapshot.Load()

	if applied, msg := m.pfbApplyControlCommand([]string{"python_control", "disable", "30"}); applied || msg != "" {
		t.Errorf("a command in a closed module = (%v, %q), want it refused", applied, msg)
	}
	if got := len(timers.all()); got != 0 {
		t.Errorf("a closed module started %d timers", got)
	}
	m.controlSleep()
	m.controlAddbypass("192.0.2.9")
	if m.snapshot.Load() != before {
		t.Errorf("a closed module published a snapshot")
	}
}

// A late build on a database that was closed at boot (the reload is what turns statistics on) opens nothing and
// recovers nothing: the corrupt file at the database's path is left as it was.
func TestALateBuildOnAColdDatabaseOpensNothingAndRemovesNothing(t *testing.T) {
	dir := opManifestModule(t, []string{"python_hsts = true"}, map[string][]string{})
	rlQuietLog(t)
	m := modMust(t, dir)
	m.stopReloadWatcher()
	m.totalRAM = func() (uint64, bool) { return 8 << 30, true }
	shortStopWait(t)
	if m.sqlite3DnsblCon.Load() {
		t.Fatal("the module booted with its statistics database open: the test needs it cold")
	}
	corrupt := []byte("this is not a database")
	if err := os.WriteFile(m.pfb.pfbPyDnsbl, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.pfb.pfbPyHsts, []byte("example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rlWriteFeeds(t, dir, map[string][]string{"feed.txt": {"late.example"}})
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ticks := make(chan time.Time)
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
	select {
	case ticks <- time.Time{}:
	case <-entered:
	}
	chWait(t, "the build to start", entered)

	m.deinit()
	close(release)
	chWait(t, "the late build to end", ended)

	m.dbMu.Lock()
	connections := len(m.dbConns)
	m.dbMu.Unlock()
	if connections != 0 || m.sqlite3DnsblCon.Load() {
		t.Errorf("the late build opened the statistics database: %d connections, open flag %v", connections, m.sqlite3DnsblCon.Load())
	}
	if got, err := os.ReadFile(m.pfb.pfbPyDnsbl); err != nil || string(got) != string(corrupt) {
		t.Errorf("the file at the database path = (%q, %v), want it left as it was", got, err)
	}
}

// Recovery removes the corrupt file and its sidecars only while it holds the database lock, with the closed check made
// under it, so that Close cannot interleave between the check and the removal.
func TestRecoveryRemovesTheCorruptDatabaseOnlyWhileHoldingTheDatabaseLock(t *testing.T) {
	r := newSqlRig(t, "", nil)
	dropDbConnections(r.m)
	path := r.path(dbResolver)
	if err := os.WriteFile(path, []byte("this is not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	var removed, heldWhileRemoving int
	previous := removeStale
	t.Cleanup(func() { removeStale = previous })
	removeStale = func(name string) error {
		removed++
		if r.m.dbMu.TryLock() {
			r.m.dbMu.Unlock()
		} else {
			heldWhileRemoving++
		}
		return previous(name)
	}
	if !r.m.validateDbWithRecovery(dbResolver) {
		t.Fatalf("a corrupt database was not recovered:\n%s", r.log)
	}
	if removed == 0 || heldWhileRemoving != removed {
		t.Errorf("recovery removed %d files, %d of them with the database lock held, want all", removed, heldWhileRemoving)
	}
}

// The status ledger is a write too: nothing is opened or closed in it once the module is closed.
func TestTheStatusLedgerIsNotWrittenOnceTheModuleIsClosed(t *testing.T) {
	m := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\n"))
	path := filepath.Join(t.TempDir(), "pfb_py_status.json")
	m.pfb.pfbPyStatus = path
	m.pfbPyStatusOpen("dnsbl", "x", "parse", "boom")
	m.deinit()
	m.pfbPyStatusOpen("dnsbl", "y", "parse", "late")
	m.pfbPyStatusClose("dnsbl", "x", "parse")
	entries := statusRead(t, path)
	if len(entries) != 1 || entries[0]["item"] != "x" {
		t.Errorf("ledger = %v after a closed module's open and close, want only the entry written before", entries)
	}
}

// Between the start of deinit and the close of the databases (the wait on the watchers) a late publisher still finds
// them open, and must not open one again: neither a read of the group epochs nor the open of the statistics database
// reopens it.
func TestAModuleThatIsClosingDoesNotReopenItsStatisticsDatabase(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", nil)
	m := r.m
	if !m.sqlite3DnsblCon.Load() {
		t.Fatal("the rig's statistics database is not open")
	}
	connections := func() int {
		m.dbMu.Lock()
		defer m.dbMu.Unlock()
		return len(m.dbConns)
	}
	dropDbConnections(m)
	m.retired.Store(true)

	if epochs := m.dbGroupEpochs(true, newSnapshot()); len(epochs) != 0 || connections() != 0 {
		t.Errorf("a read of the group epochs in a closing module = %v with %d connections, want none", epochs, connections())
	}
	m.sqlite3DnsblCon.Store(false)
	m.openDnsblStatsDb(true)
	if connections() != 0 || m.sqlite3DnsblCon.Load() {
		t.Errorf("the statistics database was opened in a closing module: %d connections, open flag %v", connections(), m.sqlite3DnsblCon.Load())
	}
}

// Once the databases are closed nothing opens them again, and a closed database is not taken for a corrupt one: a use
// fails at once (no retry, no log line), the client authority is not read through a new connection, and recovery removes
// nothing.
func TestAClosedModuleOpensNoDatabaseAndRecoversNone(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", nil)
	m := r.m
	m.closeDb()
	r.log.Reset()

	if m.dbValidate(dbDnsbl) {
		t.Errorf("a use of a closed database succeeded")
	}
	if got := r.sleeps.Load(); got != 0 || r.log.Len() != 0 {
		t.Errorf("a use of a closed database retried %d times and logged %q, want it to fail at once and quietly", got, r.log.String())
	}

	m.pfb.metricsClientIp = true
	m.sqlite3ResolverCon.Store(true)
	m.sqlite3DnsblCon.Store(true)
	m.dbCapturePrivacyEpochs()
	m.dbMu.Lock()
	connections := len(m.dbConns)
	m.dbMu.Unlock()
	if connections != 0 {
		t.Errorf("the client authority was read through %d new connections after close", connections)
	}

	if m.validateDbWithRecovery(dbDnsbl) {
		t.Errorf("recovery of a closed database succeeded")
	}
	if _, err := os.Stat(r.path(dbDnsbl)); err != nil {
		t.Errorf("recovery removed the database of a closed module: %v", err)
	}
}

// A swap that is stored just before Close writes no counts after it: deinit begins (here, in the removal of a corrupt
// statistics database that the swap's open of it meets) between the store and the count files, and the swap goes on
// without writing them.
func TestASwapThatLandsBeforeCloseWritesNoCountsAfterIt(t *testing.T) {
	m := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\n"))
	opInstall(t, m, func(s *pfbSettings) { s.forwarding = true }, nil) // statistics wanted: this opens the database
	m.dbClose(dbDnsbl)
	m.sqlite3DnsblCon.Store(false) // and now it is closed again, with a corrupt file at its path
	if err := os.WriteFile(m.pfb.pfbPyDnsbl, []byte("this is not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(m.pfb.pfbPyCount) // init wrote it
	previous := removeStale
	t.Cleanup(func() { removeStale = previous })
	var recovered bool
	removeStale = func(name string) error {
		recovered = true
		m.retired.Store(true) // what deinit does first
		return previous(name)
	}

	if !m.rebuildAndSwap(opSwapSnapshot(3, 0, nil), true) {
		t.Fatal("the swap was refused: it was stored before Close")
	}
	if !recovered {
		t.Fatal("the swap never met the corrupt database: the test did not reach the point it is about")
	}
	if _, err := os.Stat(m.pfb.pfbPyCount); err == nil {
		t.Errorf("%s was written after Close began", m.pfb.pfbPyCount)
	}
}

// controlWatcherRetiredAt drains one control record (seq 5, disable) with the module retired by controlHook at stage,
// as a deinit that lands at that point would.
func controlWatcherRetiredAt(t *testing.T, stage string) (m *pfbUnbound, before *snapshot) {
	t.Helper()
	m = chModule(t)
	chPublish(t, m, `{"seq":1,"cmd":"enable"}`)
	w := m.newControlWatcher() // the baseline marker is 1
	chPublish(t, m, `{"seq":5,"cmd":"disable"}`)
	previous := controlHook
	t.Cleanup(func() { controlHook = previous })
	controlHook = func(at string) {
		if at == stage {
			m.retired.Store(true)
		}
	}
	before = m.snapshot.Load()
	w.drainAndApply(make(chan struct{}))
	return m, before
}

// A deinit that lands after the watcher read a record but before it applies it: the command is refused, so the applied
// marker must not announce it, and nothing is published.
func TestADeinitBetweenReadingAControlRecordAndApplyingItLeavesTheMarkerAlone(t *testing.T) {
	m, before := controlWatcherRetiredAt(t, "apply")
	if got := chApplied(t, m); got != "1\n" {
		t.Errorf("applied marker = %q for a command that was refused, want the baseline 1", got)
	}
	if m.snapshot.Load() != before {
		t.Errorf("a snapshot was published after deinit began")
	}
}

// A deinit that lands after the command ran but before the marker is written: the marker is a publication, and is not
// written.
func TestADeinitBetweenApplyingAControlRecordAndItsMarkerLeavesTheMarkerAlone(t *testing.T) {
	m, _ := controlWatcherRetiredAt(t, "marker")
	if got := chApplied(t, m); got != "1\n" {
		t.Errorf("applied marker = %q after deinit began, want the baseline 1", got)
	}
}
