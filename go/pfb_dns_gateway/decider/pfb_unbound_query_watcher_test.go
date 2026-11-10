// The query watcher's own behaviour, apart from what the oracle rows freeze: how soon it answers, that it answers what is
// already on disk, that its stop waits, the mode contract of the marker helper it shares with the control and reload
// watchers, and the drain loop under a deadline.
package decider

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// queryDrain is w.drainAndAnswer with a deadline: a dedupe that never settles (the loop re-answers a record it just
// answered) fails here instead of hanging the package's test run.
func queryDrain(t *testing.T, w *queryWatcher) {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		w.drainAndAnswer(stop)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(stop)
		<-done
		t.Fatalf("drainAndAnswer did not settle: it keeps answering the record it just answered")
	}
}

// queryWaitReply is the reply file's content once it exists, or a failure after limit.
func queryWaitReply(t *testing.T, dir string, limit time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if got, err := os.ReadFile(filepath.Join(dir, "pfb_py_query.reply")); err == nil {
			return string(got)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reply within %v", limit)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// queryWaitPass waits for one drain pass of the watcher to end, or fails after a bound that only a watcher that no longer
// looks at its channel reaches.
func queryWaitPass(t *testing.T, passes <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-passes:
	case <-time.After(10 * time.Second):
		t.Fatalf("STUCK: no drain pass ended %s: the watcher looks at its channel no more", what)
	}
}

// PHP's pfb_dnsbl_query() waits at most 5 s for a reply and shares that budget with its lock wait, so a watcher that
// polls every RELOAD_POLL_INTERVAL (2 s) times concurrent hits out: the query watcher takes a tick of its own, a small
// fraction of that. No duration is asserted. The interval its ticker is made with is checked through queryNewTicker; the
// loop is checked by passes, which the watcher reports through queryDrained. A probe is answered, and the pass that
// answered it reads the channel once more before it returns, so the timed request is put in place only once that pass
// has ended. The reply to it then exists by the end of a later pass: two passes after it is in place, since the one that
// ends first may have begun before it.
func TestQueryWatcherAnswersWellInsideThePollInterval(t *testing.T) {
	oracle := loadQueryOracle(t)
	dir := t.TempDir()
	m := modMust(t, dir)
	m.snapshot.Store(oracle.Fixtures["plain"].snapshot(t))
	m.stopQueryWatcher()
	var tickEvery time.Duration // what the watcher's own ticker is made with, as the default tick makes it
	m.queryNewTicker = func(d time.Duration) *time.Ticker {
		tickEvery = d
		return time.NewTicker(d)
	}
	passes := make(chan struct{}, 1000)
	m.queryDrained = func() {
		select {
		case passes <- struct{}{}:
		default:
		}
	}
	m.startQueryWatcher()
	if tickEvery <= 0 || tickEvery >= RELOAD_POLL_INTERVAL/2 {
		t.Fatalf("the watcher's ticker is made with %v, want a small fraction of RELOAD_POLL_INTERVAL (%v)", tickEvery, RELOAD_POLL_INTERVAL)
	}
	channel, reply := filepath.Join(dir, "pfb_py_query"), filepath.Join(dir, "pfb_py_query.reply")
	if err := os.WriteFile(channel, []byte(`{"id": "probe", "domain": "clean.example.com"}`), 0o660); err != nil {
		t.Fatal(err)
	}
	queryWaitReply(t, dir, 10*time.Second)
	// Every signal in the channel now was sent before the probe was answered or by the pass that answered it; the first
	// one after the flush is from that pass or a later one. Passes run one at a time, so the answering pass has ended.
	for len(passes) > 0 {
		<-passes
	}
	queryWaitPass(t, passes, "after the probe was answered")
	if err := os.Remove(reply); err != nil {
		t.Fatal(err)
	}
	next := channel + ".new" // renamed over the channel, so that no pass reads it half written or absent
	if err := os.WriteFile(next, []byte(`{"id": "fast", "domain": "listed.example.com"}`), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, channel); err != nil {
		t.Fatal(err)
	}
	// A pause of more than one tick between the signal above and the rename lets a pass begin before the rename, so the
	// first pass signalled below may have read the probe again; the second one began after the rename.
	queryWaitPass(t, passes, "after the timed request was put in place")
	queryWaitPass(t, passes, "after a pass that began with the timed request in place")
	if !queryReplyExists(dir) {
		t.Errorf("no reply to the timed request after two later drain passes")
	}
}

// Python is stateless: a request on disk when the module starts is answered, unlike the control watcher, which adopts
// such a record as its baseline.
func TestQueryWatcherAnswersARequestAlreadyOnDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_query"), []byte(`{"id": "early", "domain": "clean.example.com"}`), 0o660); err != nil {
		t.Fatal(err)
	}
	m := modMust(t, dir)
	m.stopQueryWatcher()
	// The watcher init started may have answered the request before it stopped: only the one driven here may satisfy it.
	if err := os.Remove(filepath.Join(dir, "pfb_py_query.reply")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	w := m.newQueryWatcher()
	queryDrain(t, w)
	got, err := os.ReadFile(filepath.Join(dir, "pfb_py_query.reply"))
	if err != nil || !strings.Contains(string(got), `"id": "early"`) {
		t.Errorf("reply to a request on disk at start = %q, %v; want its answer", got, err)
	}
}

// stopQueryWatcher returns only once the watcher's goroutine has ended: its tick's release, which runs last, is still
// blocked here, so a stop that has returned did not wait.
func TestStopQueryWatcherWaitsForTheWatcherToEnd(t *testing.T) {
	m := modMust(t, t.TempDir())
	m.stopQueryWatcher()
	entered, release := make(chan struct{}), make(chan struct{})
	m.queryTick = func() (<-chan time.Time, func()) {
		return make(chan time.Time), func() {
			close(entered)
			<-release
		}
	}
	m.startQueryWatcher()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		m.stopQueryWatcher()
	}()
	chWait(t, "the watcher to reach its cleanup after stop", entered)
	for range 10000 {
		select {
		case <-returned:
			t.Fatalf("stopQueryWatcher returned while the watcher's goroutine had not ended")
		default:
			runtime.Gosched()
		}
	}
	close(release)
	chWait(t, "stopQueryWatcher to return once the watcher ended", returned)
	if m.queryStop != nil {
		t.Errorf("the watcher is still marked running after stopQueryWatcher")
	}
}

// mode 0 is "no chmod": the control and the reload markers keep the mode the file was created with.
func TestWriteMarkerWithoutAModeKeepsTheCreatedMode(t *testing.T) {
	dir := t.TempDir()
	ref := filepath.Join(dir, "ref")
	if err := os.WriteFile(ref, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	refInfo, err := os.Stat(ref)
	if err != nil {
		t.Fatal(err)
	}
	m := modMust(t, dir)
	m.stopQueryWatcher()
	m.controlWriteApplied(big.NewInt(3))
	m.reloadWriteApplied(4)
	for _, path := range []string{m.pfb.pfbPyControlApplied, m.pfb.pfbPyReloadApplied} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != refInfo.Mode().Perm() {
			t.Errorf("%s mode = %v, want the created mode %v", filepath.Base(path), info.Mode().Perm(), refInfo.Mode().Perm())
		}
	}
	if failure := writeMarker(filepath.Join(dir, "m"), "x", 0o640); failure != "" {
		t.Fatal(failure)
	}
	if info, err := os.Stat(filepath.Join(dir, "m")); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("marker written with mode 0640 = %v, %v", info, err)
	}
}

// A chmod that fails is an OSError that names the temp file, as Python's os.chmod(tmp, ...) reports it; the temp file is
// removed and the marker is not published.
func TestWriteMarkerChmodFailureNamesTheTempFileAndLeavesNothing(t *testing.T) {
	previous := markerChmod
	markerChmod = func(name string, _ os.FileMode) error {
		return &os.PathError{Op: "chmod", Path: name, Err: syscall.EPERM}
	}
	t.Cleanup(func() { markerChmod = previous })
	path := filepath.Join(t.TempDir(), "marker")
	failure := writeMarker(path, "x", 0o640)
	if want := "[Errno 1] Operation not permitted: " + "'" + path + ".tmp'"; failure != want {
		t.Errorf("failure = %q, want %q", failure, want)
	}
	for _, name := range []string{path, path + ".tmp"} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists after the failed write (%v)", name, err)
		}
	}
}
