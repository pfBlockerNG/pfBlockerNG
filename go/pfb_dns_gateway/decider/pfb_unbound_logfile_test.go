// The log pipeline of pfb_unbound.py (pfb_setup_logging, pfb_log, _log_entry_direct): one writer per module behind a
// bounded queue that drops on full, a file reopened once it is rotated, and the synchronous append a module uses when no
// writer runs. Each test waits on a flush or stop barrier, never on time.
package decider

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// withLogDir points every module booted by the test at dir for its logs.
func withLogDir(t *testing.T, dir string) {
	t.Helper()
	previous := pfbLogDir
	pfbLogDir = dir
	t.Cleanup(func() { pfbLogDir = previous })
}

func TestPipelineWritesEachFilesRowsInOrder(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.log"), filepath.Join(dir, "b.log")
	p := newLogPipeline([]string{a, b}, 5000)
	t.Cleanup(p.stop)
	var wantA, wantB strings.Builder
	for i := range 300 {
		line := fmt.Sprintf("row %d", i)
		if i%3 == 0 {
			p.emit(b, line)
			wantB.WriteString(line + "\n")
		} else {
			p.emit(a, line)
			wantA.WriteString(line + "\n")
		}
	}
	p.flush()
	if got := readLog(t, a); got != wantA.String() {
		t.Errorf("a.log = %q, want the rows in emit order", got)
	}
	if got := readLog(t, b); got != wantB.String() {
		t.Errorf("b.log = %q, want the rows in emit order", got)
	}
	if p.dropped() != 0 {
		t.Errorf("dropped = %d, want 0: the queue never filled", p.dropped())
	}
}

func TestPipelineOpensAFileOnItsFirstRowNotAtStart(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	p := newLogPipeline([]string{a}, 10)
	t.Cleanup(p.stop)
	p.flush()
	if _, err := os.Stat(a); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat(a.log) = %v, want it absent until a row is written: WatchedFileHandler(delay=True)", err)
	}
}

// stuckWatchdog bounds a wait that only a stuck run exceeds: it is how a blocking emit or stop is reported, as an
// assertion, instead of a hung test. It is never part of an expected outcome.
const stuckWatchdog = 5 * time.Second

// within runs f and reports whether it returned before the watchdog; a run that did not is left to finish when the test's
// cleanups release what holds it.
func within(f func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
		return true
	case <-time.After(stuckWatchdog):
		return false
	}
}

// stuckWriter holds the pipeline's writer in its first write until the test ends (or release is called), and returns
// once the writer is inside it.
func stuckWriter(t *testing.T, p *logPipeline, path string) (release func()) {
	t.Helper()
	entered, gate := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release) // runs before the pipeline's stop, which was registered first
	p.beforeWrite = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}
	p.emit(path, "first")
	<-entered
	return release
}

func TestPipelineDropsWhenFullAndNeverBlocksTheQuery(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	const size = 8
	p := newLogPipeline([]string{a}, size)
	t.Cleanup(p.stop)
	release := stuckWriter(t, p, a) // the writer holds "first": the queue itself is empty
	for i := range size {
		p.emit(a, fmt.Sprintf("queued %d", i))
	}
	if p.dropped() != 0 {
		t.Fatalf("dropped = %d after filling the queue exactly, want 0", p.dropped())
	}
	const extra = 5
	if !within(func() {
		for i := range extra {
			p.emit(a, fmt.Sprintf("dropped %d", i))
		}
	}) {
		t.Fatalf("emit blocked on a full queue with the writer stuck: the DNS path would wait on the disk")
	}
	if p.dropped() != extra {
		t.Errorf("dropped = %d, want %d: pfb[\"log_dropped\"] counts every row the full queue refused", p.dropped(), extra)
	}
	release()
	p.flush()
	want := "first\n"
	for i := range size {
		want += fmt.Sprintf("queued %d\n", i)
	}
	if got := readLog(t, a); got != want {
		t.Errorf("a.log = %q, want %q: the dropped rows never reach the file", got, want)
	}
}

// Python's QueueListener.stop() queues its sentinel with put_nowait; deinit catches the queue.Full it raises (and never
// reaches the join), so the listener thread lives on and writes what is queued. stop() here returns at once, leaves the
// writer running to drain the queue, and can be tried again.
func TestPipelineStopOnAFullQueueWithAStuckWriterReturnsAndLeavesTheWriterDraining(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	const size = 4
	p := newLogPipeline([]string{a}, size)
	t.Cleanup(p.stop)
	release := stuckWriter(t, p, a)
	for i := range size {
		p.emit(a, fmt.Sprintf("queued %d", i))
	}
	if !within(p.stop) {
		t.Fatal("stop blocked on a full queue with the writer stuck: deinit would hang the module's shutdown")
	}
	select {
	case <-p.done:
		t.Fatal("the writer ended with its queue not drained: Python's listener thread keeps running when the sentinel does not fit")
	default:
	}
	release()
	p.flush() // the writer is still serving the queue
	want := "first\n"
	for i := range size {
		want += fmt.Sprintf("queued %d\n", i)
	}
	if got := readLog(t, a); got != want {
		t.Errorf("a.log = %q, want %q: every queued row is still written", got, want)
	}
	if !within(p.stop) {
		t.Fatal("a second stop, with room in the queue, did not return")
	}
	select {
	case <-p.done:
	default:
		t.Error("the writer is still running after a stop that was queued: it ends once it reads the stop")
	}
}

func TestPipelineReopensAFileThatWasRenamedAway(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	p := newLogPipeline([]string{a}, 10)
	t.Cleanup(p.stop)
	p.emit(a, "before")
	p.flush()
	if err := os.Rename(a, a+".1"); err != nil {
		t.Fatal(err)
	}
	p.emit(a, "after")
	p.flush()
	if got := readLog(t, a); got != "after\n" {
		t.Errorf("a.log = %q, want only the row after the rotation in the new file", got)
	}
	if got := readLog(t, a+".1"); got != "before\n" {
		t.Errorf("a.log.1 = %q, want the row before the rotation in the rotated file", got)
	}
}

func TestPipelineReopensAFileThatWasRemoved(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	p := newLogPipeline([]string{a}, 10)
	t.Cleanup(p.stop)
	p.emit(a, "before")
	p.flush()
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	p.emit(a, "after")
	p.flush()
	if got := readLog(t, a); got != "after\n" {
		t.Errorf("a.log = %q, want the row after the removal in a new file", got)
	}
}

func TestPipelineAppendsToWhatTheFileAlreadyHolds(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	if err := os.WriteFile(a, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := newLogPipeline([]string{a}, 10)
	t.Cleanup(p.stop)
	p.emit(a, "new")
	p.flush()
	if got := readLog(t, a); got != "old\nnew\n" {
		t.Errorf("a.log = %q, want the new row appended: mode \"a\"", got)
	}
}

func TestPipelineStopWritesTheRowsStillQueued(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.log")
	p := newLogPipeline([]string{a}, 5000)
	for i := range 100 {
		p.emit(a, fmt.Sprintf("row %d", i))
	}
	p.stop()
	if n := strings.Count(readLog(t, a), "\n"); n != 100 {
		t.Errorf("a.log has %d rows after stop, want 100: QueueListener.stop() flushes the queue", n)
	}
	p.stop() // a second stop is not an error
}

func TestPipelineWriteFailureIsLoggedOnceUntilItWritesAgain(t *testing.T) {
	logs := modCaptureLog(t)
	dir := t.TempDir()
	a := filepath.Join(dir, "gone", "a.log")
	p := newLogPipeline([]string{a}, 100)
	t.Cleanup(p.stop)
	for range 5 {
		p.emit(a, "lost")
	}
	p.flush()
	if n := strings.Count(logs.String(), "\n"); n != 1 || !strings.Contains(logs.String(), a) {
		t.Errorf("log = %q, want one line naming %s for five failed rows", logs.String(), a)
	}
	if err := os.Mkdir(filepath.Dir(a), 0o755); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	p.emit(a, "kept")
	p.flush()
	if got := readLog(t, a); got != "kept\n" {
		t.Errorf("a.log = %q, want the first row after the directory appeared", got)
	}
	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing once a row is written", logs.String())
	}
	if err := os.RemoveAll(filepath.Dir(a)); err != nil {
		t.Fatal(err)
	}
	p.emit(a, "lost again")
	p.emit(a, "lost again")
	p.flush()
	if n := strings.Count(logs.String(), "\n"); n != 1 {
		t.Errorf("log = %q, want one line for the second run of failures", logs.String())
	}
}

func TestDirectAppendWritesTheRowAndNothingElse(t *testing.T) {
	logs := modCaptureLog(t)
	a := filepath.Join(t.TempDir(), "a.log")
	logEntryDirect("one", a)
	logEntryDirect("two", a)
	if got := readLog(t, a); got != "one\ntwo\n" {
		t.Errorf("a.log = %q, want both rows appended", got)
	}
	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing", logs.String())
	}
}

func TestDirectAppendRetriesFourTimesThenReportsTheLastFailure(t *testing.T) {
	logs := modCaptureLog(t)
	a := filepath.Join(t.TempDir(), "gone", "a.log")
	var slept []time.Duration
	previous := logRetrySleep
	logRetrySleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { logRetrySleep = previous })
	logEntryDirect("lost", a)
	if len(slept) != 4 {
		t.Errorf("slept %d times, want 4: one 0.25 s pause after each of the four failed attempts", len(slept))
	}
	for _, d := range slept {
		if d != 250*time.Millisecond {
			t.Errorf("slept %v, want 250ms", d)
		}
	}
	if !regexp.MustCompile(`^pfb_dns_proxy error: \[pfBlockerNG\]: log_entry: 4: .*gone.*\n$`).MatchString(logs.String()) {
		t.Errorf("log = %q, want one log_entry line for attempt 4, naming the file", logs.String())
	}
}

func TestDirectAppendSucceedsOnALaterAttempt(t *testing.T) {
	logs := modCaptureLog(t)
	dir := filepath.Join(t.TempDir(), "late")
	a := filepath.Join(dir, "a.log")
	attempts := 0
	previous := logRetrySleep
	logRetrySleep = func(time.Duration) {
		attempts++
		if attempts == 2 {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { logRetrySleep = previous })
	logEntryDirect("kept", a)
	if got := readLog(t, a); got != "kept\n" {
		t.Errorf("a.log = %q, want the row written on the third attempt", got)
	}
	if attempts != 2 || logs.Len() != 0 {
		t.Errorf("slept %d times, log %q: want two pauses and no error", attempts, logs.String())
	}
}

// moduleWithLogs boots a module that blocks lf1.example and answers allowed.example from its own resolver; its logs go
// to dir, and the returned Frontend forwards every other name to a fake Unbound that answers 192.0.2.77.
func moduleWithLogs(t *testing.T, dir string) (*pfbUnbound, *Frontend) {
	t.Helper()
	withLogDir(t, dir)
	moduleDir := t.TempDir()
	files := map[string]string{
		"pfb_unbound.ini":     "[MAIN]\npython_enable = true\npython_blocking = true\npython_reply = true\ndnsbl_ipv4 = 10.10.10.1\ndnsbl_ipv6 = fd00::1\n",
		"pfb_py_sources.json": `{"version":1,"config":{},"feeds":[{"raw":"pfb_py_raw/feed.txt","feed":"F1","group":"G1","log_flag":"1"}]}`,
		"pfb_py_raw/feed.txt": "lf1.example\n",
	}
	for rel, text := range files {
		target := filepath.Join(moduleDir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := boot(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	stopModule(t, m)
	return m, newFrontend(m)
}

func qtypeWire(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	wire, err := dnswire.Encode(&dnswire.Message{ID: 0x1234, Flags: dnswire.RD, Questions: []dnswire.Question{{Name: name, Qtype: qtype, Qclass: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// unboundAnswering192_0_2_77 is an upstream that answers every query with one A record.
func unboundAnswering192_0_2_77(t *testing.T) forward {
	return func(wire []byte) []byte {
		name := parse(t, wire).Questions[0].Name
		rr, err := dnswire.RRFromText(name + " 300 IN A 192.0.2.77")
		if err != nil {
			t.Error(err)
			return nil
		}
		return replyTo(t, wire, 0, rr)
	}
}

func TestModuleWritesItsRowsThroughItsPipelineToTheLogFiles(t *testing.T) {
	dir := t.TempDir()
	m, f := moduleWithLogs(t, dir)
	f.Resolve(qtypeWire(t, "lf1.example.", 1), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", "")
	f.Resolve(qtypeWire(t, "allowed.example.", 1), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", "")
	m.stopLogging() // flushes
	stamp := `\d{4}-\d\d-\d\d \d\d:\d\d:\d\d`
	if got, want := readLog(t, filepath.Join(dir, "dnsbl.log")), regexp.MustCompile(`^DNSBL-python,`+stamp+`,lf1\.example,192\.0\.2\.10,Python,DNSBL,G1,lf1\.example,F1,\+,A,UDP,,\n$`); !want.MatchString(got) {
		t.Errorf("dnsbl.log = %q, want one block row", got)
	}
	if got, want := readLog(t, filepath.Join(dir, "dns_reply.log")), regexp.MustCompile(`^DNS-reply,`+stamp+`,reply,A,A,300,allowed\.example,192\.0\.2\.10,192\.0\.2\.77,unk,UDP,,\n$`); !want.MatchString(got) {
		t.Errorf("dns_reply.log = %q, want one reply row", got)
	}
}

func TestModuleWithoutAWriterAppendsDirectly(t *testing.T) {
	dir := t.TempDir()
	m, f := moduleWithLogs(t, dir)
	m.stopLogging()
	f.Resolve(qtypeWire(t, "lf1.example.", 1), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", "")
	if got := readLog(t, filepath.Join(dir, "dnsbl.log")); !strings.HasPrefix(got, "DNSBL-python,") || strings.Count(got, "\n") != 1 {
		t.Errorf("dnsbl.log = %q, want the block row appended by the direct fallback", got)
	}
}

func TestLoggingNeverChangesTheAnswer(t *testing.T) {
	logs := modCaptureLog(t)
	_, working := moduleWithLogs(t, t.TempDir())
	_, broken := moduleWithLogs(t, filepath.Join(t.TempDir(), "no", "such", "dir"))
	_, silent := moduleWithLogs(t, t.TempDir())
	silent.module.logSink = func(string, string) {}
	for _, c := range []struct {
		name  string
		qtype uint16
	}{{"lf1.example.", 1}, {"lf1.example.", 28}, {"allowed.example.", 1}, {"allowed.example.", 28}, {"LF1.example.", 255}, {"a,b.example.", 1}} {
		want := working.Resolve(qtypeWire(t, c.name, c.qtype), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", "")
		if got := broken.Resolve(qtypeWire(t, c.name, c.qtype), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", ""); !bytes.Equal(got, want) {
			t.Errorf("%s type %d: the answer with unwritable logs differs from the one with working logs", c.name, c.qtype)
		}
		if got := silent.Resolve(qtypeWire(t, c.name, c.qtype), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", ""); !bytes.Equal(got, want) {
			t.Errorf("%s type %d: the answer with the rows swallowed differs from the one with working logs", c.name, c.qtype)
		}
	}
	broken.module.stopLogging()
	if !strings.Contains(logs.String(), "dnsbl.log") {
		t.Errorf("log = %q, want the failed write to be reported", logs.String())
	}
}
