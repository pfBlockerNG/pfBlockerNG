package feedparse

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
)

// What the corpus cannot say: behaviour Core has and the old path does not (UTF-16), the limits the old path sets from constants,
// and failures a directory fixture can force without a second user.

func TestNormalizeFileDecodesUTF16(t *testing.T) {
	dir := t.TempDir()
	units := utf16.Encode([]rune("a.example.com\nb.example.com\n"))
	orig := []byte{0xFF, 0xFE}
	for _, u := range units {
		orig = append(orig, byte(u), byte(u>>8))
	}
	if err := os.WriteFile(filepath.Join(dir, "feed.orig"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	got := NormalizeFile(dir, "feed")
	norm, err := os.ReadFile(filepath.Join(dir, "feed.norm"))
	if err != nil || string(norm) != "a.example.com\nb.example.com\n" || !got.Normalized || !got.Changed {
		t.Errorf("NormalizeFile = %+v; .norm = %q, %v; want the decoded text, changed and normalized", got, norm, err)
	}
}

// A .norm that cannot be replaced (here a directory stands where it belongs) is a failure: the raw .orig is parsed, no sidecar
// claims a .norm that is not there, and no temporary file is left.
func TestNormalizeFileFailureFallsBackToTheRawOrig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feed.orig"), []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "feed.norm"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := NormalizeFile(dir, "feed")
	if want := (NormResult{Path: filepath.Join(dir, "feed.orig"), Changed: true}); got != want {
		t.Errorf("NormalizeFile = %+v, want %+v", got, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "feed.norm,feed.orig" {
		t.Errorf("the directory holds %v, want only feed.norm and feed.orig", names)
	}
}

// The limits are the PHP ones: PFB_LIST_SCRIPT_TIMEOUT and PFB_HOOK_KILL_GRACE.
func TestPreScriptLimitsAreTheOldPathsConstants(t *testing.T) {
	if preScriptTimeout != 300*time.Second || preScriptGrace != 5*time.Second {
		t.Errorf("limits = %v and %v, want 300s and 5s", preScriptTimeout, preScriptGrace)
	}
}

// A script that outlives its limit is killed whatever the caller's context says: nothing but the limit ends this run.
func TestPreScriptIsHeldToItsLimit(t *testing.T) {
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "block.sh")
	block := filepath.Join(dir, "block.fifo")
	if err := syscall.Mkfifo(block, 0o600); err != nil {
		t.Skipf("no fifos on this host: %v", err)
	}
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nread -r line < \""+block+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := preScriptTimeout
	preScriptTimeout = 50 * time.Millisecond
	defer func() { preScriptTimeout = old }()
	got := RunPreScript(context.Background(), script, norm, staged, nil)
	if got.OK || got.Reason != PreScriptTimeout || got.Path != norm {
		t.Errorf("RunPreScript = %+v, want a timeout that keeps %s", got, norm)
	}
	if _, err := os.Stat(staged); err == nil {
		t.Error("the staged copy of a killed script was kept")
	}
}

func TestPreScriptOutputGoesToTheLog(t *testing.T) {
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "talk.sh")
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho out\necho err >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if got := RunPreScript(context.Background(), script, norm, staged, &log); !got.OK {
		t.Fatalf("RunPreScript = %+v", got)
	}
	if log.String() != "out\nerr\n" {
		t.Errorf("log = %q, want the script's stdout and stderr", log.String())
	}
	if got := RunPreScript(context.Background(), script, norm, staged, nil); !got.OK {
		t.Errorf("RunPreScript without a log = %+v", got)
	}
}

// CountContent is the empty-feed probe the caller hands ParseIPFeed: the old path counts content lines of the file it probes, and
// only of a file that exists and has bytes. NoProbe says there was nothing to count, which is not "no content".
func TestCountContent(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, c := range []struct {
		name string
		path string
		want int
	}{
		{"missing file", filepath.Join(dir, "missing"), NoProbe},
		{"a directory", dir, NoProbe},
		{"empty file", write("empty", ""), NoProbe},
		{"blank lines", write("blank", "\n  \n\t\r\n"), 0},
		{"comments of every kind", write("comments", "# a\n ; b\n\t! c\n// d\n  // e\n"), 0},
		{"vertical tab and form feed are whitespace", write("vtff", "\v# a\n\f; b\n\v\f\n"), 0},
		{"content lines", write("content", "# a\n1.2.3.4\n\n/ not a comment\nlast"), 3},
		{"a BOM is content", write("bom", "\xEF\xBB\xBF# a\n"), 1},
		{"a control character is content", write("ctl", "\x01# a\n"), 1},
		{"a lone CR is no line end", write("cr", "# a\r# b\r"), 0},
	} {
		if got := CountContent(c.path); got != c.want {
			t.Errorf("%s: CountContent = %d, want %d", c.name, got, c.want)
		}
	}
}

// The temporary file is made beside its target, whatever the system's temp directory is: a rename across filesystems is not
// atomic, and a missing or full /tmp must not cost a feed its .norm.
func TestNormalizeFileTempFileIsBesideTheTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feed.orig"), []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(dir, "no-such-directory"))
	if got := NormalizeFile(dir, "feed"); !got.Normalized || got.Path != filepath.Join(dir, "feed.norm") {
		t.Errorf("NormalizeFile = %+v, want the .norm built with TMPDIR unusable", got)
	}
}

// The old path writes these files with the umask's default (0644 under 022), and a pre-script that drops privileges reads its
// staged input: Core's files are no more private than that.
func TestFeedFilesAreReadableByTheScriptsUser(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	orig, script := filepath.Join(dir, "feed.orig"), filepath.Join(dir, "true.sh")
	if err := os.WriteFile(orig, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	norm := NormalizeFile(dir, "feed")
	staged := filepath.Join(dir, "feed.pre")
	pre := RunPreScript(context.Background(), script, norm.Path, staged, nil)
	if !pre.OK {
		t.Fatalf("RunPreScript = %+v", pre)
	}
	for _, name := range []string{"feed.norm", "feed.norm.src.xxhash128", "feed.pre"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if info.Mode().Perm() != 0o644 {
			t.Errorf("%s has mode %v, want 0644", name, info.Mode().Perm())
		}
	}
}

// A script is a path: a bare name would be looked up on PATH, which names no list's script. The staged copy of an earlier run is
// dropped with the refusal, as with any failure.
func TestRunPreScriptRefusesAScriptWithoutAPath(t *testing.T) {
	dir := t.TempDir()
	bin, canary := filepath.Join(dir, "bin"), filepath.Join(dir, "canary")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "hook.sh"), []byte("#!/bin/sh\n: > "+canary+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	norm, staged := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre")
	for path, text := range map[string]string{norm: "a.example.com\n", staged: "STALE\n"} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := RunPreScript(context.Background(), "hook.sh", norm, staged, nil)
	if got.OK || got.Reason != PreScriptExit || got.Status != 127 || got.Path != norm {
		t.Errorf("RunPreScript = %+v, want a refusal (exit 127) that keeps %s", got, norm)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Error("the bare name was run through PATH")
	}
	if _, err := os.Stat(staged); err == nil {
		t.Error("the stale staged copy was kept")
	}
}

// groupScript holds PFB_TEST_ALIVE open for writing, as does the descendant it starts (it inherits the descriptor), reports on
// PFB_TEST_READY and then blocks, as its descendant does, on a fifo nobody writes. The reader of PFB_TEST_ALIVE sees the end of
// file exactly when every member of the process group is gone: no sleep, no pid to probe, no zombie to mistake for a live process.
const groupScript = `exec 9> "$PFB_TEST_ALIVE"
( read -r line < "$PFB_TEST_BLOCK" ) &
echo ready > "$PFB_TEST_READY"
read -r line < "$PFB_TEST_BLOCK"
`

// guard is how long a test waits for something that must happen, before it calls it a failure; it asserts no duration.
const guard = 15 * time.Second

// freeOnCleanup writes to the blocking fifo when the test ends, so that no reader is left blocked in open or read whatever a
// mutant did to the run: a descendant that outlived a failing run is released with it.
func freeOnCleanup(t *testing.T, fifo string) {
	t.Helper()
	t.Cleanup(func() {
		if w, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			w.WriteString("x\n")
			w.Close()
		}
	})
}

// blockFifo makes the blocking fifo of a script nobody writes.
func blockFifo(t *testing.T, dir string) string {
	t.Helper()
	block := filepath.Join(dir, "block.fifo")
	if err := syscall.Mkfifo(block, 0o600); err != nil {
		t.Fatalf("no fifo: %v", err)
	}
	freeOnCleanup(t, block)
	return block
}

// aliveWatch returns a channel that closes when every writer of PFB_TEST_ALIVE has gone.
func aliveWatch(t *testing.T, dir string) <-chan struct{} {
	t.Helper()
	alive := filepath.Join(dir, "alive.fifo")
	if err := syscall.Mkfifo(alive, 0o600); err != nil {
		t.Fatalf("no fifo: %v", err)
	}
	t.Setenv("PFB_TEST_ALIVE", alive)
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		f, err := os.Open(alive) // blocks until the script opens it for writing
		if err != nil {
			return
		}
		defer f.Close()
		io.Copy(io.Discard, f)
	}()
	t.Cleanup(func() {
		if w, err := os.OpenFile(alive, os.O_RDWR, 0); err == nil { // a script that never came
			w.Close()
		}
	})
	return gone
}

func shortGrace(t *testing.T) {
	t.Helper()
	old := preScriptGrace
	preScriptGrace = 100 * time.Millisecond
	t.Cleanup(func() { preScriptGrace = old })
}

// runGroup runs groupScript (after prelude) until the caller's context ends, as the script reports it is running, and checks that
// the run is a timeout and that no member of the script's process group is left.
func runGroup(t *testing.T, prelude string) {
	t.Helper()
	shortGrace(t)
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "group.sh")
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+prelude+groupScript), 0o700); err != nil {
		t.Fatal(err)
	}
	gone := aliveWatch(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	reported, release := blockOnFifo(t, dir, cancel) // makes PFB_TEST_BLOCK and PFB_TEST_READY
	defer release()
	freeOnCleanup(t, filepath.Join(dir, "block.fifo"))
	got := RunPreScript(ctx, script, norm, staged, nil)
	select {
	case <-reported:
	default:
		t.Fatal("the script never reported it was running: the kill was not the event under test")
	}
	if got.OK || got.Reason != PreScriptTimeout || got.Path != norm {
		t.Errorf("RunPreScript = %+v, want a timeout that keeps %s", got, norm)
	}
	select {
	case <-gone:
	case <-time.After(guard):
		t.Error("a member of the script's process group outlived the run")
	}
}

// TERM goes to the script's whole process group, which is its own: a descendant dies with the script, and nothing else does.
func TestPreScriptTermReachesTheWholeGroup(t *testing.T) { runGroup(t, "") }

// A group that ignores TERM is killed once its grace is over, descendants included.
func TestPreScriptKillsAGroupThatIgnoresTerm(t *testing.T) { runGroup(t, "trap '' TERM\n") }

// A script that has ended leaves a descendant that holds the log open alone; the run does not wait for it.
func TestPreScriptDoesNotWaitForADescendantHoldingTheLog(t *testing.T) {
	shortGrace(t)
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "leave.sh")
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n( read -r line < \"$PFB_TEST_BLOCK\" ) &\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFB_TEST_BLOCK", blockFifo(t, dir))
	done := make(chan PreScriptResult, 1)
	go func() { done <- RunPreScript(context.Background(), script, norm, staged, io.Discard) }() // io.Discard is no file: the log is a pipe
	select {
	case got := <-done:
		if !got.OK || got.Path != staged {
			t.Errorf("RunPreScript = %+v, want the transform to have run", got)
		}
	case <-time.After(guard):
		t.Error("the run waits for a descendant that holds the log open")
	}
}

// A script that a signal ended exits as a shell reports it: 128 plus the signal.
func TestPreScriptSignalExitIs128PlusTheSignal(t *testing.T) {
	for name, want := range map[string]int{"KILL": 128 + 9, "TERM": 128 + 15, "HUP": 128 + 1} {
		dir := t.TempDir()
		norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "die.sh")
		if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(script, []byte("#!/bin/sh\nkill -"+name+" $$\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		got := RunPreScript(context.Background(), script, norm, staged, nil)
		if got.OK || got.Reason != PreScriptExit || got.Status != want {
			t.Errorf("a script ended by %s: RunPreScript = %+v, want exit status %d", name, got, want)
		}
	}
}

// What a feed logs reaches the sink as the feed is read, so a feed that cannot be read to its end has logged its lines before it:
// the PHP loops write their logs the same way. Nothing is kept for the caller to read afterwards.
func TestFeedLogsAreStreamedToTheSink(t *testing.T) {
	t.Run("IP", func(t *testing.T) {
		const feed = "0.0.0.0/0\n999.999.999.999\n1.2.3.4\n"
		cfg := IPConfig{VType: "_v4", PFType: "auto", FloorV4: "Disabled", FloorV6: "Disabled", Suppression: true}
		var whole, cut recorder
		if _, err := ParseIPFeed(strings.NewReader(feed), cfg, "127.1.7.7", NoProbe, io.Discard, whole.sink()); err != nil {
			t.Fatal(err)
		}
		if len(whole.messages) == 0 || len(whole.fails) != 1 {
			t.Fatalf("the reference run logged %q and %v: the feed no longer exercises both sinks", whole.messages, whole.fails)
		}
		_, err := ParseIPFeed(&thenError{data: "0.0.0.0/0\n999.999.999.999\n", err: errRead}, cfg, "127.1.7.7", NoProbe, io.Discard, cut.sink())
		if err == nil || !sameStrings(cut.messages, whole.messages) || !sameRecords(cut.fails, whole.fails) {
			t.Errorf("a feed cut after its failing line: error %v, logged %q and %v; want the lines read before it, %q and %v", err, cut.messages, cut.fails, whole.messages, whole.fails)
		}
	})
	t.Run("DNSBL", func(t *testing.T) {
		cfg := DNSBLConfig{DNSBLIP: true, Lenient: true}
		var cut recorder
		_, err := ParseDNSBLFeed(&thenError{data: "bücher.de\ninvalid_domain\n", err: errRead}, cfg, io.Discard, cut.sink())
		want := []FailRecord{{LineNo: 2, Line: "invalid_domain", Raw: "invalid_domain"}}
		if err == nil || !sameRecords(cut.fails, want) || len(cut.messages) != 1 {
			t.Errorf("a feed cut after its failing line: error %v, logged %q and %v; want one notice and %v", err, cut.messages, cut.fails, want)
		}
	})
}

// repeatReader yields line n times.
type repeatReader struct {
	line string
	n    int
	off  int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	k := copy(p, r.line[r.off:])
	if r.off += k; r.off == len(r.line) {
		r.off, r.n = 0, r.n-1
	}
	return k, nil
}

// A hostile feed of failing lines costs the sink's callbacks, not memory: the result holds counts, never a record per line (the
// download ceiling is 2 GiB, and the PHP loops stream their failures to a log file).
func TestFailingLinesAreNotRetained(t *testing.T) {
	const lines = 200_000
	measure := func(t *testing.T, run func(sink Sink) (any, error)) {
		t.Helper()
		var failed, noticed int
		sink := Sink{Fail: func(FailRecord) { failed++ }, Message: func(string) { noticed++ }}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		result, err := run(sink)
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(result)
		if err != nil {
			t.Fatal(err)
		}
		if failed != lines {
			t.Fatalf("the sink saw %d failures, want %d", failed, lines)
		}
		if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 1<<20 {
			t.Errorf("the live heap grew by %d bytes over %d failing lines: the result keeps what it should have streamed", grown, lines)
		}
	}
	t.Run("IP", func(t *testing.T) {
		measure(t, func(sink Sink) (any, error) {
			return ParseIPFeed(&repeatReader{line: "999.999.999.999\n", n: lines}, IPConfig{VType: "_v4", PFType: "auto", FloorV4: "Disabled", FloorV6: "Disabled"}, "127.1.7.7", NoProbe, io.Discard, sink)
		})
	})
	t.Run("DNSBL", func(t *testing.T) {
		measure(t, func(sink Sink) (any, error) {
			return ParseDNSBLFeed(&repeatReader{line: "invalid_domain\n", n: lines}, DNSBLConfig{DNSBLIP: true, Lenient: true}, io.Discard, sink)
		})
	})
}
