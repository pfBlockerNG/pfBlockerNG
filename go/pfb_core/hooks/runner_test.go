//go:build linux || freebsd

package hooks_test

// Runner behaviour the corpus cannot express: a context that ends, the environment the runner inherits, a relative hook
// directory, and output read while a hook runs. Ordering waits on events (files, FIFOs); the hang cap only fails a hung
// test.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
)

const hang = 30 * time.Second // fails a hung test; never decides an order

// watchedLog is a log that closes seen at the first write after which it holds want, and holds that write until hold
// is closed.
type watchedLog struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	want       string
	seen, hold chan struct{}
	once       sync.Once
}

func newWatchedLog(want string, hold chan struct{}) *watchedLog {
	return &watchedLog{want: want, seen: make(chan struct{}), hold: hold}
}

func (w *watchedLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)
	hit := strings.Contains(w.buf.String(), w.want)
	w.mu.Unlock()
	if hit {
		w.once.Do(func() { close(w.seen); <-w.hold })
	}
	return len(p), nil
}

func (w *watchedLog) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func closed() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// fifo makes a FIFO and opens it read-write without blocking: a line written to it waits there until a hook reads it.
func fifo(t *testing.T, path string) *os.File {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func release(t *testing.T, f *os.File) {
	t.Helper()
	if _, err := f.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
}

// await polls a real condition on a short tick until it holds; the cap only fails a hung test.
func await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(hang); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("hung: %s", what)
		}
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// start runs r in the background; the returned channel closes when Run returns.
func start(ctx context.Context, r hooks.Runner, rows []hooks.Hook, c hooks.Context) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx, "pre", rows, c)
	}()
	return done
}

func finished(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(hang):
		t.Fatal("hung: the run did not return")
	}
}

func pre(scripts ...string) []hooks.Hook {
	var rows []hooks.Hook
	for _, s := range scripts {
		rows = append(rows, hooks.Hook{When: "pre", Script: s, Enabled: true})
	}
	return rows
}

// A hook's output reaches the log while the hook still runs, as today's 200 ms drain does.
func TestRunnerLogsOutputWhileTheHookRuns(t *testing.T) {
	dir := t.TempDir()
	gate := fifo(t, filepath.Join(dir, "go"))
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), "#!/bin/sh\necho line\nread x < '"+dir+"/go'\necho after\n",
		0o755)
	log := newWatchedLog("line\n", closed())
	var transcript bytes.Buffer
	done := start(context.Background(), hooks.Runner{Dir: dir, Log: log, Transcript: &transcript, Grace: time.Second},
		pre("hook_pre_a.sh"), hooks.Context{})
	select {
	case <-log.seen:
	case <-done:
		t.Fatal("the run returned while the hook was blocked")
	case <-time.After(hang):
		release(t, gate)
		finished(t, done)
		t.Fatalf("the hook's line did not reach the log while the hook ran; log after it exited: %q", log)
	}
	release(t, gate)
	finished(t, done)
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\nline\nafter\n[ pfB Hook ] pre #0 completed\n"
	if log.String() != want || transcript.String() != want {
		t.Errorf("log %q, transcript %q; want both %q", log, transcript.String(), want)
	}
}

// A context that ends is a cancelled run, never a hook timeout nor a hook that could not start: one line says so and
// how many enabled hooks did not run, and no later hook starts.
func TestRunnerReportsACancelledRunNotATimeout(t *testing.T) {
	for name, tc := range map[string]struct {
		scripts []string
		probe   bool   // the cancel lands during the Python wrapper's probe
		during  bool   // the cancel lands while the first hook runs
		want    string // the log
	}{
		"while a hook runs": {scripts: []string{"hook_pre_a.sh", "hook_pre_b.sh"}, during: true,
			want: "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n" +
				"[ pfB Hook ] pre run cancelled; 1 enabled hook did not run\n"},
		"before the first hook": {scripts: []string{"hook_pre_a.sh", "hook_pre_b.sh"},
			want: "[ pfB Hook ] pre run cancelled; 2 enabled hooks did not run\n"},
		"during the Python probe": {scripts: []string{"hook_pre_a.py", "hook_pre_b.sh"}, probe: true,
			want: "[ pfB Hook ] pre run cancelled; 2 enabled hooks did not run\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			fifo(t, filepath.Join(dir, "go")) // never released: only the cancel ends what waits on it
			writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
				"#!/bin/sh\n: > '"+dir+"/started'\nread x < '"+dir+"/go'\n", 0o755)
			writeFile(t, filepath.Join(dir, "hook_pre_a.py"), "touch '"+dir+"/canary-a'\n", 0o644)
			writeFile(t, filepath.Join(dir, "hook_pre_b.sh"), "#!/bin/sh\ntouch '"+dir+"/canary-b'\n", 0o755)
			writeFile(t, filepath.Join(dir, "wrapper.sh"), "#!/bin/sh\nif [ \"$1\" = --print-interpreter ]; then\n"+
				"\t: > '"+dir+"/started'\n\tread x < '"+dir+"/go'\n\techo /fixture/interpreter\n\texit 0\nfi\n"+
				"exec /bin/sh \"$@\"\n", 0o755)
			var log, errs, transcript bytes.Buffer
			r := hooks.Runner{Dir: dir, Python: filepath.Join(dir, "wrapper.sh"), Log: &log, Errors: &errs,
				Transcript: &transcript, Grace: time.Second}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !tc.during && !tc.probe {
				cancel()
			}
			done := make(chan struct{})
			go func() { defer close(done); r.Run(ctx, "pre", pre(tc.scripts...), hooks.Context{}) }()
			if tc.during || tc.probe {
				await(t, "the hook or the probe to start", func() bool { return exists(filepath.Join(dir, "started")) })
				cancel()
			}
			finished(t, done)
			if log.String() != tc.want || transcript.String() != tc.want {
				t.Errorf("log %q, transcript %q; want both %q", log.String(), transcript.String(), tc.want)
			}
			if want := tc.want[strings.LastIndex(tc.want[:len(tc.want)-1], "\n")+1:]; errs.String() != want {
				t.Errorf("error log %q; want %q", errs.String(), want)
			}
			for _, canary := range []string{"canary-a", "canary-b"} {
				if exists(filepath.Join(dir, canary)) {
					t.Errorf("%s exists: a hook ran after the context ended", canary)
				}
			}
		})
	}
}

// A NUL in the package operation cannot be an environment entry: PFB_PKG_OP is set empty, as when no pkg operation is
// known, and the hooks still run.
func TestRunnerSetsANULPkgOpEmpty(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
		"#!/bin/sh\nprintf '%s' \"${PFB_PKG_OP-unset}\" > '"+dir+"/pkgop'\n", 0o755)
	var log bytes.Buffer
	hooks.Runner{Dir: dir, Log: &log, Grace: time.Second}.Run(context.Background(), "pre", pre("hook_pre_a.sh"),
		hooks.Context{PkgOp: "up\x00grade"})
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n[ pfB Hook ] pre #0 completed\n"
	if got, err := os.ReadFile(filepath.Join(dir, "pkgop")); err != nil || string(got) != "" || log.String() != want {
		t.Errorf("PFB_PKG_OP = %q (%v), log %q; want set empty and log %q", got, err, log.String(), want)
	}
}

// The runner executes the vetted file itself: with the hook directory given as ".", a PATH lookup would find another
// file of that name. A Python wrapper that is not an absolute path is no usable launcher.
func TestRunnerRunsTheVettedFileNeverAPATHLookup(t *testing.T) {
	dir, bin := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), "#!/bin/sh\ntouch '"+dir+"/ran'\n", 0o755)
	writeFile(t, filepath.Join(dir, "hook_pre_b.py"), "touch '"+dir+"/canary-python'\n", 0o644)
	writeFile(t, filepath.Join(bin, "hook_pre_a.sh"), "#!/bin/sh\ntouch '"+dir+"/canary-path'\n", 0o755)
	writeFile(t, filepath.Join(bin, "pfbwrap"), "#!/bin/sh\nif [ \"$1\" = --print-interpreter ]; then\n"+
		"\techo /fixture/interpreter\n\texit 0\nfi\nexec /bin/sh \"$@\"\n", 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(dir)
	var log bytes.Buffer
	hooks.Runner{Dir: ".", Python: "pfbwrap", Log: &log, Grace: time.Second}.Run(context.Background(), "pre",
		pre("hook_pre_a.sh", "hook_pre_b.py"), hooks.Context{})
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n[ pfB Hook ] pre #0 completed\n" +
		"[ pfB Hook ] pre #1 script 'hook_pre_b.py' has no usable launcher; skipping\n"
	if log.String() != want {
		t.Errorf("log %q; want %q", log.String(), want)
	}
	for file, want := range map[string]bool{"ran": true, "canary-path": false, "canary-python": false} {
		if exists(filepath.Join(dir, file)) != want {
			t.Errorf("%s exists = %v; want %v", file, !want, want)
		}
	}
}

// The transcript holds 1,048,576 sanitized bytes of a hook's output: exactly that many give no notice, one more gives
// it.
func TestRunnerTranscriptAllowanceBoundary(t *testing.T) {
	const allowance = 1 << 20
	notice := "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
	header, footer := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n", "[ pfB Hook ] pre #0 completed\n"
	for _, tc := range []struct {
		size   int
		notice string
	}{{allowance, ""}, {allowance + 1, notice}} {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
			"#!/bin/sh\nhead -c "+strconv.Itoa(tc.size)+" /dev/zero | tr '\\000' a\n", 0o755)
		var log, transcript bytes.Buffer
		hooks.Runner{Dir: dir, Log: &log, Transcript: &transcript, Grace: time.Second}.Run(context.Background(), "pre",
			pre("hook_pre_a.sh"), hooks.Context{})
		if want := header + strings.Repeat("a", tc.size) + footer; log.String() != want {
			t.Errorf("%d bytes: log is %d bytes; want %d", tc.size, log.Len(), len(want))
		}
		if want := header + strings.Repeat("a", allowance) + tc.notice + footer; transcript.String() != want {
			t.Errorf("%d bytes: transcript %s; want %s", tc.size, clip(transcript.String()), clip(want))
		}
	}
}

// A hook inherits the runner's own environment, not only the PFB_* entries.
func TestRunnerHookInheritsTheRunnersEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOOK_TEST_MARKER", "inherited")
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
		"#!/bin/sh\nprintf '%s' \"${HOOK_TEST_MARKER-unset}\" > '"+dir+"/marker'\n", 0o755)
	hooks.Runner{Dir: dir, Grace: time.Second}.Run(context.Background(), "pre", pre("hook_pre_a.sh"), hooks.Context{})
	if got, err := os.ReadFile(filepath.Join(dir, "marker")); err != nil || string(got) != "inherited" {
		t.Errorf("HOOK_TEST_MARKER in the hook = %q (%v); want %q", got, err, "inherited")
	}
}

// Output is read up to the size the file had when the hook's own process exited: a descendant that writes after that
// is not read, even while the runner is still reading. The runner removes the capture file once that size is fixed;
// the test holds the runner inside a log write until the descendant has written.
func TestRunnerReadsOutputOnlyUpToTheHooksExit(t *testing.T) {
	dir, tmp := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	gate, late := fifo(t, filepath.Join(dir, "go")), fifo(t, filepath.Join(dir, "late"))
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), "#!/bin/sh\n"+
		"( read x < '"+dir+"/late'; echo late; : > '"+dir+"/wrote' ) &\n"+
		"echo first\nread x < '"+dir+"/go'\necho tail\n", 0o755)
	hold := make(chan struct{})
	log := newWatchedLog("first\n", hold)
	var transcript bytes.Buffer
	done := start(context.Background(), hooks.Runner{Dir: dir, Log: log, Transcript: &transcript, Grace: time.Second},
		pre("hook_pre_a.sh"), hooks.Context{})
	select {
	case <-log.seen:
	case <-time.After(hang):
		release(t, gate)
		release(t, late)
		close(hold)
		finished(t, done)
		t.Fatalf("the hook's first line did not reach the log while the hook ran; log after it exited: %q", log)
	}
	release(t, gate) // the hook writes its tail and exits while the runner is held in the log write
	await(t, "the runner to fix the read cutoff (the capture file removed)", func() bool {
		left, _ := filepath.Glob(filepath.Join(tmp, "pfb-hook-output-*"))
		return len(left) == 0
	})
	release(t, late)
	await(t, "the descendant to write after the hook exited", func() bool {
		return exists(filepath.Join(dir, "wrote"))
	})
	close(hold)
	finished(t, done)
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\nfirst\ntail\n[ pfB Hook ] pre #0 completed\n"
	if log.String() != want || transcript.String() != want {
		t.Errorf("log %q, transcript %q; want both %q (the late line unread)", log, transcript.String(), want)
	}
}

// A drain tick never reads past the size the output had when the hook's own process exited, even when that exit is
// recorded between the tick and its read: the test holds the runner in that gap while the hook exits, the runner
// removes the capture file once the cutoff is recorded, and a descendant writes a late line.
func TestRunnerTickNeverReadsPastTheExitCutoff(t *testing.T) {
	dir, tmp := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	gate, late := fifo(t, filepath.Join(dir, "go")), fifo(t, filepath.Join(dir, "late"))
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), "#!/bin/sh\n"+
		"( read x < '"+dir+"/late'; echo late; : > '"+dir+"/wrote' ) &\n"+
		"echo first\nread x < '"+dir+"/go'\n", 0o755)
	inGap, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	saved := *hooks.BeforeTickSize
	*hooks.BeforeTickSize = func() { once.Do(func() { close(inGap); <-resume }) }
	t.Cleanup(func() { *hooks.BeforeTickSize = saved })
	var log, transcript bytes.Buffer
	done := start(context.Background(), hooks.Runner{Dir: dir, Log: &log, Transcript: &transcript, Grace: time.Second},
		pre("hook_pre_a.sh"), hooks.Context{})
	select {
	case <-inGap:
	case <-time.After(hang):
		release(t, gate)
		release(t, late)
		finished(t, done)
		t.Fatal("hung: no drain tick was taken while the hook ran")
	}
	release(t, gate) // the hook exits while the runner is held between the tick and its read
	await(t, "the runner to record the read cutoff (the capture file removed)", func() bool {
		left, _ := filepath.Glob(filepath.Join(tmp, "pfb-hook-output-*"))
		return len(left) == 0
	})
	release(t, late)
	await(t, "the descendant to write after the hook exited", func() bool {
		return exists(filepath.Join(dir, "wrote"))
	})
	close(resume)
	finished(t, done)
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\nfirst\n[ pfB Hook ] pre #0 completed\n"
	if log.String() != want || transcript.String() != want {
		t.Errorf("log %q, transcript %q; want both %q (the late line unread)", log.String(), transcript.String(), want)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// A sink that fails to take a hook's output leaves one line in the error log per hook run, the other sink still gets
// all of it, and the hook's own status is kept.
func TestRunnerReportsAFailedOutputSinkOncePerHook(t *testing.T) {
	for _, sink := range []string{"main log", "transcript"} {
		t.Run(sink, func(t *testing.T) {
			dir := t.TempDir()
			gate := fifo(t, filepath.Join(dir, "go"))
			writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
				"#!/bin/sh\necho one\nread x < '"+dir+"/go'\necho two\nexit 3\n", 0o755)
			writeFile(t, filepath.Join(dir, "hook_pre_b.sh"), "#!/bin/sh\necho three\n", 0o755)
			healthy := newWatchedLog("one\n", closed())
			var errs bytes.Buffer
			r := hooks.Runner{Dir: dir, Log: failingWriter{}, Transcript: healthy, Errors: &errs, Grace: time.Second}
			if sink == "transcript" {
				r.Log, r.Transcript = healthy, failingWriter{}
			}
			done := start(context.Background(), r, pre("hook_pre_a.sh", "hook_pre_b.sh"), hooks.Context{})
			select {
			case <-healthy.seen:
			case <-time.After(hang):
				release(t, gate)
				finished(t, done)
				t.Fatalf("the hook's first line did not reach the healthy sink while the hook ran: %q", healthy)
			}
			release(t, gate) // the hook writes again into the failed sink before it exits
			finished(t, done)
			failed := "[ pfB Script Output ] Failed to write script output to " + sink + "; child status is preserved\n"
			status := "[ pfB Hook ] pre #0 exited non-zero [ 3 ]; continuing\n"
			if want := failed + status + failed; errs.String() != want {
				t.Errorf("error log %q; want %q", errs.String(), want)
			}
			want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\none\ntwo\n" + status +
				"\n[ pfB Hook ] pre #1 (hook_pre_b.sh, timeout 60s)\nthree\n[ pfB Hook ] pre #1 completed\n"
			if healthy.String() != want {
				t.Errorf("healthy sink %q; want %q", healthy, want)
			}
		})
	}
}

// A hook that exists but cannot be started for a reason other than permission or format is logged as 126, as
// timeout(1) reports "found but cannot be invoked"; 127 is only for a program that does not exist. Here its #!
// interpreter path is a symlink loop (ELOOP).
func TestRunnerLogsAStartFailureOtherThanNotFoundAs126(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), "#!"+dir+"/loop\n", 0o755)
	var log bytes.Buffer
	hooks.Runner{Dir: dir, Log: &log, Grace: time.Second}.Run(context.Background(), "pre", pre("hook_pre_a.sh"),
		hooks.Context{})
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n[ pfB Hook ] pre #0 exited non-zero [ 126 ]; continuing\n"
	if log.String() != want {
		t.Errorf("log %q; want %q", log.String(), want)
	}
}

// liveRun runs one hook that writes, blocks on the FIFO go until the log holds mark, then writes again, and returns
// the log and the transcript.
func liveRun(t *testing.T, body, mark string) (log, transcript string) {
	t.Helper()
	dir := t.TempDir()
	gate := fifo(t, filepath.Join(dir, "go"))
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"), strings.ReplaceAll(body, "{go}", "'"+dir+"/go'"), 0o755)
	watched := newWatchedLog(mark, closed())
	var out bytes.Buffer
	done := start(context.Background(), hooks.Runner{Dir: dir, Log: watched, Transcript: &out, Grace: time.Second},
		pre("hook_pre_a.sh"), hooks.Context{})
	select {
	case <-watched.seen:
	case <-time.After(hang):
		release(t, gate)
		finished(t, done)
		t.Fatalf("%q did not reach the log while the hook ran: %s", mark, clip(watched.String()))
	}
	release(t, gate)
	finished(t, done)
	return watched.String(), out.String()
}

// A UTF-8 character whose bytes arrive in two reads is kept whole, never escaped byte by byte.
func TestRunnerKeepsACharacterSplitAcrossReads(t *testing.T) {
	log, _ := liveRun(t, "#!/bin/sh\nprintf 'MARK\\303'\nread x < {go}\nprintf '\\251'\n", "MARK")
	if want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\nMARKé[ pfB Hook ] pre #0 completed\n"; log != want {
		t.Errorf("log %q; want %q", log, want)
	}
}

// The transcript allowance counts across reads: one notice, after exactly the allowance.
func TestRunnerTranscriptAllowanceSpansReads(t *testing.T) {
	const allowance, half = 1 << 20, 700000
	n := strconv.Itoa(half)
	log, transcript := liveRun(t, "#!/bin/sh\nhead -c "+n+" /dev/zero | tr '\\000' a\nprintf MARK\nread x < {go}\n"+
		"head -c "+n+" /dev/zero | tr '\\000' b\n", "MARK")
	header, footer := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n", "[ pfB Hook ] pre #0 completed\n"
	output := strings.Repeat("a", half) + "MARK" + strings.Repeat("b", half)
	if want := header + output + footer; log != want {
		t.Errorf("log %s; want %s", clip(log), clip(want))
	}
	notice := "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
	if want := header + output[:allowance] + notice + footer; transcript != want {
		t.Errorf("transcript %s; want %s", clip(transcript), clip(want))
	}
}

// The allowance cut can fall inside a run of printable text: the transcript holds exactly the allowance of sanitized
// output, then the notice.
func TestRunnerTranscriptCutsInsideAPrintableRun(t *testing.T) {
	const allowance = 1 << 20
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hook_pre_a.sh"),
		"#!/bin/sh\nprintf '\\001'\nhead -c "+strconv.Itoa(allowance)+" /dev/zero | tr '\\000' a\n", 0o755)
	var transcript bytes.Buffer
	hooks.Runner{Dir: dir, Transcript: &transcript, Grace: time.Second}.Run(context.Background(), "pre",
		pre("hook_pre_a.sh"), hooks.Context{})
	notice := "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\n" + `\x01` + strings.Repeat("a", allowance-4) + notice +
		"[ pfB Hook ] pre #0 completed\n"
	if transcript.String() != want {
		t.Errorf("transcript %s; want %s", clip(transcript.String()), clip(want))
	}
}
