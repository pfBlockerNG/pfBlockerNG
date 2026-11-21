//go:build linux || freebsd

package feedparse

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
)

// What the post-script corpus cannot say: which program a relative script folder runs, how a cancelled run differs from a
// timed-out one, a script that exited before the context ended, and a run without an output file. A blocking script
// reports through a fifo, and the test then ends the context: no case waits on the clock; guard only fails a hung test.

const blockingScript = "#!/bin/sh\necho ready > \"$PFB_TEST_READY\"\nread -r _ < \"$PFB_TEST_BLOCK\"\n"

// writeScript writes a script and a one-line feed into dir and returns the feed's path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(dir, "feed.orig")
	if err := os.WriteFile(orig, []byte("a.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return orig
}

// A script folder given as a relative path runs the vetted file, never a program of the same name found on PATH.
func TestPostScriptRunsTheVettedFileNotOneOnPath(t *testing.T) {
	dir, decoy, marks := t.TempDir(), t.TempDir(), t.TempDir()
	mark := func(name string) string { return "#!/bin/sh\n: > '" + filepath.Join(marks, name) + "'\n" }
	orig := writeScript(t, dir, "post.sh", mark("vetted"))
	writeScript(t, decoy, "post.sh", mark("decoy"))
	t.Setenv("PATH", decoy+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(dir)
	r := PostScript{Name: "post.sh", Dirs: []string{"."}, Header: "hdr"}.RunDNSBL(context.Background(), orig,
		filepath.Join(dir, "feed.post"))
	_, vetted := os.Stat(filepath.Join(marks, "vetted"))
	_, decoyRan := os.Stat(filepath.Join(marks, "decoy"))
	if vetted != nil || decoyRan == nil || r.Reason != "" || r.Skipped {
		t.Errorf("vetted file ran: %v, decoy on PATH ran: %v, result %+v; want only the vetted file run, successfully",
			vetted == nil, decoyRan == nil, r)
	}
}

// A post-script whose caller cancels the run while it runs is reported as cancelled, with its own line and no TIMED OUT;
// the IP download is put back as after any failure.
func TestPostScriptCancelledWhileRunningIsNotATimeout(t *testing.T) {
	for _, kind := range []string{"dnsbl", "_v4"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), watchdog)
			defer cancel()
			reported, release := blockOnFifo(t, dir, cancel)
			defer release()
			orig := writeScript(t, dir, "post.sh", blockingScript)
			var log, errs, transcript bytes.Buffer
			p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr", Log: &log, Errors: &errs, Transcript: &transcript}
			var r PostScriptResult
			if kind == "dnsbl" {
				r = p.RunDNSBL(ctx, orig, filepath.Join(dir, "feed.post"))
			} else {
				r = p.RunIP(ctx, orig, filepath.Join(dir, "feed.orig.post"), kind)
			}
			select {
			case <-reported:
			default:
				t.Fatal("the script never reported it was running: the cancellation was not the event under test")
			}
			line := "\n[ hdr ] post-script 'post.sh' was cancelled; discarding its output\n"
			if want := "\nExecuting post-script: post.sh\n" + line; log.String() != want || transcript.String() != want ||
				errs.String() != line {
				t.Errorf("log %q, transcript %q, error log %q; want both logs %q and the error log %q", log.String(),
					transcript.String(), errs.String(), want, line)
			}
			if r.Reason != PreScriptCancelled || r.Status != 0 || r.Skipped {
				t.Errorf("result %+v; want a cancellation", r)
			}
			if b, err := os.ReadFile(orig); err != nil || string(b) != "a.example\n" {
				t.Errorf("download %q, %v; want it untouched", b, err)
			}
		})
	}
}

// A pre-script whose caller cancels the run while it runs is reported as cancelled, not as a timeout.
func TestPreScriptCancelledWhileRunningIsNotATimeout(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	reported, release := blockOnFifo(t, dir, cancel)
	defer release()
	norm := writeScript(t, dir, "pre.sh", blockingScript)
	got := RunPreScript(ctx, filepath.Join(dir, "pre.sh"), norm, filepath.Join(dir, "feed.pre"), nil)
	select {
	case <-reported:
	default:
		t.Fatal("the script never reported it was running: the cancellation was not the event under test")
	}
	if want := (PreScriptResult{Path: norm, Reason: PreScriptCancelled}); got != want {
		t.Errorf("RunPreScript = %+v; want %+v", got, want)
	}
}

// heldLog takes a script's first write, its PID, and holds it until the script has exited and been reaped; it then ends
// the run's context and lets the write through. The script exited by itself before the context ended, and the run, which
// waits for its output, cannot have returned before it did.
type heldLog struct {
	t    *testing.T
	end  context.CancelFunc
	once sync.Once
}

func (h *heldLog) Write(p []byte) (int, error) {
	h.once.Do(func() {
		pid, err := strconv.Atoi(strings.TrimSpace(string(p)))
		if err != nil {
			h.t.Errorf("first write %q: want the script's PID", p)
			return
		}
		for deadline := time.Now().Add(guard); !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				h.t.Errorf("the script %d never exited", pid)
				return
			}
		}
		h.end()
	})
	return len(p), nil
}

// A script that exits non-zero by itself keeps its status when its caller cancels the run, or its limit ends it, after it
// exited and before the run returned.
func TestScriptThatExitedBeforeTheContextEndedKeepsItsStatus(t *testing.T) {
	for _, end := range []string{"cancelled", "limit"} {
		t.Run(end, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel, limit := limitOnEvent()
			defer cancel()
			log := &heldLog{t: t, end: cancel}
			if end == "limit" {
				log.end = limit
			}
			norm := writeScript(t, dir, "pre.sh", "#!/bin/sh\necho $$\nexit 3\n")
			got := RunPreScript(ctx, filepath.Join(dir, "pre.sh"), norm, filepath.Join(dir, "feed.pre"), log)
			if ctx.Err() == nil {
				t.Fatal("the context did not end before the run returned: the order under test did not happen")
			}
			if want := (PreScriptResult{Path: norm, Reason: PreScriptExit, Status: 3}); got != want {
				t.Errorf("RunPreScript = %+v; want %+v", got, want)
			}
		})
	}
}

// A post-script for which no output file can be made does not run, and its status is -1.
func TestPostScriptWithoutAnOutputFileHasStatusMinusOne(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	orig := writeScript(t, dir, "post.sh", "#!/bin/sh\n: > '"+marker+"'\n")
	t.Setenv("TMPDIR", filepath.Join(dir, "missing"))
	var log bytes.Buffer
	r := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr", Log: &log}.RunDNSBL(context.Background(), orig,
		filepath.Join(dir, "feed.post"))
	if _, err := os.Stat(marker); err == nil {
		t.Error("the script ran without an output file")
	}
	want := "\nExecuting post-script: post.sh\n\n[ hdr ] post-script 'post.sh' exited non-zero [ -1 ]; discarding its output\n"
	if r.Reason != PreScriptExit || r.Status != -1 || log.String() != want {
		t.Errorf("result %+v, log %q; want status -1 and the log %q", r, log.String(), want)
	}
}
