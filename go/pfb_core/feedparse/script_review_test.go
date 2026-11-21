//go:build linux || freebsd

package feedparse

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"maps"
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
// the IP download, which the script changed before it reported, is put back by RunIP itself as after any failure, and no
// staged copy or restore point is left.
func TestPostScriptCancelledWhileRunningIsNotATimeout(t *testing.T) {
	for _, kind := range []string{"dnsbl", "_v4"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), watchdog)
			defer cancel()
			reported, release := blockOnFifo(t, dir, cancel)
			defer release()
			orig := writeScript(t, dir, "post.sh", "#!/bin/sh\necho changed > \"$1\"\n"+blockingScript[len("#!/bin/sh\n"):])
			var log, errs, transcript bytes.Buffer
			p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr", Log: &log, Errors: &errs, Transcript: &transcript}
			var r PostScriptResult
			staged := filepath.Join(dir, "feed.post")
			if kind == "dnsbl" {
				r = p.RunDNSBL(ctx, orig, staged)
			} else {
				staged = filepath.Join(dir, "feed.orig.post")
				r = p.RunIP(ctx, orig, staged, kind)
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
				t.Errorf("download %q, %v; want the original", b, err)
			}
			if _, err := os.Lstat(staged); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s after the run: %v; want it gone", filepath.Base(staged), err)
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

// A FIFO at the download, which an earlier script can leave there, is refused before it is opened: the run reports a
// staging failure at once instead of blocking in open(2). Not a corpus case: today's copy() opens the FIFO and blocks for
// ever. guard only fails a hung run.
func TestPostScriptFifoAtTheDownloadIsAStagingFailure(t *testing.T) {
	for _, kind := range []string{"dnsbl", "_v4"} {
		t.Run(kind, func(t *testing.T) {
			dir, marks := t.TempDir(), t.TempDir()
			marker := filepath.Join(marks, "ran")
			body := "#!/bin/sh\n: > '" + marker + "'\n"
			orig := writeScript(t, dir, "post.sh", body)
			if err := os.Remove(orig); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(orig, 0o600); err != nil {
				t.Skipf("no fifos on this host: %v", err)
			}
			t.Cleanup(func() { // a run blocked in open(2) is let go
				if f, err := os.OpenFile(orig, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
					f.Close()
				}
			})
			p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr"}
			done := make(chan PostScriptResult, 1)
			go func() {
				if kind == "dnsbl" {
					done <- p.RunDNSBL(context.Background(), orig, filepath.Join(dir, "feed.post"))
				} else {
					done <- p.RunIP(context.Background(), orig, filepath.Join(dir, "feed.orig.post"), kind)
				}
			}()
			var r PostScriptResult
			select {
			case r = <-done:
			case <-time.After(guard):
				t.Fatal("the run blocked on the FIFO at the download")
			}
			if r.Reason != PreScriptStage || r.Skipped {
				t.Errorf("result %+v; want a staging failure", r)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("the script ran without a staged input")
			}
			if want, have := map[string]string{"feed.orig": "<fifo>", "post.sh": "=" + body}, listFeed(t, dir); !maps.Equal(want, have) {
				t.Errorf("feed folder %q; want %q", have, want)
			}
		})
	}
}

// An empty entry in Dirs (an unset flag) is no folder: it never makes the working folder a script folder.
func TestPostScriptEmptyFolderIsNoFolder(t *testing.T) {
	dir, marks := t.TempDir(), t.TempDir()
	canary := filepath.Join(marks, "canary")
	orig := writeScript(t, dir, "post.sh", "#!/bin/sh\n: > '"+canary+"'\n")
	t.Chdir(dir)
	r := PostScript{Name: "post.sh", Dirs: []string{""}, Header: "hdr"}.RunDNSBL(context.Background(), orig,
		filepath.Join(dir, "feed.post"))
	if _, err := os.Stat(canary); err == nil || !r.Skipped {
		t.Errorf("script ran: %v, result %+v; want it never vetted nor run", err == nil, r)
	}
}

// What sits at the restore point and is not a regular file (an empty folder a script left) is removed when it makes the
// staging fail, so that the next run stages normally.
func TestPostScriptFolderAtTheRestorePointDoesNotBlockLaterRuns(t *testing.T) {
	dir := t.TempDir()
	orig := writeScript(t, dir, "post.sh", "#!/bin/sh\necho changed > \"$1\"\n")
	restore := filepath.Join(dir, "feed.orig.post")
	if err := os.Mkdir(restore, 0o700); err != nil {
		t.Fatal(err)
	}
	p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr"}
	if r := p.RunIP(context.Background(), orig, restore, "_v4"); r.Reason != PreScriptStage {
		t.Errorf("first run %+v; want a staging failure", r)
	}
	if _, err := os.Lstat(restore); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("restore point after the failed run: %v; want it gone", err)
	}
	r := p.RunIP(context.Background(), orig, restore, "_v4")
	if r.Reason != "" || r.Skipped {
		t.Errorf("second run %+v; want a success", r)
	}
	if b, err := os.ReadFile(orig); err != nil || string(b) != "changed\n" {
		t.Errorf("download after the second run %q, %v; want the script's output", b, err)
	}
	r.Restore()
	if b, err := os.ReadFile(orig); err != nil || string(b) != "a.example\n" {
		t.Errorf("download after the restore %q, %v; want it put back", b, err)
	}
}

// copyFile has one temporary name per destination: a leftover there (a file, a symbolic link, an empty folder) is taken
// over, a link's target is never written, and nothing but the destination is left.
func TestCopyFileTakesOverALeftoverTemporaryFile(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "dir"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "target")
			src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
			for path, text := range map[string]string{src: "data\n", target: "precious\n"} {
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			switch tmp := dst + ".tmp"; kind {
			case "file":
				err = os.WriteFile(tmp, []byte("stale\n"), 0o600)
			case "symlink":
				err = os.Symlink(target, tmp)
			default:
				err = os.Mkdir(tmp, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := copyFile(src, dst); err != nil {
				t.Fatalf("copyFile: %v", err)
			}
			if want, have := map[string]string{"src": "=data\n", "dst": "=data\n"}, listFeed(t, dir); !maps.Equal(want, have) {
				t.Errorf("folder %q; want %q", have, want)
			}
			if b, err := os.ReadFile(target); err != nil || string(b) != "precious\n" {
				t.Errorf("link target %q, %v; want it untouched", b, err)
			}
			if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o644 {
				t.Errorf("destination %v, %v; want mode 0644", info, err)
			}
		})
	}
}

// Not a corpus row: today's PHP reports the KILL through the shell that runs timeout(1), and the result differs between
// shells (137 with a Killed line, or -1). Here a script that ignores TERM is killed once the grace is over: a timeout.
func TestPostScriptThatIgnoresTermIsKilledAtItsLimit(t *testing.T) {
	dir, test := t.TempDir(), t.TempDir()
	ctx, cancel, limit := limitOnEvent()
	defer cancel()
	reported, release := blockOnFifo(t, test, limit)
	defer release()
	body := "#!/bin/sh\ntrap '' TERM\necho started\n" + blockingScript[len("#!/bin/sh\n"):]
	orig := writeScript(t, dir, "post.sh", body)
	var log, errs, transcript bytes.Buffer
	p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr", Log: &log, Errors: &errs, Transcript: &transcript}
	got := p.RunDNSBL(ctx, orig, filepath.Join(dir, "feed.post"))
	select {
	case <-reported:
	default:
		t.Fatal("the script never reported it was running: the kill was not the event under test")
	}
	const tail = "\n[ hdr ] post-script 'post.sh' TIMED OUT (killed); discarding its output\n"
	want := "\nExecuting post-script: post.sh\nstarted\n" + tail
	if got.Reason != PreScriptTimeout || got.Status != 0 || got.Skipped {
		t.Errorf("Skipped, Reason, Status = %v, %q, %d; want false, %q, 0",
			got.Skipped, got.Reason, got.Status, PreScriptTimeout)
	}
	if log.String() != want || transcript.String() != want || errs.String() != tail {
		t.Errorf("log %q, transcript %q, errors %q; want %q, %q, %q", log.String(), transcript.String(), errs.String(), want,
			want, tail)
	}
	files := map[string]string{"feed.orig": "=a.example\n", "post.sh": "=" + body}
	if have := listFeed(t, dir); !maps.Equal(files, have) {
		t.Errorf("feed folder %q; want %q", have, files)
	}
}

// readFeedFile is the content of path, or "<none>" when nothing is there.
func readFeedFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "<none>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A result restores once, for every copy of it: once its restore point is back over the download, a later Restore on that
// result or on a copy made before never renames a later run's restore point over that run's output. A failed run, which
// RunIP undid at once, leaves a result that restores nothing.
func TestPostScriptRestoreActsOnceForEveryCopy(t *testing.T) {
	for _, first := range []string{"same result", "copy made before", "failed run"} {
		t.Run(first, func(t *testing.T) {
			dir := t.TempDir()
			orig := writeScript(t, dir, "post.sh", "#!/bin/sh\necho changed > \"$1\"\n")
			if err := os.WriteFile(filepath.Join(dir, "fail.sh"), []byte("#!/bin/sh\necho changed > \"$1\"\nexit 3\n"),
				0o755); err != nil {
				t.Fatal(err)
			}
			restore := filepath.Join(dir, "feed.orig.post")
			check := func(when, wantOrig, wantRestore string) {
				t.Helper()
				if o, r := readFeedFile(t, orig), readFeedFile(t, restore); o != wantOrig || r != wantRestore {
					t.Errorf("%s: download %q, restore point %q; want %q, %q", when, o, r, wantOrig, wantRestore)
				}
			}
			p := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr"}
			if first == "failed run" {
				p.Name = "fail.sh"
			}
			r := p.RunIP(context.Background(), orig, restore, "_v4")
			held := r
			if first == "failed run" {
				if r.Reason != PreScriptExit || r.Status != 3 {
					t.Fatalf("first run %+v; want exit status 3", r)
				}
			} else {
				r.Restore()
			}
			check("after the first run", "a.example\n", "<none>")

			if err := os.WriteFile(orig, []byte("b.example\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			p.Name = "post.sh"
			second := p.RunIP(context.Background(), orig, restore, "_v4")
			if second.Reason != "" || second.Skipped {
				t.Fatalf("second run %+v; want a success", second)
			}
			if first == "copy made before" {
				held.Restore()
			} else {
				r.Restore()
			}
			check("after the first run's result restored again", "changed\n", "b.example\n")
			second.Restore()
			check("after the second run's restore", "b.example\n", "<none>")
		})
	}
}

// A Restore whose rename failed (the script left a folder at the download) may be retried: once the folder is gone, the
// same result puts the download back.
func TestPostScriptRestoreRetriesAFailedRename(t *testing.T) {
	dir := t.TempDir()
	orig := writeScript(t, dir, "post.sh", "#!/bin/sh\nrm \"$1\"\nmkdir \"$1\"\n: > \"$1/x\"\n")
	restore := filepath.Join(dir, "feed.orig.post")
	r := PostScript{Name: "post.sh", Dirs: []string{dir}, Header: "hdr"}.RunIP(context.Background(), orig, restore, "_v4")
	if r.Reason != "" || r.Skipped {
		t.Fatalf("run %+v; want a success", r)
	}
	r.Restore()
	if b, err := os.ReadFile(restore); err != nil || string(b) != "a.example\n" {
		t.Fatalf("restore point after the failed rename %q, %v; want it kept", b, err)
	}
	if err := os.RemoveAll(orig); err != nil {
		t.Fatal(err)
	}
	r.Restore()
	if o, rp := readFeedFile(t, orig), readFeedFile(t, restore); o != "a.example\n" || rp != "<none>" {
		t.Errorf("after the retry: download %q, restore point %q; want the download back and no restore point", o, rp)
	}
}

// The empty-feed probe never opens what is not a regular file: a FIFO a post-script left at the download is no content at
// once, where open(2) would block for ever. guard only fails a hung probe.
func TestCountContentOfAFifoIsNoContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.orig")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no fifos on this host: %v", err)
	}
	t.Cleanup(func() { // a probe blocked in open(2) is let go
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	})
	done := make(chan int, 1)
	go func() { done <- CountContent(path) }()
	select {
	case n := <-done:
		if n != NoProbe {
			t.Errorf("CountContent of a FIFO = %d; want NoProbe", n)
		}
	case <-time.After(guard):
		t.Fatal("CountContent blocked on the FIFO")
	}
}
