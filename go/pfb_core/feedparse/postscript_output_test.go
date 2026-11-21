//go:build linux || freebsd

package feedparse

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// What the post-script corpus cannot say: output read while the script still runs, and a log that fails to take it. The
// script blocks on a fifo until the test has seen its first line, then writes again; guard only fails a hung test.

// watchedSink closes seen at the first write after which it holds want; it is safe for the run's drain and the test.
type watchedSink struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func newWatchedSink(want string) *watchedSink {
	return &watchedSink{want: want, seen: make(chan struct{})}
}

func (w *watchedSink) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if strings.Contains(w.buf.String(), w.want) {
		w.once.Do(func() { close(w.seen) })
	}
	return len(p), nil
}

func (w *watchedSink) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type brokenSink struct{}

func (brokenSink) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// postScriptWhileBlocked runs body as the DNSBL post-script post.sh, with {block} replaced by a fifo it may read from, and
// returns once the run has returned. watched must see mark before the fifo is written: the script is still blocked then.
func postScriptWhileBlocked(t *testing.T, body string, p PostScript, watched *watchedSink) PostScriptResult {
	t.Helper()
	dir := t.TempDir()
	block := blockFifo(t, dir)
	script := "#!/bin/sh\n" + strings.ReplaceAll(body, "{block}", "'"+block+"'") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "post.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(dir, "feed.orig")
	if err := os.WriteFile(orig, []byte("a.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.Name, p.Dirs, p.Header = "post.sh", []string{dir}, "hdr"
	// Read-write, so that opening it waits for no one; held until the run has returned, so that a line written before the
	// script opened the fifo is still queued when it does.
	w, err := os.OpenFile(block, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	result := make(chan PostScriptResult, 1)
	go func() { result <- p.RunDNSBL(context.Background(), orig, filepath.Join(dir, "feed.post")) }()
	unblock := func() {
		if _, err := w.WriteString("go\n"); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-watched.seen:
	case r := <-result:
		t.Fatalf("the run returned while the script was blocked: %+v", r)
	case <-time.After(guard):
		unblock()
		<-result
		t.Fatalf("%q did not reach the log while the script ran; log after it exited: %q", watched.want, watched)
	}
	unblock()
	select {
	case r := <-result:
		return r
	case <-time.After(guard):
		t.Fatal("hung: the run did not return after the script was released")
	}
	return PostScriptResult{}
}

// A post-script's output reaches the main log and the transcript while the script still runs, as today's 200 ms drain does.
func TestPostScriptLogsOutputWhileTheScriptRuns(t *testing.T) {
	log := newWatchedSink("line\n")
	var transcript, errs bytes.Buffer
	r := postScriptWhileBlocked(t, "echo line\nread -r _ < {block}\necho after", PostScript{Log: log, Transcript: &transcript,
		Errors: &errs}, log)
	want := "\nExecuting post-script: post.sh\nline\nafter\n"
	if log.String() != want || transcript.String() != want || errs.String() != "" || r.Reason != "" || r.Skipped {
		t.Errorf("log %q, transcript %q, error log %q, result %+v; want both logs %q, no error, success", log,
			transcript.String(), errs.String(), r, want)
	}
}

// A sink that fails to take a post-script's output leaves one line in the error log for the run, the other sink still gets
// all of it, and the script's own status is kept.
func TestPostScriptReportsAFailedOutputSinkOnce(t *testing.T) {
	for _, sink := range []string{"main log", "transcript"} {
		t.Run(sink, func(t *testing.T) {
			healthy := newWatchedSink("one\n")
			var errs bytes.Buffer
			p := PostScript{Log: brokenSink{}, Transcript: healthy, Errors: &errs}
			if sink == "transcript" {
				p.Log, p.Transcript = healthy, brokenSink{}
			}
			r := postScriptWhileBlocked(t, "echo one\nread -r _ < {block}\necho two\nexit 3", p, healthy)
			failed := "[ pfB Script Output ] Failed to write script output to " + sink + "; child status is preserved\n"
			status := "\n[ hdr ] post-script 'post.sh' exited non-zero [ 3 ]; discarding its output\n"
			if want := failed + status; errs.String() != want {
				t.Errorf("error log %q; want %q", errs.String(), want)
			}
			if want := "\nExecuting post-script: post.sh\none\ntwo\n" + status; healthy.String() != want {
				t.Errorf("healthy sink %q; want %q", healthy, want)
			}
			if r.Reason != PreScriptExit || r.Status != 3 {
				t.Errorf("result %+v; want the script's exit status 3", r)
			}
		})
	}
}
