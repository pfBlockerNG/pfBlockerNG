package feedstage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// Scenario: a changed probe's body is consumed by a run that then fails.
// Given a published baseline and a changed HTTP source that the stage 6 probe kept as ".probe" with its validators, when the
// feed's pre-script fails, then the run publishes the removal of the live probe body and its validators and nothing of the
// new download: the baseline and its validators stand.
func TestAFailedRunRetiresTheProbeBodyItConsumed(t *testing.T) {
	var version atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := `"v` + string(rune('0'+version.Load())) + `"`
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("198.51.100." + string(rune('0'+version.Load())) + "\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	stage.Paths.ScriptDirs = []string{t.TempDir()}
	dir := stage.Paths.FeedDir
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	version.Store(1)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	version.Store(2)
	change := detect(stage, feed, "none")
	if change.Verdict != VerdictChanged || !regularExists(filepath.Join(dir, "feed_v4.probe")) {
		t.Fatalf("the probe = %+v, want a changed verdict and the kept probe body", change)
	}
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "pre.sh"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed.PreScript = "pre.sh"
	baseline := publishedState(t, dir)
	got := stage.Run(context.Background(), feed, change)
	if got.Disposition != "failed" || got.Stage != "script" {
		t.Fatalf("the run = %+v, want failed at the pre-script", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "feed_v4.probe") {
			t.Errorf("%s is live after the run consumed the probe body and failed", e.Name())
		}
		delete(baseline, e.Name())
	}
	for name := range baseline {
		if !strings.HasPrefix(name, "feed_v4.probe") {
			t.Errorf("%s vanished from the feed folder", name)
		}
	}
	if got := readFile(t, filepath.Join(dir, "feed_v4.orig")); got != "198.51.100.1\n" {
		t.Errorf("the baseline is %q, want it unchanged", got)
	}
}

type panicWriter struct{ hit *bool }

func (p panicWriter) Write([]byte) (int, error) {
	*p.hit = true
	panic("parse error sink failed")
}

// Scenario: the run panics after its download was staged.
// Given a published baseline and a changed source with a line the parser rejects, when the caller's parse-error writer
// panics, then the panic goes on unwinding and the run publishes nothing: the feed folder is as it was and no run folder
// is left.
func TestAPanickingRunPublishesNothing(t *testing.T) {
	stage, feed, source := localStage(t)
	dir := stage.Paths.FeedDir
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	baseline := publishedState(t, dir)
	writeFile(t, source, "1.2.3.4.5\n198.51.100.2\n")
	hit := false
	stage.ParseErrors = panicWriter{&hit}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		run(stage, feed, "none")
	}()
	if !hit || recovered == nil {
		t.Fatalf("the parse-error writer was reached = %v, panic = %v, want both", hit, recovered)
	}
	if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
		t.Errorf("the feed folder is %q after a panicking run, want %q", got, baseline)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), runPrefix) {
			t.Errorf("run folder %s is left after the panic", e.Name())
		}
	}
}

// Scenario: a post-script that appears after the first lookup.
// Given a feed whose configured post-script is no file when the run starts and is installed while the download transfers,
// when the run parses and the script runs, then the reuse record stays empty: the lists were shaped by a script, and the
// next run must not reuse them as the download's alone.
func TestALatePostScriptLeavesNoReuseRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.1\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	scriptDir, witness := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	stage.Paths.ScriptDirs = []string{scriptDir}
	resolve := stage.Fetcher.Policy.Resolve
	stage.Fetcher.Policy.Resolve = func(c context.Context, host string) ([]netip.Addr, error) {
		script := "#!/bin/sh\ntouch '" + witness + "'\n"
		if err := os.WriteFile(filepath.Join(scriptDir, "post.sh"), []byte(script), 0o755); err != nil {
			t.Error(err)
		}
		return resolve(c, host)
	}
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	feed.PostScript = "post.sh"
	if got := run(stage, feed, "download"); got.Disposition != "changed" || got.PostScriptFailed {
		t.Fatalf("the run = %+v, want the download parsed", got)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Fatalf("the late post-script did not run: %v", err)
	}
	if got := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.src.xxhash128")); got != "" {
		t.Errorf("the reuse record is %q after a post-script took part, want it empty", got)
	}
}

// Scenario: "0" is no post-script. Given a post-script folder that cannot be made, when the feed's post-script is "0", then
// nothing is staged and nothing fails; a configured name that resolves to no file still gets its copy, as a script that
// appears mid-run must never write a published file.
func TestAnUnsetPostScriptStagesNoCopy(t *testing.T) {
	for name, tc := range map[string]struct {
		script string
		failed bool
	}{"zero": {"0", false}, "empty": {"", false}, "unresolved name": {"missing.sh", true}} {
		t.Run(name, func(t *testing.T) {
			stage, feed, source := localStage(t)
			writeFile(t, source, "198.51.100.1\n")
			feed.PostScript = tc.script
			withFault(t, func(op, path string) error {
				if op == "rename" && filepath.Base(filepath.Dir(path)) == ".post" {
					return syscall.EIO
				}
				return nil
			})
			got := run(stage, feed, "none")
			if got.Disposition != "changed" || got.PostScriptFailed != tc.failed {
				t.Errorf("the run = %+v, want the download published with PostScriptFailed = %v", got, tc.failed)
			}
		})
	}
}
