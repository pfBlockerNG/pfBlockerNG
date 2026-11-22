package feedstage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// localStage is a stage over fresh folders whose feed reads the local file it returns, which the test writes.
func localStage(t *testing.T) (*Stage, Feed, string) {
	t.Helper()
	stage := testStage(t)
	sourceDir, scriptDir := t.TempDir(), t.TempDir()
	stage.Fetcher.Policy.LocalDirs = []string{sourceDir}
	stage.Paths.ScriptDirs = []string{scriptDir}
	source := filepath.Join(sourceDir, "feed.txt")
	return stage, testFeed("ipv4", "enabled", "auto", "file://"+source), source
}

// Scenario: the record of an abandoned download survives its failed run.
// Given a published baseline and a changed source whose pre-script fails after the new download was normalized, when the
// normalization record of that download is left in place (as a KILL before its removal, or a failed removal, leaves it),
// then the next run, which ingests the same download again, parses it instead of reusing the baseline's list.
func TestStaleNormalizationRecordIsNeverReused(t *testing.T) {
	stage, feed, source := localStage(t)
	dir := stage.Paths.FeedDir
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	record, saved := filepath.Join(dir, "feed_v4.norm.src.xxhash128"), filepath.Join(t.TempDir(), "record")
	script := fmt.Sprintf("#!/bin/sh\ncp '%s' '%s'\nexit 1\n", record, saved)
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "pre.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "198.51.100.2\n")
	scripted := feed
	scripted.PreScript = "pre.sh"
	if r := run(stage, scripted, "none"); r.Disposition != "failed" || r.Stage != "script" {
		t.Fatalf("the run whose pre-script fails = %+v", r)
	}
	writeFile(t, record, readFile(t, saved))

	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the next run = %+v, want the change parsed, not the baseline's list reused", r)
	}
	if got := readFile(t, filepath.Join(dir, "feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Fatalf("the next run published %q, want the changed source", got)
	}
}

var errScriptStarted = errors.New("the script started")

// cancelWhenScriptStarts returns a script body that signals through a FIFO and then blocks until it is killed, and a context
// the signal cancels with errScriptStarted.
func cancelWhenScriptStarts(t *testing.T) (context.Context, string) {
	t.Helper()
	dir := t.TempDir()
	started, block := filepath.Join(dir, "started"), filepath.Join(dir, "block")
	for _, fifo := range []string{started, block} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A read-write open never blocks; closing it at the end ends the read below.
	events, err := os.OpenFile(started, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The cap only fails a hung run: its cause is not errScriptStarted.
	capped, stop := context.WithTimeoutCause(context.Background(), 2*time.Minute, errors.New("the run hung"))
	ctx, cancel := context.WithCancelCause(capped)
	go func() {
		if _, err := events.Read(make([]byte, 1)); err == nil {
			cancel(errScriptStarted)
		}
	}()
	t.Cleanup(func() {
		cancel(nil)
		stop()
		events.Close()
	})
	return ctx, fmt.Sprintf("#!/bin/sh\nprintf x > '%s'\nread line < '%s'\n", started, block)
}

// A caller's cancellation while the pre-script runs is the caller's, never the script's failure (plan C row 38).
func TestCancelDuringThePreScriptIsReportedCancelled(t *testing.T) {
	ctx, script := cancelWhenScriptStarts(t)
	stage, feed, _ := localStage(t)
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "blocks.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	feed.PreScript = "blocks.sh"
	orig, parsed := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")
	writeFile(t, orig, "203.0.113.5\n")
	writeFile(t, parsed, "203.0.113.6\n")
	got := stage.Run(ctx, feed, Change{Force: "parse"})
	if cause := context.Cause(ctx); !errors.Is(cause, errScriptStarted) {
		t.Fatalf("the run = %+v ended with cause %v, want it cancelled once the script started", got, cause)
	}
	if got.Disposition != "failed" || got.Stage != "script" || got.Reason != "cancelled" || got.PreScriptFailed {
		t.Fatalf("a run cancelled in its pre-script = %+v, want failed/script/cancelled without a script failure", got)
	}
	for path, want := range map[string]string{orig: "203.0.113.5\n", parsed: "203.0.113.6\n"} {
		if data := readFile(t, path); data != want {
			t.Fatalf("a cancelled run changed %s: %q", filepath.Base(path), data)
		}
	}
}

// Every folder of Paths is absolute and clean, valid UTF-8 without a control character (the rule CheckPath gives the
// loop's paths); one that is not is refused before anything is touched.
func TestPathsMustBeAbsoluteAndClean(t *testing.T) {
	base := t.TempDir()
	for _, tc := range []struct {
		name   string
		paths  Paths
		reason string
	}{
		{"feed folder with a trailing slash", Paths{FeedDir: base + "/"}, "feed_directory_invalid"},
		{"feed folder ending in a dot", Paths{FeedDir: base + "/."}, "feed_directory_invalid"},
		{"feed folder with a control character", Paths{FeedDir: base + "/a\x01"}, "feed_directory_invalid"},
		{"feed folder that is no UTF-8", Paths{FeedDir: base + "/\xff"}, "feed_directory_invalid"},
		{"relative GeoIP folder", Paths{FeedDir: base, GeoIPDir: "GeoIP"}, "geoip_directory_invalid"},
		{"unclean GeoIP folder", Paths{FeedDir: base, GeoIPDir: base + "/x/../GeoIP"}, "geoip_directory_invalid"},
		{"empty script folder", Paths{FeedDir: base, ScriptDirs: []string{""}}, "script_directory_invalid"},
		{"unclean script folder", Paths{FeedDir: base, ScriptDirs: []string{base + "//scripts"}}, "script_directory_invalid"},
	} {
		stage := testStage(t)
		stage.Paths = tc.paths
		got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
			Format: "auto", Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "download"})
		if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != tc.reason {
			t.Errorf("%s: run = %+v, want a settings failure %s", tc.name, got, tc.reason)
		}
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("refused runs left %d files in the feed folder", len(entries))
	}
}

// A feed's parse failures are one summary line in the main and error logs, today's (pfb_ip_parse_fail_warn()); the records
// go to Stage.ParseErrors.
func TestParseFailuresAreOneSummaryLine(t *testing.T) {
	stage := testStage(t)
	var log, errs strings.Builder
	stage.Log, stage.Errors = &log, &errs
	got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
		Format: "auto", Custom: true, CustomText: "203.0.113.21\n1.2.3.4.5\n300.1.1.1\n"}, Change{Force: "none"})
	if got.ParseFailures != 2 {
		t.Fatalf("run = %+v, want two parse failures", got)
	}
	summary := "\n[!] Parse Errors [ Test_custom_v4 ]: 2\n"
	if strings.Count(log.String(), "Parse Errors") != 1 || !strings.Contains(log.String(), summary) || strings.Contains(log.String(), "parse failure") {
		t.Fatalf("the main log = %q, want the one summary line %q", log.String(), summary)
	}
	if !strings.Contains(errs.String(), summary) {
		t.Fatalf("the error log = %q, want the summary line %q", errs.String(), summary)
	}
}

// A custom list whose publication fails leaves no staged file behind.
func TestCustomListPublishFailureLeavesNoStagedFile(t *testing.T) {
	stage := testStage(t)
	dir := stage.Paths.FeedDir
	saved := step
	t.Cleanup(func() { step = saved })
	step = func(name string) {
		if name == "custom-staged" { // a download that cannot be replaced fails the publication
			if err := os.Mkdir(filepath.Join(dir, "Test_custom_v4.orig"), 0o700); err != nil {
				t.Errorf("replacing the download by a folder: %v", err)
			}
		}
	}
	got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
		Format: "auto", Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "none"})
	if got.Disposition != "failed" || got.Reason != "custom_source_unavailable" {
		t.Fatalf("run = %+v, want the publication of the custom list failed", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagePrefix) {
			t.Errorf("the failed publication left %s", e.Name())
		}
	}
}

// The disposition follows the source: an identical custom list under a forced download is parsed again, not changed.
func TestIdenticalCustomListUnderForceIsReparsed(t *testing.T) {
	stage := testStage(t)
	feed := Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled", Format: "auto", Custom: true,
		CustomText: "203.0.113.21\n"}
	if got := stage.Run(context.Background(), feed, Change{Force: "none"}); got.Disposition != "changed" {
		t.Fatalf("the first run = %+v", got)
	}
	if got := stage.Run(context.Background(), feed, Change{Force: "download"}); got.Disposition != "reparsed" || got.SourceChanged {
		t.Fatalf("an identical custom list under a forced download = %+v, want reparsed and no source change", got)
	}
}
