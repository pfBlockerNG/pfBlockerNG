package feedstage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// stuckRecord is a stage over a published baseline with a kept probe body the content gates refuse, its validators and its
// source record, whose removal from the run folder fails.
func stuckRecord(t *testing.T) (*Stage, Feed, string) {
	t.Helper()
	stage, feed, source := localStage(t)
	live := filepath.Join(stage.Paths.FeedDir, feed.Name)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, live+".probe", corruptGzip(t))
	writeFile(t, live+".probe.etag", `"probe"`)
	writeFile(t, live+".probe.src", "0123")
	return stage, feed, live
}

func recordRemoval(path string) bool {
	return strings.Contains(path, runPrefix) && strings.HasSuffix(path, ProbeSource)
}

// A cancelled transfer is reported cancelled, whatever happened to the probe record.
func TestCancelledTransferWithAStuckRecordIsCancelled(t *testing.T) {
	stage, feed, live := stuckRecord(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	defer func(saved func(op, path string) error) { fault = saved }(fault)
	fault = func(op, path string) error {
		if op == "remove" && recordRemoval(path) {
			cancel() // the caller's cancellation lands while the transfer ends
			return errors.New("injected")
		}
		return nil
	}
	if r := stage.Run(ctx, feed, Change{Verdict: VerdictChanged, Force: "none"}); r.Reason != "cancelled" {
		t.Fatalf("run = %+v, want cancelled", r)
	}
	if regularExists(live + ".fail") {
		t.Fatal("a cancelled transfer left a fail marker")
	}
}

// The probe record's failure stays the run's reason when the commit of the failed transfer fails too.
func TestStuckRecordReasonSurvivesAFailedCommit(t *testing.T) {
	stage, feed, _ := stuckRecord(t)
	defer func(saved func(op, path string) error) { fault = saved }(fault)
	commitFailed := false
	fault = func(op, path string) error {
		if op == "create" && strings.HasSuffix(path, commitName+".tmp") {
			commitFailed = true
			return errors.New("injected")
		}
		if op == "remove" && recordRemoval(path) {
			return errors.New("injected")
		}
		return nil
	}
	if r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: "none"}); r.Reason != "probe_record_remove_failed" {
		t.Fatalf("run = %+v, want failed as probe_record_remove_failed", r)
	}
	if !commitFailed {
		t.Fatal("the commit never ran, so its failure was never injected")
	}
}

// A failed transfer that consumed the kept body takes the body's validators with it: none is published without its body.
func TestConsumedProbeBodyTakesItsValidators(t *testing.T) {
	stage, feed, live := stuckRecord(t)
	writeFile(t, live+".probe.lastmod", "Mon, 01 Jan 2024 00:00:00 GMT")
	writeFile(t, live+".probe.size", "20")
	if r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: "none"}); r.Disposition != "failed" {
		t.Fatalf("run = %+v, want the refused body failed", r)
	}
	for _, suffix := range probeFiles {
		if regularExists(live + suffix) {
			t.Errorf("%s stands without the body it describes", suffix)
		}
	}
}
