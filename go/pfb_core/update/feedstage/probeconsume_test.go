package feedstage

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// A failed transfer that consumed the kept body keeps its own bookkeeping when the body's source record cannot be removed:
// the fail marker is created as after any failed download, and the run reports the record it could not remove.
func TestFailedTransferWithAStuckProbeRecordKeepsItsFailMarker(t *testing.T) {
	stage, feed, source := localStage(t)
	live := filepath.Join(stage.Paths.FeedDir, feed.Name)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, live+".probe", corruptGzip(t)) // a body the content gates refuse
	writeFile(t, live+".probe.src", "0123")
	defer func(saved func(op, path string) error) { fault = saved }(fault)
	fault = func(op, path string) error {
		if op == "remove" && strings.Contains(path, runPrefix) && strings.HasSuffix(path, ProbeSource) {
			return errors.New("injected")
		}
		return nil
	}
	r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	if r.Disposition != "failed" || r.Reason != "probe_record_remove_failed" {
		t.Fatalf("run = %+v, want failed as probe_record_remove_failed", r)
	}
	if !regularExists(live + ".fail") {
		t.Fatal("the failed transfer left no fail marker")
	}
}

// A transfer that never reached the kept body leaves the body and its source record as they are.
func TestTransferThatNeverReadTheProbeKeepsItsRecord(t *testing.T) {
	stage, feed, source := localStage(t)
	live := filepath.Join(stage.Paths.FeedDir, feed.Name)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, live+".probe", "198.51.100.2\n")
	writeFile(t, live+".probe.src", "0123")
	feed.Source = "file:///nonexistent-folder/feed.txt" // outside the local folders: refused before any body is read
	if r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: "none"}); r.Disposition != "failed" {
		t.Fatalf("run = %+v, want the refused source failed", r)
	}
	if !regularExists(live+".probe") || !regularExists(live+".probe.src") {
		t.Fatalf("the body stands %v, its record stands %v; want both kept", regularExists(live+".probe"),
			regularExists(live+".probe.src"))
	}
}
