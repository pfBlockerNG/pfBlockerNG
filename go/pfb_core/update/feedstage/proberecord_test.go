package feedstage

import (
	"bytes"
	"compress/gzip"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// A transfer that consumed a kept probe body and failed still takes the body's source record with it: the commit that
// publishes the failure publishes the record's removal, so no record outlives its body.
func TestProbeSourceRecordGoesWithAFailedIngest(t *testing.T) {
	stage, feed, source := localStage(t)
	live := filepath.Join(stage.Paths.FeedDir, feed.Name)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, live+".probe", corruptGzip(t)) // a body the content gates refuse
	writeFile(t, live+".probe.src", "0123")
	if r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: "none"}); r.Disposition != "failed" {
		t.Fatalf("run = %+v, want the refused body failed", r)
	}
	if regularExists(live+".probe") || regularExists(live+".probe.src") {
		t.Fatalf("the body stands %v, its record stands %v; want both gone", regularExists(live+".probe"),
			regularExists(live+".probe.src"))
	}
}

// corruptGzip is a gzip member whose trailer checksum is wrong, which the structural test refuses.
func corruptGzip(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte("198.51.100.2\n")); err != nil || w.Close() != nil {
		t.Fatal("cannot compress")
	}
	data := b.Bytes()
	data[len(data)-8] ^= 0xff
	return string(data)
}

// A source record the run cannot remove fails the run, which then publishes nothing of the body it consumed but its
// removal: the record never stands for a body that is gone without the run saying so.
func TestProbeSourceRecordThatStaysFailsTheRun(t *testing.T) {
	stage, feed, source := localStage(t)
	live := filepath.Join(stage.Paths.FeedDir, feed.Name)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, live+".probe", "198.51.100.2\n")
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
	if regularExists(live + ".probe") {
		t.Fatal("the consumed probe body stands")
	}
	if got := readFile(t, live+".orig"); got != "198.51.100.1\n" {
		t.Fatalf("the baseline = %q, want the one before the failed run", got)
	}
}
