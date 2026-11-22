package feedstage

import (
	"path/filepath"
	"testing"
)

// The record of a kept probe body's source (".probe.src", written by stage 6, worklist) is one of the probe's files: Recover
// removes its temporary, and a run that consumes or retires the body takes the record with it, so no record outlives its
// body.
func TestProbeSourceRecordGoesWithItsBody(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a_v4.probe.src.part"), "x")
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if regularExists(filepath.Join(dir, "a_v4.probe.src.part")) {
		t.Error("Recover left the source record's temporary")
	}

	for _, force := range []string{"none", "download"} {
		stage, feed, source := localStage(t)
		live := filepath.Join(stage.Paths.FeedDir, feed.Name)
		writeFile(t, source, "198.51.100.1\n")
		if r := run(stage, feed, "none"); r.Disposition != "changed" {
			t.Fatalf("the baseline run = %+v", r)
		}
		writeFile(t, live+".probe", "198.51.100.2\n")
		writeFile(t, live+".probe.src", "0123")
		r := stage.Run(t.Context(), feed, Change{Verdict: VerdictChanged, Force: force})
		if r.Disposition != "changed" {
			t.Fatalf("force %s: run = %+v, want changed", force, r)
		}
		if regularExists(live+".probe") || regularExists(live+".probe.src") {
			t.Errorf("force %s: the body stands %v, its record stands %v; want both gone", force, regularExists(live+".probe"),
				regularExists(live+".probe.src"))
		}
	}
}
