package main

import (
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// The Core Updater folds a record only when there is one: no record is not a report of nothing, which would settle every
// removed dnsbl/* resource at once.
func TestNoRecordIsNotAnEmptyReport(t *testing.T) {
	state := t.TempDir()
	report, err := readApplied(state)
	if err != nil || report != nil {
		t.Fatalf("readApplied without a record = %v, %v; want nil, nil", report, err)
	}
	if err := writeApplied(state, map[string]resources.Cursor{}); err != nil {
		t.Fatal(err)
	}
	report, err = readApplied(state)
	if err != nil || report == nil || len(report) != 0 {
		t.Fatalf("readApplied of a report of nothing = %v (nil %t), %v; want an empty, non-nil report", report, report == nil, err)
	}
	want := map[string]resources.Cursor{"dnsbl/manifest": {Generation: 7, Digest: digestA}}
	if err := writeApplied(state, want); err != nil {
		t.Fatal(err)
	}
	if report, err = readApplied(state); err != nil || len(report) != 1 || report["dnsbl/manifest"] != want["dnsbl/manifest"] {
		t.Errorf("readApplied = %v, %v; want %v", report, err, want)
	}
}
