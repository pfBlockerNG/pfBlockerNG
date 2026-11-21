package geoip

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// asnRoot is an asn.csv with one AS and a previous table beside it.
func asnRoot(t *testing.T) ASNTable {
	root := t.TempDir()
	a := ASNTable{CSV: filepath.Join(root, "asn.csv"), Table: filepath.Join(root, "pfblockerng_asn.txt")}
	os.WriteFile(a.CSV, []byte("start_ip,end_ip,asn,name,domain\n1.0.0.0,1.0.0.255,AS13335,Cloudflare,c\n"), 0o644)
	os.WriteFile(a.Table, []byte("AS0 [ previous ]\n"), 0o644)
	return a
}

// assertPreviousTable checks that the run kept the previous table, logged no update and left no temporary file.
func assertPreviousTable(t *testing.T, a ASNTable, ok bool, log string) {
	t.Helper()
	if ok {
		t.Error("Run = true, want false")
	}
	if got, _ := os.ReadFile(a.Table); string(got) != "AS0 [ previous ]\n" {
		t.Errorf("pfblockerng_asn.txt = %q, want the previous table", got)
	}
	if strings.Contains(log, "updated") {
		t.Errorf("Extras log %q reports an update", log)
	}
	if entries, _ := os.ReadDir(filepath.Dir(a.Table)); len(entries) != 2 {
		t.Errorf("the folder holds %d entries, want asn.csv and the table only", len(entries))
	}
}

// Today the table is truncated before the pipeline writes it, so a failure leaves it short; Core publishes it whole or not
// at all.
func TestAFailedPublicationKeepsThePreviousTable(t *testing.T) {
	a := asnRoot(t)
	var log strings.Builder
	a.Log = &log
	defer func(r func(string, string) error) { rename = r }(rename)
	rename = func(string, string) error { return errors.New("rename refused") }
	assertPreviousTable(t, a, a.Run(context.Background()), log.String())
}

func TestACancelledRunKeepsThePreviousTable(t *testing.T) {
	a := asnRoot(t)
	var log strings.Builder
	a.Log = &log
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertPreviousTable(t, a, a.Run(ctx), log.String())
}

func TestARunReportsItsPublication(t *testing.T) {
	a := asnRoot(t)
	if !a.Run(context.Background()) {
		t.Fatal("Run = false, want true")
	}
	if got, _ := os.ReadFile(a.Table); string(got) != "AS13335 [ Cloudflare ]\n" {
		t.Errorf("pfblockerng_asn.txt = %q", got)
	}
}

// The shell's -f test passes over a FIFO named asn.csv; opening one would wait for a writer that never comes.
func TestAFIFONamedAsnCSVIsNotRead(t *testing.T) {
	a := asnRoot(t)
	os.Remove(a.CSV)
	if err := syscall.Mkfifo(a.CSV, 0o644); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	a.Log = &log
	assertPreviousTable(t, a, a.Run(context.Background()), log.String())
}
