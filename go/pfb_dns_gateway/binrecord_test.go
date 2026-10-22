package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// issue #3566: beside the ready file, PATH.sha256 holds the SHA-256 of the gateway's own executable (64 lowercase hex
// digits and a newline), written before the ready file is published and never removed: pfBlockerNG compares it with the
// installed binary to know whether a package update changed the running gateway.

func executableRecord(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) + "\n"
}

func requireRecord(t *testing.T, path, when string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if want := executableRecord(t); err != nil || string(got) != want {
		t.Fatalf("%s: %s holds %q (err %v), want %q", when, path, got, err, want)
	}
}

func TestTheReadyFileHasTheSHA256OfTheGatewayBinaryBesideIt(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.readyFile = filepath.Join(t.TempDir(), "ready")
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	requireRecord(t, cfg.readyFile+".sha256", "once the gateway serves")
	if pid := readReadyPid(t, cfg.readyFile); pid != os.Getpid() {
		t.Fatalf("ready file names pid %d, want %d: its format is unchanged", pid, os.Getpid())
	}
	srv.shutdown()
	requireRecord(t, cfg.readyFile+".sha256", "after the stop")
}

// The record comes first: when the ready file cannot be published (a directory is in its place), the record is there.
func TestTheBinaryRecordIsWrittenBeforeTheReadyFile(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.readyFile = filepath.Join(t.TempDir(), "ready")
	if err := os.MkdirAll(filepath.Join(cfg.readyFile, "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	if srv, err := start(cfg, logs.logf); err == nil || !strings.Contains(err.Error(), "ready file") {
		t.Fatalf("start: got srv=%v err=%v, want the ready-file error", srv, err)
	}
	requireRecord(t, cfg.readyFile+".sha256", "when the ready file could not be published")
}

func TestNoBinaryRecordIsWrittenWithoutAReadyFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // where a record named after an empty path would land
	cfg, logs := lifecycleConfig(t, "serve")
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	srv.shutdown()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("with no --ready-file the gateway wrote %v (err %v), want nothing", entries, err)
	}
}
