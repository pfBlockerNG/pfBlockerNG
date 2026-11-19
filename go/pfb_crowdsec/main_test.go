package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeConfigFile(t *testing.T, m map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pfb_crowdsec.json")
	if err := os.WriteFile(path, configJSON(t, m), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionFlagPrintsTheVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"-version"}, &out, &errOut); code != 0 {
		t.Fatalf("-version exited %d (%s)", code, errOut.String())
	}
	if out.String() != "pfb_crowdsec "+version+"\n" {
		t.Fatalf("-version printed %q", out.String())
	}
}

func TestTestFlagValidatesTheConfigAndExits(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"-t", "-c", writeConfigFile(t, validConfigMap())}, &out, &errOut); code != 0 {
		t.Fatalf("-t on a valid config exited %d (%s)", code, errOut.String())
	}
	bad := validConfigMap()
	bad["update_frequency"] = "1s"
	out.Reset()
	errOut.Reset()
	if code := realMain([]string{"-t", "-c", writeConfigFile(t, bad)}, &out, &errOut); code != 1 {
		t.Fatalf("-t on an invalid config exited %d; want 1", code)
	}
	if !strings.Contains(errOut.String(), "update_frequency") {
		t.Fatalf("stderr = %q; want the bad field named", errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), testKey) {
		t.Fatal("the key was printed")
	}
}

func TestMissingConfigFlagIsAUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain(nil, &out, &errOut); code != 2 {
		t.Fatalf("no -c exited %d; want 2", code)
	}
	if code := realMain([]string{"-c", "x", "extra"}, &out, &errOut); code != 2 {
		t.Fatalf("a stray argument exited %d; want 2", code)
	}
	if code := realMain([]string{"-listen", ":8080", "-c", "x"}, &out, &errOut); code != 2 {
		t.Fatalf("an unknown flag exited %d; want 2", code)
	}
}

func TestPreflightNeedsPfctlAndTheDevice(t *testing.T) {
	dir := t.TempDir()
	pfctlPath := filepath.Join(dir, "pfctl")
	dev := filepath.Join(dir, "pf")
	if err := preflight(pfctlPath, dev); err == nil || !strings.Contains(err.Error(), pfctlPath) {
		t.Fatalf("preflight without pfctl = %v; want an error naming it", err)
	}
	if err := os.WriteFile(pfctlPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := preflight(pfctlPath, dev); err == nil || !strings.Contains(err.Error(), dev) {
		t.Fatalf("preflight without the device = %v; want an error naming it", err)
	}
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflight(pfctlPath, dev); err != nil {
		t.Fatalf("preflight with both = %v", err)
	}
	if err := os.Chmod(pfctlPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflight(pfctlPath, dev); err == nil {
		t.Fatal("preflight accepted a pfctl that is not executable")
	}
}

// The process really receives SIGUSR1 on the channel the run loop reads.
func TestNotifyUSR1DeliversTheSignal(t *testing.T) {
	ch, stop := notifyUSR1()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-ch:
		if s != syscall.SIGUSR1 {
			t.Fatalf("got %v; want SIGUSR1", s)
		}
	case <-time.After(time.Minute): // salvage watchdog only; delivery is immediate
		t.Fatal("STUCK/ENVIRONMENT: SIGUSR1 never arrived")
	}
}
