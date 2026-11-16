package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A group id goes to chown(2) as a Go int: one that does not fit 31 bits is a usage error, never a wrapped id.
func TestRunRefusesASocketGroupBeyond31Bits(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	var stderr bytes.Buffer
	args := []string{"--socket", filepath.Join(scratchDir(t), "run", "api.sock"), "--socket-group", "2147483648"}
	if code := run(stopped, args, &stderr); code != 2 {
		t.Errorf("run %v = %d, want 2; stderr %q", args, code, stderr.String())
	}
}

// --update-cmd is how Core is told to run Updates: the usage line a missing --socket or --state-dir prints names it.
func TestUsageNamesTheUpdateCmdFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--update-cmd PATH") {
		t.Errorf("the usage text does not name --update-cmd: %q", stderr.String())
	}
}

// --zoneinfo is how Core is told where the host keeps its time zone: the usage line names it.
func TestUsageNamesTheZoneinfoFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--zoneinfo PATH") {
		t.Errorf("the usage text does not name --zoneinfo: %q", stderr.String())
	}
}

func TestUsageNamesTheMaintenanceCmdFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--maintenance-cmd PATH") {
		t.Errorf("the usage text does not name --maintenance-cmd: %q", stderr.String())
	}
}

func TestMaintenanceCmdAcceptsEmptyAndRejectsControlCharacters(t *testing.T) {
	for _, value := range []string{"", "bad\npath", "bad\tpath", "bad\x00path"} {
		var stderr bytes.Buffer
		if code := run(context.Background(), []string{"--maintenance-cmd", value}, &stderr); code != 2 {
			t.Errorf("run with maintenance path %q = %d, want usage error 2", value, code)
		}
		if value == "" && strings.Contains(stderr.String(), "control character") {
			t.Errorf("empty optional maintenance path was rejected: %q", stderr.String())
		}
		if value != "" && !strings.Contains(stderr.String(), "control character") {
			t.Errorf("control character was not rejected before state creation: %q", stderr.String())
		}
	}
}
