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
