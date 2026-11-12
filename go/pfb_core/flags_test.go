package main

import (
	"bytes"
	"context"
	"path/filepath"
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
