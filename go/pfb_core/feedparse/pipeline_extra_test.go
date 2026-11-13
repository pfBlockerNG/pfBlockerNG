package feedparse

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
)

// What the corpus cannot say: behaviour Core has and the old path does not (UTF-16), the limits the old path sets from constants,
// and failures a directory fixture can force without a second user.

func TestNormalizeFileDecodesUTF16(t *testing.T) {
	dir := t.TempDir()
	units := utf16.Encode([]rune("a.example.com\nb.example.com\n"))
	orig := []byte{0xFF, 0xFE}
	for _, u := range units {
		orig = append(orig, byte(u), byte(u>>8))
	}
	if err := os.WriteFile(filepath.Join(dir, "feed.orig"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	got := NormalizeFile(dir, "feed")
	norm, err := os.ReadFile(filepath.Join(dir, "feed.norm"))
	if err != nil || string(norm) != "a.example.com\nb.example.com\n" || !got.Normalized || !got.Changed {
		t.Errorf("NormalizeFile = %+v; .norm = %q, %v; want the decoded text, changed and normalized", got, norm, err)
	}
}

// A .norm that cannot be replaced (here a directory stands where it belongs) is a failure: the raw .orig is parsed, no sidecar
// claims a .norm that is not there, and no temporary file is left.
func TestNormalizeFileFailureFallsBackToTheRawOrig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "feed.orig"), []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "feed.norm"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := NormalizeFile(dir, "feed")
	if want := (NormResult{Path: filepath.Join(dir, "feed.orig"), Changed: true}); got != want {
		t.Errorf("NormalizeFile = %+v, want %+v", got, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "feed.norm,feed.orig" {
		t.Errorf("the directory holds %v, want only feed.norm and feed.orig", names)
	}
}

// The limits are the PHP ones: PFB_LIST_SCRIPT_TIMEOUT and PFB_HOOK_KILL_GRACE.
func TestPreScriptLimitsAreTheOldPathsConstants(t *testing.T) {
	if preScriptTimeout != 300*time.Second || preScriptGrace != 5*time.Second {
		t.Errorf("limits = %v and %v, want 300s and 5s", preScriptTimeout, preScriptGrace)
	}
}

// A script that outlives its limit is killed whatever the caller's context says: nothing but the limit ends this run.
func TestPreScriptIsHeldToItsLimit(t *testing.T) {
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "block.sh")
	block := filepath.Join(dir, "block.fifo")
	if err := syscall.Mkfifo(block, 0o600); err != nil {
		t.Skipf("no fifos on this host: %v", err)
	}
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nread -r line < \""+block+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := preScriptTimeout
	preScriptTimeout = 50 * time.Millisecond
	defer func() { preScriptTimeout = old }()
	got := RunPreScript(context.Background(), script, norm, staged, nil)
	if got.OK || got.Reason != PreScriptTimeout || got.Path != norm {
		t.Errorf("RunPreScript = %+v, want a timeout that keeps %s", got, norm)
	}
	if _, err := os.Stat(staged); err == nil {
		t.Error("the staged copy of a killed script was kept")
	}
}

func TestPreScriptOutputGoesToTheLog(t *testing.T) {
	dir := t.TempDir()
	norm, staged, script := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre"), filepath.Join(dir, "talk.sh")
	if err := os.WriteFile(norm, []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho out\necho err >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if got := RunPreScript(context.Background(), script, norm, staged, &log); !got.OK {
		t.Fatalf("RunPreScript = %+v", got)
	}
	if log.String() != "out\nerr\n" {
		t.Errorf("log = %q, want the script's stdout and stderr", log.String())
	}
	if got := RunPreScript(context.Background(), script, norm, staged, nil); !got.OK {
		t.Errorf("RunPreScript without a log = %+v", got)
	}
}
