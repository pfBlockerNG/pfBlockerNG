//go:build linux || freebsd

package feedparse

import (
	"bytes"
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPreScriptDetachedDescendantOutlivesGroupAndWaitDelay(t *testing.T) {
	dir := t.TempDir()
	norm, staged := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre")
	if err := os.WriteFile(norm, []byte("original.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFB_LIFETIME_EXE", exe)
	t.Setenv("PFB_DETACHED_READY", filepath.Join(dir, "ready"))
	gone := aliveWatch(t, dir)
	release := blockFifo(t, dir)
	t.Setenv("PFB_TEST_BLOCK", release)
	script := filepath.Join(dir, "script.sh")
	body := "#!/bin/sh\nPFB_LIFETIME_HELPER=detach \"$PFB_LIFETIME_EXE\" -test.run '^TestPreScriptDetachedHelper$' &\nwhile [ ! -e \"$PFB_DETACHED_READY\" ]; do sleep 0.01; done\nprintf 'transformed.example\\n' > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), guard)
	defer cancel()
	var log bytes.Buffer
	got := RunPreScript(ctx, script, norm, staged, &log)
	if got != (PreScriptResult{OK: true, Path: staged}) {
		t.Fatalf("RunPreScript = %+v; want successful detached transform", got)
	}
	if !bytes.Contains(log.Bytes(), []byte("detached-output\n")) {
		t.Errorf("detached output = %q; want the helper's output", log.String())
	}
	select {
	case <-gone:
		_, readyErr := os.Stat(os.Getenv("PFB_DETACHED_READY"))
		t.Fatalf("detached helper exited before release: ready file stat = %v; captured output = %q", readyErr, log.String())
	default:
	}
	writer, err := os.OpenFile(release, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("quit\n"); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	select {
	case <-gone:
	case <-time.After(guard):
		t.Error("detached helper did not exit after its cooperative release")
	}
	got.Cleanup()
}

func TestPreScriptDetachedHelper(t *testing.T) {
	if os.Getenv("PFB_LIFETIME_HELPER") != "detach" {
		return
	}
	if _, err := syscall.Setsid(); err != nil {
		t.Fatalf("detach helper: %v", err)
	}
	signal.Ignore(syscall.SIGTERM)
	alive, err := os.OpenFile(os.Getenv("PFB_TEST_ALIVE"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer alive.Close()
	if _, err := alive.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("PFB_DETACHED_READY"), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("detached-output\n")); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(os.Getenv("PFB_TEST_BLOCK"), os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	var b [1]byte
	if _, err := release.Read(b[:]); err != nil {
		t.Fatal(err)
	}
}
