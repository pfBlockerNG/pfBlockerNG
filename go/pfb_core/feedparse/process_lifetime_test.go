package feedparse

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPreScriptCleansAttachedChildBeforeSuccessfulReturn(t *testing.T) {
	dir := t.TempDir()
	norm, staged := filepath.Join(dir, "feed.norm"), filepath.Join(dir, "feed.pre")
	alivePath, readyPath, releasePath := filepath.Join(dir, "alive"), filepath.Join(dir, "ready"), filepath.Join(dir, "release")
	for _, path := range []string{alivePath, readyPath, releasePath} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive, err := os.OpenFile(alivePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alive.Close() })
	release, err := os.OpenFile(releasePath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close() })
	ready, err := os.OpenFile(readyPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close() })
	t.Cleanup(func() {
		_, _ = release.Write([]byte("release\n"))
		deadline := time.Now().Add(guard)
		for {
			var b [1]byte
			n, err := syscall.Read(int(alive.Fd()), b[:])
			if n == 0 && err == nil {
				return
			}
			if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
				t.Errorf("waiting for attached child cleanup: read = %d, %v", n, err)
				return
			}
			if time.Now().After(deadline) {
				t.Error("attached child did not exit after its cooperative release")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	if err := os.WriteFile(norm, []byte("original.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFB_STRICT_ALIVE", alivePath)
	t.Setenv("PFB_STRICT_READY", readyPath)
	t.Setenv("PFB_STRICT_RELEASE", releasePath)
	script := filepath.Join(dir, "script.sh")
	body := "#!/bin/sh\n( exec 9> \"$PFB_STRICT_ALIVE\"; echo ready > \"$PFB_STRICT_READY\"; read -r line < \"$PFB_STRICT_RELEASE\" ) &\nread -r line < \"$PFB_STRICT_READY\"\nprintf 'transformed.example\\n' > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(dir, "script.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	got := RunPreScript(context.Background(), script, norm, staged, log)
	if got != (PreScriptResult{OK: true, Path: staged}) {
		t.Fatalf("RunPreScript = %+v; want successful staged transform", got)
	}
	var b [1]byte
	n, err := syscall.Read(int(alive.Fd()), b[:])
	if n != 0 || err != nil {
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("attached child probe = %d, %v; want EOF after the runner's cleanup", n, err)
		}
		t.Fatalf("attached child still holds the FIFO at successful return: read = %d, %v", n, err)
	}
	got.Cleanup()
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("staged file after Cleanup = %v; want not-exist", err)
	}
}
