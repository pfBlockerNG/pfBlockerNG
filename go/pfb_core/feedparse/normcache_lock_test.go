package feedparse

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Two calls must not interleave their temporary and cache pair. A competing call may use raw fallback;
// after A finishes, rebuilding and reusing the cache must serve B's replacement text.
func TestNormalizeFileSerializesCallsForOneFeed(t *testing.T) {
	dir := t.TempDir()
	orig, norm := filepath.Join(dir, "feed.orig"), filepath.Join(dir, "feed.norm")
	f, err := os.Create(orig)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("1.2.3.4\n"), 128<<10)
	for range 32 {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	aDone := make(chan NormResult, 1)
	go func() { aDone <- NormalizeFile(dir, "feed") }()
	for {
		select {
		case got := <-aDone:
			t.Fatalf("call A finished (%+v) before its temporary was seen mid-write", got)
		default:
		}
		if info, err := os.Stat(norm + ".tmp"); err == nil && info.Size() > 0 {
			break
		}
		runtime.Gosched()
	}

	replacement := filepath.Join(dir, "feed.orig.new")
	if err := os.WriteFile(replacement, []byte("b.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, orig); err != nil {
		t.Fatal(err)
	}
	b := NormalizeFile(dir, "feed")
	a := <-aDone
	if b != (NormResult{Path: orig, Changed: true}) && b != (NormResult{Path: norm, Changed: true, Normalized: true}) {
		t.Errorf("call B = %+v, want raw fallback or normalized replacement", b)
	}

	rebuilt := NormalizeFile(dir, "feed")
	if want := (NormResult{Path: norm, Changed: !b.Normalized, Normalized: true}); rebuilt != want {
		t.Errorf("after A=%+v and B=%+v rebuild = %+v, want %+v", a, b, rebuilt, want)
	}
	got := NormalizeFile(dir, "feed")
	text, err := os.ReadFile(norm)
	if err != nil {
		t.Fatal(err)
	}
	if got != (NormResult{Path: norm, Normalized: true}) || string(text) != "b.example.com\n" {
		t.Errorf("after A=%+v and B=%+v the cache answers %+v with %d bytes (prefix %q), want B's text %q", a, b, got, len(text), text[:min(len(text), 32)], "b.example.com\n")
	}
}

func TestNormalizeFileLockContentionPreservesCache(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "existing"}[cached], func(t *testing.T) {
			dir := t.TempDir()
			orig, norm := filepath.Join(dir, "feed.orig"), filepath.Join(dir, "feed.norm")
			sidecar := norm + ".src.xxhash128"
			if err := os.WriteFile(orig, []byte("old.example.com\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if cached {
				if got := NormalizeFile(dir, "feed"); got != (NormResult{Path: norm, Changed: true, Normalized: true}) {
					t.Fatalf("initial cache = %+v", got)
				}
			}
			if err := os.WriteFile(orig, []byte("new.example.com  \n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tmp := norm + ".tmp"
			if err := os.WriteFile(tmp, []byte("another normalizer's pending output\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			for _, path := range []string{orig, norm, sidecar, tmp} {
				data, err := os.ReadFile(path)
				if err != nil && !(os.IsNotExist(err) && !cached && (path == norm || path == sidecar)) {
					t.Fatal(err)
				}
				before[path] = data
			}
			lock, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			done := make(chan NormResult, 1)
			go func() { done <- NormalizeFile(dir, "feed") }()
			watchdog := time.NewTimer(5 * time.Second)
			defer watchdog.Stop()
			select {
			case got := <-done:
				if want := (NormResult{Path: orig, Changed: true}); got != want {
					t.Errorf("contended normalization = %+v, want %+v", got, want)
				}
			case <-watchdog.C:
				// Release and reap the blocked call before failing, rather than strand a goroutine.
				lock.Close()
				got := <-done
				t.Fatalf("STUCK: normalization waited for directory lock release, returned %+v", got)
			}
			for path, want := range before {
				got, err := os.ReadFile(path)
				if want == nil {
					if !os.IsNotExist(err) {
						t.Errorf("contended call created %s: bytes %q, error %v", path, got, err)
					}
				} else if err != nil || !bytes.Equal(got, want) {
					t.Errorf("contended call modified %s: bytes %q, error %v, want %q", path, got, err, want)
				}
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			if got := NormalizeFile(dir, "feed"); got != (NormResult{Path: norm, Changed: true, Normalized: true}) {
				t.Fatalf("released normalization = %+v, want rebuilt cache", got)
			}
			if got := NormalizeFile(dir, "feed"); got != (NormResult{Path: norm, Normalized: true}) {
				t.Errorf("cache reuse = %+v, want unchanged normalized cache", got)
			}
			if got, err := os.ReadFile(norm); err != nil || string(got) != "new.example.com\n" {
				t.Errorf("normalized bytes = %q, error %v, want new.example.com\\n", got, err)
			}
			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Errorf("rebuilt temporary remains: %v", err)
			}
		})
	}
}
