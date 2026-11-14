package feedparse

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Two calls for one feed must not interleave. Call A streams a large .orig; once its temporary holds bytes, the .orig is
// replaced and call B runs. Interleaved, B truncates A's temporary, publishes it with B's sidecar, and A keeps writing into
// the published .norm; serialized, B waits and rebuilds from the new .orig. Either way the cache must then serve B's text.
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
	if !b.Normalized {
		t.Errorf("call B = %+v, want a normalized feed", b)
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
