package main

import (
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
)

// WHEN the hook context has been read in full by the time a signal ends the wait for it THEN the one-shot goes on with
// what it read, on every call, whichever ready case select would pick.
func TestHookInputTakesAFinishedReadOverASimultaneousSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 200 {
		got := make(chan hookInput, 1)
		got <- hookInput{data: []byte("{}")}
		in, ok := awaitHookInput(ctx, got)
		if !ok || string(in.data) != "{}" {
			t.Fatalf("call %d: got %q and read %v, want the finished read {} taken", i, in.data, ok)
		}
	}
}

// WHEN the settings come through an adapter program THEN the one-shot never looks at the --state-dir, which a stalled
// mount could hang on: only the file backend needs it.
func TestRunHooksThroughTheAdapterNeverChecksTheStateDirectory(t *testing.T) {
	stats, orig := 0, statStateDir
	statStateDir = func(name string) (fs.FileInfo, error) { stats++; return orig(name) }
	t.Cleanup(func() { statStateDir = orig })
	dir := t.TempDir()
	var stderr bytes.Buffer
	status := runHooks(context.Background(), "pre", filepath.Join(dir, "missing"), filepath.Join(dir, "no-backend"),
		hooks.Runner{Dir: dir}, strings.NewReader("{}"), &bytes.Buffer{}, &stderr)
	if stats != 0 || status != 1 || !strings.Contains(stderr.String(), "from the adapter backend") {
		t.Errorf("state directory checks %d, status %d and stderr %q; want 0, 1 and the adapter's failure", stats, status,
			stderr.String())
	}
}
