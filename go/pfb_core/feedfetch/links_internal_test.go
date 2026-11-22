package feedfetch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// linkedFile writes body to a file outside the feed folder and links it in as name: what the feed stage's run folder
// holds, the published file seeded by a hard link.
func linkedFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	outside := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(outside, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return outside
}

func readBack(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The validators are replaced whole, never written through: a file linked to another keeps the other's bytes.
func TestValidatorsAreReplacedNotWrittenThrough(t *testing.T) {
	dir := t.TempDir()
	etag := linkedFile(t, dir, "feed.orig.etag", `"old"`)
	lastMod := linkedFile(t, dir, "feed.orig.lastmod", "100")
	writeValidators(Feed{Dir: dir, Name: "feed"}, `"new"`, time.Unix(200, 0))
	if got := readBack(t, etag); got != `"old"` {
		t.Errorf("the linked ETag became %q, want it untouched", got)
	}
	if got := readBack(t, lastMod); got != "100" {
		t.Errorf("the linked Last-Modified became %q, want it untouched", got)
	}
	if got := readBack(t, filepath.Join(dir, "feed.orig.etag")); got != `"new"` {
		t.Errorf("the ETag is %q, want the new one", got)
	}
	if got := readBack(t, filepath.Join(dir, "feed.orig.lastmod")); got != "200" {
		t.Errorf("the Last-Modified is %q, want the new one", got)
	}
}

// A transfer never writes through the staged archive an earlier run kept: the new body is a file of its own.
func TestTransferNeverWritesThroughTheKeptArchive(t *testing.T) {
	dir, db := t.TempDir(), t.TempDir()
	list := filepath.Join(db, "list.txt")
	if err := os.WriteFile(list, []byte("198.51.100.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := linkedFile(t, dir, "feed.raw", "kept archive\n")
	f := &Fetcher{Policy: Policy{LocalDirs: []string{db}}}
	if r := f.Ingest(context.Background(), Feed{Dir: dir, Name: "feed"}, Request{URL: "file://" + list}); !r.OK {
		t.Fatalf("Ingest = %+v", r)
	}
	if got := readBack(t, raw); got != "kept archive\n" {
		t.Errorf("the linked archive became %q, want it untouched", got)
	}
	if got := readBack(t, filepath.Join(dir, "feed.orig")); got != "198.51.100.2\n" {
		t.Errorf("the published copy is %q, want the transferred body", got)
	}
}

// The newline a finished body gains goes to a copy, never through the probe body it came from.
func TestFinishNeverWritesThroughTheProbeBody(t *testing.T) {
	dir, db := t.TempDir(), t.TempDir()
	list := filepath.Join(db, "list.txt")
	if err := os.WriteFile(list, []byte("198.51.100.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := linkedFile(t, dir, "feed.probe", "198.51.100.9")
	f := &Fetcher{Policy: Policy{LocalDirs: []string{db}}}
	if r := f.Ingest(context.Background(), Feed{Dir: dir, Name: "feed"}, Request{URL: "file://" + list}); !r.OK {
		t.Fatalf("Ingest = %+v", r)
	}
	if got := readBack(t, probe); got != "198.51.100.9" {
		t.Errorf("the linked probe body became %q, want it untouched", got)
	}
	if got := readBack(t, filepath.Join(dir, "feed.orig")); got != "198.51.100.9\n" {
		t.Errorf("the published copy is %q, want the probe body with its newline", got)
	}
}
