package feedfetch_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Scenario: an FTP feed is ingested from the body its probe kept, and that body is a hard link of a published file.
// Given a probe body linked to a file outside the feed folder (what the feed stage's run folder holds) and the probe's
// MDTM beside it, when Ingest publishes that body, then the published copy carries the MDTM while the linked file keeps
// its own modification time: the time goes to a file the transfer made, never through the link.
func TestAnFTPProbeBodyKeepsItsLinkedFileTime(t *testing.T) {
	stub := newFTPStub(t, nil)
	f, feed := quickFetcher(t)
	outside := filepath.Join(t.TempDir(), "published.probe")
	if err := os.WriteFile(outside, []byte("198.51.100.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := time.Unix(1_500_000_000, 0)
	if err := os.Chtimes(outside, kept, kept); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(feed.Dir, feed.Name+".probe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feed.Dir, feed.Name+".probe.lastmod"), []byte("1600000000"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt")); !res.OK {
		t.Fatalf("Ingest = %+v, want the probe body published", res)
	}
	if got := published(t, feed); got != "198.51.100.9\n" {
		t.Fatalf("the published copy is %q, want the probe body", got)
	}
	if got := modTime(t, filepath.Join(feed.Dir, feed.Name+".orig")); got.Unix() != 1_600_000_000 {
		t.Errorf("the published copy's time is %v, want the MDTM 1600000000", got.Unix())
	}
	if got := modTime(t, outside); !got.Equal(kept) {
		t.Errorf("the linked file's time became %v, want %v untouched", got.Unix(), kept.Unix())
	}
}

func modTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

// Scenario: an FTP feed is ingested from a probe body that is not a hard link.
// Given a probe body with one link only, when Ingest publishes it, then the published copy is that very file, given the
// MDTM in place: a copy is made only where the body is shared with another name.
func TestAnUnlinkedFTPProbeBodyIsRetimedInPlace(t *testing.T) {
	stub := newFTPStub(t, nil)
	f, feed := quickFetcher(t)
	probe := filepath.Join(feed.Dir, feed.Name+".probe")
	if err := os.WriteFile(probe, []byte("198.51.100.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feed.Dir, feed.Name+".probe.lastmod"), []byte("1600000000"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt")); !res.OK {
		t.Fatalf("Ingest = %+v, want the probe body published", res)
	}
	after, err := os.Stat(filepath.Join(feed.Dir, feed.Name+".orig"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("the published copy is a copy of the probe body, want the body itself")
	}
	if got := after.ModTime().Unix(); got != 1_600_000_000 {
		t.Errorf("the published copy's time is %v, want the MDTM 1600000000", got)
	}
}
