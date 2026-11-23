package update

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// WHEN a stale feed's file vanishes between the cleanup's listing and its inspection THEN the cleanup goes on: an absent
// file is no failure, the feed is removed and the issue raised.
func TestAFileThatVanishesDuringTheCleanupIsNoFailure(t *testing.T) {
	s, settings := sideListTree(t) // Old is staged and no longer configured
	touch(t, filepath.Join(s.FeedDir, "Old.orig"), "raw\n")
	vanished := filepath.Join(s.FeedDir, "Old.orig")
	dnsblLstat = func(name string) (fs.FileInfo, error) {
		if name == vanished {
			os.Remove(name)
			return nil, fs.ErrNotExist
		}
		return os.Lstat(name)
	}
	t.Cleanup(func() { dnsblLstat = os.Lstat })
	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatalf("a file vanished during the cleanup: %v, want no error", err)
	}
	if left, _ := filepath.Glob(filepath.Join(s.FeedDir, "Old.*")); len(left) != 0 {
		t.Errorf("Old's files: %q, want none", left)
	}
	if len(out.Issues) != 1 || out.Issues[0].Code != "feed_files_removed" {
		t.Errorf("issues = %+v, want one feed_files_removed", out.Issues)
	}
}
