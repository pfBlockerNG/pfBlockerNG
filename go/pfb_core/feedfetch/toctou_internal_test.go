package feedfetch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A local file swapped for a symlink after the source was admitted is not followed (#3911): the read is of the file
// that was checked, or nothing.
func TestALocalFileSwappedForASymlinkAfterTheCheckIsNotRead(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	list, secret := filepath.Join(dir, "list.txt"), filepath.Join(outside, "secret")
	os.WriteFile(list, []byte("feed\n"), 0o600)
	os.WriteFile(secret, []byte("SECRET\n"), 0o600)
	f := &Fetcher{Policy: Policy{LocalDirs: []string{dir}}}
	src, _ := f.entry(context.Background(), Request{URL: "file://" + list})
	if src == nil || src.kind != kindLocal {
		t.Fatalf("the local file was not admitted: %+v", src)
	}

	os.Remove(list)
	if err := os.Symlink(secret, list); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "FEED.raw")
	tr := f.fetch(context.Background(), src, Request{}, dst, nil)
	if b, _ := os.ReadFile(dst); tr.reason == "" || string(b) == "SECRET\n" {
		t.Fatalf("the swapped-in symlink was followed: %+v, read %q", tr, b)
	}
}
