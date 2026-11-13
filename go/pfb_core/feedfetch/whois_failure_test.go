package feedfetch_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// A cancelled run stops at the entry it is on: it does not go on to look up the rest of a long list.
func TestWhoisStopsLookingUpOnceCancelled(t *testing.T) {
	f, feed, _ := whoisFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	lookups := 0
	f.Lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		lookups++
		cancel()
		return nil, ctx.Err()
	}
	f.Whois(ctx, feed, feedfetch.WhoisRequest{List: "a.example,b.example,c.example"})
	if lookups != 1 {
		t.Errorf("%d lookups after the first cancelled, want none further", lookups-1)
	}
}

// A copy that cannot be written is reported and costs nothing: the backup of the previous copy is still there to restore.
func TestWhoisKeepsTheBackupWhenTheNewCopyCannotBeWritten(t *testing.T) {
	f, feed, orig := whoisFixture(t)
	bk := filepath.Join(feed.Dir, feed.Name+".bk")
	if err := os.WriteFile(bk, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(orig+".tmp", 0o700); err != nil { // the staging name is taken by a directory, root or not
		t.Fatal(err)
	}
	res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example"})
	if res.Reason == "" || res.Found {
		t.Errorf("Reason=%q Found=%v, want the write reported and nothing found", res.Reason, res.Found)
	}
	if got, _ := os.ReadFile(bk); string(got) != "198.51.100.7\n" {
		t.Errorf("backup = %q, want it kept", got)
	}
	if _, err := os.Stat(orig); err == nil {
		t.Error("a published copy appeared although it could not be written")
	}
}

// A whois write replaces ".orig", so the digest sidecars recorded for the copy it replaced go with it: left behind, a
// local source holding the replaced bytes would read as unchanged against a published copy that no longer holds them.
func TestAWhoisWriteDropsTheReplacedCopysDigests(t *testing.T) {
	const old = "same\n"
	for sidecar, digest := range map[string]string{ // xxh128 and md5 of "same\n"
		".orig.xxhash128": "7e1402559176eb98e66aa82c39de3587",
		".orig.md5":       "847676261680bff61c72961c8198abc0",
	} {
		t.Run(sidecar, func(t *testing.T) {
			f, feed, orig := whoisFixture(t)
			src := t.TempDir()
			f.Policy.LocalDirs = []string{src}
			if err := os.WriteFile(filepath.Join(src, "list.txt"), []byte(old), 0o600); err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string]string{orig: old, filepath.Join(feed.Dir, feed.Name+sidecar): digest} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			req := feedfetch.Request{URL: "file://" + filepath.Join(src, "list.txt")}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Unchanged {
				t.Fatalf("probe over the seeded baseline: %+v, want OK and unchanged", res)
			}

			if res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example"}); !res.Found {
				t.Fatalf("whois %+v, want a new published copy", res)
			}
			if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed {
				t.Fatalf("probe of the replaced bytes after the write: %+v, want OK and changed", res)
			}
			for _, s := range []string{".orig.xxhash128", ".orig.md5"} {
				if b, err := os.ReadFile(filepath.Join(feed.Dir, feed.Name+s)); err == nil && string(b) == digest {
					t.Errorf("%s still holds %q, the digest of the replaced copy", s, b)
				}
			}
		})
	}
}

// A digest that cannot be dropped stops the write: a new copy under the old digest is the stale baseline, so the
// previous copy stays and the failure is reported.
func TestWhoisKeepsThePreviousCopyWhenItsDigestCannotBeDropped(t *testing.T) {
	f, feed, orig := whoisFixture(t)
	if err := os.WriteFile(orig, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(feed.Dir, feed.Name+".orig.md5")
	if err := os.MkdirAll(filepath.Join(stuck, "keep"), 0o700); err != nil { // a non-empty directory cannot be removed, root or not
		t.Fatal(err)
	}
	res := f.Whois(context.Background(), feed, feedfetch.WhoisRequest{List: "a.example"})
	if res.Reason == "" || res.Found {
		t.Errorf("Reason=%q Found=%v, want the failure reported and nothing found", res.Reason, res.Found)
	}
	if got, _ := os.ReadFile(orig); string(got) != "198.51.100.7\n" {
		t.Errorf("published copy = %q, want the previous one kept", got)
	}
}
