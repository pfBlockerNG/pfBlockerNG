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
