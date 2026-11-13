package feedfetch_test

// Review round of #3911.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// A self-hosted name with several self addresses is read from the first that answers, as PHP's stream wrapper tries
// each: here ::1 first, while the server listens on 127.0.0.1 only.
func TestASelfHostedFeedTriesEachSelfAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("SELF\n")) }))
	defer srv.Close()
	f, feed := fetcherFor(t)
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "http://self.example:" + port(t, srv.URL) + "/list", Timeout: 5 * time.Second})
	if !res.OK || published(t, feed) != "SELF\n" {
		t.Fatalf("a self-hosted feed was not read from its second self address: %+v, published %q", res, published(t, feed))
	}
}

// An earlier run's rsync temporary file is gone before rsync starts, not only after it ends.
func TestAnEarlierRsyncTemporaryFileIsGoneBeforeRsyncStarts(t *testing.T) {
	tools := t.TempDir()
	script := "#!/bin/sh\neval \"dst=\\${$#}\"\nfor f in \"$(dirname \"${dst}\")\"/.FEED.raw.*; do [ -e \"$f\" ] && exit 9; done\n" +
		"printf full >\"${dst}\"\n"
	if err := os.WriteFile(filepath.Join(tools, "rsync"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	f, feed := fetcherFor(t)
	f.RsyncBin = filepath.Join(tools, "rsync")
	os.WriteFile(filepath.Join(feed.Dir, ".FEED.raw.Zz99Yy"), []byte("earlier\n"), 0o600)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "rsync://feed.example/feeds/list.txt", Rsync: true, Timeout: 5 * time.Second})
	if !res.OK {
		t.Fatalf("rsync started beside an earlier run's temporary file: %+v", res)
	}
}
