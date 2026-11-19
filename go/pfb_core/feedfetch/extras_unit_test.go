package feedfetch_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// #2658 on the Extras: an archive no directory of the publication has room for is refused before extraction, and the
// published file stays (pfb_extract_space_shortfall). PHP asks the real file system, so the shared corpus cannot pin it.
func TestAnExtrasArchiveWithoutRoomIsRefusedAndKeepsThePublishedFile(t *testing.T) {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body.Bytes()) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	share := t.TempDir()
	target := filepath.Join(share, "asn.csv")
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		free uint64
		want string
	}{{"room for the archive", uint64(body.Len()), "new\n"}, {"one byte short", uint64(body.Len() - 1), "old\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			f := &feedfetch.Fetcher{RetryDelay: 1}
			f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.5")}, nil
			}
			f.FreeBytes = func(string) (uint64, bool) { return tc.free, true }
			url := "http://ipinfo.io:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/data/free/asn.csv.gz?token="
			res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: t.TempDir()},
				[]feedfetch.Extra{{Kind: "asn", URL: url, Dir: share, Download: "asn.csv.gz", File: "asn.csv"}})
			got, _ := os.ReadFile(target)
			if string(got) != tc.want || res.OK != (tc.want == "new\n") {
				t.Errorf("(ok, asn.csv) = (%v, %q), want asn.csv %q", res.OK, got, tc.want)
			}
		})
	}
}

// An Extra of a kind not translated yet fails before anything is fetched or written.
func TestAnExtraOfAnUntranslatedKindIsRefusedBeforeItIsFetched(t *testing.T) {
	var asked atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { asked.Store(true) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.5")}, nil
	}
	dir := t.TempDir()
	url := "http://dsi.ut-capitole.fr:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/blacklists/download/ads.tar.gz"
	res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: dir},
		[]feedfetch.Extra{{Kind: "unknown", URL: url, Dir: dir, Download: "ads.tar.gz", File: "ads"}})
	srv.Close()
	entries, _ := os.ReadDir(dir)
	if res.OK || asked.Load() || len(entries) != 0 {
		t.Errorf("(ok, fetched, files) = (%v, %v, %d), want (false, false, 0)", res.OK, asked.Load(), len(entries))
	}
}

// A run whose context has ended is aborted, not failed by MaxMind: no geoip row reports a MaxMind error that would read
// as a bad key or a bad download (#4059 review).
func TestAnEndedContextIsNoMaxMindError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.7")}, nil
	}
	share := t.TempDir()
	res := f.DownloadExtras(ctx, feedfetch.ExtrasConfig{DBDir: t.TempDir(), MaxMindAccount: "1", MaxMindKey: "k"},
		[]feedfetch.Extra{{Kind: "geoip", URL: "http://download.maxmind.com:9/geoip/databases/GeoLite2-Country/download?suffix=tar.gz",
			Dir: share, Download: "GeoLite2-Country.tar.gz", File: "GeoLite2-Country.mmdb"}})
	if res.OK || res.MaxMindError {
		t.Errorf("(ok, maxmind error) = (%v, %v), want (false, false)", res.OK, res.MaxMindError)
	}
}

// A run cancelled while a geoip row downloads is aborted, not failed by MaxMind (#4059 review).
func TestARunCancelledMidTransferIsNoMaxMindError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.7")}, nil
	}
	url := "http://download.maxmind.com:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) +
		"/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
	res := f.DownloadExtras(ctx, feedfetch.ExtrasConfig{DBDir: t.TempDir(), MaxMindAccount: "1", MaxMindKey: "k"},
		[]feedfetch.Extra{{Kind: "geoip", URL: url, Dir: t.TempDir(), Download: "GeoLite2-Country.tar.gz", File: "GeoLite2-Country.mmdb"}})
	if res.OK || res.MaxMindError {
		t.Errorf("(ok, maxmind error) = (%v, %v), want (false, false)", res.OK, res.MaxMindError)
	}
}
