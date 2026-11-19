package feedfetch_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
			if r := res.Rows[0]; !res.OK && (r.Stage != "size" || r.Reason != "staging_space_low") {
				t.Errorf("refusal (stage, reason) = (%q, %q), want (size, staging_space_low)", r.Stage, r.Reason)
			}
		})
	}
}

// #2658 on a blacklist row: a category archive no directory has room for is refused before extraction, and the
// category folder stays.
func TestACategoryArchiveWithoutRoomKeepsTheFolder(t *testing.T) {
	var tarball bytes.Buffer
	tw := tar.NewWriter(&tarball)
	if err := tw.WriteHeader(&tar.Header{Name: "bl/adult/domains", Mode: 0o644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("new\n"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	zw.Write(tarball.Bytes())
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
	for _, tc := range []struct {
		name string
		free uint64
		want string
	}{{"room for the archive", uint64(body.Len()), "new\n"}, {"one byte short", uint64(body.Len() - 1), "old\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			db := t.TempDir()
			published := filepath.Join(db, "ut1", "ut1_adult")
			if err := os.Mkdir(filepath.Dir(published), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(published, []byte("old\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			f := &feedfetch.Fetcher{RetryDelay: 1}
			f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.9")}, nil
			}
			f.FreeBytes = func(string) (uint64, bool) { return tc.free, true }
			url := "http://bl.example:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/ut1.tar.gz"
			res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: db}, []feedfetch.Extra{
				{Kind: "blacklist", URL: url, Dir: db, Download: "ut1.tar.gz", File: "ut1.tar.gz", Name: "UT1"}})
			got, _ := os.ReadFile(published)
			if string(got) != tc.want || res.OK != (tc.want == "new\n") {
				t.Errorf("(ok, ut1/ut1_adult) = (%v, %q), want ut1/ut1_adult %q", res.OK, got, tc.want)
			}
			if r := res.Rows[0]; !res.OK && (r.Stage != "size" || r.Reason != "staging_space_low") {
				t.Errorf("refusal (stage, reason) = (%q, %q), want (size, staging_space_low)", r.Stage, r.Reason)
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
	// The refusal names the aborted run, never a fault of the feed or the key.
	if r := res.Rows[0]; r.Stage != "aborted" || r.Reason != context.Canceled.Error() {
		t.Errorf("refusal (stage, reason) = (%q, %q), want (aborted, %q)", r.Stage, r.Reason, context.Canceled)
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
	// The refusal names the aborted run, never a fault of the feed or the key.
	if r := res.Rows[0]; r.Stage != "aborted" || r.Reason != context.Canceled.Error() {
		t.Errorf("refusal (stage, reason) = (%q, %q), want (aborted, %q)", r.Stage, r.Reason, context.Canceled)
	}
}

// #2658 on the TOP1M row: a list archive no directory has room for is refused before extraction, and the list stays.
func TestATop1MListWithoutRoomKeepsTheList(t *testing.T) {
	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	w, err := zw.Create("top-1m.csv")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("1,new.example\n"))
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
	db := t.TempDir()
	list := filepath.Join(db, "top-1m.csv")
	if err := os.WriteFile(list, []byte("1,old.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.11")}, nil
	}
	f.FreeBytes = func(string) (uint64, bool) { return uint64(body.Len() - 1), true }
	url := "http://tranco-list.eu:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/top-1m.csv.zip"
	res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: db}, []feedfetch.Extra{
		{Kind: "top1m", URL: url, Dir: db, Download: "top-1m.csv.zip", File: "top-1m.csv", Provider: "tranco"}})
	got, _ := os.ReadFile(list)
	if r := res.Rows[0]; res.OK || string(got) != "1,old.example\n" || r.Stage != "size" || r.Reason != "staging_space_low" {
		t.Errorf("(ok, list, stage, reason) = (%v, %q, %q, %q), want (false, the old list, size, staging_space_low)",
			res.OK, got, r.Stage, r.Reason)
	}
}

// A self-hosted source's transfer error never carries the URL's query into the refusal: a key in a configured Blacklist
// URL stays out of what the verbs log.
func TestATransferRefusalCarriesNoQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close() // nothing listens: the transfer fails with the client's error
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	db := t.TempDir()
	res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: db}, []feedfetch.Extra{{Kind: "blacklist",
		URL: "http://lists.example:" + port + "/bl.tar.gz?key=qtoken", Dir: db, Download: "bl.tar.gz", File: "bl.tar.gz", Name: "BL"}})
	if r := res.Rows[0]; res.OK || r.Reason == "" || strings.Contains(r.Reason+r.Detected, "qtoken") {
		t.Errorf("(ok, reason, detected) = (%v, %q, %q), want a refusal without the query", res.OK, r.Reason, r.Detected)
	}
}
