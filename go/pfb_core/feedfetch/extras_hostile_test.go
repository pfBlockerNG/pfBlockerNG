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
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// What the Extras corpus cannot reach: today's PHP caps an extraction with a fixed `ulimit -f`, has no proxy switch the
// corpus runner sets, and the corpus does not observe modification times.

// extrasServer answers every path with body (and lastMod, when set) and counts the requests; it returns its port.
func extrasServer(t *testing.T, body []byte, lastMod time.Time, asked *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if asked != nil {
			asked.Add(1)
		}
		if !lastMod.IsZero() {
			w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
		}
		w.Write(body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

func extrasFetcher() *feedfetch.Fetcher {
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.9")}, nil
	}
	return f
}

func tarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	tw.Write(data)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(tb.Bytes())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func zipOne(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An archive member past the per-file extraction ceiling (#2658) refuses the row: a GeoIP tar member, the one member of
// a GeoIP zip, a Blacklist category member. What was published stays; with room, the same archive publishes.
func TestAnExtrasMemberPastTheCeilingKeepsWhatWasPublished(t *testing.T) {
	mmdb := append(make([]byte, 64<<10), "\xab\xcd\xefMaxMind.com"...)
	domains := bytes.Repeat([]byte("big.example\n"), 64<<10/12)
	for _, tc := range []struct {
		name, kind, host, download, file, published string
		body                                        []byte
	}{
		{"geoip tar member", "geoip", "download.maxmind.com", "GeoLite2-Country.tar.gz", "GeoLite2-Country.mmdb",
			"GeoLite2-Country.mmdb", tarGz(t, "GeoLite2-Country_1/GeoLite2-Country.mmdb", mmdb)},
		{"geoip zip member", "geoip", "download.maxmind.com", "GeoLite2-Country.zip", "GeoLite2-Country.mmdb",
			"GeoLite2-Country.mmdb", zipOne(t, "GeoLite2-Country.mmdb", mmdb)},
		{"blacklist member", "blacklist", "bl.example", "ut1.tar.gz", "ut1.tar.gz", "ut1/ut1_adult",
			tarGz(t, "bl/adult/domains", domains)},
	} {
		port := extrasServer(t, tc.body, time.Time{}, nil)
		for _, room := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: " with room", false: " past the ceiling"}[room], func(t *testing.T) {
				dir := t.TempDir()
				published := filepath.Join(dir, tc.published)
				writeFile(t, published, "old\n")
				f := extrasFetcher()
				f.SetExtractMax(16 << 10)
				if room {
					f.SetExtractMax(1 << 20)
				}
				res := f.DownloadExtras(context.Background(),
					feedfetch.ExtrasConfig{DBDir: dir, MaxMindAccount: "1", MaxMindKey: "k"},
					[]feedfetch.Extra{{Kind: tc.kind, URL: "http://" + tc.host + ":" + port + "/" + tc.download,
						Dir: dir, Download: tc.download, File: tc.file, Name: "UT1"}})
				got, _ := os.ReadFile(published)
				if res.OK != room || (string(got) == "old\n") == room {
					t.Errorf("(ok, %s replaced) = (%v, %v), want (%v, %v)", tc.published, res.OK, string(got) != "old\n",
						room, room)
				}
			})
		}
	}
}

// With the proxy unusable (pfb_proxy_unusable), every Extra is refused before it is fetched, and nothing is written.
func TestAnUnusableProxyRefusesEveryExtraBeforeItIsFetched(t *testing.T) {
	var asked atomic.Int32
	port := extrasServer(t, []byte("body\n"), time.Time{}, &asked)
	for _, x := range []feedfetch.Extra{
		{Kind: "asn", URL: "http://ipinfo.io:" + port + "/asn.csv.gz?token=", Download: "asn.csv.gz", File: "asn.csv"},
		{Kind: "geoip", URL: "http://download.maxmind.com:" + port + "/db", Download: "GeoLite2-Country.tar.gz",
			File: "GeoLite2-Country.mmdb"},
		{Kind: "top1m", URL: "http://tranco-list.eu:" + port + "/top-1m.csv.zip", Download: "top-1m.csv.zip",
			File: "top-1m.csv", Provider: "tranco"},
		{Kind: "blacklist", URL: "http://bl.example:" + port + "/ut1.tar.gz", Download: "ut1.tar.gz", File: "ut1.tar.gz",
			Name: "UT1"},
	} {
		t.Run(x.Kind, func(t *testing.T) {
			dir := t.TempDir()
			x.Dir = dir
			f := extrasFetcher()
			f.ProxyUnusable = true
			res := f.DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: dir}, []feedfetch.Extra{x})
			entries, _ := os.ReadDir(dir)
			if res.OK || asked.Load() != 0 || len(entries) != 0 {
				t.Errorf("(ok, requests, files) = (%v, %d, %d), want (false, 0, 0)", res.OK, asked.Load(), len(entries))
			}
		})
	}
}

// The remote timestamp (Last-Modified) is set on the staged download, so it reaches what is published from it whole:
// an ASN database renamed into place, and the Blacklist archive kept beside its category folder.
func TestTheRemoteTimestampReachesWhatIsPublishedWhole(t *testing.T) {
	stamp := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name string
		x    feedfetch.Extra
		body []byte
		kept string
	}{
		{"asn database", feedfetch.Extra{Kind: "asn", Download: "asn.mmdb", File: "asn.mmdb"},
			[]byte("\x00db\x00\xab\xcd\xefMaxMind.com"), "asn.mmdb"},
		{"blacklist archive", feedfetch.Extra{Kind: "blacklist", Download: "ut1.tar.gz", File: "ut1.tar.gz", Name: "UT1"},
			tarGz(t, "bl/adult/domains", []byte("adult.example\n")), "ut1.tar.gz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := extrasServer(t, tc.body, stamp, nil)
			dir := t.TempDir()
			x := tc.x
			x.Dir = dir
			x.URL = "http://" + map[string]string{"asn": "ipinfo.io", "blacklist": "bl.example"}[x.Kind] + ":" + port +
				"/" + x.Download + map[string]string{"asn": "?token="}[x.Kind]
			res := extrasFetcher().DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: dir}, []feedfetch.Extra{x})
			info, err := os.Stat(filepath.Join(dir, tc.kept))
			if !res.OK || err != nil || !info.ModTime().Equal(stamp) {
				t.Errorf("(ok, %s, err) = (%v, %v, %v), want (true, %v, nil)", tc.kept, res.OK, info, err, stamp)
			}
		})
	}
}
