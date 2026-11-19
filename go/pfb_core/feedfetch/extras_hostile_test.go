package feedfetch_test

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// What the Extras corpus cannot reach: today's PHP caps an extraction with a fixed `ulimit -f`, has no proxy switch the
// corpus runner sets, and the corpus does not observe modification times. Each Extras type runs its own copy of these
// checks, so each is covered here apart from the feeds' tests of the same mechanism.

// extrasPort serves body (with lastMod, when set) on every path and returns the server's port and request count.
func extrasPort(t *testing.T, body []byte, lastMod time.Time) (string, func() int32) {
	t.Helper()
	srvURL, hits := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if !lastMod.IsZero() {
			w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
		}
		w.Write(body)
	})
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port(), hits.Load
}

func extrasFetcher() *feedfetch.Fetcher {
	f := &feedfetch.Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.9")}, nil
	}
	return f
}

// A member one byte past the per-file extraction ceiling (#2658) refuses the row, and what was published stays; a ceiling
// of exactly the member's size publishes the same archive, so the ceiling is what refused it. The members: a GeoIP tar
// member, the one member of a GeoIP zip, a Blacklist category member, the TOP1M list in its zip.
func TestAnExtrasMemberPastTheCeilingKeepsWhatWasPublished(t *testing.T) {
	mmdb := append(make([]byte, 64<<10), "\xab\xcd\xefMaxMind.com"...)
	domains := bytes.Repeat([]byte("big.example\n"), 64<<10/12)
	list := bytes.Repeat([]byte("1,good.example\n"), 64<<10/15)
	for _, tc := range []struct {
		name, kind, host, download, file, published string
		member                                      []byte
		body                                        []byte
	}{
		{"geoip tar member", "geoip", "download.maxmind.com", "GeoLite2-Country.tar.gz", "GeoLite2-Country.mmdb",
			"GeoLite2-Country.mmdb", mmdb, gzipOf(t, tarNamed(t, "GeoLite2-Country_1/GeoLite2-Country.mmdb", mmdb))},
		{"geoip zip member", "geoip", "download.maxmind.com", "GeoLite2-Country.zip", "GeoLite2-Country.mmdb",
			"GeoLite2-Country.mmdb", mmdb, zipNamed(t, "GeoLite2-Country.mmdb", string(mmdb))},
		{"blacklist member", "blacklist", "bl.example", "ut1.tar.gz", "ut1.tar.gz", "ut1/ut1_adult",
			domains, gzipOf(t, tarNamed(t, "bl/adult/domains", domains))},
		{"top1m zip member", "top1m", "tranco-list.eu", "top-1m.csv.zip", "top-1m.csv", "top-1m.csv",
			list, zipNamed(t, "top-1m.csv", string(list))},
	} {
		port, _ := extrasPort(t, tc.body, time.Time{})
		for _, room := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: " at the ceiling", false: " one byte past it"}[room], func(t *testing.T) {
				dir := t.TempDir()
				published := filepath.Join(dir, tc.published)
				if err := os.MkdirAll(filepath.Dir(published), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(published, []byte(oldCopy), 0o644); err != nil {
					t.Fatal(err)
				}
				f := extrasFetcher()
				f.SetExtractMax(int64(len(tc.member)) - 1)
				if room {
					f.SetExtractMax(int64(len(tc.member)))
				}
				res := f.DownloadExtras(context.Background(),
					feedfetch.ExtrasConfig{DBDir: dir, MaxMindAccount: "1", MaxMindKey: "k"},
					[]feedfetch.Extra{{Kind: tc.kind, URL: "http://" + tc.host + ":" + port + "/" + tc.download,
						Dir: dir, Download: tc.download, File: tc.file, Name: "UT1", Provider: "tranco"}})
				got, err := os.ReadFile(published)
				if err != nil {
					t.Fatalf("ok %v, %s: %v", res.OK, tc.published, err)
				}
				want := []byte(oldCopy)
				if room {
					want = tc.member
				}
				if res.OK != room || !bytes.Equal(got, want) {
					t.Errorf("(ok, %s replaced) = (%v, %v), want (%v, %v)", tc.published, res.OK, string(got) != oldCopy,
						room, room)
				}
			})
		}
	}
}

// With the proxy unusable (pfb_proxy_unusable), every Extra is refused before it is fetched, and nothing is written.
func TestAnUnusableProxyRefusesEveryExtraBeforeItIsFetched(t *testing.T) {
	port, hits := extrasPort(t, []byte("body\n"), time.Time{})
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
			if res.OK || hits() != 0 || len(entries) != 0 {
				t.Errorf("(ok, requests, files) = (%v, %d, %d), want (false, 0, 0)", res.OK, hits(), len(entries))
			}
		})
	}
}

// The remote timestamp (Last-Modified) is set on the staged download, so it reaches what is published from it whole:
// an ASN database renamed into place, and the Blacklist archive kept beside its category folder.
func TestTheRemoteTimestampReachesWhatIsPublishedWhole(t *testing.T) {
	stamp := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		name, host, query string
		x                 feedfetch.Extra
		body              []byte
	}{
		{"asn database", "ipinfo.io", "?token=", feedfetch.Extra{Kind: "asn", Download: "asn.mmdb", File: "asn.mmdb"},
			[]byte("\x00db\x00\xab\xcd\xefMaxMind.com")},
		{"blacklist archive", "bl.example", "",
			feedfetch.Extra{Kind: "blacklist", Download: "ut1.tar.gz", File: "ut1.tar.gz", Name: "UT1"},
			gzipOf(t, tarNamed(t, "bl/adult/domains", []byte("adult.example\n")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, _ := extrasPort(t, tc.body, stamp)
			dir := t.TempDir()
			x := tc.x
			x.Dir, x.URL = dir, "http://"+tc.host+":"+port+"/"+x.Download+tc.query
			res := extrasFetcher().DownloadExtras(context.Background(), feedfetch.ExtrasConfig{DBDir: dir}, []feedfetch.Extra{x})
			info, err := os.Stat(filepath.Join(dir, x.File))
			if err != nil {
				t.Fatalf("ok %v, %s: %v", res.OK, x.File, err)
			}
			if !res.OK || !info.ModTime().Equal(stamp) {
				t.Errorf("(ok, %s mtime) = (%v, %v), want (true, %v)", x.File, res.OK, info.ModTime(), stamp)
			}
		})
	}
}
