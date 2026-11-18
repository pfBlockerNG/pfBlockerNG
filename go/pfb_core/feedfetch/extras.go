package feedfetch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The Extras (#3978): the translation of pfblockerng_download_extras() and the Extras branches of pfb_download(), held
// to the parity corpus in tests/extras/fixtures/parity. A failed or refused Extra keeps what it published before. The
// asn and geoip types are translated so far; any other kind is refused before it is fetched.

// extrasTimeout is what every pfblockerng.php verb passes pfblockerng_download_extras().
const extrasTimeout = 600 * time.Second

// Extra is one row of the Extras table (pfblockerng.php:166-256).
type Extra struct {
	Kind     string // asn or geoip
	URL      string // an asn URL ends in "token=": the token is appended, encoded
	Dir      string // the folder: the GeoIP share or the database folder
	Download string // the download's file name in Dir (file_dwn)
	File     string // the published file's name in Dir; empty for the GeoLite2 CSV zip
}

// ExtrasConfig is what the extras projection and the Core's flags give a run. The secrets are held in memory only.
type ExtrasConfig struct {
	DBDir                      string // where the update markers go ($pfb['dbdir'])
	MaxMindAccount, MaxMindKey string
	ASNToken                   string
	Timeout                    time.Duration // per transfer; zero is the verbs' 600 s
	// ASNTable is `pfblockerng.sh asn_table`, run after a gzipped body is published on an asn row, as pfb_download() does
	// (the GeoIP and ASN conversion's, #4034); nil runs nothing.
	ASNTable func(ctx context.Context)
}

// ExtrasResult is pfblockerng_download_extras()'s return and the flags it leaves in $pfb.
type ExtrasResult struct {
	OK           bool
	MaxMindError bool // a geoip row failed: it blocks the country conversion
}

// DownloadExtras downloads every Extra in order, as pfblockerng_download_extras() does.
func (f *Fetcher) DownloadExtras(ctx context.Context, cfg ExtrasConfig, extras []Extra) ExtrasResult {
	if cfg.Timeout <= 0 {
		cfg.Timeout = extrasTimeout
	}
	res := ExtrasResult{OK: true}
	for _, x := range extras {
		if ctx.Err() != nil {
			res.OK = false // the run is aborted: the rows left are not failed by their feeds
			break
		}
		req := Request{URL: x.URL, Timeout: cfg.Timeout}
		switch x.Kind {
		case "asn":
			req.URL += rawURLEncode(cfg.ASNToken)
		case "geoip":
			req.Username, req.Password = cfg.MaxMindAccount, cfg.MaxMindKey
		}
		if !f.extra(ctx, cfg, x, req) {
			res.OK = false
			if x.Kind == "geoip" && ctx.Err() == nil {
				res.MaxMindError = true
			}
		}
	}
	return res
}

// extra is pfb_download() for one Extra: the transfer to "<download>.raw", the content gates, the update marker and the
// publication of its type. It reports whether the Extra succeeded.
func (f *Fetcher) extra(ctx context.Context, cfg ExtrasConfig, x Extra, req Request) bool {
	if x.Kind != "asn" && x.Kind != "geoip" {
		return false
	}
	src, _ := f.entry(ctx, req)
	if src == nil || f.proxyUnusableFor(src) {
		return false
	}
	base := filepath.Join(x.Dir, x.Download)
	raw, target := base+".raw", filepath.Join(x.Dir, x.File)
	defer os.Remove(raw)
	t := f.fetch(ctx, src, req, raw, nil)
	if t.reason != "" {
		return false
	}
	if t.status == 304 {
		// Unchanged is a success only while something is in service: PHP also reports it with nothing published.
		_, orig := os.Stat(base + ".orig")
		_, published := os.Stat(target)
		return orig == nil && published == nil
	}
	if t.status != 200 && t.status != 221 && t.status != 226 {
		return false
	}

	mime, ok := f.extraVerdict(ctx, raw, src.host)
	if !ok {
		return false
	}
	// A type the row cannot publish is refused before the update marker: PHP reports an asn bzip2 or zip a success
	// with only "<download>.orig" written, which nothing reads, and fails a geoip bzip2 after the marker.
	if mime == mimeBzip2 || mime == mimeZip && x.Kind == "asn" {
		return false
	}
	archive := mime == mimeGzip || mime == mimeBzip2 || mime == mimeZip || mime == mimeTar
	if isDatabase(target) {
		// A database row takes a MaxMind DB and nothing else: a text page is not one, and a database is never scanned as
		// text (owner, #4058; PHP renames any text body over it, and its sanity scan refuses the binary asn.mmdb).
		if !archive && !maxMindDB(raw) {
			return false
		}
	} else if f.Sanity && (mime == mimeText || mime == mimeHTML) {
		if sane(raw) != "" {
			return false
		}
	}
	touch(filepath.Join(cfg.DBDir, x.Kind+".update"))
	if !t.lastMod.IsZero() {
		os.Chtimes(raw, t.lastMod, t.lastMod)
	}
	if archive && f.extractShort(raw, x.Dir, cfg.DBDir, target, filepath.Dir(target)) {
		return false
	}
	if x.Kind == "geoip" {
		return f.publishGeoIP(ctx, mime, raw, x.Dir, target)
	}
	return f.publishASN(ctx, cfg, mime, raw, target)
}

// extraVerdict is pfb_filter(FILE_MIME) with its host exception: an octet stream from ipinfo.io (the binary asn.mmdb)
// is taken for text/plain before any structural recovery.
func (f *Fetcher) extraVerdict(ctx context.Context, raw, host string) (string, bool) {
	if h, err := os.Open(raw); err == nil {
		mime := classify(head(h))
		h.Close()
		if mime == mimeOctet && host == "ipinfo.io" {
			return mimeText, true
		}
	}
	mime, _, ok := verdict(ctx, raw)
	return mime, ok
}

// extractShort is pfb_extract_space_shortfall(): one of the directories cannot hold the archive itself.
func (f *Fetcher) extractShort(raw string, dirs ...string) bool {
	info, err := os.Stat(raw)
	if err != nil {
		return false
	}
	free := f.FreeBytes
	if free == nil {
		free = freeBytes
	}
	for _, d := range dirs {
		if avail, known := free(d); known && avail < uint64(info.Size()) {
			return true
		}
	}
	return false
}

// publishASN is the asn branch: a gzip's stream or a tar's members replace the published file whole (pfb_stage_publish),
// any other body is renamed over it.
func (f *Fetcher) publishASN(ctx context.Context, cfg ExtrasConfig, mime, raw, target string) bool {
	switch mime {
	case mimeGzip, mimeTar:
		staged, err := f.stage(ctx, Feed{Dir: filepath.Dir(target)}, mime, raw, false)
		if err != nil {
			return false
		}
		// A database row takes a MaxMind DB: what an archive holds is checked as a bare body is (owner, #4058).
		if isDatabase(target) && !maxMindDB(staged) {
			os.Remove(staged)
			return false
		}
		if os.Rename(staged, target) != nil {
			os.Remove(staged)
			return false
		}
		if mime == mimeGzip && cfg.ASNTable != nil {
			cfg.ASNTable(ctx)
		}
		return true
	}
	return os.Rename(raw, target) == nil
}

// rawURLEncode is PHP's rawurlencode(): everything but letters, digits and "-_.~" is percent-encoded.
func rawURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// maxMindMarker opens a MaxMind DB's metadata section, which the format puts within the file's last 128 KiB.
var maxMindMarker = []byte("\xab\xcd\xefMaxMind.com")

// isDatabase tells a row whose published file is a MaxMind DB (GeoLite2-Country.mmdb, asn.mmdb).
func isDatabase(target string) bool { return strings.HasSuffix(target, ".mmdb") }

// maxMindDB tells that the file at path carries the MaxMind DB metadata marker in its last 128 KiB.
func maxMindDB(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	off := max(info.Size()-128<<10, 0)
	tail := make([]byte, info.Size()-off)
	if _, err := f.ReadAt(tail, off); err != nil {
		return false
	}
	return bytes.Contains(tail, maxMindMarker)
}
