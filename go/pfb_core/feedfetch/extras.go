package feedfetch

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The Extras (#3978): the translation of pfblockerng_download_extras() and the Extras branches of pfb_download(), held
// to the parity corpus in tests/extras/fixtures/parity. A failed or refused Extra keeps what it published before. The
// asn, blacklist, geoip and top1m types are translated; any other kind is refused before it is fetched.

// extrasTimeout is what every pfblockerng.php verb passes pfblockerng_download_extras().
const extrasTimeout = 600 * time.Second

// Extra is one row of the Extras table (pfblockerng.php:166-256).
type Extra struct {
	Kind     string // asn, blacklist, geoip or top1m
	URL      string // an asn URL ends in "token=": the token is appended, encoded
	Dir      string // the folder: the GeoIP share or the database folder
	Download string // the download's file name in Dir (file_dwn)
	File     string // the published file's name in Dir; empty for the GeoLite2 CSV zip
	Provider string // top1m: the provider (PfbTop1mSource), which also names its row shape
	// A blacklist row: the provider's title, which names it in the report, and any credentials of its own.
	Name, Username, Password string
}

// ExtrasConfig is what the extras projection and the Core's flags give a run. The secrets are held in memory only.
type ExtrasConfig struct {
	DBDir                      string // where the update markers go ($pfb['dbdir'])
	MaxMindAccount, MaxMindKey string
	ASNToken                   string
	Top1MToken                 string        // Cloudflare Radar's Bearer token
	Timeout                    time.Duration // per transfer; zero is the verbs' 600 s
	// ASNTable is `pfblockerng.sh asn_table`, run after a gzipped body is published on an asn row, as pfb_download() does
	// (the GeoIP and ASN conversion's, #4034); nil runs nothing.
	ASNTable func(ctx context.Context)
	// Detect is the dcc verb: the TOP1M row runs its change detector first and is downloaded only when it changed.
	Detect bool
}

// ExtrasRow is one Extra's outcome. A refused row's Reason, Stage and Detected say why, as Result does for a feed, so the
// verbs can tell a bad key from a full disk: Stage is transfer, size, mime, plaintext, structural, member, extract,
// top1m or publish, and Reason is the code pfb_validate_log() writes wherever today's PHP writes one. No secret reaches
// them.
type ExtrasRow struct {
	Kind, Download string
	Result
}

// ExtrasResult is pfblockerng_download_extras()'s return and the flags it leaves in $pfb.
type ExtrasResult struct {
	OK           bool
	Rows         []ExtrasRow // one per Extra, in order
	MaxMindError bool        // a geoip row failed: it blocks the country conversion
	Top1MChanged bool        // dcc downloaded a changed TOP1M list: the DNSBL update is due
	// Top1MLedger is what the TOP1M download ledger entry (dnsbl/top1m/download) is to become: nil leaves it, "" closes it,
	// and any other text opens it with that message.
	Top1MLedger *string
	// Report is the Blacklist report the bls verb prints: "\t<name> ... Completed" or "... Failed", a line per blacklist row.
	Report string
}

// DownloadExtras downloads every Extra in order, as pfblockerng_download_extras() does.
func (f *Fetcher) DownloadExtras(ctx context.Context, cfg ExtrasConfig, extras []Extra) ExtrasResult {
	if cfg.Timeout <= 0 {
		cfg.Timeout = extrasTimeout
	}
	res := ExtrasResult{OK: true}
	for _, x := range extras {
		req := Request{URL: x.URL, Timeout: cfg.Timeout}
		var r Result
		switch x.Kind {
		case "top1m":
			r = f.top1m(ctx, cfg, x, req, &res)
		case "blacklist":
			req.Username, req.Password = x.Username, x.Password
			r = f.blacklist(ctx, cfg, x, req)
			res.Report += "\t" + x.Name + " ... " + map[bool]string{true: "Completed", false: "Failed"}[r.OK] + "\n"
		default:
			switch x.Kind {
			case "asn":
				req.URL += rawURLEncode(cfg.ASNToken)
			case "geoip":
				req.Username, req.Password = cfg.MaxMindAccount, cfg.MaxMindKey
			}
			r = f.extra(ctx, cfg, x, req)
			if !r.OK && x.Kind == "geoip" && ctx.Err() == nil { // an aborted run is no MaxMind failure
				res.MaxMindError = true
			}
		}
		if !r.OK {
			res.OK = false
		}
		res.Rows = append(res.Rows, ExtrasRow{Kind: x.Kind, Download: x.Download, Result: r})
	}
	return res
}

// refused is a refusal at stage, as pfb_validate_log() records one ("stage=<stage> reason=<reason> detected=<detected>").
func refused(stage, reason, detected string) Result {
	return Result{Reason: reason, Stage: stage, Detected: detected}
}

// accepted is a row that succeeded.
var accepted = Result{OK: true}

// extrasFetch is how every Extra starts: the entry gate, the proxy and the transfer to raw. It returns the source and the
// transfer, or the refusal; a status the row does not accept is the caller's.
func (f *Fetcher) extrasFetch(ctx context.Context, req Request, raw string) (*source, transfer, *Result) {
	src, reason := f.entry(ctx, req)
	if src == nil {
		r := refused("transfer", cmp.Or(reason, "invalid feed URL"), "")
		return nil, transfer{}, &r
	}
	if f.proxyUnusableFor(src) {
		r := refused("transfer", "proxy_unusable", "")
		return nil, transfer{}, &r
	}
	t := f.fetch(ctx, src, req, raw, nil)
	if t.reason != "" {
		stage := "transfer"
		if t.reason == "download_too_large" {
			stage = "size" // pfb_validate_log()'s stage for the transfer ceiling
		}
		r := refused(stage, t.reason, "")
		r.Status = t.status
		return nil, t, &r
	}
	return src, t, nil
}

// transferRefused is a final status the row does not accept.
func transferRefused(status int) Result {
	r := refused("transfer", statusReason(status), "")
	r.Status = status
	return r
}

// accepts tells a final status whose body the row takes: 200, an FTP 226 or a file:// 221.
func accepts(status int) bool { return status == 200 || status == 221 || status == 226 }

// extra is pfb_download() for one Extra: the transfer to "<download>.raw", the content gates, the update marker and the
// publication of its type.
func (f *Fetcher) extra(ctx context.Context, cfg ExtrasConfig, x Extra, req Request) Result {
	if x.Kind != "asn" && x.Kind != "geoip" {
		return refused("transfer", "unknown Extra kind "+x.Kind, "")
	}
	base := filepath.Join(x.Dir, x.Download)
	raw, target := base+".raw", filepath.Join(x.Dir, x.File)
	defer os.Remove(raw)
	src, t, r := f.extrasFetch(ctx, req, raw)
	if r != nil {
		return *r
	}
	if t.status == 304 {
		// Unchanged is a success only while something is in service: PHP also reports it with nothing published.
		_, orig := os.Stat(base + ".orig")
		_, published := os.Stat(target)
		if orig == nil && published == nil {
			return accepted
		}
		return transferRefused(304)
	}
	if !accepts(t.status) {
		return transferRefused(t.status)
	}

	mime, detected, ok := f.extraVerdict(ctx, raw, src.host)
	if !ok {
		return refused("mime", "mime_not_allowed", detected)
	}
	// A type the row cannot publish is refused before the update marker: PHP reports an asn bzip2 or zip a success
	// with only "<download>.orig" written, which nothing reads, and fails a geoip bzip2 after the marker.
	if mime == mimeBzip2 || mime == mimeZip && x.Kind == "asn" {
		return refused("extract", "archive_not_publishable", mime)
	}
	archive := mime == mimeGzip || mime == mimeZip || mime == mimeTar
	if isDatabase(target) {
		// A database row takes a MaxMind DB and nothing else: a text page is not one, and a database is never scanned as
		// text (owner, #4058; PHP renames any text body over it, and its sanity scan refuses the binary asn.mmdb).
		if !archive && !maxMindDB(raw) {
			return refused("structural", "not_a_maxmind_db", filepath.Base(raw))
		}
	} else if f.Sanity && (mime == mimeText || mime == mimeHTML) {
		if why := sane(raw); why != "" {
			return refused("plaintext", why, filepath.Base(raw))
		}
	}
	touch(filepath.Join(cfg.DBDir, x.Kind+".update"))
	if !t.lastMod.IsZero() {
		os.Chtimes(raw, t.lastMod, t.lastMod)
	}
	if archive {
		if f.extractShort(raw, x.Dir, cfg.DBDir, target, filepath.Dir(target)) {
			return refused("size", "staging_space_low", filepath.Base(raw))
		}
		if structural(ctx, mime, raw, io.Discard) != nil {
			return refused("structural", "probe_failed", mime+" "+filepath.Base(raw))
		}
	}
	if x.Kind == "geoip" {
		return f.publishGeoIP(ctx, mime, raw, x.Dir, target)
	}
	return f.publishASN(ctx, cfg, mime, raw, target)
}

// extraVerdict is pfb_filter(FILE_MIME) with its host exception: an octet stream from ipinfo.io (the binary asn.mmdb)
// is taken for text/plain before any structural recovery.
func (f *Fetcher) extraVerdict(ctx context.Context, raw, host string) (mime, detected string, ok bool) {
	if h, err := os.Open(raw); err == nil {
		mime := classify(head(h))
		h.Close()
		if mime == mimeOctet && host == "ipinfo.io" {
			return mimeText, "", true
		}
	}
	return verdict(ctx, raw)
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
func (f *Fetcher) publishASN(ctx context.Context, cfg ExtrasConfig, mime, raw, target string) Result {
	switch mime {
	case mimeGzip, mimeTar:
		staged, err := f.stage(ctx, Feed{Dir: filepath.Dir(target)}, mime, raw, false)
		if err != nil {
			return refused("extract", err.Error(), filepath.Base(raw))
		}
		// A database row takes a MaxMind DB: what an archive holds is checked as a bare body is (owner, #4058).
		if isDatabase(target) && !maxMindDB(staged) {
			os.Remove(staged)
			return refused("structural", "not_a_maxmind_db", filepath.Base(raw))
		}
		if err := os.Rename(staged, target); err != nil {
			os.Remove(staged)
			return refused("publish", err.Error(), "")
		}
		if mime == mimeGzip && cfg.ASNTable != nil {
			cfg.ASNTable(ctx)
		}
		return accepted
	}
	if err := os.Rename(raw, target); err != nil {
		return refused("publish", err.Error(), "")
	}
	return accepted
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
