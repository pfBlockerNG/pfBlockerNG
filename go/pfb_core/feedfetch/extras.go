package feedfetch

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
// verbs can tell a bad key from a full disk. Unlike a feed's, every refusal has a Stage: pfb_validate_log()'s fetch, size,
// mime, plaintext, structural, member or extract, or top1m, publish, aborted (the run's context ended) or unsupported;
// Reason is the code pfb_validate_log() writes wherever today's PHP writes one. No URL query and no secret reaches them,
// except a secret under six bytes as plain text: such a secret collides with reason text too often to be told from it. A
// row refused for its own reason just as the run's context ends reads aborted: the run ended. Status is set on a transfer
// refusal only.
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
			outcome := "Completed"
			if !r.OK {
				outcome = "Failed"
			}
			res.Report += "\t" + x.Name + " ... " + outcome + "\n"
		default:
			switch x.Kind {
			case "asn":
				req.URL += rawURLEncode(cfg.ASNToken)
			case "geoip":
				req.Username, req.Password = cfg.MaxMindAccount, cfg.MaxMindKey
			}
			r = f.extra(ctx, cfg, x, req)
		}
		if !r.OK {
			res.OK = false
			if err := ctx.Err(); err != nil {
				r = refused("aborted", err.Error(), "") // the run ended, not the feed or its key
			} else if x.Kind == "geoip" {
				res.MaxMindError = true
			}
			r.Reason, r.Detected = cfg.redact(r.Reason, x), cfg.redact(r.Detected, x)
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

// urlQuery is a URL's query string in a reason, to its closing double quote (Go's client quotes the URL it failed on,
// escaping a quote inside it) or to white space; an apostrophe, in the path or the query, is part of the URL.
var urlQuery = regexp.MustCompile(`(?i)((?:https?|ftp)://(?:\\.|[^\s"?\\])*)\?(?:\\.|[^\s"\\])*`)

// urlUserinfo is a URL's user and password, as a Blacklist row's ftp://user:pass@host carries them, through the last "@"
// before the host, as net/url splits them.
var urlUserinfo = regexp.MustCompile(`(?i)((?:https?|ftp)://)(?:\\.|[^\s"/?#\\])*@`)

// redact is what a refused row may carry: every URL query, as pfb_redact_url() hides it, and every secret of the run and
// row, raw, as it travels in a URL or in the Basic authorization it makes, gone, the longest form first. A secret under
// six bytes stays as plain text, where it would collide with reason text too often; its Basic authorization, eight bytes
// or more, still goes.
func (cfg ExtrasConfig) redact(s string, x Extra) string {
	if _, query, ok := strings.Cut(x.URL, "?"); ok && query != "" {
		s = strings.ReplaceAll(s, "?"+query, "?[redacted]") // whole, though a space would end urlQuery's match
	}
	s = urlQuery.ReplaceAllString(s, "$1?[redacted]")
	s = urlUserinfo.ReplaceAllString(s, "$1[redacted]@")
	var forms []string
	add := func(user, secret string) {
		if secret == "" {
			return
		}
		if len(secret) >= 6 {
			forms = append(forms, secret, rawURLEncode(secret), url.QueryEscape(secret), url.PathEscape(secret))
		}
		// A password alone is still sent, as Basic ":<password>".
		if auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + secret)); len(auth) >= 8 {
			forms = append(forms, auth)
		}
	}
	add(cfg.MaxMindAccount, cfg.MaxMindKey)
	add("", cfg.ASNToken)
	add("", cfg.Top1MToken)
	add(x.Username, x.Password)
	slices.SortFunc(forms, func(a, b string) int { return len(b) - len(a) })
	for _, form := range forms {
		s = strings.ReplaceAll(s, form, "[redacted]")
	}
	return s
}

// extrasEntry is the entry gate and the proxy every Extra passes before it is fetched: the source, or why it is refused.
func (f *Fetcher) extrasEntry(ctx context.Context, req Request) (*source, string) {
	src, reason := f.entry(ctx, req)
	if src == nil {
		return nil, cmp.Or(reason, "invalid feed URL")
	}
	if f.proxyUnusableFor(src) {
		return nil, "proxy_unusable"
	}
	return src, ""
}

// extrasFetch is how every Extra starts: the entry gate, the proxy and the transfer to raw. It returns the source and the
// transfer, or the refusal; a status the row does not accept is the caller's.
func (f *Fetcher) extrasFetch(ctx context.Context, req Request, raw string) (*source, transfer, *Result) {
	src, reason := f.extrasEntry(ctx, req)
	if src == nil {
		r := refused("fetch", reason, "")
		return nil, transfer{}, &r
	}
	t := f.fetch(ctx, src, req, raw, nil)
	if t.reason != "" {
		r := transferFailed(t)
		return nil, t, &r
	}
	return src, t, nil
}

// transferFailed is a transfer that ended with a reason: the transfer ceiling is pfb_validate_log()'s size stage, any
// other reason its fetch stage.
func transferFailed(t transfer) Result {
	stage := "fetch"
	if t.reason == "download_too_large" {
		stage = "size"
	}
	r := refused(stage, t.reason, "")
	r.Status = t.status
	return r
}

// transferRefused is a final status the row does not accept.
func transferRefused(status int) Result {
	r := refused("fetch", statusReason(status), "")
	r.Status = status
	return r
}

// extrasExtraction is pfb_download()'s text for each Extra's extraction: its name and the tool that runs it.
var extrasExtraction = map[string]string{
	"asn":        "asn extraction failed (gunzip exit %d)",
	"top1m gzip": "top1m extraction failed (gunzip exit %d)",
	"top1m tar":  "top1m extraction failed (tar exit %d)",
	"top1m zip":  "top1m zip extraction failed (tar exit %d)",
	"geoip":      "geoip extraction failed (tar exit %d)",
	"geoip zip":  "geoip zip extraction failed (tar exit %d)",
	"blacklist":  "blacklist extraction failed (tar exit %d)",
}

// extractRefused is the refusal for an extraction err ended, found in detail: a database the row cannot take, a member
// that leaves its folder, a TOP1M archive that is not one list, else pfb_download()'s text for what was extracted (an
// Extra's name in extrasExtraction, or a MIME type). A Blacklist archive with no category reads as PHP's: tar exit 0.
func extractRefused(what string, err error, detail string) Result {
	switch {
	case errors.Is(err, errNotADatabase):
		return refused("structural", "not_a_maxmind_db", detail)
	case errors.Is(err, errNoDatabase):
		return refused("structural", "no_database", detail)
	case errors.Is(err, errUnsafeMember):
		return refused("member", "unsafe_member_name", detail)
	case errors.Is(err, errTop1MArchive):
		return refused("extract", err.Error(), detail)
	}
	return refused("extract", extractionFailure(what, err), detail)
}

// publishRefused is a publication that did not complete; the error's paths stay out of the reason.
var publishRefused = refused("publish", "publication_failed", "")

// accepts tells a final status whose body the row takes: 200, an FTP 226 or a file:// 221.
func accepts(status int) bool { return status == 200 || status == 221 || status == 226 }

// extra is pfb_download() for one Extra: the transfer to "<download>.raw", the content gates, the update marker and the
// publication of its type.
func (f *Fetcher) extra(ctx context.Context, cfg ExtrasConfig, x Extra, req Request) Result {
	if x.Kind != "asn" && x.Kind != "geoip" {
		return refused("unsupported", "unknown Extra kind "+x.Kind, "")
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
		served := classify(head(h))
		h.Close()
		if served == mimeOctet && host == "ipinfo.io" {
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
			what := mime
			if mime == mimeGzip {
				what = "asn"
			}
			return extractRefused(what, err, filepath.Base(raw))
		}
		// A database row takes a MaxMind DB: what an archive holds is checked as a bare body is (owner, #4058).
		if isDatabase(target) && !maxMindDB(staged) {
			os.Remove(staged)
			return refused("structural", "not_a_maxmind_db", filepath.Base(raw))
		}
		if os.Rename(staged, target) != nil {
			os.Remove(staged)
			return publishRefused
		}
		if mime == mimeGzip && cfg.ASNTable != nil {
			cfg.ASNTable(ctx)
		}
		return accepted
	}
	if os.Rename(raw, target) != nil {
		return publishRefused
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
