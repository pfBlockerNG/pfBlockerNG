// Package feedfetch transfers feed sources and decides whether they changed: the Core translation of pfb_download()'s
// transfer stage and post-transfer content gates and of pfb_update_check()'s change detection (map #3813, #3905, #3973),
// held to the parity corpus in tests/feedfetch/fixtures/parity. Every refusal keeps the published copy
// (last-known-good).
//
// After the transfer an ordinary feed passes the content gates (content.go, archive.go): the MIME verdict and its
// allow-list, the opt-in sanity scan of a text body (ADR-49, sanity.go), then for a gzip, bzip2, zip or tar the
// structural test, the inner verdict, the extraction (every member, under a 2 GiB per-file ceiling, through the standard
// library alone) and the sanity scan of what it extracted; a zip whose last member is a workbook publishes the addresses
// of its shared strings instead (xlsx, iqrisk.go). The published copy is UTF-16/32 text transcoded to UTF-8, and
// newline-terminated; an ET IQRisk feed publishes its Block categories' addresses. Not yet here: Extras.
//
// A feed's files live in Feed.Dir under Feed.Name: the published copy "<name>.orig", its validators ".orig.etag" and
// ".orig.lastmod", the xxh128 of the raw bytes it was published from ".orig.xxhash128", a changed probe's body ".probe"
// (the next ingest publishes it instead of fetching again), and the staged body ".raw": consumed by a text feed's
// publication, kept by an archive's (its digest is of those bytes, and ET reuses it), gone after any refusal.
//
// A whois or asn feed has no body to fetch: Whois resolves its Domain/AS list (the translation of whoisconvert(), #3974)
// into the published copy "<name>.orig", and leaves "<name>.fail" when an entry failed or the batch ran out of time.
package feedfetch

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// DefaultMaxBytes is the transfer ceiling when a request names none (PFB_DOWNLOAD_MAX_BYTES).
const DefaultMaxBytes = 2 << 30

const (
	defaultTimeout = 300 * time.Second
	connectTimeout = 15 * time.Second
	maxRedirects   = 10
	attempts       = 3
	killGrace      = 5 * time.Second
	retryDelay     = 5 * time.Second // pfb_download()'s pause between attempts
)

// Policy decides which hosts a feed may be fetched from.
type Policy struct {
	NoFilter  bool                                                         // turns the feed-host internal-address filter off (on by default, as in PHP)
	Allow     []netip.Prefix                                               // internal-address exemptions (an IP is a full-length prefix)
	Self      []netip.Addr                                                 // the host's own addresses; 127.0.0.1 and ::1 always are
	LocalDirs []string                                                     // a file:// source must sit directly in one of these
	Resolve   func(ctx context.Context, host string) ([]netip.Addr, error) // vetting resolver; nil is the system resolver
}

// Fetcher holds what is shared by every feed of a run.
type Fetcher struct {
	Policy
	Proxy      *url.URL       // forward proxy, credentials in its userinfo
	UserAgent  string         // empty: Go's default
	RootCAs    *x509.CertPool // nil: the system roots
	RsyncBin   string         // the rsync executable
	RetryDelay time.Duration  // pause between attempts; zero is pfb_download()'s 5 s
	// FreeBytes is the space the process may still write in dir; ok is false when it cannot tell, which is no shortfall
	// (pfb_extract_space_shortfall). Nil reads the file system.
	FreeBytes func(dir string) (free uint64, ok bool)
	Sanity    bool // ADR-49's opt-in plain-text sanity scan (gen/pfb_feed_sanity); off by default, as in PHP
	// ET IQRisk, a feed whose URL holds "iprepdata.txt" (processet): its category split goes to ETDir, the addresses of
	// the ETMatch categories to ETMatchFile, and those of the ETBlock categories are published. Empty selects none.
	ETDir, ETMatchFile string
	ETBlock, ETMatch   []string

	// Whois only.
	Lookup    func(ctx context.Context, network, host string) ([]netip.Addr, error) // one family's addresses ("ip4" or "ip6"); nil is the system resolver
	Now       func() time.Time                                                      // the batch clock; nil is time.Now
	ASNCSV    string                                                                // the IPinfo asn.csv the AS entries are read from
	EnsureASN func(ctx context.Context)                                             // the first-use asn.csv download; nil leaves a missing file missing

	extractMax int64 // test seam: the per-file ceiling of an extraction; zero is maxExtract
}

// Request is one feed's source as the Outpost translated it.
type Request struct {
	URL                string        // http(s):// or ftp://, a self-hosted http URL, file://, or for Rsync rsync:// or host::module
	Rsync              bool          // the feed's format is rsync
	Username, Password string        // Basic credentials, sent to the feed's origin only
	Headers            []string      // extra "Name: value" headers; an Authorization header is scoped like credentials
	Timeout            time.Duration // whole transfer per attempt; zero is 300 s
	MaxBytes           int64         // transfer ceiling; zero is DefaultMaxBytes
	Flex               bool          // after a first TLS failure, retry without verification
	BindAddr           netip.Addr    // source address (the Outpost's source interface)
}

// Feed names where a feed's files live.
type Feed struct{ Dir, Name string }

func (f Feed) path(suffix string) string { return filepath.Join(f.Dir, f.Name+suffix) }

// valid holds the name to a word, as pfb_update_check() holds the feed header (PFB_FILTER_WORD).
func (f Feed) valid() bool { return f.Name != "" && allIn(f.Name, wordChars) }

// Decision is a probe's verdict; the zero Decision is Failed, so an unset verdict fails closed.
type Decision int

const (
	Failed Decision = iota
	Unchanged
	Changed
)

func (d Decision) String() string {
	return [...]string{"failed", "unchanged", "changed"}[d]
}

// Result is the outcome of Ingest or Probe. Reason names a refusal in pfb_download()'s words (a validation reason code
// such as "download_too_large", the skip text such as "too many redirects", or the refused status); a failure always
// carries one. Stage and Detected carry the rest of a validation refusal as pfb_validate_log() writes it ("stage=<stage> reason=<reason>
// detected=<detail>"): empty for a refusal that is no validation line.
type Result struct {
	OK       bool
	Decision Decision // Probe only
	Status   int      // the final HTTP status, when there was one
	Reason   string
	Stage    string
	Detected string
}

func fail(reason string) Result { return Result{Reason: reason} }

// statusReason is pfb_download()'s log text for a final status it does not accept: its status table's "<code> <text>",
// else "Unknown Failure Code [<code>]".
func statusReason(code int) string {
	if text := http.StatusText(code); text != "" {
		return fmt.Sprintf("%d %s", code, text)
	}
	return fmt.Sprintf("Unknown Failure Code [%d]", code)
}

func (r Request) maxBytes() int64 {
	if r.MaxBytes > 0 {
		return r.MaxBytes
	}
	return DefaultMaxBytes
}

func (f *Fetcher) retryDelay() time.Duration {
	if f.RetryDelay > 0 {
		return f.RetryDelay
	}
	return retryDelay
}

func (r Request) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultTimeout
}

// transfer is what a fetch learned besides the body.
type transfer struct {
	status  int
	etag    string
	lastMod time.Time
	reason  string
}

// Ingest fetches the feed and publishes it. A failure keeps the published copy and drops the stored validators, so a
// refused body cannot hide behind a 304 on the next probe (#2820).
func (f *Fetcher) Ingest(ctx context.Context, feed Feed, req Request) Result {
	res := f.ingest(ctx, feed, req)
	if !res.OK {
		os.Remove(feed.path(".orig.etag"))
		os.Remove(feed.path(".orig.lastmod"))
	}
	return res
}

func (f *Fetcher) ingest(ctx context.Context, feed Feed, req Request) Result {
	if !feed.valid() {
		return fail("invalid feed name")
	}
	src, reason := f.entry(ctx, req)
	if src == nil {
		return fail(reason)
	}
	staged, probe, published := feed.path(".raw"), feed.path(".probe"), feed.path(".orig")
	keepRaw := false // an archive's success leaves the staged archive: the digest is of it, and ET reuses it (A35)
	defer func() {
		if !keepRaw {
			os.Remove(staged)
		}
	}()
	defer os.Remove(probe)

	var t transfer
	fromProbe := false
	if _, err := os.Stat(probe); err == nil && src.kind != kindRsync {
		fromProbe = true
		// The probe already fetched this body.
		if err := os.Rename(probe, staged); err != nil {
			return fail("probe body could not be staged")
		}
		t.status = 200
	} else {
		t = f.fetch(ctx, src, req, staged, nil)
	}
	if t.reason != "" {
		return Result{Status: t.status, Reason: t.reason}
	}
	if t.status == 304 {
		if _, err := os.Stat(published); err == nil {
			return Result{OK: true, Status: 304}
		}
		return Result{Status: 304, Reason: statusReason(304)}
	}
	if t.status != 200 && t.status != 221 && t.status != 226 {
		return Result{Status: t.status, Reason: statusReason(t.status)}
	}
	body, refusal := f.gate(ctx, feed, staged, t.lastMod)
	if refusal != nil {
		refusal.Status = t.status
		return *refusal
	}
	if body != staged {
		defer os.Remove(body) // an extraction whose publication failed
	}
	// The digest is of the wire bytes (#713): body itself for a text feed, before it is finished; the archive otherwise.
	digest, err := fileDigest(staged)
	if err != nil {
		return Result{Status: t.status, Reason: "staged body could not be read"}
	}
	if err := finish(body); err != nil {
		return Result{Status: t.status, Reason: err.Error()}
	}
	archive := body != staged
	if strings.Contains(req.URL, "iprepdata.txt") {
		// ET IQRisk is split after the finish, as pfb_download() runs processet() on the finished copy. Its failure
		// keeps last-known-good: the published copy is replaced only by the split's outcome.
		et, err := f.iqrisk(ctx, feed, body)
		if err != nil {
			if ctxEnded(err) {
				return Result{Status: t.status, Reason: err.Error()}
			}
			return Result{Status: t.status, Reason: "et processing failed (script exit 1)"}
		}
		defer os.Remove(et)
		body = et
	}
	if err := publish(feed, body, digest, t.lastMod); err != nil {
		return Result{Status: t.status, Reason: err.Error()}
	}
	keepRaw = archive
	if fromProbe {
		// The probe's validators describe the body just published (#3911).
		for _, v := range [...]string{".etag", ".lastmod"} {
			os.Remove(published + v)
			os.Rename(probe+v, published+v)
		}
	}
	return Result{OK: true, Status: t.status}
}

// Probe decides whether the feed changed since it was published (ADR-42): a conditional GET for a remote feed, the
// content hash for a local file; a self-hosted URL and an rsync feed are always due. A changed remote body is kept for
// the next Ingest.
func (f *Fetcher) Probe(ctx context.Context, feed Feed, req Request) Result {
	if !feed.valid() {
		return Result{Decision: Failed, Reason: "invalid feed name"}
	}
	src, reason := f.entry(ctx, req)
	if src == nil {
		return Result{Decision: Failed, Reason: reason}
	}
	published := feed.path(".orig")
	if _, err := os.Stat(published); err != nil {
		return Result{OK: true, Decision: Changed}
	}
	switch src.kind {
	case kindRsync, kindSelfHosted:
		return Result{OK: true, Decision: Changed}
	case kindLocal:
		return Result{OK: true, Decision: localDecision(src.path, feed)}
	}

	// The body becomes ".probe", which the next Ingest publishes, only once the probe decided: a probe killed
	// mid-body leaves only ".probe.part", which nothing reads.
	part, probe := feed.path(".probe.part"), feed.path(".probe")
	defer os.Remove(part)
	t := f.fetch(ctx, src, req, part, readValidators(feed))
	res := Result{Status: t.status, Reason: t.reason}
	switch {
	case t.reason == "" && t.status == 304:
		writeValidators(feed, t.etag, t.lastMod)
		res.OK, res.Decision = true, Unchanged
	case t.reason == "" && t.status == 200:
		sum, err := digest.File(part)
		algo, baseline := digest.Read(feed.path(".orig"))
		res.OK, res.Decision = true, Changed
		// An md5 baseline cannot confirm unchanged (pfb_update_check): it re-ingests once and the ingest replaces it.
		if err == nil && algo == digest.XXH128 && sum == baseline {
			res.Decision = Unchanged
			writeValidators(feed, t.etag, t.lastMod)
		}
	default:
		res.Decision = Failed
		if res.Reason == "" {
			res.Reason = statusReason(t.status)
		}
	}
	switch res.Decision {
	case Unchanged:
		// An earlier changed probe's body is stale now (PHP unlinks {header}.md5.raw here).
		for _, s := range [...]string{"", ".etag", ".lastmod"} {
			os.Remove(probe + s)
		}
	case Changed:
		os.Remove(probe + ".etag")
		os.Remove(probe + ".lastmod")
		if os.Rename(part, probe) != nil {
			return Result{Status: t.status, Decision: Failed, Reason: "probe body could not be kept"}
		}
		// They describe the probe body, not the published copy: kept beside it until the ingest publishes it (#3911).
		writeValidatorsAt(probe, t.etag, t.lastMod)
	}
	return res
}

// fetch transfers the source's body to dst; cond carries the probe's conditional-GET validators.
func (f *Fetcher) fetch(ctx context.Context, src *source, req Request, dst string, cond *validators) transfer {
	switch src.kind {
	case kindRsync:
		return f.fetchRsync(ctx, src, req, dst)
	case kindLocal:
		return fetchFile(src, req, dst)
	case kindSelfHosted:
		return fetchSelfHosted(ctx, src, req, dst)
	}
	if src.ftp != nil && f.Proxy == nil {
		return f.fetchFTP(ctx, src, req, dst) // no conditional GET exists for ftp: the probe's cond is not sent
	}
	// Through a proxy an ftp feed is an HTTP request to it (ftpViaProxy), as cURL makes it.
	return f.fetchHTTP(ctx, src, req, dst, cond)
}
