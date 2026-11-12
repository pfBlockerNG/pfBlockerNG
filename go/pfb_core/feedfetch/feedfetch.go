// Package feedfetch transfers feed sources and decides whether they changed: the Core translation of pfb_download()'s
// transfer stage and pfb_update_check()'s change detection (map #3813, #3905), held to the parity corpus in
// tests/feedfetch/fixtures/parity. Every refusal keeps the published copy (last-known-good).
//
// A feed's files live in Feed.Dir under Feed.Name: the published copy "<name>.orig", its validators ".orig.etag" and
// ".orig.lastmod", the SHA-256 of the raw bytes it was published from ".orig.sha256", a changed probe's body ".probe"
// (the next ingest publishes it instead of fetching again), and the staged body ".raw", which never outlives a call.
package feedfetch

import (
	"context"
	"crypto/x509"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// DefaultMaxBytes is the transfer ceiling when a request names none (PFB_DOWNLOAD_MAX_BYTES).
const DefaultMaxBytes = 2 << 30

const (
	defaultTimeout = 300 * time.Second
	connectTimeout = 15 * time.Second
	maxRedirects   = 10
	attempts       = 3
	killGrace      = 5 * time.Second
)

// Policy decides which hosts a feed may be fetched from.
type Policy struct {
	Filter    bool                                                         // the feed-host internal-address filter
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
	RetryDelay time.Duration  // pause between attempts (5 s in pfb_download)
}

// Request is one feed's source as the Outpost translated it.
type Request struct {
	URL                string        // http(s)://, a self-hosted http URL, file://, or for Rsync rsync:// or host::module
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

// Decision is a probe's verdict.
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
// such as "download_too_large", or the skip text such as "too many redirects"); it may be empty on failure.
type Result struct {
	OK       bool
	Decision Decision // Probe only
	Status   int      // the final HTTP status, when there was one
	Reason   string
}

func fail(reason string) Result { return Result{Reason: reason} }

func (r Request) maxBytes() int64 {
	if r.MaxBytes > 0 {
		return r.MaxBytes
	}
	return DefaultMaxBytes
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
	defer os.Remove(staged)
	defer os.Remove(probe)

	var t transfer
	if _, err := os.Stat(probe); err == nil && src.kind != kindRsync {
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
		return Result{Status: 304}
	}
	if t.status != 200 && t.status != 221 && t.status != 226 {
		return Result{Status: t.status}
	}
	if err := publish(feed, staged, t.lastMod); err != nil {
		return Result{Status: t.status, Reason: err.Error()}
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
	part := feed.path(".probe.part")
	defer os.Remove(part)
	t := f.fetch(ctx, src, req, part, readValidators(feed))
	res := Result{Status: t.status, Reason: t.reason}
	switch {
	case t.reason == "" && t.status == 304:
		writeValidators(feed, t.etag, t.lastMod)
		res.OK, res.Decision = true, Unchanged
	case t.reason == "" && t.status == 200:
		digest, err := fileDigest(part)
		baseline, _ := os.ReadFile(feed.path(".orig.sha256"))
		writeValidators(feed, t.etag, t.lastMod)
		res.OK, res.Decision = true, Changed
		if err == nil && len(baseline) > 0 && digest == string(baseline) {
			res.Decision = Unchanged
		}
	default:
		res.Decision = Failed
	}
	if res.Decision == Changed && os.Rename(part, feed.path(".probe")) != nil {
		return Result{Status: t.status, Decision: Failed, Reason: "probe body could not be kept"}
	}
	return res
}

// fetch transfers the source's body to dst; cond carries the probe's conditional-GET validators.
func (f *Fetcher) fetch(ctx context.Context, src *source, req Request, dst string, cond *validators) transfer {
	switch src.kind {
	case kindRsync:
		return f.fetchRsync(ctx, src, req, dst)
	case kindLocal:
		return fetchFile(src.path, req, dst)
	case kindSelfHosted:
		return fetchSelfHosted(ctx, src.url, req, dst)
	}
	return f.fetchHTTP(ctx, src, req, dst, cond)
}
