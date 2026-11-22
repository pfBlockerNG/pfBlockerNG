package feedfetch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// top1mProvider is a row of pfb_top1m_providers() as far as a download needs it: how a row of the list is read, whether
// the provider takes the Bearer token, and the list's URL.
type top1mProvider struct {
	rankDomain         bool // the first column is a numeric rank (parse "rank_domain")
	header             bool // the first line is a header
	domainCol, columns int
	bearer             bool // Cloudflare Radar: "Authorization: Bearer <token>"
	url                string
}

var top1mProviders = map[string]top1mProvider{
	"tranco":       {rankDomain: true, domainCol: 1, columns: 2, url: "https://tranco-list.eu/top-1m.csv.zip"},
	"cisco":        {rankDomain: true, domainCol: 1, columns: 2, url: "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"},
	"openpagerank": {header: true, domainCol: 1, columns: 5, url: "https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip"},
	"majestic":     {header: true, domainCol: 2, columns: 12, url: "https://downloads.majestic.com/majestic_million.csv"},
	"cloudflare":   {header: true, domainCol: 0, columns: 1, bearer: true, url: "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000"},
}

// top1mProviderOf is pfb_top1m_active_provider(): an unknown provider is Tranco.
func top1mProviderOf(name string) top1mProvider {
	if p, ok := top1mProviders[name]; ok {
		return p
	}
	return top1mProviders["tranco"]
}

// top1mAuthHeaders is pfb_top1m_auth_headers(): the Bearer header of a provider that takes one, CR and LF stripped from
// the token; none without a token.
func top1mAuthHeaders(p top1mProvider, token string) []string {
	if !p.bearer || token == "" {
		return nil
	}
	return []string{"Authorization: Bearer " + strings.NewReplacer("\r", "", "\n", "").Replace(token)}
}

// top1mIdentity is pfb_top1m_source_identity(): the provider, the URL and each header's SHA-256, as PHP's json_encode()
// writes them with JSON_UNESCAPED_SLASHES for the ASCII values the provider table holds (PHP would escape non-ASCII as
// \uXXXX). A changed identity drops the detector's baseline.
func top1mIdentity(provider, url string, headers []string) string {
	hashes := []string{}
	for _, h := range headers {
		sum := sha256.Sum256([]byte(h))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(struct {
		Provider string   `json:"provider"`
		URL      string   `json:"url"`
		Headers  []string `json:"headers"`
	}{provider, url, hashes}) != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

var top1mDomain = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.(?:[A-Za-z]{2,}|[Xx][Nn]--[A-Za-z0-9][A-Za-z0-9-]+)$`)

// top1mRow is pfb_top1m_parse_source_row(): the lowercased domain of one line of the list, or false. A row is read as
// CSV by encoding/csv, not with str_getcsv()'s quirks (owner, 2026-11-19): Unicode white space before a field is
// skipped, quoted or not. Text after a closing quote stays in the field with its quote (LazyQuotes), where PHP drops the
// quote, and a line break an unterminated quote takes in stays too: top1mDomain, which has no quote and no (?m), refuses
// both.
func top1mRow(line string, p top1mProvider) (string, bool) {
	if line == "" || !strings.Contains(line, ".") || p.domainCol > 0 && !strings.Contains(line, ",") {
		return "", false
	}
	var fields []string
	if strings.Contains(line, `"`) {
		// The line keeps its ending here, as str_getcsv() gets it: an unterminated quote takes the line break into the field.
		r := csv.NewReader(strings.NewReader(line))
		r.FieldsPerRecord, r.LazyQuotes, r.TrimLeadingSpace = -1, true, true
		var err error
		if fields, err = r.Read(); err != nil {
			return "", false
		}
	} else { // an unquoted row is its commas; a csv.Reader per row made a full list 4x slower than PHP
		fields = strings.Split(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), ",")
		for i, f := range fields {
			if f != "" && (f[0] <= ' ' || f[0] >= utf8.RuneSelf) { // most fields start with neither
				fields[i] = strings.TrimLeftFunc(f, unicode.IsSpace)
			}
		}
	}
	if len(fields) != p.columns {
		return "", false
	}
	if p.rankDomain && !allIn(fields[0], "0123456789") || p.rankDomain && fields[0] == "" {
		return "", false
	}
	domain := strings.ToLower(fields[p.domainCol])
	if !top1mDomain.MatchString(domain) {
		return "", false
	}
	return domain, true
}

// top1mCandidate is pfb_top1m_candidate_valid(): a readable file that passes the text sanity scan and holds at least one
// row of the provider's shape after its header.
func top1mCandidate(path string, p top1mProvider) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || sane(path) != "" {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	rd := bufio.NewReader(file)
	header := p.header
	for {
		line, err := rd.ReadString('\n')
		if line != "" {
			if header {
				header = false
			} else if _, ok := top1mRow(line, p); ok {
				return true
			}
		}
		if err != nil {
			return false
		}
	}
}

// Top1MLedger messages: what the TOP1M download ledger entry opens with.
const (
	top1mProbeFailed    = "TOP1M probe failed"
	top1mDownloadFailed = "TOP1M download failed"
)

// top1m is the TOP1M row of pfblockerng_download_extras() and pfb_download(): under dcc the change detector first (the
// conditional GET against the stored validators, the source identity and the xxh128 baseline), then the download, whose
// list is published over File with the downloaded body as the new baseline. A failure keeps the published list and the
// baseline as they were.
func (f *Fetcher) top1m(ctx context.Context, cfg ExtrasConfig, x Extra, req Request, res *ExtrasResult) Result {
	p := top1mProviderOf(x.Provider)
	req.Headers = top1mAuthHeaders(p, cfg.Top1MToken)
	base := filepath.Join(x.Dir, x.Download)
	identity := top1mIdentity(x.Provider, x.URL, req.Headers)
	ledger := func(msg string) { res.Top1MLedger = &msg }
	probeBody := base + ".md5.raw"
	// Only this run's probe body is reused: one an earlier run left behind (a crash) is dropped first. PHP publishes the
	// leftover without a request (owner, 2026-11-18).
	os.Remove(probeBody)
	defer os.Remove(probeBody)

	var probe transfer
	if cfg.Detect {
		stored, err := os.ReadFile(base + ".source")
		matches := err == nil && string(stored) == identity
		if !matches {
			top1mDropBaseline(base)
		}
		probe = f.top1mProbe(ctx, req, x, probeBody)
		switch top1mDecision(probe, probeBody, base, x, matches) {
		case Failed:
			ledger(top1mProbeFailed)
			if probe.reason != "" {
				return transferFailed(probe)
			}
			return transferRefused(probe.status)
		case Unchanged:
			writeValidatorsAt(base+".orig", probe.etag, probe.lastMod)
			os.WriteFile(base+".source", []byte(identity), 0o644)
			ledger("")
			return accepted
		}
		if probe.status == 304 {
			// A 304 that reads changed (the baseline is not trusted) has no body to reuse: the list is downloaded in full.
			// PHP reuses the empty probe body and fails for as long as the server answers 304 (owner, 2026-11-18).
			os.Remove(probeBody)
		}
	}
	r, fetched := f.top1mDownload(ctx, cfg, x, req, p, base, probeBody)
	if !r.OK {
		ledger(top1mDownloadFailed)
		return r
	}
	os.WriteFile(base+".source", []byte(identity), 0o644)
	if !cfg.Detect {
		// No probe validated this list: validators of an older version would let a server that reverts to it answer 304
		// for a list Core no longer holds. PHP keeps them (owner, 2026-11-18).
		os.Remove(base + ".orig.etag")
		os.Remove(base + ".orig.lastmod")
		return accepted
	}
	if fetched != nil {
		probe = *fetched // the list came from its own download (after an untrusted 304): its validators describe it
	}
	// Only the published body's own validators stay: one its response did not carry would be the old version's.
	os.Remove(base + ".orig.etag")
	os.Remove(base + ".orig.lastmod")
	writeValidatorsAt(base+".orig", probe.etag, probe.lastMod)
	res.Top1MChanged = true
	ledger("")
	return accepted
}

// top1mProbe is pfb_download()'s change_detect mode: a conditional GET with the validators stored beside the baseline,
// its body kept at probeBody for the download to reuse.
func (f *Fetcher) top1mProbe(ctx context.Context, req Request, x Extra, probeBody string) transfer {
	src, reason := f.extrasEntry(ctx, req)
	if src == nil {
		return transfer{reason: reason}
	}
	return f.fetch(ctx, src, req, probeBody, readValidators(Feed{Dir: x.Dir, Name: x.Download}))
}

// top1mDecision is pfb_top1m_detector_decision(): a baseline that is not this source's, not a regular file, or no longer
// matches its xxh128 makes any answered probe changed, as does a 304 with no validator stored; otherwise a 304 is
// unchanged and a 200 is unchanged only when its body hashes to the baseline. A published list that is gone reads changed
// too, so the list is published again; PHP trusts the baseline alone (owner, 2026-11-18).
func top1mDecision(probe transfer, probeBody, base string, x Extra, identityMatches bool) Decision {
	answered := probe.reason == "" && (probe.status == 200 || probe.status == 304)
	changed := Failed
	if answered {
		changed = Changed
	}
	if info, err := os.Stat(filepath.Join(x.Dir, x.File)); err != nil || !info.Mode().IsRegular() {
		return changed
	}
	orig := base + ".orig"
	if info, err := os.Stat(orig); !identityMatches || err != nil || !info.Mode().IsRegular() {
		return changed
	}
	algo, baseline := digest.Read(base)
	if algo != digest.XXH128 {
		return changed
	}
	if live, err := digest.File(orig); err != nil || live != baseline {
		return changed
	}
	if probe.status == 304 && readValidators(Feed{Dir: x.Dir, Name: x.Download}) == nil {
		return changed
	}
	switch {
	case !answered:
		return Failed
	case probe.status == 304:
		return Unchanged
	}
	if body, err := digest.File(probeBody); err != nil || body != baseline {
		return Changed
	}
	return Unchanged
}

// top1mDropBaseline is pfb_top1m_invalidate_baseline(): the baseline, its digests, the identity and the validators.
func top1mDropBaseline(base string) {
	for _, suffix := range []string{".orig", ".xxhash128", ".md5", ".source", ".orig.etag", ".orig.lastmod"} {
		os.Remove(base + suffix)
	}
}

// top1mDownload is pfb_download() for the TOP1M row: the body (the probe's, when dcc kept one) through the content gates,
// then the list it holds staged, checked as the provider's and published with the body as its baseline. It returns the
// transfer it made, nil when it reused the probe's body.
func (f *Fetcher) top1mDownload(ctx context.Context, cfg ExtrasConfig, x Extra, req Request, p top1mProvider, base, probeBody string) (Result, *transfer) {
	raw, target := base+".raw", filepath.Join(x.Dir, x.File)
	defer os.Remove(raw)
	status := 200
	var fetched *transfer
	if _, err := os.Stat(probeBody); err == nil {
		// The probe already downloaded the body: it is used instead of downloading twice.
		if os.Rename(probeBody, raw) != nil {
			return refused("fetch", "probe body could not be staged", ""), nil
		}
	} else {
		_, t, r := f.extrasFetch(ctx, req, raw)
		if r != nil {
			return *r, nil
		}
		status, fetched = t.status, &t
	}
	if status == 304 {
		// A 304 confirms what is published: the list and its baseline both have to be there.
		_, orig := os.Stat(base + ".orig")
		if info, err := os.Stat(target); orig == nil && err == nil && info.Mode().IsRegular() {
			return accepted, fetched
		}
		return transferRefused(304), fetched
	}
	if !accepts(status) {
		return transferRefused(status), nil
	}
	mime, detected, ok := verdict(ctx, raw)
	if !ok {
		return refused("mime", "mime_not_allowed", detected), nil
	}
	archive := mime == mimeGzip || mime == mimeBzip2 || mime == mimeZip || mime == mimeTar
	if !archive && f.Sanity && (mime == mimeText || mime == mimeHTML) {
		if why := sane(raw); why != "" {
			return refused("plaintext", why, filepath.Base(raw)), nil
		}
	}
	if archive && f.extractShort(raw, x.Dir, cfg.DBDir, target, filepath.Dir(target)) {
		return refused("size", "staging_space_low", filepath.Base(raw)), nil
	}
	stage, list, err := f.top1mStage(ctx, mime, raw, target)
	if err != nil {
		if !archive { // a plain body is only copied: what failed is the disk, not an extraction
			return publishRefused, nil
		}
		return extractRefused(top1mExtraction[mime], err, filepath.Base(raw)), nil
	}
	defer os.Remove(stage)
	if !top1mCandidate(stage, p) {
		return refused("top1m", "semantic_invalid", list), nil
	}
	if !top1mCommit(stage, target, base, raw) {
		return publishRefused, nil
	}
	touch(filepath.Join(cfg.DBDir, "top-1m.update"))
	return accepted, fetched
}

var errTop1MArchive = errors.New("archive is not one TOP1M list")

// top1mExtraction is the extrasExtraction name of each archive the TOP1M row extracts.
var top1mExtraction = map[string]string{mimeGzip: "top1m gzip", mimeTar: "top1m tar", mimeZip: "top1m zip"}

// top1mStage writes the list a body holds to a file beside target: a gzip's stream, the one member of a zip or tar, or
// the body itself. It also returns the list's name: the member's, else target's.
func (f *Fetcher) top1mStage(ctx context.Context, mime, raw, target string) (string, string, error) {
	list := filepath.Base(target)
	switch mime {
	case mimeGzip:
		if structural(ctx, mime, raw, io.Discard) != nil {
			return "", list, errTop1MArchive
		}
		staged, err := f.stage(ctx, Feed{Dir: filepath.Dir(target)}, mime, raw, false)
		return staged, list, err
	case mimeTar:
		names, ok := tarNames(ctx, mime, raw)
		if structural(ctx, mime, raw, io.Discard) != nil || !ok || len(names) != 1 || unsafeMember(names) != "" {
			return "", list, errTop1MArchive
		}
		staged, err := f.stage(ctx, Feed{Dir: filepath.Dir(target)}, mime, raw, true)
		return staged, path.Base(names[0]), err
	case mimeZip:
		return f.top1mZipStage(ctx, raw, target)
	case mimeBzip2:
		// shortcut: no TOP1M provider serves bzip2; refused until a corpus row pins pfb_download()'s path for it.
		return "", list, errTop1MArchive
	}
	staged, err := os.CreateTemp(filepath.Dir(target), ".pfbtop1m_")
	if err != nil {
		return "", list, err
	}
	in, err := os.Open(raw)
	if err == nil {
		_, err = io.Copy(staged, in)
		in.Close()
	}
	if cerr := staged.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(staged.Name())
		return "", list, err
	}
	return staged.Name(), list, nil
}

// top1mZipStage is the zip branch: exactly one member, a regular file with a safe name, that is not an HTML page. It also
// returns the member's name.
func (f *Fetcher) top1mZipStage(ctx context.Context, raw, target string) (string, string, error) {
	list := filepath.Base(target)
	file, err := os.Open(raw)
	if err != nil {
		return "", list, err
	}
	defer file.Close()
	zr, err := openZip(file)
	if err != nil || len(zr.File) != 1 || unsafeMember([]string{zr.File[0].Name}) != "" || !zr.File[0].Mode().IsRegular() {
		return "", list, errTop1MArchive
	}
	list = path.Base(zr.File[0].Name)
	staged, err := os.CreateTemp(filepath.Dir(target), ".pfbtop1m_")
	if err != nil {
		return "", list, err
	}
	err = copyZipMember(ctx, zr.File[0], &capWriter{w: staged, left: f.ceiling()})
	if cerr := staged.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if h, oerr := os.Open(staged.Name()); oerr == nil {
			if classify(head(h)) == mimeHTML {
				err = errTop1MArchive
			}
			h.Close()
		}
	}
	if err != nil {
		os.Remove(staged.Name())
		return "", list, err
	}
	return staged.Name(), list, nil
}

// top1mStaging prefixes the files a TOP1M publication stages beside their targets (#4198).
const top1mStaging = ".pfbtop1m_new_"

// top1mCommit publishes stage as target, and raw as its baseline (base.orig, with its xxh128 in base.xxhash128), by renames
// alone (#4198). Each file is first staged whole beside its target; then the baseline, the list and the digest are renamed
// into place in that order, and the legacy md5 sidecar goes. A run killed at any point leaves the list whole, the old one or
// the new one, and a baseline whose digest is missing or does not match it reads as changed (top1mDecision), so the next run
// downloads and publishes again: the digest goes last, so a baseline never vouches for a list that is not yet live. Nothing
// is set aside and nothing is ever put back. The first step removes what an interrupted publication staged.
func top1mCommit(stage, target, base, raw string) bool {
	top1mSweep(filepath.Dir(target), filepath.Dir(base))
	orig, err := top1mStaged(filepath.Dir(base), func(f *os.File) error {
		in, err := os.Open(raw)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(f, in)
		return err
	})
	if err != nil {
		return false
	}
	defer os.Remove(orig) // gone already once renamed
	sum, err := digest.File(orig)
	if err != nil {
		return false
	}
	sidecar, err := top1mStaged(filepath.Dir(base), func(f *os.File) error {
		_, err := f.WriteString(sum)
		return err
	})
	if err != nil {
		return false
	}
	defer os.Remove(sidecar)
	if rename(orig, base+".orig") != nil || rename(stage, target) != nil || rename(sidecar, base+".xxhash128") != nil {
		return false
	}
	os.Remove(base + ".md5")
	return true
}

// top1mStaged writes a new file in dir through write, whole and synced, mode 0644, and returns its name.
func top1mStaged(dir string, write func(*os.File) error) (string, error) {
	f, err := os.CreateTemp(dir, top1mStaging)
	if err != nil {
		return "", err
	}
	err = write(f)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// top1mSweep removes from dirs what an interrupted TOP1M publication left: its staged files, and the copies of the old list
// and baseline that publications before #4198 set aside (".pfbtop1m_active_", ".pfbtop1m_base_"). Nothing in them is
// restored: the published list and baseline are each whole, and the detector reads a mismatched pair as changed.
func top1mSweep(dirs ...string) {
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			for _, prefix := range []string{top1mStaging, ".pfbtop1m_active_", ".pfbtop1m_base_"} {
				if strings.HasPrefix(e.Name(), prefix) {
					os.RemoveAll(filepath.Join(dir, e.Name()))
				}
			}
		}
	}
}
