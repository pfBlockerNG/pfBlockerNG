// Package feedstage is the per-feed sequence of the Core Updater's DNSBL and IP stages (spec §3, stages 8 and 12; issue
// #4038): for one feed, the reuse decision, the transfer or the custom list, normalize, the pre-script, the parse, the
// post-script, the empty check and the staged publication, with a snapshot of the baseline that is put back when the feed
// fails. Recover puts back what a killed run left in a feed folder. The group-level work (DNSBLIP, the sets, publication to
// the resource store) is the caller's.
//
// A feed's files live in Paths.FeedDir under Feed.Name: the download "<name>.orig" and its sidecars (feedfetch), the
// normalized copy (feedparse), and the parsed list the next stages read: "<name>.parsed.ip" for an IP feed, the rows
// "<name>.parsed.ndjson" and the side lists "<name>.parsed.v4.ip" and "<name>.parsed.v6.ip" for a DNSBL feed. A parsed list
// holds real entries only: the placeholder outcome is reported, never written. The parity corpus with today's per-feed
// blocks is tests/updateloop/fixtures/feedstage.
package feedstage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

// Paths are the folders a run touches, each given by the caller; an unset one is an error, never a default.
type Paths struct {
	FeedDir    string   // the feed folder: absolute, a real directory (a symbolic link is refused)
	ScriptDirs []string // the list-script folders, in search order
	GeoIPDir   string   // the country lists a geoip-format feed reads; the caller lists it in Fetcher.Policy.LocalDirs
}

// Config is what the parse reads of the settings besides the feed.
type Config struct {
	Suppression      bool
	FloorV4, FloorV6 int // the Suppression CIDR Limit per family; 0 is Disabled
	DNSBLIP, Lenient bool
}

// Feed is one feed as the caller resolved it from the settings.
type Feed struct {
	ID     string // the outcome id
	Kind   string // ipv4, ipv6 or dnsbl
	Name   string // the file stem in the feed folder: [A-Za-z0-9_]+
	State  string // enabled, disabled, hold or flex
	Format string // auto, regex, geoip, whois, asn or rsync
	Source string // the URL; a geoip feed's country code; a whois or asn feed's list

	Username, Password    string // the source's own credentials
	PreScript, PostScript string // file names, looked up in Paths.ScriptDirs

	Custom          bool
	CustomText      string // the custom list, decoded
	WhoisConvert    bool   // a custom list of domains and AS numbers to resolve
	SuppressionCIDR int    // the group's IPv4 Suppression CIDR Limit, over Config.FloorV4 when set
}

// Result is what a run did. Disposition is changed (the source changed and the feed was parsed), reparsed (parsed again from
// the baseline), unchanged, empty (parsed to nothing: the last list stays), held, or failed with a Stage and a Reason.
type Result struct {
	ID                string `json:"id"`
	Disposition       string `json:"disposition"`
	Stage             string `json:"stage"`
	Reason            string `json:"reason"`
	SourceChanged     bool   `json:"sourceChanged"`
	NormalizedChanged bool   `json:"normalizedChanged"`
	PreScriptFailed   bool   `json:"preScriptFailed"`
	PostScriptFailed  bool   `json:"postScriptFailed"` // the feed is still published, as today ("side effects incomplete")
	Entries           int    `json:"entries"`
	ParseFailures     int    `json:"parseFailures"`
	Suppressed        bool   `json:"suppressed"`
	Placeholder       string `json:"placeholder"` // feedparse.PlaceholderEmpty or PlaceholderSuppressed: the list is empty
	DNSBLRows         int    `json:"dnsblRows"`
	IPv4Count         int    `json:"ipv4Count"`
	IPv6Count         int    `json:"ipv6Count"`
	UpdateIP          bool   `json:"updateIP"`
	SchemeSkipped     int    `json:"schemeSkipped"`
	HPHostsStop       bool   `json:"hpHostsStop"`
}

// Stage runs feeds one at a time: the scripts and the staged files assume no concurrent run on the same feed folder.
type Stage struct {
	Paths   Paths
	Fetcher *feedfetch.Fetcher
	Config  Config
	// Log takes the parser's notices and the scripts' runner lines; the post-script's output also goes to Errors and
	// Transcript as feedparse.PostScript writes it. A nil writer discards.
	Log, Errors, Transcript io.Writer
}

// step is a test seam: called at the named boundaries of a run. Production never sets it.
var step = func(name string) {}

const httpStatusNotModified = 304

func failedFeed(id, stage, reason string) Result {
	return Result{ID: id, Disposition: "failed", Stage: stage, Reason: reason}
}

// Run runs one feed. force is the Update's: none, parse (from the baseline), download or both (download and drop the
// digests too).
func (s *Stage) Run(ctx context.Context, f Feed, force string) (result Result) {
	result = Result{ID: f.ID}
	if reason := s.validate(f); reason != "" {
		return failedFeed(f.ID, "settings", reason)
	}
	if f.State == "disabled" {
		result.Disposition, result.Reason = "held", "disabled"
		return result
	}
	if ctx.Err() != nil {
		return failedFeed(f.ID, "probe", "cancelled")
	}
	dir := s.Paths.FeedDir
	feed := feedfetch.Feed{Dir: dir, Name: f.Name}
	origPath := feedPath(feed, ".orig")
	hasOrig := regularExists(origPath)
	if force == "parse" && !hasOrig {
		force = "download"
	}
	if f.State == "hold" && force != "parse" {
		if !hasOrig || f.PreScript == "" && f.PostScript == "" {
			result.Disposition, result.Reason = "held", "hold"
			return result
		}
		force = "parse"
	}

	var backup *pathSnapshot
	var backupErr error
	defer func() {
		if backup == nil {
			return
		}
		partialWhois := result.Disposition == "failed" && result.Stage == "whois" && result.SourceChanged
		if result.Disposition == "failed" && !partialWhois {
			if err := backup.restore(); err != nil {
				result = failedFeed(f.ID, "publish", "baseline_restore_failed")
			}
			// The normalization cache may describe the abandoned download: without its baseline the next run reparses.
			_ = removeIfExists(feedPath(feed, normBaseline))
		} else {
			backup.discard()
		}
	}()

	sourceChanged, whoisPartial := false, false
	if force != "parse" {
		switch {
		case f.Custom && !f.WhoisConvert:
			same, err := sameFileContents(origPath, f.CustomText)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return failedFeed(f.ID, "fetch", "custom_source_unavailable")
			}
			if !same {
				backup, err = snapshotPaths(feedStatePaths(feed))
				if err != nil {
					return failedFeed(f.ID, "fetch", "baseline_backup_failed")
				}
				staged, err := stageOutput(dir, func(w io.Writer) error {
					_, err := io.WriteString(w, f.CustomText)
					return err
				})
				if err != nil || publishStaged(dir, []stagedFeedFile{{name: f.Name + ".orig", temp: staged}}) != nil {
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				// The digest describes the bytes of the last transfer, which the custom text replaced.
				_ = removeIfExists(feedPath(feed, ".orig.xxhash128"))
				sourceChanged = true
			}
		case f.WhoisConvert || f.Format == "whois" || f.Format == "asn":
			backup, backupErr = snapshotPaths(feedStatePaths(feed))
			if backupErr != nil {
				return failedFeed(f.ID, "whois", "baseline_backup_failed")
			}
			list := f.Source
			if f.Custom {
				list = f.CustomText
			}
			whois := s.Fetcher.Whois(ctx, feed, feedfetch.WhoisRequest{List: list, IPv6: f.Kind == "ipv6"})
			if ctx.Err() != nil || whois.Reason != "" || !whois.Found {
				return failedFeed(f.ID, "whois", "whois_failed")
			}
			sourceChanged, whoisPartial = true, whois.Failed
		default:
			request, reason := s.request(f)
			if reason != "" {
				return failedFeed(f.ID, "settings", reason)
			}
			if force == "none" {
				probe := s.Fetcher.Probe(ctx, feed, request)
				switch {
				case !probe.OK || probe.Decision == feedfetch.Failed:
					return failedFeed(f.ID, "probe", s.safeReason(probe.Reason, "feed_probe_failed", f))
				case probe.Decision == feedfetch.Unchanged:
					// NormalizeFile below decides whether the cached artifacts are reusable.
				default:
					backup, backupErr = snapshotPaths(feedStatePaths(feed))
					if backupErr != nil {
						return failedFeed(f.ID, "fetch", "baseline_backup_failed")
					}
					ingested := s.Fetcher.Ingest(ctx, feed, request)
					if !ingested.OK {
						backup.keepAbsent(validatorPaths(feed)...)
						return failedFeed(f.ID, "fetch", s.safeReason(ingested.Reason, "feed_fetch_failed", f))
					}
					sourceChanged = ingested.Status != httpStatusNotModified
				}
			} else {
				backup, backupErr = snapshotPaths(feedStatePaths(feed))
				if backupErr != nil {
					return failedFeed(f.ID, "fetch", "baseline_backup_failed")
				}
				if err := clearForcedState(feed, force); err != nil {
					return failedFeed(f.ID, "fetch", "feed_force_prepare_failed")
				}
				ingested := s.Fetcher.Ingest(ctx, feed, request)
				if !ingested.OK {
					backup.keepAbsent(validatorPaths(feed)...)
					return failedFeed(f.ID, "fetch", s.safeReason(ingested.Reason, "feed_fetch_failed", f))
				}
				sourceChanged = ingested.Status != httpStatusNotModified
			}
		}
	}
	if ctx.Err() != nil {
		return failedFeed(f.ID, "fetch", "cancelled")
	}
	result.SourceChanged = sourceChanged
	disposition := "changed"
	if force == "parse" || force == "none" && !sourceChanged {
		disposition = "reparsed"
	}
	result = s.parseAndPublish(ctx, f, feed, force, disposition, whoisPartial, result)
	if result.Disposition != "failed" && whoisPartial {
		result.Disposition, result.Stage, result.Reason = "failed", "whois", "whois_partial"
	}
	return result
}

// validate refuses a feed whose folders or name could reach outside what the caller named.
func (s *Stage) validate(f Feed) string {
	switch {
	case s.Fetcher == nil:
		return "fetcher_missing"
	case s.Paths.FeedDir == "":
		return "feed_directory_missing"
	case !filepath.IsAbs(s.Paths.FeedDir):
		return "feed_directory_invalid"
	case !validFeedWord(f.Name):
		return "feed_name_invalid"
	}
	if info, err := os.Lstat(s.Paths.FeedDir); err != nil || !info.IsDir() {
		return "feed_directory_unavailable"
	}
	return ""
}

func (s *Stage) request(f Feed) (feedfetch.Request, string) {
	request := feedfetch.Request{Rsync: f.Format == "rsync", Flex: f.State == "flex", Username: f.Username, Password: f.Password,
		URL: f.Source}
	switch {
	case f.Source == "":
		return request, "feed_source_invalid"
	case f.Format == "rsync" && s.Fetcher.RsyncBin == "":
		return request, "rsync_unavailable"
	case f.Format == "geoip":
		country := strings.Fields(f.Source)
		if len(country) == 0 || !validFeedWord(country[0]) {
			return request, "feed_source_invalid"
		}
		if s.Paths.GeoIPDir == "" || !filepath.IsAbs(s.Paths.GeoIPDir) {
			return request, "geoip_directory_missing"
		}
		request.URL = fileURL(filepath.Join(s.Paths.GeoIPDir, country[0]+familySuffix(f.Kind)+".txt"))
	}
	return request, ""
}

// safeReason keeps feedfetch's reason when it is short printable text that names no path or credential.
func (s *Stage) safeReason(reason, fallback string, f Feed) string {
	if len(reason) == 0 || len(reason) > 64 {
		return fallback
	}
	for i := range reason {
		if reason[i] < 0x20 || reason[i] > 0x7e || reason[i] == '/' || reason[i] == '\\' {
			return fallback
		}
	}
	if f.Username != "" && strings.Contains(reason, f.Username) || f.Password != "" && strings.Contains(reason, f.Password) {
		return fallback
	}
	if s.Fetcher.Proxy != nil && s.Fetcher.Proxy.User != nil {
		username := s.Fetcher.Proxy.User.Username()
		password, _ := s.Fetcher.Proxy.User.Password()
		if username != "" && strings.Contains(reason, username) || password != "" && strings.Contains(reason, password) {
			return fallback
		}
	}
	return reason
}

func (s *Stage) parseAndPublish(ctx context.Context, f Feed, feed feedfetch.Feed, force, disposition string, whoisPartial bool,
	result Result) Result {
	result.Stage = "normalize"
	norm := feedparse.NormalizeFile(feed.Dir, feed.Name)
	result.NormalizedChanged = norm.Changed
	if ctx.Err() != nil {
		return failedFeed(f.ID, "normalize", "cancelled")
	}
	// issue #1960: a configured pre- or post-script runs every pass, so only a feed without one reuses its list.
	if force == "none" && f.PreScript == "" && f.PostScript == "" && parsedArtifactsExist(feed, f.Kind) && norm.Normalized &&
		!norm.Changed && !whoisPartial {
		result.Disposition, result.Stage, result.Reason = "unchanged", "normalize", "normalized_unchanged"
		return result
	}
	parsePath, probePath := norm.Path, feedPath(feed, ".orig")
	if f.PreScript != "" {
		script, ok := feedparse.ResolveListScript(f.PreScript, s.Paths.ScriptDirs)
		if !ok {
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_unavailable", true
			return result
		}
		listType := familySuffix(f.Kind)
		if f.Kind == "dnsbl" {
			listType = "dnsbl"
		}
		outcome := feedparse.RunPreScript(ctx, script, norm.Path, feedPath(feed, ".pre"), s.Log, listType)
		if !outcome.OK {
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_failed", true
			return result
		}
		defer outcome.Cleanup()
		parsePath, probePath = outcome.Path, outcome.Path
	}
	if ctx.Err() != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "parse", "cancelled"
		return result
	}
	sink := feedparse.Sink{
		Message: func(message string) {
			if s.Log != nil {
				fmt.Fprintf(s.Log, "feed %s: %s\n", f.ID, message)
			}
		},
		Fail: func(record feedparse.FailRecord) {
			if s.Log != nil {
				fmt.Fprintf(s.Log, "feed %s: parse failure at line %d\n", f.ID, record.LineNo)
			}
		},
	}
	post := feedparse.PostScript{Name: f.PostScript, Dirs: s.Paths.ScriptDirs, Header: f.Name, Log: s.Log, Errors: s.Errors,
		Transcript: s.Transcript}
	if f.Kind == "dnsbl" {
		return s.parseDNSBL(ctx, f, feed, parsePath, post, disposition, result, sink)
	}
	return s.parseIP(ctx, f, feed, parsePath, probePath, post, disposition, result, sink)
}

func (s *Stage) parseIP(ctx context.Context, f Feed, feed feedfetch.Feed, parsePath, probePath string, post feedparse.PostScript,
	disposition string, result Result, sink feedparse.Sink) Result {
	input, err := os.Open(parsePath)
	if err != nil {
		return failedFeed(f.ID, "parse", "normalized_feed_unavailable")
	}
	defer input.Close()
	floorV4, floorV6 := s.Config.FloorV4, s.Config.FloorV6
	if f.Format == "geoip" {
		floorV4, floorV6 = 0, 0
	}
	if f.Kind == "ipv4" && f.SuppressionCIDR > 0 {
		floorV4 = f.SuppressionCIDR
	}
	cfg := feedparse.IPConfig{
		VType: familySuffix(f.Kind), PFType: feedparse.IPParseType(f.Format, f.Source), Custom: f.Custom,
		FloorV4: cidrFloor(floorV4), FloorV6: cidrFloor(floorV6), Suppression: s.Config.Suppression,
	}
	var parsed feedparse.IPFeed
	staged, err := stageOutput(feed.Dir, func(writer io.Writer) error {
		var err error
		// The empty check reads the file after the post-script, so the parse counts no content here.
		parsed, err = feedparse.ParseIPFeed(input, cfg, "", feedparse.NoProbe, writer, sink)
		return err
	})
	if err != nil {
		return failedFeed(f.ID, "parse", "ip_parse_failed")
	}
	defer os.Remove(staged)

	// The post-script runs on the download itself, with a restore point put back after the empty check (spec §5).
	ran := post.RunIP(ctx, feedPath(feed, ".orig"), feedPath(feed, ".orig.post"), cfg.VType)
	defer ran.Restore()
	if ran.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil {
		return failedFeed(f.ID, "post-script", "cancelled")
	}
	result.PostScriptFailed = ran.Reason != ""
	if !ran.Skipped && ran.Reason == "" {
		step("post-script")
	}
	if parsed.Entries == 0 && parsed.Placeholder == "" {
		// The placeholder rule is ParseIPFeed's: asked again with the content of what the post-script left.
		again, _ := feedparse.ParseIPFeed(strings.NewReader(""), cfg, "", feedparse.CountContent(probePath), io.Discard, feedparse.Sink{})
		parsed.Placeholder = again.Placeholder
	}
	if parsed.Placeholder != "" {
		if err := os.Truncate(staged, 0); err != nil {
			return failedFeed(f.ID, "parse", "ip_parse_failed")
		}
	}
	result.Disposition, result.Stage = disposition, "parse"
	result.Entries, result.ParseFailures = parsed.Entries, parsed.ParseFail
	result.Suppressed, result.Placeholder = parsed.Suppressed, parsed.Placeholder
	if parsed.Entries == 0 && parsed.Placeholder == "" {
		result.Disposition = "empty"
		ran.Restore()
		return result
	}
	if err := publishStaged(feed.Dir, []stagedFeedFile{{name: feed.Name + ".parsed.ip", temp: staged}}); err != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	ran.Restore()
	return result
}

func (s *Stage) parseDNSBL(ctx context.Context, f Feed, feed feedfetch.Feed, parsePath string, post feedparse.PostScript,
	disposition string, result Result, sink feedparse.Sink) Result {
	input, err := os.Open(parsePath)
	if err != nil {
		return failedFeed(f.ID, "parse", "normalized_feed_unavailable")
	}
	defer input.Close()
	var parsed feedparse.DNSBLFeed
	stagedNDJSON, err := stageOutput(feed.Dir, func(writer io.Writer) error {
		var err error
		parsed, err = feedparse.ParseDNSBLFeed(input, feedparse.DNSBLConfig{
			DNSBLIP: s.Config.DNSBLIP, Lenient: s.Config.Lenient, Custom: f.Custom, Suppression: s.Config.Suppression,
		}, writer, sink)
		return err
	})
	if err != nil {
		return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedNDJSON)
	stagedV4, err := stageOutput(feed.Dir, func(w io.Writer) error { return writeLines(w, parsed.IP4) })
	if err != nil {
		return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedV4)
	stagedV6, err := stageOutput(feed.Dir, func(w io.Writer) error { return writeLines(w, parsed.IP6) })
	if err != nil {
		return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedV6)

	// The DNSBL post-script runs on a throwaway copy of the download; nothing reads what it leaves.
	ran := post.RunDNSBL(ctx, feedPath(feed, ".orig"), feedPath(feed, ".post"))
	if ran.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil {
		return failedFeed(f.ID, "post-script", "cancelled")
	}
	result.PostScriptFailed = ran.Reason != ""
	result.Disposition, result.Stage = disposition, "parse"
	result.DNSBLRows, result.IPv4Count, result.IPv6Count = parsed.Rows, len(parsed.IP4), len(parsed.IP6)
	result.UpdateIP, result.SchemeSkipped, result.HPHostsStop = parsed.UpdateIP, parsed.SchemeSkipped, parsed.Stopped
	files := []stagedFeedFile{
		{name: feed.Name + ".parsed.v4.ip", temp: stagedV4},
		{name: feed.Name + ".parsed.v6.ip", temp: stagedV6},
	}
	rows := feedPath(feed, ".parsed.ndjson")
	if parsed.Rows > 0 {
		files = append(files, stagedFeedFile{name: feed.Name + ".parsed.ndjson", temp: stagedNDJSON})
	} else {
		// No domain: the last rows stay, or an empty list stands for a feed that never had one.
		result.Disposition = "empty"
		if !regularExists(rows) {
			files = append(files, stagedFeedFile{name: feed.Name + ".parsed.ndjson", temp: stagedNDJSON})
		}
	}
	if err := publishStaged(feed.Dir, files); err != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	return result
}

func writeLines(w io.Writer, values []string) error {
	for _, value := range values {
		if _, err := io.WriteString(w, value+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func cidrFloor(value int) string {
	if value <= 0 {
		return "Disabled"
	}
	return strconv.Itoa(value)
}

func familySuffix(kind string) string {
	switch kind {
	case "ipv4":
		return "_v4"
	case "ipv6":
		return "_v6"
	}
	return ""
}

func feedPath(feed feedfetch.Feed, suffix string) string {
	return filepath.Join(feed.Dir, feed.Name+suffix)
}

func fileURL(path string) string { return (&url.URL{Scheme: "file", Path: path}).String() }

func parsedArtifactsExist(feed feedfetch.Feed, kind string) bool {
	names := []string{feed.Name + ".parsed.ip"}
	if kind == "dnsbl" {
		names = []string{feed.Name + ".parsed.ndjson", feed.Name + ".parsed.v4.ip", feed.Name + ".parsed.v6.ip"}
	}
	for _, name := range names {
		if !regularExists(filepath.Join(feed.Dir, name)) {
			return false
		}
	}
	return true
}

func clearForcedState(feed feedfetch.Feed, force string) error {
	suffixes := []string{".orig.etag", ".orig.lastmod", ".orig.size", ".probe", ".probe.etag", ".probe.lastmod", ".probe.size"}
	if force == "both" {
		suffixes = append(suffixes, ".orig.xxhash128")
	}
	for _, suffix := range suffixes {
		if err := removeIfExists(feedPath(feed, suffix)); err != nil {
			return err
		}
	}
	return nil
}

// validFeedWord is the grammar of a feed's file stem and of a GeoIP country code.
func validFeedWord(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		c := value[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
