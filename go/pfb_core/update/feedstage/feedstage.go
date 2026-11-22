// Package feedstage runs one feed through the Core Updater's DNSBL and IP stages (spec §3, stages 8 and 12). The
// group-level work (DNSBLIP, the sets, publication to the resource store) is the caller's.
//
// A feed's files live in Paths.FeedDir under Feed.Name. The next stages read its parsed lists: "<name>.parsed.ip" for an IP
// feed; the rows "<name>.parsed.ndjson" and the side lists "<name>.parsed.v4.ip" and "<name>.parsed.v6.ip" for a DNSBL
// feed. A parsed list holds real entries only: the placeholder outcome is reported, never written.
package feedstage

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
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
	Format string // auto, regex, geoip, whois, asn or rsync; any other value is auto, as today
	// Source is the URL; a geoip feed's country code; a whois feed's list. An asn feed's is its AS number, "AS<digits>":
	// anything after the first space (the description the Groups editor keeps, "AS64500 Example") is cut off, as today.
	Source string

	Username, Password    string     // the source's own credentials
	BindAddress           netip.Addr // the source address of the transfer (the settings' bindAddress); the zero value is none
	PreScript, PostScript string     // file names, looked up in Paths.ScriptDirs

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
	// ParseErrors takes one record per parse failure, as pfb_parse_fail_log() writes them; the caller owns the file and its
	// cap. A nil writer discards.
	ParseErrors io.Writer
}

// Verdict is stage 6's change detection answer for a transferred feed (sub-slice 9d produces it): Run never probes.
type Verdict string

const (
	VerdictChanged   Verdict = "changed"   // Run ingests, which consumes the probe body stage 6 kept
	VerdictUnchanged Verdict = "unchanged" // Run keeps the download and follows the reuse rule
	VerdictFailed    Verdict = "failed"    // Run fails the feed at the probe with Change.Reason
)

// Change is Run's input from stage 6 and the request. The verdict is required when Force is none and read only then, for a
// transferred feed: a custom list compares its own text and a whois feed is resolved again every run.
type Change struct {
	Verdict Verdict
	Reason  string // a failed verdict's reason, feedfetch's; reported only when it names no path or credential
	Force   string // none, parse (from the baseline), download, or both (download and drop the digests too)
}

// step is a test seam: called at the named boundaries of a run. Production never sets it.
var step = func(name string) {}

const httpStatusNotModified = 304

func failedFeed(id, stage, reason string) Result {
	return Result{ID: id, Disposition: "failed", Stage: stage, Reason: reason}
}

// Run runs one feed with stage 6's verdict and the Update's force. Stage 6's change probe reads the files Run journals, the
// validators among them: the caller runs Recover on the feed folder before stage 6 probes a feed in it, and stops the feed
// when Recover fails, so that no probe reads what an unfinished run left.
func (s *Stage) Run(ctx context.Context, f Feed, change Change) (result Result) {
	result = Result{ID: f.ID}
	// Today's per-feed blocks and pfb_download() compare the format with these names case-sensitively, and any other value,
	// such as the category editor's "Auto" or an empty one, falls through to auto.
	if !slices.Contains([]string{"auto", "regex", "geoip", "whois", "asn", "rsync"}, f.Format) {
		if s.Log != nil && f.Format != "" && f.Format != "Auto" {
			fmt.Fprintf(s.Log, "feed %s: format %q is no known format name; running it as auto\n", f.ID, f.Format)
		}
		f.Format = "auto"
	}
	if reason := s.validate(f, change); reason != "" {
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
	// A set an earlier run could not finish is finished before this run reads the feed's files or opens a set of its own:
	// left to a later Recover beside this run's sets, its backups could put an older download back over a newer one.
	if finishFeedSets(dir, f.Name) != nil {
		return failedFeed(f.ID, "publish", "baseline_restore_failed")
	}
	feed := feedfetch.Feed{Dir: dir, Name: f.Name}
	origPath := feedPath(feed, ".orig")
	hasOrig, err := baselineExists(origPath)
	if err != nil {
		return failedFeed(f.ID, "fetch", "baseline_unavailable")
	}
	force := change.Force
	if force == "parse" && !hasOrig {
		force = "download"
	}
	// As today, a script that does not resolve is no script, for reuse as for Hold (apply.inc:4071, :2641).
	pre, _ := feedparse.ResolveListScript(f.PreScript, s.Paths.ScriptDirs)
	post, _ := feedparse.ResolveListScript(f.PostScript, s.Paths.ScriptDirs)
	// A Reload (force parse) is never held, as today's Reload skips the Hold fast path (apply.inc:4116-4140, :2786-2800).
	if f.State == "hold" && change.Force != "parse" {
		// Hold is download once: held while its published list stands, unless a script asks for the download to be parsed
		// again; a list that is gone is parsed again from the download, and a feed never downloaded downloads once.
		switch {
		case parsedArtifactsExist(feed, f.Kind) && (!hasOrig || pre == "" && post == ""):
			result.Disposition, result.Reason = "held", "hold"
			return result
		case hasOrig:
			force = "parse"
		}
	}

	// The download and its sidecars are one journal set, committed when the run stands and rolled back when it fails. The
	// lists and their record commit in a set of their own first: when this set then rolls back, or a KILL leaves it to
	// Recover, the new lists stand beside the old download, and the record (the digest of the normalized input they were
	// parsed from, with the parse settings) differs from the old download's, so reuse parses that download again.
	var backup *journal
	var backupErr error
	defer func() {
		if backup == nil {
			return
		}
		partialWhois := result.Disposition == "failed" && result.Stage == "whois" && result.SourceChanged
		if result.Disposition == "failed" && !partialWhois {
			// A restore point that stays holds the run's download: rolled back now, the set would leave it to go over the
			// baseline later. Recover (or the feed's next run) puts it back first, then rolls the set back.
			if _, err := os.Lstat(feedPath(feed, restorePoint)); !errors.Is(err, fs.ErrNotExist) {
				result = failedFeed(f.ID, "publish", "baseline_restore_failed")
			} else if err := backup.rollback(); err != nil {
				result = failedFeed(f.ID, "publish", "baseline_restore_failed")
			}
			step("restored")
		} else if err := backup.commit(); err != nil {
			_ = backup.rollback() // a commit that is not durable fails the feed (journal.commit)
			// A marker that could not be removed leaves the new files standing, so the files on disk may be the new ones:
			// the caller must treat this reason as "may have changed".
			result = failedFeed(f.ID, "publish", "baseline_commit_failed")
		}
	}()
	// The IP post-script rewrites the download in place (feedparse.RunIP), and a 304 transfer leaves that file: its backup
	// is a copy. The configured name decides: RunIP resolves the script again and runs one installed since.
	var copies []string
	if f.Kind != "dnsbl" && f.PostScript != "" {
		copies = []string{origPath}
	}

	sourceChanged, whoisPartial := false, false
	if force != "parse" {
		switch {
		case f.Custom && !f.WhoisConvert:
			same, err := sameFileContents(origPath, f.CustomText)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return failedFeed(f.ID, "fetch", "custom_source_unavailable")
			}
			if !same {
				backup, err = snapshotPaths(feedStatePaths(feed), copies...)
				if err != nil {
					return failedFeed(f.ID, "fetch", "baseline_backup_failed")
				}
				staged, err := stageOutput(dir, func(w io.Writer) error {
					_, err := io.WriteString(w, f.CustomText)
					return err
				})
				if err != nil {
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				defer remove(staged)
				step("custom-staged")
				if rename(staged, origPath) != nil { // the journal set above puts the last text back on a failure
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				// The digest describes the bytes of the last transfer, which the custom text replaced.
				if removeIfExists(feedPath(feed, ".orig.xxhash128")) != nil {
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				sourceChanged = true
			}
		case f.WhoisConvert || f.Format == "whois" || f.Format == "asn":
			backup, backupErr = snapshotPaths(feedStatePaths(feed), copies...)
			if backupErr != nil {
				return failedFeed(f.ID, "whois", "baseline_backup_failed")
			}
			list := s.listSource(f)
			if f.Custom {
				list = f.CustomText
			}
			whois := s.Fetcher.Whois(ctx, feed, feedfetch.WhoisRequest{List: list, IPv6: f.Kind == "ipv6"})
			if ctx.Err() != nil || whois.Reason != "" || !whois.Found {
				return failedFeed(f.ID, "whois", "whois_failed")
			}
			sourceChanged, whoisPartial = true, whois.Failed
		default:
			if force == "none" && change.Verdict == "" {
				return failedFeed(f.ID, "settings", "verdict_invalid")
			}
			request, reason := s.request(f)
			if reason != "" {
				return failedFeed(f.ID, "settings", reason)
			}
			if force == "none" && change.Verdict == VerdictFailed {
				return failedFeed(f.ID, "probe", s.safeReason(change.Reason, "feed_probe_failed", f))
			}
			if force == "none" && change.Verdict == VerdictUnchanged {
				break // the reuse rule below decides whether the published lists stand
			}
			if backup, backupErr = snapshotPaths(feedStatePaths(feed), copies...); backupErr != nil {
				return failedFeed(f.ID, "fetch", "baseline_backup_failed")
			}
			if force != "none" && clearForcedState(feed, force) != nil {
				return failedFeed(f.ID, "fetch", "feed_force_prepare_failed")
			}
			ingested := s.Fetcher.Ingest(ctx, feed, request)
			if !ingested.OK {
				if backup.keepAbsent(validatorPaths(feed)...) != nil {
					return failedFeed(f.ID, "fetch", "validators_retire_failed")
				}
				return failedFeed(f.ID, "fetch", s.safeReason(ingested.Reason, "feed_fetch_failed", f))
			}
			sourceChanged = ingested.Status != httpStatusNotModified
		}
	}
	if ctx.Err() != nil {
		return failedFeed(f.ID, "fetch", "cancelled")
	}
	result.SourceChanged = sourceChanged
	disposition := "reparsed"
	if sourceChanged {
		disposition = "changed"
	}
	result = s.parseAndPublish(ctx, f, feed, pre, post, force, disposition, whoisPartial, result)
	if result.Disposition != "failed" && whoisPartial {
		result.Disposition, result.Stage, result.Reason = "failed", "whois", "whois_partial"
	}
	return result
}

// validate refuses a feed whose folders or name could reach outside what the caller named, and an input Run does not know.
// An empty verdict is refused only where Run reads it, for a transfer.
func (s *Stage) validate(f Feed, change Change) string {
	switch {
	case !slices.Contains([]string{"none", "parse", "download", "both"}, change.Force):
		return "force_invalid"
	case change.Verdict != "" && !slices.Contains([]Verdict{VerdictChanged, VerdictUnchanged, VerdictFailed}, change.Verdict):
		return "verdict_invalid"
	case !slices.Contains([]string{"ipv4", "ipv6", "dnsbl"}, f.Kind):
		return "feed_kind_invalid"
	case !slices.Contains([]string{"enabled", "disabled", "hold", "flex"}, f.State):
		return "feed_state_invalid"
	case s.Fetcher == nil:
		return "fetcher_missing"
	case s.Paths.FeedDir == "":
		return "feed_directory_missing"
	case !cleanPath(s.Paths.FeedDir):
		return "feed_directory_invalid"
	case !validFeedWord(f.Name):
		return "feed_name_invalid"
	case s.Paths.GeoIPDir != "" && !cleanPath(s.Paths.GeoIPDir):
		return "geoip_directory_invalid"
	case slices.ContainsFunc(s.Paths.ScriptDirs, func(p string) bool { return !cleanPath(p) }):
		return "script_directory_invalid"
	}
	if info, err := os.Lstat(s.Paths.FeedDir); err != nil || !info.IsDir() {
		return "feed_directory_unavailable"
	}
	return ""
}

func (s *Stage) request(f Feed) (feedfetch.Request, string) {
	request := feedfetch.Request{Rsync: f.Format == "rsync", Flex: f.State == "flex", Username: f.Username, Password: f.Password,
		URL: f.Source, BindAddr: f.BindAddress}
	switch {
	case f.Source == "":
		return request, "feed_source_invalid"
	case f.Format == "rsync" && s.Fetcher.RsyncBin == "":
		return request, "rsync_unavailable"
	case f.Format == "geoip":
		list := s.listSource(f)
		if list == "" {
			return request, "feed_source_invalid"
		}
		if s.Paths.GeoIPDir == "" {
			return request, "geoip_directory_missing"
		}
		request.URL = fileURL(list)
	}
	return request, ""
}

// listSource is f.Source as today's feed block rewrites it, before the transfer and the parser's choice, for a feed that is
// no custom list (pfblockerng_apply.inc, "Adjust 'geoip' format" and "Remove 'whois' source field description"): a GeoIP
// feed's country code becomes its country list's path ("" for a code that is no word), and an asn feed's source is cut at
// its first space and trimmed, as pfb_download() trims it.
func (s *Stage) listSource(f Feed) string {
	if f.Custom {
		return f.Source
	}
	switch f.Format {
	case "geoip":
		country, _, _ := strings.Cut(f.Source, " ")
		if !validFeedWord(country) {
			return ""
		}
		return filepath.Join(s.Paths.GeoIPDir, country+familySuffix(f.Kind)+".txt")
	case "asn":
		number, _, _ := strings.Cut(f.Source, " ")
		return strings.Trim(number, " \t\n\r\x00\x0b")
	}
	return f.Source
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

func (s *Stage) parseAndPublish(ctx context.Context, f Feed, feed feedfetch.Feed, pre, post, force, disposition string,
	whoisPartial bool, result Result) Result {
	result.Stage = "normalize"
	norm := feedparse.NormalizeFile(feed.Dir, feed.Name)
	result.NormalizedChanged = norm.Changed
	if ctx.Err() != nil {
		return failedFeed(f.ID, "normalize", "cancelled")
	}
	// The input the lists will stand for: the normalized download, when no script takes part (issue #1960: a configured
	// script runs every pass, so a feed with one is never reused), with every setting the parse reads, so that a changed
	// setting parses an unchanged download once again. Today's reuse has no settings term: a deliberate improvement, which
	// the Go tests cover and no corpus row can (today's block differs by design).
	source := ""
	if norm.Normalized && pre == "" && post == "" {
		if normalized, err := digest.File(norm.Path); err == nil {
			source = digest.Bytes([]byte(normalized + "\n" + s.parseSettings(f)))
		}
	}
	if force == "none" && source != "" && !whoisPartial && parsedArtifactsExist(feed, f.Kind) && recordedSource(feed) == source {
		result.Disposition, result.Stage, result.Reason = "unchanged", "normalize", "normalized_unchanged"
		return result
	}
	parsePath, probePath := norm.Path, feedPath(feed, ".orig")
	if pre == "" && f.PreScript != "" && f.PreScript != "0" {
		s.sinks().Line(true, "\n[ %s ] pre-script '%s' is not a file in the list-script folders; skipping\n", f.Name, f.PreScript)
	}
	if pre != "" {
		outcome := feedparse.RunPreScript(ctx, pre, norm.Path, feedPath(feed, ".pre"), s.Log, cmp.Or(familySuffix(f.Kind), "dnsbl"))
		switch {
		case outcome.OK:
		case outcome.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil:
			return failedFeed(f.ID, "script", "cancelled")
		default:
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
			if s.ParseErrors != nil {
				fmt.Fprintf(s.ParseErrors, "%s,%s,%s,%s,%d\n", time.Now().Format(time.DateTime), f.Name, record.Line, record.Raw,
					record.LineNo)
			}
		},
	}
	input, err := os.Open(parsePath)
	if err != nil {
		return failedFeed(f.ID, "parse", "normalized_feed_unavailable")
	}
	defer input.Close()
	script := feedparse.PostScript{Name: f.PostScript, Dirs: s.Paths.ScriptDirs, Header: f.Name, Log: s.Log, Errors: s.Errors,
		Transcript: s.Transcript}
	if f.Kind == "dnsbl" {
		result = s.parseDNSBL(ctx, f, feed, input, script, source, disposition, result, sink)
	} else {
		result = s.parseIP(ctx, f, feed, input, probePath, script, source, disposition, result, sink)
	}
	return result
}

func (s *Stage) sinks() output.Sinks {
	return output.Sinks{Log: s.Log, Transcript: s.Transcript, Errors: s.Errors}
}

// parseSettings is every setting the parse of f reads, as its configuration.
func (s *Stage) parseSettings(f Feed) string {
	if f.Kind == "dnsbl" {
		return fmt.Sprintf("%+v", s.dnsblConfig(f))
	}
	return fmt.Sprintf("%+v", s.ipConfig(f))
}

func (s *Stage) ipConfig(f Feed) feedparse.IPConfig {
	floorV4, floorV6 := s.Config.FloorV4, s.Config.FloorV6
	if f.Format == "geoip" {
		floorV4, floorV6 = 0, 0
	}
	if f.Kind == "ipv4" && f.SuppressionCIDR > 0 {
		floorV4 = f.SuppressionCIDR
	}
	return feedparse.IPConfig{
		VType: familySuffix(f.Kind), PFType: feedparse.IPParseType(f.Format, s.listSource(f)), Custom: f.Custom,
		FloorV4: cidrFloor(floorV4), FloorV6: cidrFloor(floorV6), Suppression: s.Config.Suppression,
	}
}

func (s *Stage) dnsblConfig(f Feed) feedparse.DNSBLConfig {
	return feedparse.DNSBLConfig{DNSBLIP: s.Config.DNSBLIP, Lenient: s.Config.Lenient, Custom: f.Custom, Suppression: s.Config.Suppression}
}

func (s *Stage) parseIP(ctx context.Context, f Feed, feed feedfetch.Feed, input io.Reader, probePath string,
	post feedparse.PostScript, source, disposition string, result Result, sink feedparse.Sink) Result {
	cfg := s.ipConfig(f)
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
	defer remove(staged)
	// One summary line per feed, today's (pfb_ip_parse_fail_warn()); the records went to ParseErrors.
	if parsed.ParseFail > 0 {
		s.sinks().Line(true, "\n[!] Parse Errors [ %s ]: %d\n", f.Name, parsed.ParseFail)
	}

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
		if err := truncate(staged); err != nil {
			return failedFeed(f.ID, "parse", "ip_parse_failed")
		}
	}
	// The download goes back before the list is published: one that cannot go back may hold the script's output, which
	// must never become the baseline, so the feed fails and the journal rolls the download back.
	if ran.Restore() != nil {
		return failedFeed(f.ID, "post-script", "post_script_restore_failed")
	}
	result.Disposition, result.Stage = disposition, "parse"
	result.Entries, result.ParseFailures = parsed.Entries, parsed.ParseFail
	result.Suppressed, result.Placeholder = parsed.Suppressed, parsed.Placeholder
	files := []stagedFeedFile{{name: feed.Name + ".parsed.ip", temp: staged}}
	if parsed.Entries == 0 && parsed.Placeholder == "" {
		result.Disposition, files = "empty", nil // the last list stays, and stands for this input
	}
	return publishResult(feed, files, source, result)
}

func (s *Stage) parseDNSBL(ctx context.Context, f Feed, feed feedfetch.Feed, input io.Reader, post feedparse.PostScript,
	source, disposition string, result Result, sink feedparse.Sink) Result {
	var parsed feedparse.DNSBLFeed
	stagedNDJSON, err := stageOutput(feed.Dir, func(writer io.Writer) error {
		var err error
		parsed, err = feedparse.ParseDNSBLFeed(input, s.dnsblConfig(f), writer, sink)
		return err
	})
	if err != nil {
		return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
	}
	defer remove(stagedNDJSON)
	var files []stagedFeedFile
	for _, side := range []struct {
		suffix string
		lines  []string
	}{{".parsed.v4.ip", parsed.IP4}, {".parsed.v6.ip", parsed.IP6}} {
		staged, err := stageOutput(feed.Dir, func(w io.Writer) error { return writeLines(w, side.lines) })
		if err != nil {
			return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
		}
		defer remove(staged)
		files = append(files, stagedFeedFile{name: feed.Name + side.suffix, temp: staged})
	}

	// The DNSBL post-script runs on a throwaway copy of the download; nothing reads what it leaves.
	ran := post.RunDNSBL(ctx, feedPath(feed, ".orig"), feedPath(feed, ".post"))
	if ran.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil {
		return failedFeed(f.ID, "post-script", "cancelled")
	}
	result.PostScriptFailed = ran.Reason != ""
	result.Disposition, result.Stage = disposition, "parse"
	result.DNSBLRows, result.IPv4Count, result.IPv6Count = parsed.Rows, len(parsed.IP4), len(parsed.IP6)
	result.UpdateIP, result.SchemeSkipped, result.HPHostsStop = parsed.UpdateIP, parsed.SchemeSkipped, parsed.Stopped
	rows := feedPath(feed, ".parsed.ndjson")
	if parsed.Rows > 0 {
		files = append(files, stagedFeedFile{name: feed.Name + ".parsed.ndjson", temp: stagedNDJSON})
	} else {
		// No domain: the last rows stay, or an empty list stands for a feed that never had one; the v4 and v6 side lists are
		// still replaced, as today's block unlinks them.
		result.Disposition = "empty"
		if !regularExists(rows) {
			files = append(files, stagedFeedFile{name: feed.Name + ".parsed.ndjson", temp: stagedNDJSON})
		}
	}
	return publishResult(feed, files, source, result)
}

func publishResult(feed feedfetch.Feed, files []stagedFeedFile, source string, result Result) Result {
	if err := publishParsed(feed, files, source); err != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	return result
}

// publishParsed publishes the staged lists of a feed with the record of the input they stand for ("" for none) in one
// commit: reuse needs that record to equal the current input, so no KILL or restore order can pair a list with another
// download.
func publishParsed(feed feedfetch.Feed, files []stagedFeedFile, source string) error {
	record, err := stageOutput(feed.Dir, func(w io.Writer) error {
		_, err := io.WriteString(w, source)
		return err
	})
	if err != nil {
		return err
	}
	defer remove(record)
	return publishStaged(feed.Dir, append(files, stagedFeedFile{name: feed.Name + parsedSource + "." + digest.XXH128, temp: record}))
}

func recordedSource(feed feedfetch.Feed) string {
	if algo, recorded := digest.Read(feedPath(feed, parsedSource)); algo == digest.XXH128 {
		return recorded
	}
	return ""
}

// cleanPath is the rule the loop applies to its paths (update.CheckPath): absolute and clean, valid UTF-8 without a control
// character.
func cleanPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && utf8.ValidString(p) && strings.IndexFunc(p, unicode.IsControl) < 0
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
