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
	// SkipFeedPassed: the feed's failures today are past the skipfeed threshold, so a failed transfer removes the fail marker
	// instead of creating it (pfb_download_failure()). The caller computes it from today's failure count: the skipfeed
	// setting against $pfb['failed'][$header], as pfb_download_failure() does. That caller (sub-slice 9d or 9i) is not
	// written yet, so nothing sets it outside the tests.
	SkipFeedPassed bool
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

// Stage runs feeds one at a time: a feed has one run folder, and the scripts assume no concurrent run on the same feed
// folder.
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

// Run runs one feed with stage 6's verdict and the Update's force. The run works in a run folder of its own and reaches the
// feed folder only through its commit; a failed run leaves the feed folder as it was, but for a failed transfer, which
// still retires the validators and consumes the probe body (#2820). Stage 6's change probe reads the feed's files, the
// validators among them: the caller runs Recover on the feed folder before stage 6 probes a feed in it, and stops the feed
// when Recover fails, so that no probe reads the feed while a committed run is unfinished.
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
	// A run folder an earlier run of the feed left is finished or deleted before this run reads the feed's files.
	if recoverFeed(dir, f.Name) != nil {
		return failedFeed(f.ID, "publish", "run_folder_unrecoverable")
	}
	live := feedfetch.Feed{Dir: dir, Name: f.Name}
	baseline, err := regularFile(feedPath(live, ".orig"))
	if err != nil {
		return failedFeed(f.ID, "fetch", "baseline_unavailable")
	}
	hasOrig := baseline != nil
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
		case parsedArtifactsExist(live, f.Kind) && (!hasOrig || pre == "" && post == ""):
			result.Disposition, result.Reason = "held", "hold"
			return result
		case hasOrig:
			force = "parse"
		}
	}

	runDir, err := openRun(dir, f.Name)
	if err != nil {
		return failedFeed(f.ID, "fetch", "run_folder_failed")
	}
	feed := feedfetch.Feed{Dir: runDir, Name: f.Name}
	// What the run publishes when it fails: nothing, but for a failed transfer (retired) and a failed whois (its marker).
	var retire []string
	retireReason, retireStage := "", ""
	clearFail := false // the run's download succeeded, which removes the fail marker as today (apply.inc:2859, :4276)
	returned := false  // Run is returning normally; a panic unwinding leaves it false
	defer func() {
		if !returned {
			_ = discard(runDir) // an abnormal unwind publishes nothing: what stays is Recover's
			return
		}
		partialWhois := result.Disposition == "failed" && result.Stage == "whois" && result.SourceChanged
		suffixes, removable := retire, seeded
		if result.Disposition != "failed" || partialWhois {
			suffixes = published
		}
		if clearFail {
			// A successful download removes the marker whatever a later step does; the removal is published with the rest.
			removable = clearable
			if !slices.Contains(suffixes, ".fail") {
				suffixes = append(slices.Clone(suffixes), ".fail")
			}
		}
		done, markerOnly, err := false, false, error(nil)
		if suffixes != nil {
			done, markerOnly, err = commit(dir, runDir, f.Name, suffixes, removable)
		}
		if !done {
			_ = discard(runDir) // what stays is Recover's
			step("discarded")
		}
		switch {
		case err == nil:
		case result.Disposition == "failed" && !partialWhois:
			// Only the failure the branch itself returned takes its reason; a later stage keeps its own.
			if retireReason != "" && result.Stage == retireStage {
				if markerOnly {
					retireReason = "fail_marker_publish_failed"
				}
				result = failedFeed(f.ID, result.Stage, retireReason)
			}
		case done:
			// COMMIT stands and Recover finishes it: the caller must treat this reason as "may have changed".
			result = failedFeed(f.ID, "publish", "baseline_commit_failed")
		default:
			result = failedFeed(f.ID, "publish", "parsed_publish_failed")
		}
	}()
	// Registered last, so it runs first: it sees a panic, which it passes on, and marks a normal return otherwise.
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
		returned = true
	}()

	sourceChanged, whoisPartial := false, false
	if force != "parse" {
		origPath := feedPath(feed, ".orig")
		switch {
		case f.Custom && !f.WhoisConvert:
			same, err := sameFileContents(origPath, f.CustomText)
			if err != nil {
				return failedFeed(f.ID, "fetch", "custom_source_unavailable")
			}
			if !same {
				staged, err := stageOutput(runDir, func(w io.Writer) error {
					_, err := io.WriteString(w, f.CustomText)
					return err
				})
				if err != nil {
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				step("custom-staged")
				if rename(staged, origPath) != nil {
					return failedFeed(f.ID, "fetch", "custom_source_unavailable")
				}
				// The digests describe the bytes of the last transfer, which the custom text replaced.
				for _, suffix := range feedfetch.DigestSuffixes() {
					if removeIfExists(feedPath(feed, suffix)) != nil {
						return failedFeed(f.ID, "fetch", "custom_source_unavailable")
					}
				}
				sourceChanged = true
			}
		case f.WhoisConvert || f.Format == "whois" || f.Format == "asn":
			list := s.listSource(f)
			if f.Custom {
				list = f.CustomText
			}
			whois := s.Fetcher.Whois(ctx, feed, feedfetch.WhoisRequest{List: list, IPv6: f.Kind == "ipv6"})
			// A custom WhoisConvert list's marker, left by a failed entry, stands whatever the run does next, as today.
			retire, retireReason, retireStage = []string{".fail"}, "fail_marker_publish_failed", "whois"
			// Today's whois and asn formats go through pfb_download(), which succeeds whatever the entries did, and its
			// caller then unlinks the marker (apply.inc:4276); a custom list's whoisconvert never does.
			if !f.Custom && ctx.Err() == nil && whois.Reason == "" {
				if removeIfExists(feedPath(feed, ".fail")) != nil {
					return failedFeed(f.ID, "whois", "whois_failed")
				}
				clearFail = true
			}
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
			if force != "none" && clearForcedState(feed, force) != nil {
				return failedFeed(f.ID, "fetch", "feed_force_prepare_failed")
			}
			probeKept := regularExists(feedPath(feed, ".probe"))
			ingested := s.Fetcher.Ingest(ctx, feed, request)
			if !ingested.OK {
				// Force both drops the digests before the transfer, whatever its outcome (pfb_force_clear_validators()).
				retire, retireReason, retireStage = forcedSuffixes(force), "validators_retire_failed", "fetch"
				// A failed transfer touches the marker, or past the skipfeed threshold removes it (pfb_download_failure()). A
				// cancelled run did not fail the feed: it neither creates nor removes the marker, as the whois branch. A
				// deadline that passed is a failed download.
				cancelled := errors.Is(ctx.Err(), context.Canceled)
				reason := s.safeReason(ingested.Reason, "feed_fetch_failed", f)
				switch {
				case cancelled:
					reason = "cancelled"
				case f.SkipFeedPassed:
					clearFail = true
				default:
					file, err := create(feedPath(feed, ".fail"))
					if err != nil {
						if s.Log != nil {
							fmt.Fprintf(s.Log, "feed %s: fail marker could not be created: %v\n", f.ID, err)
						}
						break
					}
					_ = file.Close()
					retire = append(slices.Clone(retire), ".fail")
				}
				return failedFeed(f.ID, "fetch", reason)
			}
			sourceChanged, clearFail = ingested.Status != httpStatusNotModified, true
			if probeKept {
				// The ingest consumed the live probe body, which a failure later in the run must not leave to be staged again.
				retire = slices.Clone(probeFiles)
			}
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
	case slices.ContainsFunc(s.Paths.ScriptDirs, func(p string) bool { return p != "" && !cleanPath(p) }): // "" is unset, skipped
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
	live := feedfetch.Feed{Dir: s.Paths.FeedDir, Name: f.Name}
	if force == "none" && source != "" && !whoisPartial && parsedArtifactsExist(live, f.Kind) && recordedSource(live) == source {
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
	list := &lazyFile{path: feedPath(feed, ".parsed.ip")}
	// The empty check reads the file after the post-script, so the parse counts no content here.
	parsed, err := feedparse.ParseIPFeed(input, cfg, "", feedparse.NoProbe, list, sink)
	if errors.Join(err, list.Close()) != nil {
		return failedFeed(f.ID, "parse", "ip_parse_failed")
	}
	// One summary line per feed, today's (pfb_ip_parse_fail_warn()); the records went to ParseErrors.
	if parsed.ParseFail > 0 {
		s.sinks().Line(true, "\n[!] Parse Errors [ %s ]: %d\n", f.Name, parsed.ParseFail)
	}

	// The post-script runs on a copy of the download (spec §5), whose output the empty check reads and which the run
	// folder then drops: the script's output never becomes the download. The configured name decides: RunIP resolves the
	// script again and runs one installed since.
	ran := feedparse.PostScriptResult{Skipped: true}
	if f.PostScript != "" && f.PostScript != "0" { // "0" is no name: a name that resolves to no file still gets the copy
		if copied, err := postCopy(feed); err != nil {
			s.sinks().Line(true, "\n[ %s ] post-script '%s' could not stage its input; skipping\n", f.Name, f.PostScript)
			ran.Skipped, ran.Reason = false, feedparse.PreScriptStage
		} else {
			ran = post.RunIP(ctx, copied, copied+".post", cfg.VType)
			if probePath == feedPath(feed, ".orig") {
				probePath = copied
			}
		}
	}
	if ran.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil {
		return failedFeed(f.ID, "post-script", "cancelled")
	}
	result.PostScriptFailed = ran.Reason != ""
	if !ran.Skipped {
		source = "" // a script shaped the list, one that RunIP found though the first lookup did not: nothing is reused
	}
	if !ran.Skipped && ran.Reason == "" {
		step("post-script")
	}
	if parsed.Entries == 0 && parsed.Placeholder == "" {
		// The placeholder rule is ParseIPFeed's: asked again with the content of what the post-script left.
		again, _ := feedparse.ParseIPFeed(strings.NewReader(""), cfg, "", feedparse.CountContent(probePath), io.Discard, feedparse.Sink{})
		parsed.Placeholder = again.Placeholder
	}
	if parsed.Placeholder != "" { // the list is published empty
		if removeIfExists(list.path) != nil || newFile(list.path, writeLines(nil)) != nil {
			return failedFeed(f.ID, "parse", "ip_parse_failed")
		}
	}
	result.Disposition, result.Stage = disposition, "parse"
	result.Entries, result.ParseFailures = parsed.Entries, parsed.ParseFail
	result.Suppressed, result.Placeholder = parsed.Suppressed, parsed.Placeholder
	if parsed.Entries == 0 && parsed.Placeholder == "" {
		result.Disposition = "empty" // the parse wrote no list: the last one stays, and stands for this input
	}
	return withRecord(feed, source, result)
}

func (s *Stage) parseDNSBL(ctx context.Context, f Feed, feed feedfetch.Feed, input io.Reader, post feedparse.PostScript,
	source, disposition string, result Result, sink feedparse.Sink) Result {
	// The rows are written only when the parse yields one: rows the run does not publish are never in its folder.
	rows := &lazyFile{path: feedPath(feed, ".parsed.ndjson")}
	parsed, err := feedparse.ParseDNSBLFeed(input, s.dnsblConfig(f), rows, sink)
	if errors.Join(err, rows.Close()) != nil {
		return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
	}
	for _, side := range []struct {
		suffix string
		lines  []string
	}{{".parsed.v4.ip", parsed.IP4}, {".parsed.v6.ip", parsed.IP6}} {
		if newFile(feedPath(feed, side.suffix), writeLines(side.lines)) != nil {
			return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
		}
	}

	// The DNSBL post-script runs on a throwaway copy of the download; nothing reads what it leaves.
	ran := post.RunDNSBL(ctx, feedPath(feed, ".orig"), feedPath(feed, ".post"))
	if ran.Reason == feedparse.PreScriptCancelled || ctx.Err() != nil {
		return failedFeed(f.ID, "post-script", "cancelled")
	}
	result.PostScriptFailed = ran.Reason != ""
	if !ran.Skipped {
		source = "" // as for an IP feed: a script that took part leaves no reuse record
	}
	result.Disposition, result.Stage = disposition, "parse"
	result.DNSBLRows, result.IPv4Count, result.IPv6Count = parsed.Rows, len(parsed.IP4), len(parsed.IP6)
	result.UpdateIP, result.SchemeSkipped, result.HPHostsStop = parsed.UpdateIP, parsed.SchemeSkipped, parsed.Stopped
	if parsed.Rows == 0 {
		// No domain: the last rows stay, or an empty list stands for a feed that never had one; the v4 and v6 side lists are
		// still replaced, as today's block unlinks them.
		result.Disposition = "empty"
		if !regularExists(filepath.Join(s.Paths.FeedDir, feed.Name+".parsed.ndjson")) && newFile(rows.path, writeLines(nil)) != nil {
			return failedFeed(f.ID, "parse", "dnsbl_parse_failed")
		}
	}
	return withRecord(feed, source, result)
}

// withRecord writes the record of the input the run's lists stand for ("" for none) beside them in the run folder. One
// COMMIT publishes them with the download, and a KILL inside it is finished forward: no list stands beside another
// download.
func withRecord(feed feedfetch.Feed, source string, result Result) Result {
	if newFile(feedPath(feed, parsedSource+"."+digest.XXH128), func(w io.Writer) error {
		_, err := io.WriteString(w, source)
		return err
	}) != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	return result
}

// postCopy copies the download of the run folder to "<run>/.post/<name>.orig", the file the IP post-script runs on: the
// download's name, in a folder of its own, so that no file the script leaves beside it has a published name.
func postCopy(feed feedfetch.Feed) (string, error) {
	folder := filepath.Join(feed.Dir, ".post")
	if err := mkdir(folder); err != nil {
		return "", err
	}
	staged, err := stageOutput(folder, func(w io.Writer) error {
		in, err := os.Open(feedPath(feed, ".orig"))
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if err != nil {
		return "", err
	}
	copied := filepath.Join(folder, feed.Name+".orig")
	return copied, rename(staged, copied)
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

// writeLines is the writer of values, one per line.
func writeLines(values []string) func(io.Writer) error {
	return func(w io.Writer) error {
		for _, value := range values {
			if _, err := io.WriteString(w, value+"\n"); err != nil {
				return err
			}
		}
		return nil
	}
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

// forcedSuffixes are what a forced transfer drops before it runs: the validators and the probe body (retired), and for
// force both the digests too.
func forcedSuffixes(force string) []string {
	if force == "both" {
		return append(slices.Clone(retired), feedfetch.DigestSuffixes()...)
	}
	return retired
}

func clearForcedState(feed feedfetch.Feed, force string) error {
	for _, suffix := range forcedSuffixes(force) {
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
