package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

type stagedFeedFile struct {
	name, temp string
}

type pathSnapshot struct {
	items []snapshotItem
}

type snapshotItem struct {
	target, backup string
	existed        bool
}

func (p *feedPhaseRunner) runFeed(ctx context.Context, spec phaseFeed, force string, fetcher *feedfetch.Fetcher, ingest map[string]any, log io.Writer) (result FeedPhaseResult) {
	result = FeedPhaseResult{ID: spec.id}
	if spec.disabled || spec.groupAction == "Disabled" || spec.state == "disabled" {
		result.Disposition, result.Reason = "held", "disabled"
		return result
	}
	if ctx.Err() != nil {
		return failedFeed(spec.id, "probe", "cancelled")
	}
	dir := p.flags.OrigDir
	if spec.kind == "dnsbl" {
		dir = p.flags.DNSBLOrigDir
	}
	if dir == "" {
		return failedFeed(spec.id, "settings", "feed_directory_missing")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return failedFeed(spec.id, "settings", "feed_directory_unavailable")
	}
	feed := feedfetch.Feed{Dir: dir, Name: spec.name}
	origPath := feedPath(feed, ".orig")
	hasOrig := regularExists(origPath)
	if force == "parse" && !hasOrig {
		return failedFeed(spec.id, "probe", "baseline_missing")
	}
	if spec.state == "hold" && force != "parse" {
		if !hasOrig || spec.preScript == "" {
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
				result = failedFeed(spec.id, "publish", "baseline_restore_failed")
			}
		} else {
			backup.discard()
		}
	}()

	sourceChanged, whoisPartial, asnMissing := false, false, false
	if force != "parse" {
		switch {
		case spec.custom && !spec.whoisConvert:
			same, err := sameFileContents(origPath, spec.customText)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return failedFeed(spec.id, "fetch", "custom_source_unavailable")
			}
			if !same {
				backup, err = snapshotPaths(feedStatePaths(feed))
				if err != nil {
					return failedFeed(spec.id, "fetch", "baseline_backup_failed")
				}
				staged, err := stageOutput(dir, ".pfbraw-", func(w io.Writer) error {
					_, err := io.Copy(w, strings.NewReader(spec.customText))
					return err
				})
				if err != nil {
					return failedFeed(spec.id, "fetch", "custom_source_unavailable")
				}
				if err := publishStaged(dir, []stagedFeedFile{{name: spec.name + ".orig", temp: staged}}); err != nil {
					return failedFeed(spec.id, "fetch", "custom_source_unavailable")
				}
				if err := removeIfExists(feedPath(feed, ".orig.xxhash128")); err != nil {
				}
				sourceChanged = true
			}
		case spec.whoisConvert || spec.format == "whois" || spec.format == "asn":
			backup, backupErr = snapshotPaths(feedStatePaths(feed))
			if backupErr != nil {
				return failedFeed(spec.id, "whois", "baseline_backup_failed")
			}
			list := spec.source
			if spec.custom {
				list = spec.customText
			}
			whois := fetcher.Whois(ctx, feed, feedfetch.WhoisRequest{List: list, IPv6: spec.kind == "ipv6"})
			if ctx.Err() != nil || whois.Reason != "" || !whois.Found {
				reason := "whois_failed"
				if whois.ASNMissing && whois.Reason == "" {
					reason = "asn_database_missing"
				}
				return failedFeed(spec.id, "whois", reason)
			}
			sourceChanged, whoisPartial, asnMissing = true, whois.Failed, whois.ASNMissing
		case true:
			request, err := p.feedRequest(spec, fetcher)
			if err != nil {
				return failedFeed(spec.id, "settings", "feed_source_invalid")
			}
			probeRequired := force == "none"
			if !request.Rsync {
				if source, err := url.Parse(request.URL); err == nil && strings.EqualFold(source.Scheme, "ftp") {
					probeRequired = false
				}
			}
			if probeRequired {
				probe := fetcher.Probe(ctx, feed, request)
				switch {
				case !probe.OK || probe.Decision == feedfetch.Failed:
					return failedFeed(spec.id, "probe", "feed_probe_failed")
				case probe.Decision == feedfetch.Unchanged:
					// NormalizeFile below decides whether the cached artifacts are reusable.
				default:
					backup, err = snapshotPaths(feedStatePaths(feed))
					if err != nil {
						return failedFeed(spec.id, "fetch", "baseline_backup_failed")
					}
					ingested := fetcher.Ingest(ctx, feed, request)
					if !ingested.OK {
						backup.keepAbsent(feedPath(feed, ".orig.etag"), feedPath(feed, ".orig.lastmod"))
						return failedFeed(spec.id, "fetch", "feed_fetch_failed")
					}
					sourceChanged = ingested.Status != httpStatusNotModified
				}
			} else {
				backup, err = snapshotPaths(feedStatePaths(feed))
				if err != nil {
					return failedFeed(spec.id, "fetch", "baseline_backup_failed")
				}
				if force != "none" {
					if err := clearForcedState(feed, force); err != nil {
						return failedFeed(spec.id, "fetch", "feed_force_prepare_failed")
					}
				}
				ingested := fetcher.Ingest(ctx, feed, request)
				if !ingested.OK {
					backup.keepAbsent(feedPath(feed, ".orig.etag"), feedPath(feed, ".orig.lastmod"))
					return failedFeed(spec.id, "fetch", "feed_fetch_failed")
				}
				sourceChanged = ingested.Status != httpStatusNotModified
			}
		}
	}
	if ctx.Err() != nil {
		return failedFeed(spec.id, "fetch", "cancelled")
	}
	result.SourceChanged = sourceChanged
	disposition := "changed"
	if force == "parse" || force == "none" && !sourceChanged {
		disposition = "reparsed"
	}
	result = p.parseAndPublish(ctx, spec, feed, force, ingest, disposition, whoisPartial, result, log)
	if result.Disposition != "failed" {
		if asnMissing {
			result.Disposition, result.Stage, result.Reason = "failed", "whois", "asn_database_missing"
		} else if whoisPartial {
			result.Disposition, result.Stage, result.Reason = "failed", "whois", "whois_partial"
		}
	}
	return result
}

const httpStatusNotModified = 304

func (p *feedPhaseRunner) feedRequest(spec phaseFeed, fetcher *feedfetch.Fetcher) (feedfetch.Request, error) {
	source := spec.source
	request := feedfetch.Request{Rsync: spec.format == "rsync", Flex: spec.state == "flex"}
	if source == "" && !spec.synthetic {
		return request, errors.New("empty source")
	}
	if spec.synthetic {
		source = filepath.Join(p.flags.DBDir, spec.header+".txt")
		fetcher.Policy.LocalDirs = addLocalDir(fetcher.Policy.LocalDirs, p.flags.DBDir)
		request.URL = fileFeedURL(source)
	} else if spec.format == "geoip" {
		country := strings.Fields(source)
		if len(country) == 0 || !validFeedWord(country[0]) {
			return request, errors.New("invalid GeoIP source")
		}
		source = filepath.Join(p.flags.GeoIPDir, country[0]+familySuffix(spec.kind)+".txt")
		fetcher.Policy.LocalDirs = addLocalDir(fetcher.Policy.LocalDirs, p.flags.GeoIPDir)
		request.URL = fileFeedURL(source)
	} else {
		request.URL = source
	}
	if spec.credentials != "" {
		request.Username, request.Password, _ = strings.Cut(spec.credentials, ":")
	}
	if spec.bindAddress != "" {
		address, err := netip.ParseAddr(spec.bindAddress)
		if err != nil {
			return request, errors.New("invalid source bind address")
		}
		request.BindAddr = address
	}
	return request, nil
}

func familySuffix(kind string) string {
	switch kind {
	case "ipv4":
		return "_v4"
	case "ipv6":
		return "_v6"
	default:
		return ""
	}
}
func feedPath(feed feedfetch.Feed, suffix string) string {
	return filepath.Join(feed.Dir, feed.Name+suffix)
}

func fileFeedURL(path string) string { return (&url.URL{Scheme: "file", Path: path}).String() }

func addLocalDir(dirs []string, dir string) []string {
	if dir == "" {
		return dirs
	}
	for _, have := range dirs {
		if have == dir {
			return dirs
		}
	}
	return append(dirs, dir)
}

func (p *feedPhaseRunner) parseAndPublish(ctx context.Context, spec phaseFeed, feed feedfetch.Feed, force string, ingest map[string]any,
	disposition string, whoisPartial bool, result FeedPhaseResult, log io.Writer) FeedPhaseResult {
	result.Stage = "normalize"
	norm := feedparse.NormalizeFile(feed.Dir, feed.Name)
	result.NormalizedChanged = norm.Changed
	if ctx.Err() != nil {
		return failedFeed(spec.id, "normalize", "cancelled")
	}
	if force == "none" && spec.preScript == "" && parsedArtifactsExist(feed, spec.kind) && norm.Normalized && !norm.Changed && !whoisPartial {
		result.Disposition, result.Stage, result.Reason = "unchanged", "normalize", "normalized_unchanged"
		return result
	}
	parsePath, contentPath := norm.Path, feedPath(feed, ".orig")
	if spec.preScript != "" {
		script := resolveListScript(spec.preScript, p.flags.ScriptDirs)
		if script == "" {
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_unavailable", true
			return result
		}
		temp, err := os.CreateTemp(feed.Dir, ".pfb-prescript-*")
		if err != nil {
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_stage_failed", true
			return result
		}
		staged := temp.Name()
		if err := temp.Close(); err != nil {
			os.Remove(staged)
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_stage_failed", true
			return result
		}
		out := io.Writer(nil)
		if log != nil {
			out = log
		}
		outcome := feedparse.RunPreScript(ctx, script, norm.Path, staged, out)
		if !outcome.OK {
			result.Disposition, result.Stage, result.Reason, result.PreScriptFailed = "failed", "script", "script_failed", true
			return result
		}
		defer outcome.Cleanup()
		parsePath, contentPath = outcome.Path, outcome.Path
	}
	if ctx.Err() != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "parse", "cancelled"
		return result
	}
	sink := feedparse.Sink{
		Message: func(message string) {
			if log != nil {
				fmt.Fprintf(log, "feed %s: %s\n", spec.id, message)
			}
		},
		Fail: func(record feedparse.FailRecord) {
			if log != nil {
				fmt.Fprintf(log, "feed %s: parse failure at line %d\n", spec.id, record.LineNo)
			}
		},
	}
	if spec.kind == "dnsbl" {
		return p.parseDNSBL(ctx, spec, feed, parsePath, ingest, disposition, result, sink)
	}
	return p.parseIP(ctx, spec, feed, parsePath, contentPath, ingest, disposition, result, sink)
}

func (p *feedPhaseRunner) parseIP(ctx context.Context, spec phaseFeed, feed feedfetch.Feed, parsePath, contentPath string, ingest map[string]any,
	disposition string, result FeedPhaseResult, sink feedparse.Sink) FeedPhaseResult {
	input, err := os.Open(parsePath)
	if err != nil {
		return failedFeed(spec.id, "parse", "normalized_feed_unavailable")
	}
	defer input.Close()
	floorV4 := intSetting(ingest, "suppressionCidrV4")
	if spec.kind == "ipv4" && spec.suppressionCidr > 0 {
		floorV4 = spec.suppressionCidr
	}
	cfg := feedparse.IPConfig{
		VType: familySuffix(spec.kind), PFType: "auto", Custom: spec.custom,
		FloorV4: cidrFloor(floorV4), FloorV6: cidrFloor(intSetting(ingest, "suppressionCidrV6")),
		Suppression: boolSetting(ingest, "suppression"),
	}
	if spec.format == "regex" {
		cfg.PFType = "regex"
	}
	content := feedparse.CountContent(contentPath)
	var parsed feedparse.IPFeed
	staged, err := stageOutput(feed.Dir, ".pfbparsed-", func(writer io.Writer) error {
		var err error
		parsed, err = feedparse.ParseIPFeed(input, cfg, "", content, writer, sink)
		return err
	})
	if err != nil {
		return failedFeed(spec.id, "parse", "ip_parse_failed")
	}
	defer os.Remove(staged)
	result.Disposition, result.Stage = disposition, "parse"
	result.Entries, result.ParseFailures = parsed.Entries, parsed.ParseFail
	result.Suppressed, result.MappedDrops, result.Placeholder = parsed.Suppressed, parsed.MappedDrops, parsed.Placeholder
	if ctx.Err() != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "parse", "cancelled"
		return result
	}
	if err := publishStaged(feed.Dir, []stagedFeedFile{{name: feed.Name + ".parsed.ip", temp: staged}}); err != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	return result
}

func (p *feedPhaseRunner) parseDNSBL(ctx context.Context, spec phaseFeed, feed feedfetch.Feed, parsePath string, ingest map[string]any,
	disposition string, result FeedPhaseResult, sink feedparse.Sink) FeedPhaseResult {
	input, err := os.Open(parsePath)
	if err != nil {
		return failedFeed(spec.id, "parse", "normalized_feed_unavailable")
	}
	defer input.Close()
	var parsed feedparse.DNSBLFeed
	stagedNDJSON, err := stageOutput(feed.Dir, ".pfbparsed-", func(writer io.Writer) error {
		var err error
		parsed, err = feedparse.ParseDNSBLFeed(input, feedparse.DNSBLConfig{
			DNSBLIP: boolSetting(ingest, "dnsblIp"), Lenient: boolSetting(ingest, "dnsblLenient"),
			Custom: spec.custom, Suppression: boolSetting(ingest, "suppression"),
		}, writer, sink)
		return err
	})
	if err != nil {
		return failedFeed(spec.id, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedNDJSON)
	stagedV4, err := stageOutput(feed.Dir, ".pfbparsed-", func(w io.Writer) error { return writeIPSet(w, parsed.IP4) })
	if err != nil {
		return failedFeed(spec.id, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedV4)
	stagedV6, err := stageOutput(feed.Dir, ".pfbparsed-", func(w io.Writer) error { return writeIPSet(w, parsed.IP6) })
	if err != nil {
		return failedFeed(spec.id, "parse", "dnsbl_parse_failed")
	}
	defer os.Remove(stagedV6)
	result.Disposition, result.Stage = disposition, "parse"
	result.DNSBLRows, result.IPv4Count, result.IPv6Count = parsed.Rows, len(parsed.IP4), len(parsed.IP6)
	result.UpdateIP, result.SchemeSkipped, result.HPHostsStop = parsed.UpdateIP, parsed.SchemeSkipped, parsed.Stopped
	if ctx.Err() != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "parse", "cancelled"
		return result
	}
	if err := publishStaged(feed.Dir, []stagedFeedFile{
		{name: feed.Name + ".parsed.ndjson", temp: stagedNDJSON},
		{name: feed.Name + ".parsed.v4.ip", temp: stagedV4},
		{name: feed.Name + ".parsed.v6.ip", temp: stagedV6},
	}); err != nil {
		result.Disposition, result.Stage, result.Reason = "failed", "publish", "parsed_publish_failed"
	}
	return result
}

func writeIPSet(w io.Writer, values []string) error {
	for _, value := range values {
		if _, err := io.WriteString(w, value); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
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

func regularExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func clearForcedState(feed feedfetch.Feed, force string) error {
	for _, suffix := range [...]string{".orig.etag", ".orig.lastmod", ".probe", ".probe.etag", ".probe.lastmod"} {
		if err := removeIfExists(feedPath(feed, suffix)); err != nil {
			return err
		}
	}
	if force == "both" {
		return removeIfExists(feedPath(feed, ".orig.xxhash128"))
	}
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func resolveListScript(name string, dirs []string) string {
	base := filepath.Base(name)
	if base == string(filepath.Separator) {
		base = ""
	}
	if base == "" {
		return ""
	}
	for _, dir := range dirs {
		realDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		realDir, err = filepath.Abs(realDir)
		if err != nil {
			continue
		}
		candidate := filepath.Join(dir, base)
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(real)
		if err == nil && info.Mode().IsRegular() && filepath.Dir(real) == realDir {
			return candidate
		}
	}
	return ""
}

func stageOutput(dir, pattern string, write func(io.Writer) error) (string, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if err = write(file); err == nil {
		err = file.Chmod(0o644)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func publishStaged(dir string, files []stagedFeedFile) error {
	for _, file := range files {
		if filepath.Base(file.name) != file.name || filepath.Dir(file.temp) != dir {
			return errors.New("invalid staged feed file")
		}
		if info, err := os.Lstat(filepath.Join(dir, file.name)); err == nil && !info.Mode().IsRegular() {
			return errors.New("parsed target is not a regular file")
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	backup, err := snapshotTargets(dir, files)
	if err != nil {
		return err
	}
	committed := 0
	for i, file := range files {
		if err := os.Rename(file.temp, filepath.Join(dir, file.name)); err != nil {
			if restoreErr := backup.restoreThrough(committed); restoreErr != nil {
				return errors.Join(err, restoreErr)
			}
			backup.discard()
			return err
		}
		committed = i + 1
	}
	directory, err := os.Open(dir)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	if err != nil {
		if restoreErr := backup.restoreThrough(committed); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		backup.discard()
		return err
	}
	backup.discard()
	return nil
}

func snapshotTargets(dir string, files []stagedFeedFile) (*pathSnapshot, error) {
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = filepath.Join(dir, file.name)
	}
	return snapshotPaths(paths)
}

func feedStatePaths(feed feedfetch.Feed) []string {
	paths := make([]string, 0, 5)
	for _, suffix := range [...]string{".orig", ".orig.xxhash128", ".orig.md5", ".orig.etag", ".orig.lastmod"} {
		paths = append(paths, feedPath(feed, suffix))
	}
	return paths
}

func snapshotPaths(paths []string) (*pathSnapshot, error) {
	backup := &pathSnapshot{items: make([]snapshotItem, 0, len(paths))}
	for _, target := range paths {
		item := snapshotItem{target: target}
		info, err := os.Lstat(target)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			backup.discard()
			return nil, err
		case !info.Mode().IsRegular():
			backup.discard()
			return nil, errors.New("feed artifact is not a regular file")
		default:
			item.existed = true
			item.backup, err = backupFile(target, filepath.Dir(target), info.Mode().Perm())
			if err != nil {
				backup.discard()
				return nil, err
			}
		}
		backup.items = append(backup.items, item)
	}
	return backup, nil
}

func backupFile(source, dir string, mode fs.FileMode) (string, error) {
	placeholder, err := os.CreateTemp(dir, ".pfbbackup-")
	if err != nil {
		return "", err
	}
	name := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := os.Link(source, name); err == nil {
		return name, nil
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(output, input)
	if err == nil {
		err = output.Sync()
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func (s *pathSnapshot) restore() error {
	if err := s.restoreThrough(len(s.items)); err != nil {
		return err
	}
	s.discard()
	return nil
}

func (s *pathSnapshot) keepAbsent(paths ...string) {
	for _, path := range paths {
		for i := range s.items {
			item := &s.items[i]
			if item.target == path {
				item.existed = false
				if item.backup != "" {
					os.Remove(item.backup)
					item.backup = ""
				}
				break
			}
		}
	}
}

func (s *pathSnapshot) restoreThrough(n int) error {
	var first error
	for i := n - 1; i >= 0; i-- {
		item := &s.items[i]
		if item.existed {
			if err := os.Rename(item.backup, item.target); err != nil {
				if first == nil {
					first = err
				}
			} else {
				item.backup = ""
			}
		} else if err := removeIfExists(item.target); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *pathSnapshot) discard() {
	for _, item := range s.items {
		if item.backup != "" {
			os.Remove(item.backup)
		}
	}
}

func sameFileContents(path, want string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("feed source is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if info.Size() != int64(len(want)) {
		return false, nil
	}
	buf := make([]byte, 64<<10)
	for offset := 0; offset < len(want); {
		n := min(len(buf), len(want)-offset)
		if _, err := io.ReadFull(file, buf[:n]); err != nil {
			return false, err
		}
		for i, b := range buf[:n] {
			if b != want[offset+i] {
				return false, nil
			}
		}
		offset += n
	}
	return true, nil
}
