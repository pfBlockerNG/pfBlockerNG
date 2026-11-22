// Package worklist decides the Core Updater's work for one Update (spec §3, stages 3 and 6, and the decision of stage 7):
// which feeds stage 6 checks, in which order, what each feed the per-feed stage runs is handed (feedstage.Change), the
// outcomes stage 17 reports, and whether the pass applies now, is left pending, or does not run. It is today's
// pfb_core_update_run() routing, pfblockerng_sync_cron() walk and pfb_update_check(), held to the corpus
// tests/updateloop/fixtures/worklist/scenarios.json. Its only I/O is the feed folders: feedstage.Recover, the probe, the
// fail marker "<name>.fail" the stage leaves after a failed download (read; removed only where today's walk consumes it),
// and "<name>.probe.src", the source a kept probe body was fetched from. Core keeps no update marker: a change that is not
// built leaves the baseline's validators as they were, so the next probe finds it again.
package worklist

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// Decision is stage 7's answer.
type Decision string

const (
	Now     Decision = "now"     // the pass runs and applies (today's sync_package_pfblockerng(), noupdates included)
	Pending Decision = "pending" // outside the apply window: no build; the apply records the pending work
	Nothing Decision = "nothing" // a scheduled or retry Update with nothing due: no pass at all
)

// The outcomes stage 17 reports for a checked feed (update.Result.Outcomes).
const (
	OutcomeSuccess       = "success"
	OutcomeRetryCapReach = "retry-cap-reached"
)

// Request is the Update's request (update.Request): trigger scheduled, retry, manual or apply; a manual one's scope (ip,
// dnsbl, both) and force (none, parse, download, both). The other triggers' scope and force are not read: Core never sends
// them, and today's program reads them as both and none.
type Request struct {
	Trigger, Scope, Force string
	Feeds                 []string // the feed ids a scheduled or retry Update names
}

// Input is what Build reads. Every path is the stages'.
type Input struct {
	Request Request
	// Settings are the projections as Store.GetClear answers them: feeds/ipv4, feeds/ipv6, feeds/dnsbl and feeds/geoip.
	Settings map[string]map[string]any
	// Stages are the per-feed stages by kind (ipv4, ipv6, dnsbl): their Paths.FeedDir is the kind's feed folder, their
	// Fetcher makes the probe. Two kinds may share a folder.
	Stages map[string]*feedstage.Stage
	// InWindow is stage 7's window test for now (schedule.InApplyWindow), the caller's while the window is in no
	// projection (sub-slice 9c).
	InWindow bool
	// ExtrasChanged: an Extra of this Update changed its data (today's $dcc_changed). PendingApply: the Outpost holds a
	// change that waits for an apply (pfb_core_update_pending_apply()).
	ExtrasChanged, PendingApply bool
	// SkipFeed is the skipfeed limit (0: none) and Failures the failed downloads of each feed today, by its name, before
	// this Update: the caller's, as neither is in a projection (pfb_failures() counts the error log's FAIL lines).
	SkipFeed int
	Failures map[string]int
}

// Item is one feed the per-feed stage runs, in walk order, or one it must not run (Stopped).
type Item struct {
	Feed   feedstage.Feed
	Change feedstage.Change
	// Checked: stage 6 checked the feed (pfb_update_check()), with a probe unless its markers or format decided.
	Checked bool
	Outcome string // OutcomeSuccess, OutcomeRetryCapReach or "": what stage 17 reports for the feed
	// Stopped is why the feed is not run this Update (its folder could not be recovered, or a kept probe or a fail marker
	// could not be handled): no change and no outcome, so the occurrence stays pending.
	Stopped string
}

// Plan is the work list and stage 7's decision.
type Plan struct {
	Items    []Item
	Decision Decision
}

var kinds = []string{"ipv4", "ipv6", "dnsbl"}

// probeFiles are a kept probe body and its validators (feedfetch), and the record of its source.
var probeFiles = []string{".probe", ".probe.etag", ".probe.lastmod", ".probe.size", probeSource}

const probeSource = ".probe.src"

type candidate struct {
	feed  feedstage.Feed
	stage *feedstage.Stage
	dir   string
}

type builder struct {
	ctx       context.Context
	in        Input
	recovered map[string]error
	found     bool // today's $pfb['update_cron']: a check found a change, or asked for the pass
}

// Build decides the work of one Update, after the lifetime lock and the snapshot. It writes only the record of a kept
// probe body's source, by a rename, and it drops a kept probe body whose source is not the feed's now (issue #4038).
func Build(ctx context.Context, in Input) (Plan, error) {
	r := in.Request
	b := &builder{ctx: ctx, in: in, recovered: map[string]error{}}
	switch {
	case r.Trigger == "scheduled" || r.Trigger == "retry":
		return b.scheduled()
	case r.Trigger == "apply":
		// No feed work and no Extras: the apply applies what is published (spec §3, stage 7).
		return Plan{Decision: Now}, nil
	case r.Trigger != "manual":
		return Plan{}, fmt.Errorf("trigger %q is no Update trigger", r.Trigger)
	case !slices.Contains([]string{"ip", "dnsbl", "both"}, r.Scope):
		return Plan{}, fmt.Errorf("scope %q is no Update scope", r.Scope)
	case !slices.Contains([]string{"none", "parse", "download", "both"}, r.Force):
		return Plan{}, fmt.Errorf("force %q is no Update force", r.Force)
	case r.Force == "none" || r.Force == "parse":
		return b.pass(r.Scope, r.Force)
	}
	// A Force Check walks every feed of the scope and hands the stage the force, which downloads (pfblockerng_sync_cron()
	// with $force_all; the stage drops the validators, and for both the digests, as pfb_force_clear_validators()).
	return b.walk(r.Scope, true, nil)
}

// scheduled is pfb_core_update_scheduled(): a walk when a feed is named or a fail marker asks for one, else the pass of a
// changed Extra.
func (b *builder) scheduled() (Plan, error) {
	cands, err := b.candidates("both", true)
	if err != nil {
		return Plan{}, err
	}
	due := len(b.in.Request.Feeds) > 0 || slices.ContainsFunc(cands, func(c candidate) bool { return present(c.path(".fail")) })
	switch {
	case due:
		pending := map[string]bool{}
		for _, id := range b.in.Request.Feeds {
			pending[id] = true
		}
		return b.walk("both", false, pending)
	case !b.in.ExtrasChanged:
		return Plan{Decision: Nothing}, nil
	case !b.in.InWindow:
		return Plan{Decision: Pending}, nil
	}
	return b.pass("both", "none")
}

// pass is a pass without a check (today's sync_package_pfblockerng() called directly): every feed of the scope, a feed
// with a fail marker or without its lists downloaded, any other reused, or every one parsed again for force parse.
func (b *builder) pass(scope, force string) (Plan, error) {
	cands, err := b.candidates(scope, false)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Decision: Now}
	for _, c := range cands {
		item, ok := b.prepare(c)
		if ok && !c.feed.Custom {
			item.Change.Verdict = feedstage.VerdictUnchanged
			if present(c.path(".fail")) || !feedstage.ListsPublished(c.dir, c.feed) {
				item.Change.Verdict = feedstage.VerdictChanged
			}
		}
		if item.Stopped == "" {
			item.Change.Force = force
		}
		plan.Items = append(plan.Items, item)
	}
	return plan, nil
}

// walk is pfblockerng_sync_cron(): a scheduled walk checks the feeds Core named and every feed with a fail marker; a Force
// Check (forceAll) every feed of the scope.
func (b *builder) walk(scope string, forceAll bool, pending map[string]bool) (Plan, error) {
	cands, err := b.candidates(scope, true)
	if err != nil {
		return Plan{}, err
	}
	force := "none"
	if forceAll {
		force = b.in.Request.Force
	}
	var plan Plan
	for _, c := range cands {
		id := c.feed.ID
		if c.feed.State == "hold" && feedstage.ListsPublished(c.dir, c.feed) {
			// Hold with its list stands: not checked, and a named feed is a success. The stage removes a fail marker only
			// after a download, which a held feed never makes, so the walk consumes it as today's does: else the marker would
			// add the feed to every later walk.
			if !forceAll && !pending[id] {
				continue
			}
			item, ok := b.prepare(c)
			if ok {
				if err := removeIfExists(c.path(".fail")); err != nil {
					item = Item{Feed: c.feed, Stopped: "fail_marker_remove_failed"}
				} else {
					item.Change = feedstage.Change{Verdict: feedstage.VerdictUnchanged, Force: force}
					if pending[id] {
						item.Outcome = OutcomeSuccess
					}
				}
			}
			plan.Items = append(plan.Items, item)
			continue
		}
		if !forceAll && !pending[id] && !present(c.path(".fail")) {
			continue
		}
		item, ok := b.prepare(c)
		if ok {
			item.Checked = true
			if !forceAll {
				item = b.check(c, item)
			}
			if item.Stopped == "" {
				item.Change.Force = force
			}
		}
		plan.Items = append(plan.Items, item)
	}
	if forceAll {
		plan.Decision = Now
		return plan, nil
	}
	if !b.found {
		b.found = b.continentEnabled()
	}
	switch {
	case b.found && !b.in.InWindow:
		plan.Decision = Pending
	case !b.found && (b.in.ExtrasChanged || b.in.PendingApply) && !b.in.InWindow:
		plan.Decision = Pending
	default:
		plan.Decision = Now // a change applied, or today's no-update pass
	}
	return plan, nil
}

// prepare makes the feed's folder and kept probe safe to read: the folder recovered (feedstage.Recover, once per folder)
// and a probe body kept for another source dropped. A feed it cannot prepare is stopped.
func (b *builder) prepare(c candidate) (Item, bool) {
	item := Item{Feed: c.feed}
	err, done := b.recovered[c.dir]
	if !done {
		err = feedstage.Recover(c.dir)
		b.recovered[c.dir] = err
	}
	if err != nil {
		item.Stopped = "feed_folder_unrecoverable"
		return item, false
	}
	if source, ok := probeIdentity(c); ok && dropStaleProbe(c, source) != nil {
		item.Stopped = "probe_unavailable"
		return item, false
	}
	return item, true
}

// check is pfb_update_check() for a feed of a scheduled walk, rule by rule in today's order.
func (b *builder) check(c candidate, item Item) Item {
	changed := func(outcome string) Item {
		b.found = true
		item.Change.Verdict, item.Outcome = feedstage.VerdictChanged, outcome
		return item
	}
	unchanged := func(outcome string) Item {
		item.Change.Verdict, item.Outcome = feedstage.VerdictUnchanged, outcome
		return item
	}
	failed := func(reason string) Item {
		item.Change.Verdict, item.Change.Reason = feedstage.VerdictFailed, reason
		return item
	}
	return b.verdict(c, changed, unchanged, failed)
}

func (b *builder) verdict(c candidate, changed, unchanged, failed func(string) Item) Item {
	f := c.feed
	switch f.Format {
	case "whois", "asn":
		// Resolved again every run: valid source, a change (today's "Update found").
		if !validListSource(f) {
			return failed("feed_source_invalid")
		}
		return changed(OutcomeSuccess)
	}
	request, reason := c.stage.Request(f)
	if reason != "" {
		return failed(reason) // today's "Invalid URL": no outcome
	}
	if b.in.SkipFeed != 0 && b.in.Failures[f.Name] >= b.in.SkipFeed {
		// Not downloaded, so no stage run removes the marker: consumed here, as pfb_update_check() does.
		if removeIfExists(c.path(".fail")) != nil {
			return Item{Feed: f, Stopped: "fail_marker_remove_failed"}
		}
		return unchanged(OutcomeRetryCapReach)
	}
	if present(c.path(".fail")) {
		return changed("") // re-attempted, with no outcome until it succeeds
	}
	if !feedstage.ListsPublished(c.dir, f) {
		return changed("")
	}
	info, err := os.Lstat(c.path(".orig"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return changed(OutcomeSuccess)
	case err != nil || !info.Mode().IsRegular():
		return failed("baseline_unavailable")
	case f.Format == "rsync":
		return changed(OutcomeSuccess)
	}
	probe := c.stage.Fetcher.Probe(b.ctx, feedfetch.Feed{Dir: c.dir, Name: f.Name}, request)
	switch probe.Decision {
	case feedfetch.Unchanged:
		return unchanged(OutcomeSuccess)
	case feedfetch.Changed:
		if source, ok := probeIdentity(c); ok && regularExists(c.path(".probe")) && writeWhole(c.path(probeSource), source) != nil {
			return Item{Feed: f, Stopped: "probe_source_write_failed"}
		}
		return changed(OutcomeSuccess)
	}
	// No outcome keeps the occurrence pending, so the retry names the feed again; the stage owns the fail marker.
	return failed(cmp.Or(probe.Reason, "feed_probe_failed"))
}

// validListSource is today's check of a whois feed's domain or an asn feed's AS number, cut at its first space.
func validListSource(f feedstage.Feed) bool {
	source, _, _ := strings.Cut(f.Source, " ")
	source = strings.Trim(source, " \t\n\r\x00\x0b")
	if source == "" || strings.ContainsFunc(source, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return false
	}
	if f.Format == "asn" {
		return !strings.ContainsFunc(source, func(r rune) bool {
			return (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
		})
	}
	return true
}

func (b *builder) continentEnabled() bool {
	for _, group := range list(b.in.Settings["feeds/geoip"], "groups") {
		if action := text(group, "action"); action != "" && action != "Disabled" {
			return true
		}
	}
	return false
}

// candidates are the feeds of the scope's kinds in today's walk order: IPv4, IPv6, DNSBL, groups and rows in config order.
// A group that is Disabled, a row that is disabled or has no source, and for a walk (cron) a group updated Never are left
// out; a pass also runs each group's custom list after its rows.
func (b *builder) candidates(scope string, cron bool) ([]candidate, error) {
	var out []candidate
	for _, kind := range kinds {
		if scope != "both" && (scope == "dnsbl") != (kind == "dnsbl") {
			continue
		}
		for _, group := range list(b.in.Settings["feeds/"+kind], "groups") {
			if action := text(group, "action"); action == "" || action == "Disabled" ||
				cron && text(group, "updateFrequency") == "Never" {
				continue
			}
			var feeds []feedstage.Feed
			for _, row := range list(group, "feeds") {
				if text(row, "state") == "disabled" || text(row, "url") == "" {
					continue
				}
				feeds = append(feeds, feedFor(kind, group, row))
			}
			if custom := text(group, "customList"); !cron && custom != "" {
				feeds = append(feeds, customFeedFor(kind, group, custom))
			}
			for _, f := range feeds {
				stage := b.in.Stages[kind]
				if stage == nil || stage.Fetcher == nil {
					return nil, fmt.Errorf("no feed stage for %s feeds", kind)
				}
				f.SkipFeedPassed = b.in.SkipFeed != 0 && b.in.Failures[f.Name] >= b.in.SkipFeed
				out = append(out, candidate{feed: f, stage: stage, dir: stage.Paths.FeedDir})
			}
		}
	}
	return out, nil
}

// feedFor is a feed row as the stage reads it. The projection's format is the adapter's, lower-cased
// (pfb_core_feed_rows_native()): a format stored "Regex", which today's pass runs as auto, arrives as regex.
func feedFor(kind string, group, row map[string]any) feedstage.Feed {
	name := text(row, "header") + suffix(kind)
	f := feedstage.Feed{ID: kind + ":" + name, Kind: kind, Name: name, State: text(row, "state"), Format: text(row, "format"),
		Source: text(row, "url"), PreScript: text(group, "preScript"), PostScript: text(group, "postScript"),
		SuppressionCIDR: number(group, "suppressionCidr")}
	f.Username, f.Password = credentials(text(row, "credentials"))
	if addr, err := netip.ParseAddr(text(group, "bindAddress")); err == nil {
		f.BindAddress = addr
	}
	return f
}

// customFeedFor is a group's custom list, the feed "<group>_custom<suffix>" today's pass runs.
func customFeedFor(kind string, group map[string]any, custom string) feedstage.Feed {
	name := text(group, "name")
	whois, _ := group["whoisConvert"].(bool)
	return feedstage.Feed{ID: "custom:" + kind + ":" + name, Kind: kind, Name: name + "_custom" + suffix(kind),
		State: "enabled", Format: "auto", Custom: true, CustomText: custom, WhoisConvert: whois,
		PreScript: text(group, "preScript"), PostScript: text(group, "postScript"), SuppressionCIDR: number(group, "suppressionCidr")}
}

// credentials splits a URL's userinfo as cURL reads it: percent-decoded, the password after the first colon.
func credentials(userinfo string) (string, string) {
	if userinfo == "" {
		return "", ""
	}
	if u, err := url.Parse("http://" + userinfo + "@h"); err == nil && u.User != nil {
		password, _ := u.User.Password()
		return u.User.Username(), password
	}
	user, password, _ := strings.Cut(userinfo, ":")
	return user, password
}

func suffix(kind string) string { return map[string]string{"ipv4": "_v4", "ipv6": "_v6"}[kind] }

func (c candidate) path(suffix string) string { return filepath.Join(c.dir, c.feed.Name+suffix) }

// probeIdentity names the source a kept probe body stands for: the transfer request's URL and credentials, by a digest,
// so the record beside the body holds no credential. A feed that transfers nothing has none.
func probeIdentity(c candidate) (string, bool) {
	if c.feed.Custom || c.feed.Format == "whois" || c.feed.Format == "asn" {
		return "", false
	}
	request, reason := c.stage.Request(c.feed)
	if reason != "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{request.URL, request.Username, request.Password,
		strconv.FormatBool(request.Rsync)}, "\x00")))
	return hex.EncodeToString(sum[:]), true
}

// dropStaleProbe removes a kept probe body, its validators and its record unless the record names source: the next
// ingest publishes a kept body without fetching (feedfetch), so a body fetched for another source must never reach it.
func dropStaleProbe(c candidate, source string) error {
	if !present(c.path(".probe")) {
		return removeIfExists(c.path(probeSource))
	}
	if recorded, err := readRecord(c.path(probeSource)); err == nil && recorded == source {
		return nil
	}
	var errs []error
	for _, suffix := range probeFiles {
		errs = append(errs, removeIfExists(c.path(suffix)))
	}
	return errors.Join(errs...)
}

// readRecord reads a small regular file without following a link or waiting on a FIFO.
func readRecord(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return "", errors.New("record is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	return string(data), err
}

// writeWhole writes path whole: a temporary beside it, renamed over it.
func writeWhole(path, content string) error {
	part := path + ".part"
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o644)
	if err != nil {
		return err
	}
	_, err = io.WriteString(file, content)
	if err = errors.Join(err, file.Close()); err == nil {
		err = os.Rename(part, path)
	}
	if err != nil {
		os.Remove(part)
	}
	return err
}

func present(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func regularExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func text(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}

func number(m map[string]any, key string) int {
	switch value := m[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		n, _ := strconv.Atoi(string(value))
		return n
	}
	return 0
}

func list(m map[string]any, key string) []map[string]any {
	values, _ := m[key].([]any)
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if row, ok := value.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}
