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
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
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

// Input is what Build reads. Every path is the stages'.
type Input struct {
	// Trigger, Scope, Force and Feeds are the Update's request (update.Request): trigger scheduled, retry, manual or apply;
	// a manual one's scope (ip, dnsbl, both) and force (none, parse, download, both). The other triggers' scope and force
	// are not read: Core never sends them, and today's program reads them as both and none.
	Trigger, Scope, Force string
	Feeds                 []string // the feed ids a scheduled or retry Update names
	// PendingFeeds are the feeds earlier Updates left to the apply (Plan.PendingFeeds), which the Core Updater's state
	// carries (sub-slice 9i).
	PendingFeeds []string
	// Settings are the projections as Store.GetClear answers them: feeds/ipv4, feeds/ipv6, feeds/dnsbl and feeds/geoip.
	Settings map[string]map[string]any
	// Stages are the per-feed stages by kind (ipv4, ipv6, dnsbl): their Paths.FeedDir is the kind's feed folder, their
	// Fetcher makes the probe. Two kinds may share a folder.
	Stages map[string]*feedstage.Stage
	// InWindow is stage 7's window test for now, the caller's: schedule.InApplyWindow on the snapshot's
	// ingest.applyWindow, in the zone today's date() reads (the scheduler's), once sub-slice 9i wires the loop.
	InWindow bool
	// ExtrasChanged: an Extra of this Update changed its data (today's $dcc_changed). PendingApply: the Outpost holds a
	// change that waits for an apply (pfb_core_update_pending_apply()).
	ExtrasChanged, PendingApply bool
	// GeoIPChanged: this Update's GeoIP conversion changed the country lists (the Extras stage, sub-slice 9f; today's
	// geoip.update).
	GeoIPChanged bool
	// ManifestMissing: the DNSBL manifest is absent while the DNSBL hosts module is on, as pfb_core_update_retry_due()
	// reads it; supplied by the Core Updater (sub-slice 9i) from the DNSBL publication (sub-slice 9g).
	ManifestMissing bool
	// SkipFeed is the skipfeed limit (0: none) and Failures the failed downloads of each feed today, by its name, before
	// this Update: the caller's, as neither is in a projection (pfb_failures() counts the error log's FAIL lines).
	SkipFeed int
	Failures map[string]int
	// BlacklistDir is the database folder ($pfb['dbdir']) the Extras stage publishes each Blacklist provider into: the
	// category <id>/<id>_<category> and, after a new download, the provider's update marker <id>/<id>.update. Each
	// selected category of schedule's categoryProviders (Settings["schedule"], categoryUpdates on) is a DNSBL feed
	// "<title>_<category>" read from that file, as today's pass lists it; empty: no category is run.
	BlacklistDir string
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
	// Marker is a Blacklist category's provider update marker, when it exists: the caller removes it once every category
	// of the provider ran without failing or stopping, as today's pass consumes it.
	Marker string
}

// Plan is the work list and stage 7's decision.
type Plan struct {
	Items    []Item
	Decision Decision
	// PendingFeeds are the feeds still pending once this plan is run: the caller's next state (Input.PendingFeeds). A
	// Pending decision builds nothing, so they are Input.PendingFeeds and the feeds this Update found changed, but for the
	// feeds it settled as an applied pass would: held, or checked unchanged or past the retry cap. Any other
	// decision hands every pending feed it can to the stage: as changed, unless the walk checked it, whose verdict stands;
	// a held feed with its list is held, and counts as built, as does a feed its check found unchanged or past the retry
	// cap (its fail marker consumed, as today, so no later Update builds it past the cap). What stays are the feeds it could
	// not build and that can be built later without a settings change: outside the scope, under a Reload, failed by its
	// check, or stopped for a reason that can clear (its folder unrecoverable, its kept probe or its fail marker not
	// handled). A feed that can never be built without a settings change is dropped: it left the settings, its name is no
	// word, the stage refuses its source (feed_source_invalid: today's "Invalid URL" and the like; not a refusal of the
	// stage's own configuration, which clears when the Core Updater's paths change), or it is a whois or asn feed whose
	// source today's check refuses while its list stands. A stopped feed stays pending but makes no scheduled Update due by
	// itself.
	PendingFeeds []string
}

var kinds = []string{"ipv4", "ipv6", "dnsbl"}

type candidate struct {
	feed   feedstage.Feed
	stage  *feedstage.Stage
	dir    string
	walked bool   // a feed the walk visits: a feed row of a group not updated Never
	stop   string // why the feed is stopped before any file of it is read: its folder or its name
	marker string // a Blacklist category's provider update marker
}

type builder struct {
	ctx        context.Context
	in         Input
	recovered  map[string]error // Recover's answer per feed folder
	configured []string         // the feed ids of the settings, in walk order
	pending    map[string]bool  // the feeds to build: Input.PendingFeeds, and every geoip feed after a GeoIP change
}

// Build decides the work of one Update, after the lifetime lock and the snapshot. It writes only the record of a kept
// probe body's source, by a rename, and it drops a kept probe body whose source is not the feed's now (issue #4038).
func Build(ctx context.Context, in Input) (Plan, error) {
	b := &builder{ctx: ctx, in: in, recovered: map[string]error{}}
	scope := "both"
	if in.Trigger == "manual" {
		switch {
		case !slices.Contains([]string{"ip", "dnsbl", "both"}, in.Scope):
			return Plan{}, fmt.Errorf("scope %q is no Update scope", in.Scope)
		case !slices.Contains([]string{"none", "parse", "download", "both"}, in.Force):
			return Plan{}, fmt.Errorf("force %q is no Update force", in.Force)
		}
		scope = in.Scope
	} else if !slices.Contains([]string{"scheduled", "retry", "apply"}, in.Trigger) {
		return Plan{}, fmt.Errorf("trigger %q is no Update trigger", in.Trigger)
	}
	b.pending = map[string]bool{}
	for _, f := range b.feeds("both") {
		if !f.Custom && f.marker == "" {
			b.configured = append(b.configured, f.ID)
			b.pending[f.ID] = feedstage.ValidName(f.Name) &&
				(slices.Contains(in.PendingFeeds, f.ID) || in.GeoIPChanged && f.Format == "geoip")
		}
	}
	var want func(id string) bool
	if in.Trigger == "apply" {
		want = func(id string) bool { return b.pending[id] } // an apply reads the pending feeds' folders only
	}
	cands, err := b.candidates(scope, want)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	switch {
	case in.Trigger == "scheduled" || in.Trigger == "retry":
		plan = b.scheduled(cands)
	case in.Trigger == "apply":
		plan = Plan{Decision: Now} // exactly the pending feeds, which settle adds: no probe, no outcome, no Extras
	case in.Force == "none" || in.Force == "parse":
		plan = b.pass(cands, in.Force)
	default:
		// A Force Check walks every feed of the scope and hands the stage the force, which downloads
		// (pfblockerng_sync_cron() with $force_all; the stage drops the validators, and for both the digests, as
		// pfb_force_clear_validators()).
		plan = b.walk(cands, true, nil)
	}
	return b.settle(plan, cands), nil
}

// buildable reports whether a pending feed of cands can be built now: one stopped already makes no Update due.
func (b *builder) buildable(cands []candidate) bool {
	return slices.ContainsFunc(cands, func(c candidate) bool { return b.pending[c.feed.ID] && c.stop == "" && !b.never(c) })
}

// never reports whether c can never be built without a settings change: the stage refuses its source
// (feed_source_invalid; a refusal of the stage's own configuration, such as no rsync program or no GeoIP folder, clears
// when the Core Updater's paths change), or it is a whois or asn feed whose source today's check refuses while its list
// stands (a name that is no word is never pending).
func (b *builder) never(c candidate) bool {
	if c.feed.Custom {
		return false
	}
	if c.feed.Format != "whois" && c.feed.Format != "asn" {
		_, reason := c.stage.Request(c.feed)
		return reason == "feed_source_invalid"
	}
	return refusedListSource(c)
}

// refusedListSource reports whether c is a whois or asn feed whose source today's check refuses while its list stands:
// today's pass reuses the list, which a stage run would resolve again, so the feed is not run.
func refusedListSource(c candidate) bool {
	return (c.feed.Format == "whois" || c.feed.Format == "asn") && !validListSource(c.feed) && c.stop == "" &&
		feedstage.ListsPublished(c.dir, c.feed)
}

// stillPending are the feeds of the settings, in walk order, pending or in extra and not done, without those that can
// never be built.
func (b *builder) stillPending(cands []candidate, done map[string]bool, extra []string) []string {
	never := map[string]bool{}
	for _, c := range cands {
		never[c.feed.ID] = b.never(c)
	}
	var out []string
	for _, id := range b.configured {
		if (b.pending[id] || slices.Contains(extra, id)) && !done[id] && !never[id] {
			out = append(out, id)
		}
	}
	return out
}

// settle hands every pending feed of a plan that builds to the stage, and sets what stays pending.
func (b *builder) settle(plan Plan, cands []candidate) Plan {
	switch plan.Decision {
	case Pending:
		return plan
	case Nothing:
		plan.PendingFeeds = b.stillPending(cands, nil, nil)
		return plan
	}
	items := map[string]Item{}
	for _, item := range plan.Items {
		items[item.Feed.ID] = item
	}
	plan.Items = nil
	done := map[string]bool{}
	for _, c := range cands {
		item, ok := items[c.feed.ID]
		if b.pending[c.feed.ID] && !b.never(c) {
			item, done[c.feed.ID] = b.build(c, item, ok)
			ok = true
		}
		if ok {
			plan.Items = append(plan.Items, item)
		}
	}
	plan.PendingFeeds = b.stillPending(cands, done, nil)
	return plan
}

// build is the item of a pending feed, and whether it leaves pending: a feed the plan runs anyway is handed to the stage
// as changed, unless its force already downloads it, a Reload parses it from the baseline, or the walk checked it, whose
// verdict stands (past the retry cap or failed, it stays pending); a held feed with its list is held, as the walk holds
// it.
func (b *builder) build(c candidate, item Item, planned bool) (Item, bool) {
	held := c.stop == "" && c.feed.State == "hold" && feedstage.ListsPublished(c.dir, c.feed)
	switch {
	case !planned && held:
		item = b.hold(c, "none")
		return item, item.Stopped == ""
	case !planned && transfers(c.feed):
		// A refusal of the stage's own configuration (no rsync program) fails the feed, as the walk's check does, and
		// keeps it pending until the configuration clears (a refused source is never pending here).
		if _, reason := c.stage.Request(c.feed); reason != "" {
			return b.prepare(c, feedstage.Change{Verdict: feedstage.VerdictFailed, Reason: reason, Force: "none"}), false
		}
		fallthrough
	case !planned:
		item = b.prepare(c, feedstage.Change{Verdict: feedstage.VerdictChanged, Force: "none"})
		return item, item.Stopped == ""
	case item.Stopped != "" || item.Change.Force == "parse":
		return item, false
	case held:
		item = b.consumeFail(c, item)
		item.Change.Verdict = feedstage.VerdictUnchanged
		return item, item.Stopped == ""
	case item.Change.Force == "download" || item.Change.Force == "both":
		return item, true
	case item.Checked:
		return item, item.Change.Verdict != feedstage.VerdictFailed
	}
	item.Change.Verdict, item.Change.Reason = feedstage.VerdictChanged, ""
	return item, true
}

// hold is the walk's rule for a held feed with its list: not checked and not built. The stage removes a fail marker only
// after a download, which a held feed never makes, so the walk consumes it for every held feed, as today's does: else the
// marker would make every later scheduled Update due.
func (b *builder) hold(c candidate, force string) Item {
	return b.consumeFail(c, b.prepare(c, feedstage.Change{Verdict: feedstage.VerdictUnchanged, Force: force}))
}

// consumeFail removes a held feed's fail marker, and stops the feed when it cannot.
func (b *builder) consumeFail(c candidate, item Item) Item {
	if item.Stopped == "" && removeIfExists(c.path(".fail")) != nil {
		return Item{Feed: c.feed, Stopped: "fail_marker_remove_failed"}
	}
	return item
}

// scheduled is pfb_core_update_scheduled(): a walk when a feed is named, a fail marker or the missing DNSBL manifest asks
// for one, else the pass of a changed Extra.
func (b *builder) scheduled(cands []candidate) Plan {
	due := len(b.in.Feeds) > 0 || b.in.ManifestMissing || b.buildable(cands) || slices.ContainsFunc(cands, func(c candidate) bool {
		return c.walked && c.stop == "" && present(c.path(".fail")) || c.downloaded()
	})
	switch {
	case due:
		pending := map[string]bool{}
		for _, id := range b.in.Feeds {
			pending[id] = true
		}
		return b.walk(cands, false, pending)
	case !b.in.ExtrasChanged:
		return Plan{Decision: Nothing}
	case !b.in.InWindow:
		return b.deferred(Plan{}, cands, nil, nil)
	}
	return b.pass(cands, "none")
}

// deferred makes plan a Pending decision: the feeds of the settings, in walk order, that earlier Updates left pending or this
// one found changed are left to the apply, but for those done: settled by this Update as an applied pass would settle them.
func (b *builder) deferred(plan Plan, cands []candidate, changed []string, done map[string]bool) Plan {
	plan.Decision, plan.PendingFeeds = Pending, b.stillPending(cands, done, changed)
	return plan
}

// pass is a pass without a check (today's sync_package_pfblockerng() called directly): every feed of the scope, a feed
// with a fail marker or without its lists downloaded, any other reused, or every one parsed again for force parse.
func (b *builder) pass(cands []candidate, force string) Plan {
	plan := Plan{Decision: Now}
	for _, c := range cands {
		switch {
		case force != "parse" && c.stop == "" && c.feed.State == "hold" && feedstage.ListsPublished(c.dir, c.feed):
			plan.Items = append(plan.Items, b.hold(c, force)) // held, as the walk holds it; a Reload is never held
			continue
		case refusedListSource(c) && (force != "parse" || !regularExists(c.path(".orig"))):
			// A Reload parses a saved baseline again without resolving the source.
			plan.Items = append(plan.Items, Item{Feed: c.feed, Stopped: "feed_source_invalid"}) // as the check stops it
			continue
		}
		change := feedstage.Change{Force: force}
		// A custom list compares its own text, and a Reload reads no verdict (feedstage).
		if !c.feed.Custom && force == "none" {
			change.Verdict = feedstage.VerdictUnchanged
			if c.stop == "" && (present(c.path(".fail")) || !feedstage.ListsPublished(c.dir, c.feed) || c.downloaded()) {
				change.Verdict = feedstage.VerdictChanged
			}
		}
		plan.Items = append(plan.Items, b.prepare(c, change))
	}
	return plan
}

// walk is pfblockerng_sync_cron(): a scheduled walk checks the feeds Core named and every feed with a fail marker; a Force
// Check (forceAll) runs every feed of the scope with the force, unchecked.
func (b *builder) walk(cands []candidate, forceAll bool, pending map[string]bool) Plan {
	force := "none"
	if forceAll {
		force = b.in.Force
	}
	var plan Plan
	found := b.buildable(cands) // today's $pfb['update_cron']: a check found a change, or feeds are left to build
	var changed []string        // the feeds today's check marks for an update ({header}.update)
	for _, c := range cands {
		id := c.feed.ID
		selected := forceAll || pending[id]
		switch {
		case c.marker != "":
			// A category is never checked: built after its provider's download, or by a Force Check.
			if forceAll || c.downloaded() {
				found = found || !forceAll
				plan.Items = append(plan.Items, b.prepare(c, feedstage.Change{Verdict: feedstage.VerdictChanged, Force: force}))
			}
			continue
		case !c.walked:
			continue
		case c.stop == "" && c.feed.State == "hold" && feedstage.ListsPublished(c.dir, c.feed):
			// A named feed is a success; a held feed that cannot be prepared is reported, named or not.
			item := b.hold(c, force)
			if item.Stopped == "" && pending[id] {
				item.Outcome = OutcomeSuccess
			}
			if selected || item.Stopped != "" {
				plan.Items = append(plan.Items, item)
			}
			continue
		case !selected && (c.stop != "" || !present(c.path(".fail"))):
			continue
		}
		item := b.prepare(c, feedstage.Change{Force: force})
		if item.Stopped == "" && !forceAll {
			v := b.check(c)
			found = found || v.found
			if v.marked {
				changed = append(changed, id)
			}
			item.Change.Verdict, item.Change.Reason, item.Outcome, item.Stopped = v.verdict, v.reason, v.outcome, v.stop
			item.Checked = v.stop == ""
			if v.stop != "" {
				item.Change = feedstage.Change{}
			}
		}
		plan.Items = append(plan.Items, item)
	}
	// An enabled continent asks for the pass as a found change does; outside the window the pass waits for the apply.
	if !forceAll && !b.in.InWindow && (found || b.continentEnabled() || b.in.ExtrasChanged || b.in.PendingApply) {
		// A feed held, or checked unchanged or past the retry cap (its fail marker consumed), is settled as an applied
		// pass settles it: the apply must not build it past the cap.
		done := map[string]bool{}
		for _, item := range plan.Items {
			done[item.Feed.ID] = item.Stopped == "" && item.Change.Verdict == feedstage.VerdictUnchanged
		}
		return b.deferred(plan, cands, changed, done)
	}
	plan.Decision = Now // a change applied, or today's no-update pass
	return plan
}

// prepare is the item of a feed with change, its kept probe body dropped when it was fetched for another source. A feed it
// cannot prepare is stopped, with no change.
func (b *builder) prepare(c candidate, change feedstage.Change) Item {
	item := Item{Feed: c.feed, Change: change}
	switch source, ok := probeIdentity(c); {
	case c.stop != "":
		item = Item{Feed: c.feed, Stopped: c.stop}
	case ok && dropStaleProbe(c, source) != nil:
		item = Item{Feed: c.feed, Stopped: "probe_unavailable"}
	}
	if c.marker != "" && present(c.marker) {
		item.Marker = c.marker
	}
	return item
}

// downloaded reports whether c is a Blacklist category whose provider the Extras stage downloaded anew.
func (c candidate) downloaded() bool { return c.marker != "" && c.stop == "" && present(c.marker) }

// verdict is what check decided for one feed: stage 6's answer, the outcome, or why the feed stops, whether today's check
// sets $pfb['update_cron'] (found), and whether the feed is left to the apply when the window defers its build (marked).
type verdict struct {
	verdict       feedstage.Verdict
	reason        string
	outcome       string
	stop          string
	found, marked bool
}

// changed is a change found: today's "Update found", which marks the feed for an update.
func changed(outcome string) verdict {
	return verdict{verdict: feedstage.VerdictChanged, outcome: outcome, found: true, marked: true}
}

// check is pfb_update_check() for a feed of a scheduled walk, rule by rule in today's order.
func (b *builder) check(c candidate) verdict {
	f := c.feed
	switch f.Format {
	case "whois", "asn":
		// Resolved again every run (today's "Update found"). A source today's check refuses ("Invalid WHOIS", "Invalid
		// ASN") gives no outcome: today's pass reuses a published list, which a stage run would resolve again, so the feed
		// is not run; without a list the pass downloads it and fails, as the stage's resolution does.
		switch {
		case validListSource(f):
			return changed(OutcomeSuccess)
		case refusedListSource(c):
			return verdict{stop: "feed_source_invalid"}
		}
		return verdict{verdict: feedstage.VerdictChanged, marked: true}
	}
	request, reason := c.stage.Request(f)
	if reason != "" {
		return verdict{verdict: feedstage.VerdictFailed, reason: reason} // today's "Invalid URL": no outcome
	}
	if b.in.SkipFeed != 0 && b.in.Failures[f.Name] >= b.in.SkipFeed {
		// Not downloaded, so no stage run removes the marker: consumed here, as pfb_update_check() does.
		if removeIfExists(c.path(".fail")) != nil {
			return verdict{stop: "fail_marker_remove_failed"}
		}
		return verdict{verdict: feedstage.VerdictUnchanged, outcome: OutcomeRetryCapReach}
	}
	if present(c.path(".fail")) {
		return changed("") // re-attempted, with no outcome until it succeeds
	}
	if !feedstage.ListsPublished(c.dir, f) {
		// Today's check marks no update for a missing list, which its pass and its pending apply download.
		return verdict{verdict: feedstage.VerdictChanged, found: true, marked: true}
	}
	info, err := os.Lstat(c.path(".orig"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return changed(OutcomeSuccess)
	case err != nil || !info.Mode().IsRegular():
		return verdict{verdict: feedstage.VerdictFailed, reason: "baseline_unavailable"}
	case f.Format == "rsync":
		return changed(OutcomeSuccess)
	}
	probe := c.stage.Fetcher.Probe(b.ctx, feedfetch.Feed{Dir: c.dir, Name: f.Name}, request)
	switch probe.Decision {
	case feedfetch.Unchanged:
		return verdict{verdict: feedstage.VerdictUnchanged, outcome: OutcomeSuccess}
	case feedfetch.Changed:
		if source, ok := probeIdentity(c); ok && regularExists(c.path(".probe")) &&
			writeWhole(c.path(feedstage.ProbeSource), source) != nil {
			return verdict{stop: "probe_source_write_failed"}
		}
		return changed(OutcomeSuccess)
	}
	// No outcome keeps the occurrence pending, so the retry names the feed again; the stage owns the fail marker.
	return verdict{verdict: feedstage.VerdictFailed, reason: cmp.Or(probe.Reason, "feed_probe_failed")}
}

// validListSource is today's check of a whois feed's domain (PFB_FILTER_DOMAIN) or an asn feed's AS number, cut at its
// first space.
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
	return feedparse.DomainOK(source)
}

// transfers reports whether the stage transfers f's source: not a custom list, a whois or an asn feed.
func transfers(f feedstage.Feed) bool {
	return !f.Custom && f.Format != "whois" && f.Format != "asn"
}

func (b *builder) continentEnabled() bool {
	for _, group := range list(b.in.Settings["feeds/geoip"], "groups") {
		if action := text(group, "action"); action != "" && action != "Disabled" {
			return true
		}
	}
	return false
}

// listed is a feed of the settings, and whether the walk (pfblockerng_sync_cron()) visits it: a feed row of a group not
// updated Never.
type listed struct {
	feedstage.Feed
	walked bool
	marker string
	taken  bool // a Blacklist category whose feed name a configured DNSBL feed holds
}

// feeds are the feeds of the scope's kinds in today's walk order: IPv4, IPv6, DNSBL, groups and rows in config order,
// each group's custom list after its rows. A group that is Disabled and a row that is disabled or has no source are left
// out.
func (b *builder) feeds(scope string) []listed {
	var out []listed
	for _, kind := range kinds {
		if scope != "both" && (scope == "dnsbl") != (kind == "dnsbl") {
			continue
		}
		for _, group := range list(b.in.Settings["feeds/"+kind], "groups") {
			if action := text(group, "action"); action == "" || action == "Disabled" {
				continue
			}
			walked := text(group, "updateFrequency") != "Never"
			for _, row := range list(group, "feeds") {
				if text(row, "state") != "disabled" && text(row, "url") != "" {
					out = append(out, listed{Feed: feedFor(kind, group, row), walked: walked})
				}
			}
			if custom := text(group, "customList"); custom != "" {
				out = append(out, listed{Feed: customFeedFor(kind, group, custom)})
			}
		}
	}
	if scope != "ip" {
		for _, c := range b.categories() {
			c.taken = slices.ContainsFunc(out, func(l listed) bool { return l.Kind == "dnsbl" && l.Name == c.Name })
			out = append(out, c)
		}
	}
	return out
}

// categories are the selected Blacklist categories as DNSBL feeds "blacklist:<id>:<category>", provider by provider in
// settings order (today's $lists, pfblockerng_apply.inc), each named "<title>_<category>", a dash of the category an
// underscore, and read from the local file <BlacklistDir>/<id>/<id>_<category>. A title that is no word stops its
// categories (feed_name_invalid); a name a configured DNSBL feed holds stops the category (feed_name_taken), so it is never
// run against that feed's files.
func (b *builder) categories() []listed {
	schedule := b.in.Settings["schedule"]
	if on, _ := schedule["categoryUpdates"].(bool); !on || b.in.BlacklistDir == "" {
		return nil
	}
	var out []listed
	for _, p := range list(schedule, "categoryProviders") {
		id := text(p, "id")
		if selected, _ := p["selected"].(bool); !selected || id == "" || strings.ContainsAny(id, "/.") {
			continue
		}
		dir := filepath.Join(b.in.BlacklistDir, id)
		for _, raw := range strings.Split(text(p, "categories"), ",") {
			category := strings.ReplaceAll(raw, "-", "_")
			if category == "" || strings.ContainsAny(category, "/") {
				continue
			}
			name := text(p, "title") + "_" + category
			out = append(out, listed{Feed: feedstage.Feed{ID: "blacklist:" + id + ":" + raw, Kind: "dnsbl", Name: name, State: "enabled",
				Format: "auto", Source: "file://" + filepath.Join(dir, id+"_"+category)}, marker: filepath.Join(dir, id+".update")})
		}
	}
	return out
}

// candidates are the feeds of the scope with their stages, all of them or those want names. Every folder is recovered
// before any rule reads a file of it.
func (b *builder) candidates(scope string, want func(id string) bool) ([]candidate, error) {
	var out []candidate
	for _, f := range b.feeds(scope) {
		if want != nil && !want(f.ID) {
			continue
		}
		stage := b.in.Stages[f.Kind]
		if stage == nil || stage.Fetcher == nil {
			return nil, fmt.Errorf("no feed stage for %s feeds", f.Kind)
		}
		f.SkipFeedPassed = b.in.SkipFeed != 0 && b.in.Failures[f.Name] >= b.in.SkipFeed
		c := candidate{feed: f.Feed, stage: stage, dir: stage.Paths.FeedDir, walked: f.walked, marker: f.marker}
		err, done := b.recovered[c.dir]
		if !done {
			err = feedstage.Recover(c.dir)
			b.recovered[c.dir] = err
		}
		switch {
		case f.taken:
			c.stop = "feed_name_taken"
		case !feedstage.ValidName(f.Name):
			c.stop = "feed_name_invalid"
		case err != nil:
			c.stop = "feed_folder_unrecoverable"
		}
		out = append(out, c)
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

// probeIdentity names the source a kept probe body stands for: the transfer request's URL, user and rsync flag, by a digest.
// The password is no part of it: no secret is hashed or written, and a body fetched from the same URL as the same user
// is that source's content whatever the password. A feed that transfers nothing has none.
func probeIdentity(c candidate) (string, bool) {
	if c.feed.Custom || c.feed.Format == "whois" || c.feed.Format == "asn" {
		return "", false
	}
	request, reason := c.stage.Request(c.feed)
	if reason != "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{request.URL, request.Username,
		strconv.FormatBool(request.Rsync)}, "\x00")))
	return hex.EncodeToString(sum[:]), true
}

// dropStaleProbe removes a kept probe body, its validators and its record unless the record names source: the next
// ingest publishes a kept body without fetching (feedfetch), so a body fetched for another source must never reach it.
func dropStaleProbe(c candidate, source string) error {
	if !present(c.path(".probe")) {
		return removeIfExists(c.path(feedstage.ProbeSource))
	}
	if recorded, err := readRecord(c.path(feedstage.ProbeSource)); err == nil && recorded == source {
		return nil
	}
	var errs []error
	for _, suffix := range feedstage.ProbeFiles() {
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
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
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

// number is an int field as Store.GetClear answers it: an int64.
func number(m map[string]any, key string) int {
	value, _ := m[key].(int64)
	return int(value)
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
