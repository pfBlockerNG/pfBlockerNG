package update

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/geoip"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/applied"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/ipset"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/worklist"
)

// The stages of the loop after the snapshot (docs/specs/go-updater-pipeline.md section 3; issue #4038, sub-slice 9i). Each
// reuses the sub-slice that ports it: the work list (9d), the per-feed stage (9e), Extras and the continent sets (9f), the
// DNSBL build (9g), the IP sets (9h) and the apply contract (9b).

// loopProjections are the projections the loop reads of its snapshot, in clear.
var loopProjections = []string{"dns", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl", "feeds/geoip", "schedule", "ingest", "policy/ip",
	"policy/dnsbl", "extras", "hooks"}

// updaterStateName is the Core Updater's own state in Core's state folder: the feeds earlier Updates left to the apply
// (worklist.Plan.PendingFeeds), what the last apply that ran to its end was requested to load and remove, and each feed's
// failed downloads on the day FailuresDay (local date), which the retry cap ingest.skipFeedLimit is compared with. It holds
// no setting.
const updaterStateName = "updater.json"

type updaterState struct {
	PendingFeeds     []string          `json:"pendingFeeds"`
	Requested        map[string]uint64 `json:"requested,omitempty"`
	RequestedRemoved []string          `json:"requestedRemoved,omitempty"`
	FailuresDay      string            `json:"failuresDay,omitempty"`
	Failures         map[string]int    `json:"failures,omitempty"` // feed name -> failed downloads on FailuresDay
}

// readUpdaterState is the Updater's state in dir; a missing or unreadable one is empty: a change no Update built left its
// baseline's validators as they were, so the next check finds it again.
func readUpdaterState(dir string) updaterState {
	var st updaterState
	if b, err := os.ReadFile(filepath.Join(dir, updaterStateName)); err != nil || json.Unmarshal(b, &st) != nil {
		return updaterState{}
	}
	return st
}

// lockState takes the lock of the Updater's state in dir, which a reset and the Updater's own saves take around their read
// and write, so that neither loses the other's change (owner, 2026-11-26). Closing the file releases it.
func lockState(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, updaterStateName+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ResetFailures clears every feed's failed downloads counted today in the Updater's state in dir, so the next Update that
// comes to a feed (its next scheduled run, or a manual one) fetches it instead of skipping it at the retry cap (issue #4257,
// "Clear Failed Downloads"). The Updater's other state is kept, and a state with no count is not written. A state that
// does not exist is left so; one that cannot be read is an error, never replaced. A reset may come while an Update runs:
// under the state's lock, the Update adds only its own failures to what it then finds (saveState).
func ResetFailures(dir string) error {
	path := filepath.Join(dir, updaterStateName)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil // nothing counted, and no lock file left behind
	}
	lock, err := lockState(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st updaterState
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s cannot be read: %w", updaterStateName, err)
	}
	if len(st.Failures) == 0 {
		return nil
	}
	st.Failures, st.FailuresDay = nil, ""
	out, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeList(path, string(out))
}

// The test seams of the Extras verbs and of the dnsbl/* publication; production never sets them.
var (
	extrasRun    = (*feedfetch.Fetcher).RunExtras
	publishDNSBL = dnsbl.Publish
	loopNow      = time.Now
)

// db is a path under the package's database folder.
func (u *updater) db(names ...string) string {
	return filepath.Join(append([]string{u.loop.DBDir}, names...)...)
}

func (u *updater) ccDir() string { return cmp.Or(u.loop.CCDir, filepath.Join(u.loop.GeoIPDir, "cc")) }

// openLog opens a log of the log folder for appending, as the main log is opened, and closes it when the loop ends;
// without a log folder it is nil, which discards.
func (u *updater) openLog(name string) (io.Writer, error) {
	if u.loop.LogDir == "" {
		return nil, nil
	}
	f, err := openMainLog(filepath.Join(u.loop.LogDir, name))
	if err != nil {
		return nil, err
	}
	u.closers = append(u.closers, f)
	return f, nil
}

// dnsblActive is whether DNSBL is active, as pfb_dnsbl_active() decides and DNSBLSet.Build reads it.
func (u *updater) dnsblActive() bool {
	return settingBool(u.snap["policy/dnsbl"], "enabled") && settingBool(u.snap["dns"], "pfbDnsEnabled")
}

// workList is stage 3: the paths, the snapshot's projections, the Updater's state and the stages the work runs on. The
// decision itself is stage 6's, which probes: it needs the Extras of stage 5 first.
func (u *updater) workList() error {
	for _, p := range []struct{ flag, path string }{{"--resource-dir", u.loop.ResourceDir}, {"--db-dir", u.loop.DBDir},
		{"--geoip-dir", u.loop.GeoIPDir}, {"--pkg-dir", u.loop.PkgDir}} {
		if p.path == "" {
			return fmt.Errorf("the loop needs %s: the %s path is not set", p.flag, strings.TrimPrefix(p.flag, "--"))
		}
	}
	if u.program == "" {
		return errors.New("the loop needs the apply program (--update-cmd)")
	}
	u.snap = map[string]map[string]any{}
	for _, id := range loopProjections {
		v, err := u.settings.GetClear(id)
		if err != nil {
			return err
		}
		u.snap[id] = v
	}
	u.state = readUpdaterState(u.stateDir)
	u.pending = u.state.PendingFeeds
	u.geoMarker = exists(u.db("geoip.update"))
	u.store = resources.Open(u.loop.ResourceDir)
	logs := map[string]*io.Writer{"error.log": &u.errors, "extras.log": &u.extrasLog, "ip_parsed_error.log": &u.ipParseLog,
		"dnsbl_parsed_error.log": &u.dnsblParseLog}
	for name, w := range logs {
		var err error
		if *w, err = u.openLog(name); err != nil {
			return fmt.Errorf("the log %s cannot be used: %w", name, err)
		}
	}
	u.sinks.Errors = u.errors
	fetcher, err := u.fetcher()
	if err != nil {
		return err
	}
	ingest := u.snap["ingest"]
	cfg := feedstage.Config{Suppression: flag(ingest, "suppression"), FloorV4: num(ingest, "suppressionCidrV4"),
		FloorV6: num(ingest, "suppressionCidrV6"), DNSBLIP: flag(ingest, "dnsblIp"), Lenient: flag(ingest, "dnsblLenient")}
	stage := func(dir string, parseErrors io.Writer) *feedstage.Stage {
		return &feedstage.Stage{Paths: feedstage.Paths{FeedDir: dir, ScriptDirs: u.loop.ScriptDirs, GeoIPDir: u.ccDir()}, Fetcher: fetcher,
			Config: cfg, Log: u.lineWriter(), Errors: u.errors, Transcript: u.sinks.Transcript, ParseErrors: parseErrors}
	}
	ip := stage(u.db("original"), u.ipParseLog)
	u.stages = map[string]*feedstage.Stage{"ipv4": ip, "ipv6": ip, "dnsbl": stage(u.db("dnsbl"), u.dnsblParseLog)}
	now := time.Now()
	u.extras = Extras{
		RunVerb: func(ctx context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
			return extrasRun(fetcher, ctx, v)
		},
		GeoIPShare: u.loop.GeoIPDir, DBDir: u.loop.DBDir, CCDir: u.ccDir(), Settings: extrasSettings(u.snap), Enabled: true,
		Convert: geoip.Conversion{Share: u.loop.GeoIPDir, CCDir: u.ccDir(), LogDir: u.loop.LogDir,
			Locale: settingText(u.snap["extras"], "maxmindLocale"), Now: now, Log: u.extrasLog}.Run,
		ASNTable: func(ctx context.Context) {
			geoip.ASNTable{CSV: filepath.Join(u.loop.GeoIPDir, "asn.csv"), Table: u.loop.ASNTable, Now: now, Log: u.extrasLog}.Run(ctx)
		},
		Log: u.extrasLog,
	}
	return nil
}

// lineWriter is the main log and the transcript, as one writer.
func (u *updater) lineWriter() io.Writer {
	var ws []io.Writer
	for _, w := range []io.Writer{u.sinks.Log, u.sinks.Transcript} {
		if w != nil {
			ws = append(ws, w)
		}
	}
	return io.MultiWriter(ws...)
}

// fetcher is the transfer configuration of the snapshot: the feed-host policy, the proxy and ET IQRisk (carried from
// fetcherFor on the #3977 branch). A selected Blacklist provider's folder is a local folder its categories are read from.
func (u *updater) fetcher() (*feedfetch.Fetcher, error) {
	ingest, policy := u.snap["ingest"], u.snap["policy/ip"]
	// the country folder holds the lists geoip-format feeds read as local files
	f := &feedfetch.Fetcher{Policy: feedfetch.Policy{NoFilter: !flag(ingest, "feedHostFilter"),
		LocalDirs: append(slices.Clone(u.loop.FeedLocalDirs), u.ccDir())},
		UserAgent: u.loop.UserAgent, RsyncBin: u.loop.RsyncBin, ProxyUnusable: flag(ingest, "proxyUnusable"), Sanity: flag(ingest, "feedSanity"),
		ASNCSV: filepath.Join(u.loop.GeoIPDir, "asn.csv"), ETDir: u.db("ET"), ETMatchFile: u.db("match", "generated", "pfB_Match_ET_v4.txt")}
	for _, p := range rows(u.snap["schedule"]["categoryProviders"]) {
		if id := str(p, "id"); id != "" && !strings.ContainsAny(id, "/.") {
			f.LocalDirs = append(f.LocalDirs, u.db(id))
		}
	}
	for _, r := range rows(ingest["feedHostAllowlist"]) {
		if prefix, err := netip.ParsePrefix(str(r, "cidr")); err == nil {
			f.Allow = append(f.Allow, prefix)
		} else if addr, err := netip.ParseAddr(str(r, "cidr")); err == nil {
			f.Allow = append(f.Allow, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	for _, r := range rows(ingest["selfAddresses"]) {
		if addr, err := netip.ParseAddr(str(r, "address")); err == nil {
			f.Self = append(f.Self, addr)
		}
	}
	if proxy := str(ingest, "proxyUrl"); proxy != "" {
		p, err := url.Parse(proxy)
		if err != nil {
			return nil, errors.New("the configured proxy is not a URL")
		}
		if user, password := str(ingest, "proxyUser"), str(ingest, "proxyPassword"); user != "" || password != "" {
			p.User = url.UserPassword(user, password)
		}
		f.Proxy = p
	}
	for _, r := range rows(policy["etBlock"]) {
		f.ETBlock = append(f.ETBlock, str(r, "category"))
	}
	for _, r := range rows(policy["etMatch"]) {
		f.ETMatch = append(f.ETMatch, str(r, "category"))
	}
	return f, nil
}

// extrasSettings is what the Extras verbs read of the snapshot.
func extrasSettings(snap map[string]map[string]any) feedfetch.ExtrasSettings {
	x, sched := snap["extras"], snap["schedule"]
	s := feedfetch.ExtrasSettings{MaxMindAccount: str(x, "maxmindAccount"), MaxMindKey: str(x, "maxmindKey"),
		MaxMindCSVDisabled: flag(x, "maxmindCsvDisabled"), ASNToken: str(x, "ipinfoToken"), Top1M: flag(snap["policy/dnsbl"], "top1m"),
		Top1MProvider: str(x, "top1mProvider"), Top1MToken: str(x, "top1mToken"), BlacklistEnabled: flag(sched, "categoryUpdates")}
	for _, p := range rows(sched["categoryProviders"]) {
		s.Providers = append(s.Providers, feedfetch.BlacklistProvider{ID: str(p, "id"), Title: str(p, "title"), Feed: str(p, "feed"),
			Username: str(p, "username"), Password: str(p, "password"), Selected: flag(p, "selected"), Categories: str(p, "categories")})
	}
	return s
}

// hookTrigger is the trigger today's pass gives its hooks (pfb_req_to_hook_trigger()): a manual Update is update, its
// Force Reload force-reload; an apply Update is update too, as pfb_core_update_apply() runs the pass as a manual one
// (pfblockerng_extra.inc); any other Update is cron.
func (u *updater) hookTrigger() string {
	switch {
	case u.req.Trigger == "manual" && u.req.Force == "parse":
		return "force-reload"
	case u.req.Trigger == "manual" && (u.req.Force == "none" || u.req.Force == ""), u.req.Trigger == "apply":
		return "update"
	}
	return "cron"
}

func (u *updater) hooks(ctx context.Context, when string, vars map[string]string) {
	if u.loop.HookDir == "" {
		return
	}
	vars["TRIGGER"] = u.hookTrigger()
	runner := hooks.Runner{Dir: u.loop.HookDir, Python: u.loop.PythonWrapper, Log: u.sinks.Log, Errors: u.errors, Transcript: u.sinks.Transcript,
		Hold: u.lock}
	runner.Run(ctx, when, hooks.Rows(u.snap["hooks"]), hooks.Context{Lifecycle: u.req.Lifecycle, PkgOp: u.req.PkgOp, Vars: vars})
}

// preHook is stage 4, where today's pass fires it: at its top, so only when a pass runs (not when nothing is due, nor
// outside the apply window).
func (u *updater) preHook() error {
	if u.building() {
		u.hooks(context.Background(), "pre", map[string]string{})
	}
	return nil
}

// outcome is stage 17: one result line of version 1 written as soon as it is known, so that an Updater that dies keeps
// what it reported (#4002). The lines add up in update.log.result.
func (u *updater) outcome(line Result) error {
	b, err := json.Marshal(struct {
		Version    int               `json:"version"`
		Outcomes   map[string]string `json:"outcomes"`
		Attempted  []string          `json:"attempted,omitempty"`
		GeoIPReady *bool             `json:"geoipReady,omitempty"`
	}{protocolVersion, line.Outcomes, line.Attempted, line.GeoIPReady})
	if err == nil {
		_, err = u.result.Write(append(b, '\n'))
	}
	return err
}

// extrasStage is stage 5. GeoIP is reported ready once the stage has run: its conversion ran or was not needed.
func (u *updater) extrasStage() error {
	if u.req.Trigger != "apply" {
		u.extrasOut = u.extras.Stage(context.Background(), u.req.Extras)
	}
	line := Result{Outcomes: map[string]string{}, Attempted: u.extrasOut.Attempted, GeoIPReady: new(true)}
	for _, id := range u.extrasOut.Succeeded {
		line.Outcomes[id] = worklist.OutcomeSuccess
	}
	if line.Attempted == nil {
		line.Attempted = []string{}
	}
	return u.outcome(line)
}

// changeDetection is stages 6 and 7: the work list and its change detection, and the apply-window decision.
func (u *updater) changeDetection() error {
	zone := time.Local
	if u.loop.Zoneinfo != "" {
		b, err := os.ReadFile(u.loop.Zoneinfo)
		if err == nil {
			zone, err = time.LoadLocationFromTZData("", b)
		}
		if err != nil {
			return fmt.Errorf("the zone file cannot be read: %w", err)
		}
	}
	_, manifestErr := u.store.Get(dnsbl.ManifestID, nil)
	// A manual request without a force is none, as the update program reads it.
	u.zone = zone
	u.inWindow = schedule.InApplyWindow(loopNow().Unix(), settingText(u.snap["ingest"], "applyWindow"), zone)
	// The failed downloads of today only, as pfb_failures() greps the error log for today's date.
	if day := loopNow().In(zone).Format(time.DateOnly); u.state.FailuresDay != day {
		u.state.FailuresDay, u.state.Failures = day, nil
	}
	plan, err := worklist.Build(context.Background(), worklist.Input{Trigger: u.req.Trigger, Scope: u.scope(),
		Force: cmp.Or(u.req.Force, "none"),
		Feeds: u.req.Feeds, PendingFeeds: u.pending, Settings: u.snap, Stages: u.stages,
		InWindow:      u.inWindow,
		ExtrasChanged: u.extrasOut.Changed, PendingApply: u.settings.PendingApply(),
		SkipFeed: num(u.snap["ingest"], "skipFeedLimit"), Failures: u.state.Failures,
		GeoIPChanged: u.geoMarker || u.extrasOut.GeoIPChanged, BlacklistDir: u.loop.DBDir,
		ManifestMissing: u.dnsblActive() && errors.Is(manifestErr, resources.ErrNotFound)})
	if err != nil {
		return err
	}
	u.plan = plan
	// Until the settle succeeds, the earlier pending feeds and every feed this Update runs stay pending: an apply that
	// defers or fails, or a stage that fails, leaves them to the next Update.
	held := slices.Concat(u.pending, plan.PendingFeeds)
	for _, item := range plan.Items {
		if item.Stopped == "" && !slices.Contains(held, item.Feed.ID) {
			held = append(held, item.Feed.ID)
		}
	}
	slices.Sort(held)
	if err := u.pendingAfter(slices.Compact(held)); err != nil {
		return err
	}
	for _, item := range plan.Items {
		if item.Stopped != "" {
			u.issues = append(u.issues, apply.Issue{Resource: u.issueResource(item.Feed), Stage: "download", Code: item.Stopped,
				Message: "the feed is not run this Update"})
		}
		// A feed the stage does not run now finished with its check.
		if item.Outcome != "" && (plan.Decision != worklist.Now || item.Stopped != "") {
			if err := u.outcome(Result{Outcomes: map[string]string{item.Feed.ID: item.Outcome}}); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyWindow is the rest of stage 7: outside the window nothing is built and the apply only records the pending work.
func (u *updater) applyWindow() error {
	switch u.plan.Decision {
	case worklist.Pending:
		u.sinks.Line(false, "Core Updater: outside the apply window: %d feeds are left to the apply\n", len(u.plan.PendingFeeds))
	case worklist.Nothing:
		u.sinks.Line(false, "Core Updater: nothing is due\n")
	}
	return nil
}

// building is whether this Update builds and publishes: stages 8 to 16.
func (u *updater) building() bool { return u.plan.Decision == worklist.Now }

// scope is the Update's scope: a manual Update's, both for any other. A narrow scope runs none of the other side's
// stages, as today.
func (u *updater) scope() string {
	if u.req.Trigger != "manual" {
		return "both"
	}
	return cmp.Or(u.req.Scope, "both")
}

// pendingAfter writes the Updater's state with feeds as the feeds left to a later Update.
func (u *updater) pendingAfter(feeds []string) error {
	u.state.PendingFeeds = feeds
	return u.saveState()
}

// saveState writes the Updater's state. The failure counts are not the Updater's alone: a reset may have cleared them since
// it read them, so under the state's lock it adds the failures it counted and has not written to the counts it finds for
// its day (none when the file holds another day, or none after a reset); the work list keeps deciding from the counts read
// at the start.
func (u *updater) saveState() error {
	lock, err := lockState(u.stateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	st := u.state
	st.Failures = map[string]int{}
	var held updaterState
	b, err := os.ReadFile(filepath.Join(u.stateDir, updaterStateName))
	switch {
	case err != nil || json.Unmarshal(b, &held) != nil:
		// missing or unreadable is no reset (a reset never removes the file): the counts read at the start stand
		maps.Copy(st.Failures, u.state.Failures)
	case held.FailuresDay == u.state.FailuresDay:
		maps.Copy(st.Failures, held.Failures)
	}
	for name, n := range u.added {
		st.Failures[name] += n
	}
	if len(st.Failures) == 0 {
		st.Failures, st.FailuresDay = nil, ""
	}
	out, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := writeList(filepath.Join(u.stateDir, updaterStateName), string(out)); err != nil {
		return err
	}
	u.added = nil
	return nil
}

// countFailure counts one failed download of the feed name today, written at once so that an Updater that dies keeps it.
func (u *updater) countFailure(name string) error {
	if u.added == nil {
		u.added = map[string]int{}
	}
	u.added[name]++
	return u.saveState()
}

// runFeeds is the per-feed stage of every item of kinds, in work-list order, each outcome written once its feed ends.
func (u *updater) runFeeds(kinds ...string) error {
	for _, item := range u.plan.Items {
		if !slices.Contains(kinds, item.Feed.Kind) {
			continue
		}
		if item.Stopped != "" {
			// a stopped category keeps its provider's marker; a stopped geoip-format feed keeps the MaxMind marker
			if item.Marker != "" {
				u.markers[item.Marker] = true
			}
			u.geoFailed = u.geoFailed || item.Feed.Format == "geoip"
			continue
		}
		r := u.stages[item.Feed.Kind].Run(context.Background(), item.Feed, item.Change)
		if failedTransfer(r) {
			if err := u.countFailure(item.Feed.Name); err != nil {
				return err
			}
		}
		switch r.Disposition {
		case "changed", "reparsed":
			u.changed[item.Feed.Name] = true
		case "failed":
			stage := map[string]string{"script": "script", "parse": "parse", "normalize": "parse", "publish": "parse"}[r.Stage]
			u.issues = append(u.issues, apply.Issue{Resource: u.issueResource(item.Feed), Stage: cmp.Or(stage, "download"), Code: cmp.Or(r.Reason, "feed_failed"),
				Message: "the feed failed at its " + cmp.Or(r.Stage, "run") + " stage; its last list stays"})
			if item.Feed.Format == "geoip" {
				u.geoFailed = true
			}
		}
		if item.Marker != "" { // a provider's marker stays while a category of it failed
			u.markers[item.Marker] = u.markers[item.Marker] || r.Disposition == "failed"
		}
		if item.Outcome != "" {
			if err := u.outcome(Result{Outcomes: map[string]string{item.Feed.ID: item.Outcome}}); err != nil {
				return err
			}
		}
	}
	return nil
}

// failedTransfer is whether r counts against the retry cap: a failed transfer, as pfb_download_failure() logs its FAIL line;
// not a cancelled one, nor a feed that fails at another stage.
func failedTransfer(r feedstage.Result) bool {
	return r.Disposition == "failed" && r.Stage == "fetch" && r.Reason != "cancelled"
}

// issueResource is what a feed's issue names: an IP feed's group set, as the ADR-61 ledger names the table today
// ("pfB_<group>_v4"); a DNSBL feed, or an IP feed whose group maps to no set, by its feed id.
func (u *updater) issueResource(f feedstage.Feed) string {
	if f.Kind == "dnsbl" {
		return "feed/" + f.ID
	}
	suffix := "_" + short(f.Kind)
	for _, g := range rows(u.snap["feeds/"+f.Kind]["groups"]) {
		owns := str(g, "name")+"_custom"+suffix == f.Name
		for _, row := range rows(g["feeds"]) {
			owns = owns || str(row, "header")+suffix == f.Name
		}
		if id, ok := apply.SetID(str(g, "name"), f.Kind); owns && ok {
			return id
		}
	}
	return "feed/" + f.ID
}

// dnsblStage is stage 8's per-feed part; the group-level part runs with the publication (stage 10).
func (u *updater) dnsblStage() error {
	if !u.building() || u.scope() == "ip" {
		return nil
	}
	return u.runFeeds("dnsbl")
}

// foldDNSBL folds what pfB-DNS reported applied (applied.json) into the store's dnsbl/* baselines, before each dnsbl/*
// publication and at settle (#4036 plan section 3.5), so that a publication failing between body writes keeps the
// bodies pfB-DNS serves. While DNSBL is off the report is stale: an empty one is folded, which deletes every removed
// dnsbl/* body (plan section C, row 10).
func (u *updater) foldDNSBL() error {
	report, err := applied.Read(u.stateDir) // a record the Core API would refuse folds nothing
	if err != nil {
		u.sinks.Line(true, "Core Updater: the applied report is not used: %s\n", oneLine(err))
		report = nil
	}
	if !u.dnsblActive() {
		report = map[string]resources.Cursor{}
	}
	return u.store.FoldApplied("dnsbl/", report)
}

// publishDNSBLStage is stages 9 and 10: DNSBLIP and the dnsbl/* publication, through the DNSBL build. An ip Update builds
// none of it: the IP sets take DNSBLIP's lists as the last DNSBL build wrote them.
func (u *updater) publishDNSBLStage() error {
	if !u.building() {
		return nil
	}
	if u.scope() == "ip" {
		u.dnsblOut.DNSBLIP = standingDNSBLIP(u.snap, u.loop.DBDir)
		return nil
	}
	if err := u.foldDNSBL(); err != nil {
		return err
	}
	out, err := DNSBLSet{Store: u.store, FeedDir: u.db("dnsbl"), ListDir: u.loop.DBDir, Top1m: u.db("pfbalexawhitelist.txt"),
		PSL: filepath.Join(u.loop.PkgDir, "dnsbl_psl"), SafeSearchDir: u.loop.PkgDir}.Build(context.Background(),
		DNSBLInput{Settings: u.snap, Changed: u.changed})
	u.dnsblOut = out
	u.issues = append(u.issues, out.Issues...)
	return err
}

// geoSets is stage 11.
func (u *updater) geoSets() error {
	if !u.building() || u.scope() == "dnsbl" {
		return nil
	}
	sets, err := GeoSets{CCDir: u.ccDir(), OrigDir: u.db("original"), Folders: u.folders(), Enabled: true,
		Force: u.req.Trigger == "manual" && u.req.Force == "parse", GeoIPChanged: u.geoMarker || u.extrasOut.GeoIPChanged,
		Log: u.lineWriter()}.Build(context.Background(), u.snap["feeds/geoip"])
	u.geoSetsOut = sets
	switch {
	case errors.Is(err, ErrNoCountryData):
		u.sinks.Line(false, "Core Updater: no GeoIP country data: no continent set is built\n")
		u.geoFailed = true
	case err != nil:
		u.sinks.Line(true, "Core Updater: %s\n", oneLine(err))
		u.issues = append(u.issues, apply.Issue{Resource: "geoip", Stage: "parse", Code: "continent_set_failed", Message: oneLine(err)})
		u.geoFailed = true
	}
	return nil
}

func oneLine(err error) string { return strings.ReplaceAll(err.Error(), "\n", "; ") }

func (u *updater) folders() map[string]string {
	return map[string]string{"deny": u.db("deny"), "permit": u.db("permit"), "match": u.db("match"), "native": u.db("native")}
}

// ipStage is stage 12's per-feed part.
func (u *updater) ipStage() error {
	if !u.building() || u.scope() == "dnsbl" {
		return nil
	}
	return u.runFeeds("ipv4", "ipv6")
}

// publishIP is stages 13 to 16: the IP sets (recompute, suppression, the canonical sets and the Uber unions run inside
// IPSets.Build), the closing report, and the geo-catalog.
func (u *updater) publishIP() error {
	if !u.building() || u.scope() == "dnsbl" {
		return nil
	}
	sets := IPSets{FeedDirs: map[string]string{"ipv4": u.db("original"), "ipv6": u.db("original")}, Folders: u.folders(),
		StateDir: u.stateDir, Store: u.store}
	geo, closer, err := CountryLookup(filepath.Join(u.loop.GeoIPDir, "GeoLite2-Country.mmdb"))
	switch {
	case err == nil:
		defer closer.Close()
		sets.Geo = geo
	case !errors.Is(err, fs.ErrNotExist): // no database is no lookup, as today; one that cannot be read is an issue
		u.issues = append(u.issues, apply.Issue{Resource: "geoip", Stage: "dedup", Code: "country_lookup_failed",
			Message: "the MaxMind country database cannot be opened: dMax and the reputation stage run without a country lookup"})
	}
	out, err := sets.Build(context.Background(), IPInput{Settings: u.snap, Changed: u.changed, GeoSets: u.geoSetsOut,
		DNSBLIP: u.dnsblOut.DNSBLIP})
	u.ipOut = out
	u.issues = append(u.issues, out.Issues...)
	if err != nil {
		return err
	}
	u.closing(out.Closing)
	members, err := GeoCatalog(u.ccDir(), u.loop.ASNTable)
	switch {
	case errors.Is(err, fs.ErrNotExist): // no conversion has published one yet
	case err != nil:
		return err
	default:
		g, err := u.store.Publish("geo-catalog", members, nil)
		if err != nil {
			return err
		}
		u.catalog = &apply.Resource{ID: "geo-catalog", Generation: g}
	}
	return nil
}

// closing is the closing report (pfblockerng.sh closingprocess, the dedup sanity part): the counts and the verdict of the
// closing pass, when it ran.
func (u *updater) closing(s *ipset.Sanity) {
	if s == nil {
		return
	}
	u.sinks.Line(false, "\n===[ FINAL Processing ]=====================================\n")
	u.sinks.Line(false, "   [ Original IP count   ]  [ %d ]\n   [ Final IP Count  ]  [ %d ]\n", s.Original, s.Final)
	if s.Passed {
		u.sinks.Line(false, "Database Sanity check [  PASSED  ]\n")
	} else {
		u.sinks.Line(false, "Database Sanity check [  FAILED  ] ** These two counts should match! **\nMasterfile Count    [ %d ]\nDeny folder Count   [ %d ]\n",
			s.MasterCat, s.Deny)
	}
	for _, l := range []struct {
		head string
		rows []string
	}{{"Masterfile/Deny folder uniq check", s.DupMaster}, {"Deny folder/Masterfile uniq check", s.DupDeny}, {"Empty Lists", s.Empty}} {
		if len(l.rows) > 0 {
			u.sinks.Line(false, "%s\n%s\n", l.head, strings.Join(l.rows, "\n"))
		}
	}
}

// request is the apply's version 2 request: every ip-set, ip-aggregate and the geo-catalog the store holds, and every
// removal, within the scope; or, outside the window, the pending mark alone. Taken from the store, it also hands the apply
// what an earlier Update published and no apply took. The token is the Updater's own snapshot's.
func (u *updater) request() (apply.Request, error) {
	outside := u.plan.Decision == worklist.Pending
	r := apply.Request{Trigger: u.req.Trigger, Scope: u.scope(), PendingOutsideWindow: outside, Issues: u.issues,
		PendingToken: u.token}
	if outside {
		return r, nil
	}
	if r.Scope != "dnsbl" {
		for _, prefix := range []string{"geo-catalog", "ip-aggregate/", "ip-set/"} {
			ids, err := u.store.IDs(prefix)
			if err != nil {
				return r, err
			}
			for _, id := range ids {
				reply, err := u.store.Current(id) // the index alone: the apply reads and checks the bodies itself
				if err != nil {
					return r, err
				}
				var meta struct {
					Action    string   `json:"action"`
					Direction []string `json:"direction"`
				}
				if err := json.Unmarshal(reply.Metadata, &meta); err != nil {
					return r, err
				}
				res := apply.Resource{ID: id, Generation: reply.Generation}
				if id != "geo-catalog" {
					res.Action, res.Direction, res.Entries = meta.Action, meta.Direction, reply.Entries
				}
				r.Resources = append(r.Resources, res)
			}
			removed, err := u.store.RemovedIDs(prefix)
			if err != nil {
				return r, err
			}
			r.Removed = append(r.Removed, removed...)
		}
	}
	if r.Scope != "ip" {
		r.DNSBL = u.dnsblOut.DNSBL
	}
	return r, nil
}

// applyStage is stage 18: the one invocation of the Outpost apply, through the holder that keeps the Update lock while the
// apply runs (process.RunIndependent: never signalled). Its stdin is the request, its fd 3 a result file of its own,
// update.log.apply, read with the version 2 rules. Its state is saved first: the plan's pending feeds.
func (u *updater) applyStage() error {
	if u.plan.Decision == worklist.Nothing {
		// Nothing is due, but inside the window the store may hold what an earlier Update published and no apply that
		// ran to its end was requested to load: it is applied now.
		waiting, err := u.unrequested()
		if err != nil || !waiting {
			return err
		}
		u.sinks.Line(false, "Core Updater: the store holds generations no apply took: the apply runs\n")
	}
	req, err := u.request()
	if err != nil {
		return err
	}
	body, err := apply.Encode(req)
	if err != nil {
		return fmt.Errorf("the apply request cannot be written: %w", err)
	}
	in, remove, err := scratch(u.stateDir, ".stdin-*")
	if err != nil {
		return err
	}
	defer remove()
	if _, err := in.Write(body); err != nil {
		return err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	result, err := replaceRegular(u.logPath + apply.ResultSuffix)
	if err != nil {
		return err
	}
	defer result.Close()
	var st workerState
	if err := runNative(u.program, u.lock, result, in, u.log, &st); err != nil {
		return err
	}
	status := -1
	switch {
	case st.Failure != "":
		return fmt.Errorf("the apply did not run: %s", st.Failure)
	case st.Signal != 0:
		u.applyErr = fmt.Errorf("the apply ended by signal %s", syscall.Signal(st.Signal))
	case st.ExitCode != nil:
		status = *st.ExitCode
	}
	exit := apply.ExitOf(status)
	switch exit {
	case apply.Deferred:
		u.sinks.Line(false, "Core Updater: the apply deferred the Update (exit status 75)\n")
		return ErrDeferred
	case apply.Refused:
		return errors.New("the apply refused the request (exit status 2)")
	case apply.Failed:
		if u.applyErr == nil {
			u.applyErr = fmt.Errorf("the apply failed: exit status %d", status)
		}
	}
	if exit == apply.Succeeded && !req.PendingOutsideWindow && req.Scope != "dnsbl" {
		u.requested = &req // recorded once the settle reconciled the result
	}
	res, err := apply.ReadResult(result, req)
	if err != nil && !errors.Is(err, apply.ErrCut) {
		return errors.Join(u.applyErr, fmt.Errorf("the apply's result cannot be read: %w", err))
	}
	if err != nil {
		u.sinks.Line(true, "Core Updater: %v\n", err)
		res.IPChanged, res.DNSBLChanged = true, true // lower bounds: assume a change
	}
	u.applied = &res
	return nil
}

// unrequested reports whether, inside the apply window and outside a dnsbl scope, the store holds an ip-set, ip-aggregate
// or geo-catalog generation, or a removal, that no apply that ran to its end was requested to load.
func (u *updater) unrequested() (bool, error) {
	// the window is read again now: the change detection's reading may have gone stale
	if !schedule.InApplyWindow(loopNow().Unix(), settingText(u.snap["ingest"], "applyWindow"), u.zone) || u.scope() == "dnsbl" {
		return false, nil
	}
	for _, prefix := range []string{"geo-catalog", "ip-aggregate/", "ip-set/"} {
		ids, err := u.store.IDs(prefix)
		if err != nil {
			return false, err
		}
		for _, id := range ids {
			// the index alone: a damaged body is the next publication's to repair, not a reason to fail the tick
			current, err := u.store.Generation(id)
			if err != nil {
				return false, err
			}
			if g, ok := u.state.Requested[id]; !ok || g != current {
				return true, nil
			}
		}
		removed, err := u.store.RemovedIDs(prefix)
		if err != nil {
			return false, err
		}
		for _, id := range removed {
			if !slices.Contains(u.state.RequestedRemoved, id) {
				return true, nil
			}
		}
	}
	return false, nil
}

// postHook is stage 19: after the apply returned, under the Update lock, before the Update is reported finished; only
// after an apply that succeeded in the window.
func (u *updater) postHook() error {
	if u.applied == nil || u.applyErr != nil || !u.building() {
		return nil
	}
	var groups []string
	if u.dnsblOut.DNSBL != nil {
		for _, g := range u.dnsblOut.DNSBL.Groups {
			if g.Changed {
				groups = append(groups, g.Name)
			}
		}
	}
	bit := map[bool]string{true: "1", false: "0"}
	u.hooks(context.Background(), "post", map[string]string{"IP_CHANGED": bit[u.applied.IPChanged], "DNSBL_CHANGED": bit[u.applied.DNSBLChanged],
		"STATUS": "ok", "CHANGED_IP_ALIASES": strings.Join(u.applied.ChangedAliases, " "), "CHANGED_DNSBL_GROUPS": strings.Join(groups, " ")})
	return nil
}

// settle is stage 20: what the apply applied becomes the store's baseline and what it removed is deleted (a failed id
// keeps its cursor), pfB-DNS's report is folded, and every file the index does not keep is swept: what a stopped
// removal or a stopped Applied left (#4181). An apply that failed fails the Update here, once what it applied is
// settled.
func (u *updater) settle() error {
	var errs []error
	if u.applied != nil {
		for _, id := range slices.Sorted(maps.Keys(u.applied.Applied)) {
			errs = append(errs, u.store.Applied(id, u.applied.Applied[id]))
		}
		for _, id := range u.applied.Removed {
			errs = append(errs, u.store.RemovalApplied(id))
		}
	}
	if u.store != nil {
		errs = append(errs, u.foldDNSBL(), u.store.Sweep())
	}
	if err := errors.Join(append(errs, u.applyErr)...); err != nil {
		return err
	}
	// Settled: what the apply was requested to load is not requested again (an id it refused is its own issue to raise),
	// the plan's pending feeds stand, and the markers whose consumers all succeeded are consumed.
	if r := u.requested; r != nil {
		u.state.Requested, u.state.RequestedRemoved = map[string]uint64{}, r.Removed
		for _, res := range r.Resources {
			u.state.Requested[res.ID] = res.Generation
		}
	}
	if err := u.pendingAfter(u.plan.PendingFeeds); err != nil {
		return err
	}
	if !u.building() {
		return nil
	}
	for marker, failed := range u.markers {
		if !failed {
			if err := os.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	if u.scope() != "dnsbl" && !u.geoFailed {
		return u.extras.ClearGeoIPUpdate()
	}
	return nil
}
