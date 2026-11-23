package update

import (
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/geoip"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
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
// (worklist.Plan.PendingFeeds). It holds no setting.
const updaterStateName = "updater.json"

type updaterState struct {
	PendingFeeds []string `json:"pendingFeeds"`
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

// The test seams of the Extras verbs and of the dnsbl/* publication; production never sets them.
var (
	extrasRun    = (*feedfetch.Fetcher).RunExtras
	publishDNSBL = dnsbl.Publish
)

// db is a path under the package's database folder.
func (u *updater) db(names ...string) string {
	return filepath.Join(append([]string{u.loop.DBDir}, names...)...)
}

func (u *updater) ccDir() string { return filepath.Join(u.loop.GeoIPDir, "cc") }

// openLog opens a log of the log folder for appending, as the main log is opened, and closes it when the loop ends.
func (u *updater) openLog(name string) (io.Writer, error) {
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
		{"--geoip-dir", u.loop.GeoIPDir}, {"--log-dir", u.loop.LogDir}, {"--pkg-dir", u.loop.PkgDir}} {
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
	u.pending = readUpdaterState(u.stateDir).PendingFeeds
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
	f := &feedfetch.Fetcher{Policy: feedfetch.Policy{NoFilter: !flag(ingest, "feedHostFilter"), LocalDirs: slices.Clone(u.loop.FeedLocalDirs)},
		UserAgent: u.loop.UserAgent, RsyncBin: u.loop.RsyncBin, ProxyUnusable: flag(ingest, "proxyUnusable"),
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

// hookTrigger is pfb_req_to_hook_trigger() of the request: a manual Update is update, its Force Reload force-reload;
// any other Update is cron.
func (u *updater) hookTrigger() string {
	switch {
	case u.req.Trigger == "manual" && u.req.Force == "parse":
		return "force-reload"
	case u.req.Trigger == "manual" && (u.req.Force == "none" || u.req.Force == ""):
		return "update"
	}
	return "cron"
}

func (u *updater) hooks(ctx context.Context, when string, vars map[string]string) {
	if u.loop.HookDir == "" {
		return
	}
	vars["TRIGGER"] = u.hookTrigger()
	runner := hooks.Runner{Dir: u.loop.HookDir, Python: u.loop.PythonWrapper, Log: u.sinks.Log, Errors: u.errors, Transcript: u.sinks.Transcript}
	runner.Run(ctx, when, hooks.Rows(u.snap["hooks"]), hooks.Context{Lifecycle: u.req.Lifecycle, PkgOp: u.req.PkgOp, Vars: vars})
}

// preHook is stage 4.
func (u *updater) preHook() error {
	u.hooks(context.Background(), "pre", map[string]string{})
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
	// A manual request without a scope or a force is both and none, as the update program reads it.
	plan, err := worklist.Build(context.Background(), worklist.Input{Trigger: u.req.Trigger, Scope: cmp.Or(u.req.Scope, "both"),
		Force: cmp.Or(u.req.Force, "none"),
		Feeds: u.req.Feeds, PendingFeeds: u.pending, Settings: u.snap, Stages: u.stages,
		InWindow:      schedule.InApplyWindow(time.Now().Unix(), settingText(u.snap["ingest"], "applyWindow"), zone),
		ExtrasChanged: u.extrasOut.Changed,
		GeoIPChanged:  u.geoMarker || u.extrasOut.GeoIPChanged, BlacklistDir: u.loop.DBDir,
		ManifestMissing: u.dnsblActive() && errors.Is(manifestErr, resources.ErrNotFound)})
	if err != nil {
		return err
	}
	u.plan = plan
	for _, item := range plan.Items {
		if item.Stopped != "" {
			u.issues = append(u.issues, apply.Issue{Resource: "feed/" + item.Feed.ID, Stage: "download", Code: item.Stopped,
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

// runFeeds is the per-feed stage of every item of kinds, in work-list order, each outcome written once its feed ends.
func (u *updater) runFeeds(kinds ...string) error {
	for _, item := range u.plan.Items {
		if !slices.Contains(kinds, item.Feed.Kind) || item.Stopped != "" {
			continue
		}
		r := u.stages[item.Feed.Kind].Run(context.Background(), item.Feed, item.Change)
		switch r.Disposition {
		case "changed", "reparsed":
			u.changed[item.Feed.Name] = true
		case "failed":
			stage := map[string]string{"script": "script", "parse": "parse", "normalize": "parse", "publish": "parse"}[r.Stage]
			u.issues = append(u.issues, apply.Issue{Resource: "feed/" + item.Feed.ID, Stage: cmp.Or(stage, "download"), Code: cmp.Or(r.Reason, "feed_failed"),
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

// dnsblStage is stage 8's per-feed part; the group-level part runs with the publication (stage 10).
func (u *updater) dnsblStage() error {
	if !u.building() {
		return nil
	}
	if err := u.runFeeds("dnsbl"); err != nil {
		return err
	}
	for marker, failed := range u.markers {
		if !failed {
			if err := os.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// foldDNSBL folds what pfB-DNS reported applied (applied.json) into the store's dnsbl/* baselines, before each dnsbl/*
// publication and at settle (#4036 plan section 3.5), so that a publication failing between body writes keeps the
// bodies pfB-DNS serves. While DNSBL is off the report is stale: an empty one is folded, which deletes every removed
// dnsbl/* body (plan section C, row 10).
func (u *updater) foldDNSBL() error {
	report := readAppliedReport(u.stateDir)
	if !u.dnsblActive() {
		report = map[string]resources.Cursor{}
	}
	return u.store.FoldApplied("dnsbl/", report)
}

// publishDNSBLStage is stages 9 and 10: DNSBLIP and the dnsbl/* publication, through the DNSBL build.
func (u *updater) publishDNSBLStage() error {
	if !u.building() {
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
	if !u.building() {
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

// ipStage is stage 12's per-feed part. The MaxMind marker is consumed once the continent sets and the geoip-format feeds
// built from the new country lists have succeeded.
func (u *updater) ipStage() error {
	if !u.building() {
		return nil
	}
	if err := u.runFeeds("ipv4", "ipv6"); err != nil {
		return err
	}
	if !u.geoFailed {
		return u.extras.ClearGeoIPUpdate()
	}
	return nil
}

// publishIP is stages 13 to 16: the IP sets (recompute, suppression, the canonical sets and the Uber unions run inside
// IPSets.Build), the closing report, and the geo-catalog.
func (u *updater) publishIP() error {
	if !u.building() {
		return nil
	}
	sets := IPSets{FeedDirs: map[string]string{"ipv4": u.db("original"), "ipv6": u.db("original")}, Folders: u.folders(),
		StateDir: u.stateDir, Store: u.store}
	geo, closer, err := CountryLookup(filepath.Join(u.loop.GeoIPDir, "GeoLite2-Country.mmdb"))
	if err == nil {
		defer closer.Close()
		sets.Geo = geo
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

// request is the apply's version 2 request: what this Update published, within its scope, or, outside the window, the
// pending mark alone. The token is the Updater's own snapshot's.
func (u *updater) request() apply.Request {
	scope := u.req.Scope
	if u.req.Trigger != "manual" || scope == "" {
		scope = "both"
	}
	outside := u.plan.Decision == worklist.Pending
	r := apply.Request{Trigger: u.req.Trigger, Scope: scope, PendingOutsideWindow: outside, Issues: u.issues,
		PendingToken: u.token}
	if !u.building() {
		return r
	}
	if scope != "dnsbl" {
		r.Resources, r.Removed = slices.Clone(u.ipOut.Resources), u.ipOut.Removed
		if u.catalog != nil {
			r.Resources = append(r.Resources, *u.catalog)
		}
	}
	if scope != "ip" {
		r.DNSBL = u.dnsblOut.DNSBL
	}
	return r
}

// applyStage is stage 18: the one invocation of the Outpost apply, through the holder that keeps the Update lock while the
// apply runs (process.RunIndependent: never signalled). Its stdin is the request, its fd 3 a result file of its own,
// update.log.apply, read with the version 2 rules. Its state is saved first: the plan's pending feeds.
func (u *updater) applyStage() error {
	if err := writeList(filepath.Join(u.stateDir, updaterStateName), mustJSON(updaterState{PendingFeeds: u.plan.PendingFeeds})); err != nil {
		return err
	}
	if u.plan.Decision == worklist.Nothing {
		return nil
	}
	req := u.request()
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
// keeps its cursor), pfB-DNS's report is folded, and files a stopped removal left are swept (#4181). An apply that failed
// fails the Update here, once what it applied is settled.
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
	return errors.Join(append(errs, u.applyErr)...)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// readAppliedReport is the report pfB-DNS made (ReportApplied, recorded in applied.json in the state folder), as the
// Core API's readApplied reads it: nil without the file or when it cannot be taken whole, which folds nothing.
func readAppliedReport(stateDir string) map[string]resources.Cursor {
	f, err := os.OpenFile(filepath.Join(stateDir, "applied.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil
	}
	var rec struct {
		Format    int `json:"format"`
		Resources map[string]struct {
			Generation string `json:"generation"`
			Digest     string `json:"digest"`
		} `json:"resources"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&rec) != nil || rec.Format != 1 || rec.Resources == nil {
		return nil
	}
	report := map[string]resources.Cursor{}
	for id, c := range rec.Resources {
		g, err := strconv.ParseUint(c.Generation, 10, 64)
		if err != nil || !resources.ValidID(id) || !strings.HasPrefix(id, "dnsbl/") || len(c.Digest) != 32 ||
			strings.Trim(c.Digest, "0123456789abcdef") != "" {
			return nil
		}
		report[id] = resources.Cursor{Generation: g, Digest: c.Digest}
	}
	return report
}
