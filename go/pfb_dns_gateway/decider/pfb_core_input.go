// pfB-DNS on the Core input (issue #4036, sub-slice 7e): the DNSBL data comes from the Core API instead of the files PHP
// writes. coreinput.Sync writes Core's dnsbl/* resources into the module directory in today's file shapes, so init and
// the reload build from them unchanged; this file decides when.
//
// Boot never waits for Core (#3848): init builds from the cache the last Sync left, when coreinput.Load trusts it, and
// otherwise serves no DNSBL and reports it degraded. A poller takes the reload sentinel's place: on each tick it syncs,
// swaps a new generation in through the RAM-gated reload, and reports what the live snapshot serves to Core's
// ReportApplied, once after the start and after each swap.
//
// The settings come the same way: coreinput.SyncSettings writes Core's settings/dns and settings/policy/dnsbl as the
// module directory's pfb_unbound.ini, which init reads, so a start without Core takes the settings Core last gave. A
// settings change is no restart: the next swap builds the snapshot from the new settings, as init would, and then the
// module applies what lives outside the snapshot (the control-channel reader, the decision cache's size, the client
// metrics authority). Like a restart, it drops what control commands changed at runtime.
package decider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
)

// CORE_POLL_INTERVAL is how often the poller asks Core whether the DNSBL data changed (owner, 2026-11-24).
const CORE_POLL_INTERVAL = 10 * time.Second

// maxRetryEvery is the most polls between two tries of a swap that keeps failing: about 10 min.
const maxRetryEvery = 64

// coreFeed is the poller's state. Only init, before the poller starts, and the poller touch it.
type coreFeed struct {
	m      *pfbUnbound
	client *coreinput.Client
	dir    string                            // the module directory
	tick   func() (<-chan time.Time, func()) // the poller's tick source
	disk   coreinput.State                   // what the module directory holds: the last Sync's state
	served map[string]coreinput.Cursor       // what the live snapshot was built from; nil: nothing
	// pending is whether the module directory holds data the live snapshot was not built from: a swap declined or failed is
	// tried again on the next poll.
	pending bool
	// retryIn is how many polls to skip before the next try, retryEvery the gap after it: a swap that keeps failing is
	// tried after 1, 2, 4, ... polls, at most every maxRetryEvery.
	retryIn, retryEvery int
	// reported is whether Core has been told what is served; lastErr is the last Sync error logged, so that a Core that
	// stays down is logged once.
	reported bool
	lastErr  string
	// reportFailed is whether the last report failed and was logged: a Core that stays down is logged once.
	reportFailed bool
	// observer is whether pfB-DNS was started with --observer, which the Outpost passes only while the Resolver forwards:
	// the module's forwarding setting.
	observer bool
	// newSettings is whether the module directory's ini holds settings the live snapshot was not built from;
	// lastSettingsErr is the last settings sync error logged.
	newSettings     bool
	lastSettingsErr string
	// read is the settings and tables the ini gave when it last changed, which each try of the swap builds with: read once,
	// so that what the read logs is logged once. nil: read at the build.
	read *readSettings
}

// readSettings is what coreFeed.readSettings gives.
type readSettings struct {
	set    *pfbSettings
	tables *snapshot
}

// bootCore boots the module in moduleDir on the Core API that client calls. tick is the poller's tick source (nil: a
// CORE_POLL_INTERVAL ticker).
func bootCore(moduleDir, logDir string, client *coreinput.Client, observer bool, tick func() (<-chan time.Time, func())) (*pfbUnbound, error) {
	if tick == nil {
		tick = func() (<-chan time.Time, func()) {
			ticker := time.NewTicker(CORE_POLL_INTERVAL)
			return ticker.C, ticker.Stop
		}
	}
	feed := &coreFeed{client: client, dir: moduleDir, tick: tick, disk: coreinput.Load(moduleDir), observer: observer}
	if ini := filepath.Join(moduleDir, coreinput.IniFile); !coreinput.Owned(ini) {
		if _, err := os.Lstat(ini); err == nil {
			logWarn("[pfBlockerNG]: the settings cache " + ini + " is not trusted and is not loaded; it is fetched from Core again")
			os.Remove(ini)
		}
	}
	if !feed.trusted() {
		if _, err := os.Lstat(filepath.Join(moduleDir, "pfb_py_sources.json")); err == nil {
			logWarn("[pfBlockerNG]: the DNSBL cache in " + moduleDir + " is not trusted and is not loaded; it is fetched from Core again")
		}
	}
	return initStandardWith(MODULE_ID, moduleDir, logDir, feed)
}

// trusted is whether init may build from the module directory: Load trusts what the last Sync left there.
func (f *coreFeed) trusted() bool { return f.disk.Manifest != (coreinput.Cursor{}) }

// run is the poller's body: drain, then wait for the next tick, until stop is closed. A panic ends only the poller, as
// one ends only the reload watcher.
func (f *coreFeed) run(stop <-chan struct{}, tick <-chan time.Time) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: Core input poller error: %v\n", err)
		}
	}()
	pollLoop(stop, tick, f.drain)
}

// drain syncs with Core, swaps a new generation in, and reports what is served until Core has taken a report. A Sync that
// fails changes nothing served: the live snapshot stays, and so does the module directory's last good state. Only stop
// ends a call to Core: a slow transfer runs to its end, and a Core that dies drops the connection (owner, 2026-11-25).
func (f *coreFeed) drain(stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	state, changed, err := coreinput.Sync(ctx, f.client, f.dir, f.disk)
	f.logSync(err)
	if changed {
		f.disk = state // the zero State after a Sync cut short in its commit: the next one fetches everything
		f.pending, f.retryIn, f.retryEvery = err == nil, 0, 1
	}
	newSettings, err := coreinput.SyncSettings(ctx, f.client, f.dir)
	f.logSettings(err)
	if newSettings {
		f.newSettings, f.retryIn, f.retryEvery, f.read = true, 0, 1, nil
		if set, tables, err := f.readSettings(); err == nil {
			f.read = &readSettings{set, tables}
			f.m.applyOptOuts(set)
		}
	}
	fresh, prev := f.newSettings, f.m.snapshot.Load().settings
	switch {
	case !f.pending && !(fresh && f.trusted()): // new settings wait for data to build with
	case f.retryIn > 0:
		f.retryIn--
	case f.m.reloadRunSwap(f.build):
		f.served, f.reported, f.pending = f.disk.Resources, false, false
		if fresh {
			f.newSettings, f.read = false, nil
			f.m.applyLiveSettings(prev)
		}
	default:
		f.retryIn, f.retryEvery = f.retryEvery-1, min(2*f.retryEvery, maxRetryEvery)
	}
	if !f.reported {
		err := f.client.ReportApplied(ctx, f.served)
		if err != nil && !f.reportFailed {
			logWarn("[pfBlockerNG]: DNSBL: reporting the generation served to Core failed: " + err.Error())
		}
		f.reported, f.reportFailed = err == nil, err != nil
	}
}

// refetch has the next Sync fetch everything whole: a trusted cache that did not build.
func (f *coreFeed) refetch() { f.disk = coreinput.State{} }

// build is the reload builder, with SafeSearch read from the module directory, where Sync keeps Core's. After a settings
// change it builds from the new settings, with the tables they bring, instead of the live ones.
func (f *coreFeed) build() (*snapshot, error) {
	build := f.m.reloadBuilder
	if build == nil {
		build = f.m.reloadBuildSnapshot
	}
	if f.newSettings {
		build = f.buildSettings
	}
	next, err := build()
	if next != nil {
		next.safeSearchDB, next.freshSafeSearch = map[string]safeSearchEntry{}, true
		if !f.m.readSafesearch(next.safeSearchDB) {
			if isFile(f.m.pfb.pfbPySs) {
				return nil, errors.New("SafeSearch: " + f.m.pfb.pfbPySs + " could not be read")
			}
			next.safeSearchDB = nil // Core publishes none
		}
	}
	return next, err
}

// buildSettings builds the snapshot from the module directory's ini, as init does: its settings and tables, not the live
// ones. What init opens with the settings is opened first, so that the snapshot says what is open.
func (f *coreFeed) buildSettings() (*snapshot, error) {
	m := f.m
	if f.read == nil {
		set, tables, err := f.readSettings()
		if err != nil {
			return nil, err
		}
		f.read = &readSettings{set, tables}
	}
	set, tables := f.read.set, f.read.tables
	if !m.sqlite3ResolverCon.Load() {
		if m.validateDbWithRecovery(dbResolver) {
			m.sqlite3ResolverCon.Store(true)
			m.resolverDbFailure.clear()
		} else {
			m.dbOpenFailed(&m.resolverDbFailure, "Failed to open pfb_py_resolver.sqlite database")
		}
	}
	set.pythonMaxmind = m.maxmindFor(set.pythonReply)

	next, err := m.reloadBuildSnapshotWith(set, func() *regexDB { return tables.userRegexDB })
	if next != nil {
		next.settings, next.carryRuntime = set, false
		next.noAAAADB, next.gpListDB, next.gpNetDB = tables.noAAAADB, tables.gpListDB, tables.gpNetDB
	}
	return next, err
}

// readSettings is the settings and tables the module directory's ini gives, as init loads them.
func (f *coreFeed) readSettings() (*pfbSettings, *snapshot, error) {
	config := f.m.loadIniConfig()
	if config == nil {
		return nil, nil, errors.New("settings: " + f.m.pfb.pfbUnboundIni + " is gone")
	}
	set, tables := newModuleSettings(f.dir), newSnapshot()
	if err := f.m.loadIniSettings(config, &set, tables); err != nil {
		return nil, nil, err
	}
	set.forwarding = f.observer
	if !set.pythonEnable {
		return nil, nil, errors.New("settings: python_enable is off")
	}
	return &set, tables, nil
}

// applyOptOuts turns client metrics and the control reader off as soon as new settings turn them off, ahead of the swap
// that applies the rest, which may wait (no data yet, the RAM gate).
func (m *pfbUnbound) applyOptOuts(set *pfbSettings) {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.retired.Load() {
		return
	}
	if !set.metricsClientIp {
		m.dbCapturePrivacyEpochsFor(false)
	}
	if !set.pythonControl {
		m.stopControlWatcher()
	}
}

// applyLiveSettings applies what a settings swap changes outside the snapshot, from the live settings that replaced prev;
// nothing once the module is closing.
func (m *pfbUnbound) applyLiveSettings(prev *pfbSettings) {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.retired.Load() {
		return
	}
	set := m.snapshot.Load().settings
	m.decisionDB.resize(intOf(set.decisiondbMax))
	if set.pythonControl {
		m.startControlWatcher()
	} else {
		m.stopControlWatcher()
	}
	// Captured again on each settings swap, as a start captures it: each open database grants what it holds now, one an
	// opt-out dropped or one this swap opened included.
	m.dbCapturePrivacyEpochsFor(set.metricsClientIp)
	if set.pythonControlLegacy && !prev.pythonControlLegacy {
		warnIfLegacyControlEnabled(true)
	}
}

// logSettings logs a settings sync error once until it changes, and that Core gives settings again.
func (f *coreFeed) logSettings(err error) {
	msg := ""
	switch {
	case errors.Is(err, coreinput.ErrNoSettings):
		msg = "Core holds no settings yet; keeping the settings loaded"
	case err != nil:
		msg = "fetching the settings from Core failed, keeping the settings loaded: " + err.Error()
	}
	logChange(&f.lastSettingsErr, msg, "settings from Core: Core answers again")
}

// logChange logs msg, an error, unless it is last's; an empty msg after an error logs recovered.
func logChange(last *string, msg, recovered string) {
	if msg == *last {
		return
	}
	if msg != "" {
		logWarn("[pfBlockerNG]: " + msg)
	} else {
		logInfo("[pfBlockerNG]: " + recovered)
	}
	*last = msg
}

// logSync logs a Sync error once until it changes, and that Core answers again.
func (f *coreFeed) logSync(err error) {
	msg := ""
	switch {
	case errors.Is(err, coreinput.ErrNoData):
		msg = "Core publishes no DNSBL data; serving what is loaded"
	case err != nil:
		msg = "fetching the DNSBL data from Core failed, serving what is loaded: " + err.Error()
	}
	logChange(&f.lastErr, msg, "DNSBL data from Core: Core answers again")
}
