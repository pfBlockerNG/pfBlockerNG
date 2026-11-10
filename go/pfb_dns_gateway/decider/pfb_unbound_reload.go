// Go translation of the live DNSBL update of src/usr/local/pkg/pfblockerng/pfb_unbound.py (ADR-10): PHP flips the
// generation in pfb_py_reload when the feeds change, pfb_reload_watcher sees it advance, the RAM gate decides, the
// reload builder (_build_swap_snapshot) builds a fresh snapshot from the manifest and rebuildAndSwap publishes it, and
// the applied record (pfb_py_reload.applied) names the generation that is live, which PHP waits for.
//
// A query keeps the snapshot it loaded (qstate.snap), so one in flight finishes on the old data and a new one sees the
// new. Python's watcher runs on a daemon thread and waits on a kqueue or a poll; here it is a goroutine that polls.
package decider

import (
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// RELOAD_BYTES_PER_ENTRY is the steady-state retained bytes per matcher entry (ADR-05 3a / ADR-10 spike: 274-276), which
// projects the both-resident transient of a build; RELOAD_RAM_HEADROOM_BYTES is what the projection must leave free.
const (
	RELOAD_BYTES_PER_ENTRY    = 276
	RELOAD_RAM_HEADROOM_BYTES = 64 * 1024 * 1024
)

// reloadGenerationReadLimit is how much of the sentinel is read: Python's text reader decodes one 8 KiB chunk to return the
// first line.
const reloadGenerationReadLimit = 8192

// reloadReadGeneration is _reload_read_generation: the generation on the first line of the sentinel, int() of the stripped
// line (a sign is accepted, as in Python), or none when the file is absent, unreadable, empty on that line or not an
// integer. A directory is unreadable.
// shortcut: Python raises on an undecodable byte anywhere in the first chunk and Go only on one in the first line, which
// then is no integer either way; the sentinel is a PHP-written decimal.
func reloadReadGeneration(path string) (int64, bool) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, reloadGenerationReadLimit))
	if err != nil {
		return 0, false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line, _, _ = strings.Cut(line, "\r")
	if line = pyStrip(line); line == "" {
		return 0, false
	}
	return reloadParseInt(line)
}

// reloadParseInt is int(text) for the generation: an optional sign, then decimal digits of any Unicode script (category
// Nd, mixed freely) with single underscores between them; more than 4300 digits is a ValueError, as in CPython 3.11. text
// is already stripped.
// shortcut: Python's int is unbounded and a generation here is an int64, so a value past int64 stays at the nearest bound;
// PHP writes the counter, which cannot get there. Two such generations compare equal here, where Python's differ.
func reloadParseInt(text string) (int64, bool) {
	negative := false
	if text != "" && (text[0] == '+' || text[0] == '-') {
		negative = text[0] == '-'
		text = text[1:]
	}
	if text == "" || text[0] == '_' || text[len(text)-1] == '_' || strings.Contains(text, "__") {
		return 0, false
	}
	var value int64
	saturated := false
	digits := 0
	for _, r := range text {
		if r == '_' {
			continue
		}
		digit, ok := decimalDigit(r)
		if !ok {
			return 0, false
		}
		digits++
		switch {
		case saturated:
		case value > (math.MaxInt64-int64(digit))/10: // the next step would pass int64: stop at the bound
			saturated = true
		default:
			value = value*10 + int64(digit)
		}
	}
	if digits > pyIntMaxStrDigits {
		return 0, false
	}
	switch {
	case saturated && negative:
		return math.MinInt64, true
	case saturated:
		return math.MaxInt64, true
	case negative:
		return -value, true
	}
	return value, true
}

// reloadRAMGateOK is _reload_ram_gate_ok: whether the both-resident transient of a rebuild for entryCount entries (2 x
// entryCount x 276 bytes) plus the headroom fits total physical RAM. Unknown RAM declines, fail closed.
func reloadRAMGateOK(entryCount int, totalRAM func() (uint64, bool)) bool {
	total, ok := totalRAM()
	if !ok {
		return false
	}
	return total >= reloadProjectedBytes(entryCount)+RELOAD_RAM_HEADROOM_BYTES
}

func reloadProjectedBytes(entryCount int) uint64 {
	return 2 * uint64(max(entryCount, 0)) * RELOAD_BYTES_PER_ENTRY
}

// reloadRunSwap is _reload_run_swap: one RAM-gated rebuildAndSwap. The gate projects the LIVE snapshot's counts +
// regex_count and is asked first: a box that cannot fit the transient declines, the old snapshot stays live and the
// builder is not called. It reports whether a snapshot was swapped in, so that only then the caller advances the applied
// marker: a decline or a failed build leaves PHP's wait to time out.
func (m *pfbUnbound) reloadRunSwap(build func() (*snapshot, error)) bool {
	entryCount := 0
	if snap := m.snapshot.Load(); snap != nil {
		entryCount = snap.counts + snap.regexCount
	}
	total := m.totalRAM
	if total == nil {
		total = totalPhysicalRAM
	}
	if !reloadRAMGateOK(entryCount, total) {
		logInfo(fmt.Sprintf("[pfBlockerNG]: DNSBL reload DECLINED -- RAM-constrained box (projected ~%d MiB for %d entries would not fit "+
			"total RAM); keeping current lists, the update needs the restart fallback", reloadProjectedBytes(entryCount)>>20, entryCount))
		return false
	}
	if m.rebuildAndSwap(build, true) {
		logInfo("[pfBlockerNG]: DNSBL lists reloaded with no restart (zero-downtime swap)")
		return true
	}
	return false
}

// reloadWriteApplied is _reload_write_applied: gen is published as the applied-generation marker (temp file, fsync,
// rename), once at startup with the baseline and after each successful swap. A write failure is logged and the swap still
// stands; PHP's wait then times out.
func (m *pfbUnbound) reloadWriteApplied(gen int64) {
	path := m.pfb.pfbPyReloadApplied
	if path == "" {
		return
	}
	if err := writeMarker(path, strconv.FormatInt(gen, 10)+"\n"); err != nil {
		fmt.Fprintf(logOutput, "[pfBlockerNG]: failed to write applied-generation marker [ %s ]: %v\n", path, err)
	}
}

// reloadBuildSnapshot is _build_swap_snapshot: every stratum rebuilt into FRESH values from the files, nothing live
// written. It returns no snapshot (Python's None) when the manifest is absent or cannot be built, which fails the swap
// closed.
//
// Like Python it re-reads the ini for [MAIN] regex_list and nothing else: every other setting is the live snapshot's (the
// module's, from init), and so are the TLD Allow roots and the PSL policies. The snapshot carries no settings (the swap
// takes the live ones) and is marked carryRuntime, so the swap gives it the runtime tables.
func (m *pfbUnbound) reloadBuildSnapshot() (*snapshot, error) {
	settings := &m.pfb
	if live := m.snapshot.Load(); live != nil {
		settings = live.settings
	}
	build := m.dnsblBuildFromManifest(settings.pfbPySources)
	if build == nil {
		return nil, nil
	}

	next := newSnapshot()
	next.dataDB, next.zoneDB, next.feedGroupIndexDB, next.whiteDB = build.dataDB, build.zoneDB, build.feedGroupIndexDB, build.whiteDB
	next.pslRules, next.builtinLogFlag, next.rejects = build.pslRules, build.builtinLogFlag, build.rejects
	regexDBUpdate(next.regexDB, build.regexDB)
	regexDBUpdate(next.allowRegexDB, build.allowRegexDB)
	// The user regex of the ini come first; the Custom_List rows of the manifest follow them.
	regexDBUpdate(next.userRegexDB, m.reloadUserRegex(settings))
	regexDBUpdate(next.userRegexDB, build.userRegexDB)
	regexDBUpdate(next.userAllowRegexDB, build.userAllowRegexDB)
	next.importantRules = build.importantRules || next.userRegexDB.len() > 0

	// hstsDB is no part of the manifest: omitting it would ship an empty one and flip HSTS NULL-vs-VIP behaviour.
	if settings.pythonHsts && isFile(settings.pfbPyHsts) {
		if data, err := m.readFile(settings.pfbPyHsts); err != nil {
			logErr(fmt.Sprintf("[pfBlockerNG]: reload: failed to load %s: %v", settings.pfbPyHsts, err))
		} else {
			addHstsLines(next.hstsDB, data)
		}
	}

	loaded := len(next.dataDB) > 0 || len(next.zoneDB) > 0 || next.regexDB.len() > 0 || next.allowRegexDB.len() > 0 ||
		next.userRegexDB.len() > 0 || next.userAllowRegexDB.len() > 0
	m.finishSnapshot(next, settings, m.dnsblStatsWanted(settings) || loaded)
	next.carryRuntime = true
	return next, nil
}

// reloadUserRegex is the user regex of [MAIN] regex_list, through the same admission gate and opt-in length cap as init's
// load. An ini that cannot be read loads none, and is logged.
func (m *pfbUnbound) reloadUserRegex(settings *pfbSettings) *regexDB {
	if !isFile(settings.pfbUnboundIni) {
		return nil
	}
	config := newConfigParser()
	if err := config.read(settings.pfbUnboundIni); err != nil {
		logErr("[pfBlockerNG]: reload: failed to load user REGEX ini: " + err.Error())
		return nil
	}
	return dnsblCompileUserRegex(loadUserRegexEntries(config), settings.regexCap)
}

// reloadWatcher is the state of pfb_reload_watcher: the sentinel, the builder, and the last generation it acted on.
//
// A panic in the loop body ends only the watcher, as Python's uncaught exception ends only the watcher thread: run
// recovers it and logs it, and the module goes on without a reload watcher (reloadStop stays set, as Python leaves
// pfb["reload_watcher"] True, so nothing restarts it). A builder's failure is not that: it is the error rebuildAndSwap
// catches, and the watcher lives.
type reloadWatcher struct {
	m        *pfbUnbound
	sentinel string
	build    func() (*snapshot, error)
	lastGen  int64
	hasLast  bool // Python's last_gen is None until a generation is seen
}

// newReloadWatcher adopts the generation already on the sentinel WITHOUT building (init loaded the lists synchronously:
// the watcher only acts on a FUTURE advance) and publishes it as the applied generation, so that PHP's first wait has a
// floor to compare against. Python does this on the watcher thread; here it is done before the goroutine starts.
func (m *pfbUnbound) newReloadWatcher() *reloadWatcher {
	w := &reloadWatcher{m: m, sentinel: m.pfb.pfbPyReload, build: m.reloadBuilder}
	if w.build == nil {
		w.build = m.reloadBuildSnapshot
	}
	if gen, ok := reloadReadGeneration(w.sentinel); ok {
		w.lastGen, w.hasLast = gen, true
		m.reloadWriteApplied(gen)
	}
	return w
}

// drainAndSwap is the watcher's single-flight: it builds for the latest generation, then re-reads the sentinel, and builds
// once more if it advanced during the build, until it is stable or stop is closed. The generation is taken as seen BEFORE
// the build, so a declined or failed one is not retried; the applied marker advances only on a real swap.
func (w *reloadWatcher) drainAndSwap(stop <-chan struct{}) {
	for !stopped(stop) {
		cur, ok := reloadReadGeneration(w.sentinel)
		if !ok || (w.hasLast && cur <= w.lastGen) {
			return
		}
		w.lastGen, w.hasLast = cur, true
		if w.m.reloadRunSwap(w.build) {
			w.m.reloadWriteApplied(cur)
		}
	}
}

// run is the daemon body: drain, then wait for the next tick, until stop is closed.
// shortcut: Python waits on a kqueue (EVFILT_VNODE on the sentinel's directory) on FreeBSD and polls elsewhere; Go polls
// on every tick, which only adds up to RELOAD_POLL_INTERVAL of latency to a swap. Upgrade if that latency matters.
func (w *reloadWatcher) run(stop <-chan struct{}, tick <-chan time.Time) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: reload watcher error: %v\n", err)
		}
	}()
	pollLoop(stop, tick, w.drainAndSwap)
}

// startReloadWatcher starts the watcher (pfb["reload_watcher"] True: reloadStop is set) unless it already runs.
func (m *pfbUnbound) startReloadWatcher() {
	if m.reloadStop != nil {
		return
	}
	m.reloadStop = startPoller(m.reloadTick, m.newReloadWatcher().run)
}

// stopReloadWatcher is deinit's stop of the watcher: it returns once the watcher has ended.
func (m *pfbUnbound) stopReloadWatcher() {
	if m.reloadStop != nil {
		m.reloadStop()
		m.reloadStop = nil
	}
}
