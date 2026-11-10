// Go translation of the DNSBL control surface of src/usr/local/pkg/pfblockerng/pfb_unbound.py (PFBL-03):
// pfb_apply_control_command, the one handler both transports route to (the legacy DNS-TXT branch of operate() and the
// local privileged command channel), its timers, and the channel's reader, pfb_control_watcher.
//
// Python mutates pfb["python_blacklist"], pfb["gpListDB"] and the gpListDB dict in place. A published snapshot is never
// written (the owner's #3511 rule), so a command here loads the live snapshot, edits copies of what it changes and
// publishes the copy with the same gen: Python clears no decision memo on a control command either, and neither the
// gate nor the Group Policy bypass is memoized. Every publisher (a command, a timer expiry, rebuildAndSwap) holds
// pfbUnbound.publishMu across its load and its store, so two of them never lose each other's write; a query in flight
// keeps the snapshot it loaded (qstate.snap).
package decider

import (
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// RELOAD_POLL_INTERVAL is how often the control watcher looks at the channel.
const RELOAD_POLL_INTERVAL = 2 * time.Second

// controlEdit is the copy-on-write view of the live snapshot that one control command writes: nothing is copied until it
// is written. openStats marks a command that newly wants the DNSBL statistics database: it opens once the edit is
// published, outside publishMu, so that a database that is slow to open holds no publisher.
type controlEdit struct {
	live      *snapshot
	settings  *pfbSettings
	gpListDB  map[string]int
	openStats bool
}

func newControlEdit(m *pfbUnbound) *controlEdit { return &controlEdit{live: m.snapshot.Load()} }

func (e *controlEdit) writeSettings() *pfbSettings {
	if e.settings == nil {
		copied := *e.live.settings
		e.settings = &copied
	}
	return e.settings
}

func (e *controlEdit) readSettings() *pfbSettings {
	if e.settings != nil {
		return e.settings
	}
	return e.live.settings
}

func (e *controlEdit) writeGpListDB() map[string]int {
	if e.gpListDB == nil {
		e.gpListDB = maps.Clone(e.live.gpListDB)
		if e.gpListDB == nil {
			e.gpListDB = map[string]int{}
		}
	}
	return e.gpListDB
}

// listed is gpListDB.get(ip) is not None.
func (e *controlEdit) listed(ip string) bool {
	table := e.live.gpListDB
	if e.gpListDB != nil {
		table = e.gpListDB
	}
	_, ok := table[ip]
	return ok
}

// publishControl stores what the edit changed as the next snapshot; the caller holds publishMu.
func (m *pfbUnbound) publishControl(e *controlEdit) {
	if e.settings == nil && e.gpListDB == nil {
		return
	}
	if m.retired.Load() {
		return
	}
	next := *e.live
	next.carryRuntime = false // a control edit is no reload build
	if e.settings != nil {
		next.settings = e.settings
	}
	if e.gpListDB != nil {
		next.gpListDB = e.gpListDB
	}
	m.snapshot.Store(&next)
}

// pyIntMaxStrDigits is sys.get_int_max_str_digits(): CPython 3.11's int() raises a ValueError for a string of more
// digits than this, leading zeros included.
const pyIntMaxStrDigits = 4300

// pyErrReprLimit is the precision of the "%.200R" CPython's int() error text formats the offending string with.
const pyErrReprLimit = 200

// controlDuration is python_control_duration: the seconds of a valid duration (1-3600), else 0 (Python's False). The
// ValueError arms of int() write Python's stderr line.
// shortcut: str.isnumeric() is Unicode's Numeric_Type != None; unicode.IsNumber is Nd, Nl and No, so a CJK numeral
// such as "一" (isnumeric, but int() raises) is "not numeric" here. The result is the same, 0; only Python's stderr
// line for it is not written.
// shortcut: Go's unicode tables are Unicode 17 where Python 3.11's are Unicode 14, so a digit or numeral added since is
// numeric here and not there; only a duration made of such characters, which no writer of the channel emits, differs.
func controlDuration(duration string) int {
	if duration == "" || strings.ContainsFunc(duration, func(r rune) bool { return !unicode.IsNumber(r) }) {
		return 0
	}
	value, digits := 0, 0
	for _, r := range duration {
		digit, ok := decimalDigit(r)
		if !ok {
			// int() takes decimal digits only: "²" is numeric but not an int
			fmt.Fprint(logOutput, "[pfBlockerNG] python_control_duration: invalid literal for int() with base 10: "+pyErrRepr(duration))
			return 0
		}
		digits++
		if value <= 3600 { // past the range the value only has to stay out of it
			value = value*10 + digit
		}
	}
	if digits > pyIntMaxStrDigits {
		fmt.Fprintf(logOutput, "[pfBlockerNG] python_control_duration: Exceeds the limit (%d digits) for integer string conversion: "+
			"value has %d digits; use sys.set_int_max_str_digits() to increase the limit", pyIntMaxStrDigits, digits)
		return 0
	}
	if 0 < value && value <= 3600 {
		return value
	}
	return 0
}

// pyErrRepr is repr(text) cut to the first pyErrReprLimit characters, as "%.200R" formats it.
func pyErrRepr(text string) string {
	repr := []rune(pysem.Repr(text))
	if len(repr) > pyErrReprLimit {
		repr = repr[:pyErrReprLimit]
	}
	return string(repr)
}

// decimalDigit is the value of a Unicode decimal digit (category Nd): the Nd characters come in contiguous runs of ten
// that start at a zero.
func decimalDigit(r rune) (int, bool) {
	if !unicode.Is(unicode.Nd, r) {
		return 0, false
	}
	start := r
	for unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return int((r - start) % 10), true
}

// controlThread is python_control_thread: whether a control timer of that name is running. A timer is a thread in
// Python and stays active until its body returns; here it is a name in controlActive until its callback ends.
func (m *pfbUnbound) controlThread(tname string) bool {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	_, active := m.controlActive[tname]
	return active
}

// controlStartThread is python_control_start_thread: body runs after delay, off the caller's goroutine, and the name
// stays active until it returns. Python's "thread failed" arms have no Go counterpart: starting a timer cannot fail.
func (m *pfbUnbound) controlStartThread(tname string, delay time.Duration, body func()) {
	m.controlMu.Lock()
	if m.controlActive == nil {
		m.controlActive = map[string]struct{}{}
	}
	m.controlActive[tname] = struct{}{}
	m.controlMu.Unlock()
	schedule := m.afterFunc
	if schedule == nil {
		schedule = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	}
	schedule(delay, func() {
		body()
		m.controlMu.Lock()
		delete(m.controlActive, tname)
		m.controlMu.Unlock()
	})
}

// controlSleep is python_control_sleep's body once the sleep is over: blocking is back on, and the DNSBL statistics
// database init skipped opens (issue #870).
func (m *pfbUnbound) controlSleep() {
	m.publishMu.Lock()
	edit := newControlEdit(m)
	edit.writeSettings().pythonBlacklist = true
	m.publishControl(edit)
	m.publishMu.Unlock()
	m.openDnsblStatsDbIfWanted(edit.readSettings())
}

// controlAddbypass is python_control_addbypass's body once the sleep is over: the IP leaves the Group Policy bypass list.
func (m *pfbUnbound) controlAddbypass(bIP string) bool {
	m.publishMu.Lock()
	defer m.publishMu.Unlock()
	edit := newControlEdit(m)
	if !edit.listed(bIP) {
		return false
	}
	delete(edit.writeGpListDB(), bIP)
	m.publishControl(edit)
	return true
}

// pfbApplyControlCommand is pfb_apply_control_command: the single DNSBL-control handler. controlCommand is the
// dot-split token list both transports build; the IP and the duration are validated here, never trusted from the
// transport. It returns (applied, message). It holds publishMu while it edits and publishes, so the check for a running
// timer and the start of one are one step, as the Python callers' GIL-held sequence is not.
func (m *pfbUnbound) pfbApplyControlCommand(controlCommand []string) (bool, string) {
	m.publishMu.Lock()
	if m.retired.Load() {
		m.publishMu.Unlock()
		return false, ""
	}
	edit := newControlEdit(m)
	controlRcd, controlMsg := m.applyControlCommand(edit, controlCommand)
	m.publishControl(edit)
	m.publishMu.Unlock()
	if edit.openStats {
		m.openDnsblStatsDbIfWanted(edit.readSettings())
	}
	return controlRcd, controlMsg
}

func (m *pfbUnbound) applyControlCommand(edit *controlEdit, controlCommand []string) (bool, string) {
	controlRcd := false
	controlMsg := ""

	if len(controlCommand) >= 2 {
		switch controlCommand[1] {
		case "disable":
			controlRcd = true
			controlMsg = "Python_control: DNSBL disabled"
			edit.writeSettings().pythonBlacklist = false

			// If duration specified, disable DNSBL Blocking for specified time in seconds
			if len(controlCommand) == 3 && controlCommand[2] != "" {
				// Validate Duration argument
				if duration := controlDuration(controlCommand[2]); duration != 0 {
					// Ensure thread is not active
					if !m.controlThread("sleep") {
						m.controlStartThread("sleep", time.Duration(duration)*time.Second, m.controlSleep)
						controlMsg = fmt.Sprintf("%s for %d second(s)", controlMsg, duration)
					} else {
						controlRcd = false
						controlMsg = "Python_control: DNSBL disabled: Previous call still in progress"
					}
				} else {
					controlRcd = false
					controlMsg = fmt.Sprintf("Python_control: DNSBL disabled: duration [ %s ] out of range (1-3600sec)", controlCommand[2])
				}
			}

		case "enable":
			controlRcd = true
			controlMsg = "Python_control: DNSBL enabled"
			edit.writeSettings().pythonBlacklist = true
			// Enabling newly satisfies _dnsbl_stats_wanted: the statistics database init skipped at boot opens once this is
			// published (issue #870).
			edit.openStats = true

		case "addbypass", "removebypass":
			// PFBL-03: reject a malformed bypass command instead of raising
			if len(controlCommand) < 3 || controlCommand[2] == "" {
				return false, "Python_control: Missing bypass IP"
			}
			bIP := strings.ReplaceAll(controlCommand[2], "-", ".")
			if _, err := pysem.IPAddress(bIP); err != nil {
				return false, fmt.Sprintf("Python_control: Invalid IP: [ %s ]", bIP)
			}

			if !edit.readSettings().gpListDB {
				edit.writeSettings().gpListDB = true
			}

			controlRcd = true
			if controlCommand[1] == "addbypass" {
				controlMsg = fmt.Sprintf("Python_control: Add bypass for IP: [ %s ]", bIP)

				// If duration specified, disable DNSBL Blocking for specified time in seconds
				if len(controlCommand) == 4 && controlCommand[3] != "" {
					// Validate Duration argument
					if duration := controlDuration(controlCommand[3]); duration != 0 {
						// Ensure thread is not active
						if !m.controlThread("addbypass" + bIP) {
							m.controlStartThread("addbypass"+bIP, time.Duration(duration)*time.Second, func() { m.controlAddbypass(bIP) })
							edit.writeGpListDB()[bIP] = 0
							controlMsg = fmt.Sprintf("%s for %d second(s)", controlMsg, duration)
						} else {
							controlRcd = false
							controlMsg = fmt.Sprintf("Python_control: Add bypass for IP: [ %s ]: Previous call still in progress", bIP)
						}
					} else {
						controlRcd = false
						controlMsg = fmt.Sprintf("Python_control: Add bypass for IP: [ %s ]: duration [ %s ] out of range (1-3600sec)", bIP, controlCommand[3])
					}
				} else {
					// Add bypass called without duration
					edit.writeGpListDB()[bIP] = 0
				}
			} else {
				if edit.listed(bIP) {
					controlMsg = fmt.Sprintf("Python_control: Remove bypass for IP: [ %s ]", bIP)
					delete(edit.writeGpListDB(), bIP)
				} else {
					controlMsg = fmt.Sprintf("Python_control: IP not in Group Policy: [ %s ]", bIP)
				}
			}
		}
	}

	return controlRcd, controlMsg
}

// --- the control channel: pfb_control_watcher ---

// controlReadRecord is _control_read_record: the channel's JSON record, or nil if the file is absent, unreadable, not
// UTF-8 text, empty, malformed or not an object. Any read or parse error is "no command".
func controlReadRecord(path string) *jsonObject { return channelReadRecord(path, parsePyJSON) }

// channelReadRecord is _control_read_record with the JSON parser the caller's record needs: the query channel's reaches
// a reply, so it keeps a lone surrogate (parsePyJSONSurrogates).
func channelReadRecord(path string, parse func(string) (any, bool)) *jsonObject {
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return nil
	}
	value, ok := parse(string(data))
	if !ok {
		return nil
	}
	record, _ := value.(*jsonObject)
	return record
}

// controlSeq is record.get("seq") when isinstance(seq, int): a JSON integer of any size, and a JSON true or false, which
// are 1 and 0 because bool is an int in Python. A float, a string, null or a missing seq is none.
func controlSeq(record *jsonObject) (*big.Int, bool) {
	switch seq := record.vals["seq"].(type) {
	case *big.Int:
		return seq, true
	case bool:
		if seq {
			return big.NewInt(1), true
		}
		return new(big.Int), true
	}
	return nil, false
}

// markerChmod is os.Chmod; a test replaces it to reach the chmod failure, which a process that owns the file cannot cause.
var markerChmod = os.Chmod

// writeMarker publishes text at path the way Python's marker writers do: a temp file next to it, written, fsynced and
// renamed over it, so a reader sees the old marker or the new one. A mode that is not 0 is chmod'ed onto the temp file
// before the rename, as the query reply's 0o640 is. A failure leaves no temp file and is returned as the text Python's
// OSError prints (str(e)): an open or a chmod error names the temp file, a rename error both files, and an error of the
// write, the fsync or the close names none. "" is success.
func writeMarker(path, text string, mode os.FileMode) string {
	tmp := path + ".tmp"
	err := func() error {
		fh, err := os.Create(tmp)
		if err != nil {
			return err
		}
		_, err = fh.WriteString(text)
		if err == nil {
			err = fh.Sync()
		}
		if closeErr := fh.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return &os.PathError{Op: "write", Path: tmp, Err: errors.Unwrap(err)}
		}
		if mode != 0 {
			if err := markerChmod(tmp, mode); err != nil {
				return err
			}
		}
		return os.Rename(tmp, path)
	}()
	if err == nil {
		return ""
	}
	syscall.Unlink(tmp) // not os.Remove, which also removes an empty directory: Python's os.unlink refuses one
	var pathErr *os.PathError
	var linkErr *os.LinkError
	switch {
	case errors.As(err, &linkErr):
		// os.Rename refuses a directory in the way with EEXIST before it asks the kernel; rename(2), which Python calls, says
		// EISDIR for a file renamed over a directory.
		reason := linkErr.Err
		if info, statErr := os.Lstat(linkErr.New); reason == syscall.EEXIST && statErr == nil && info.IsDir() {
			reason = syscall.EISDIR
		}
		return pyOSError(reason, "") + ": " + pysem.Repr(linkErr.Old) + " -> " + pysem.Repr(linkErr.New)
	case errors.As(err, &pathErr) && (pathErr.Op == "open" || pathErr.Op == "chmod"):
		return pyOSError(pathErr.Err, pathErr.Path)
	case errors.As(err, &pathErr):
		return pyOSError(pathErr.Err, "")
	}
	return err.Error()
}

// controlWriteApplied is _control_write_applied: seq is published as the applied-sequence marker (temp file, fsync,
// rename). A write failure is logged and the command still stands. A module that is closing writes none, whether its
// command was refused or ran just before deinit began: the check is made at the write.
func (m *pfbUnbound) controlWriteApplied(seq *big.Int) {
	path := m.pfb.pfbPyControlApplied
	if path == "" {
		return
	}
	m.whileNotRetired(func() {
		if failure := writeMarker(path, seq.String()+"\n", 0); failure != "" {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: failed to write control applied marker [ %s ]: %s\n", path, failure)
		}
	})
}

// controlRecordToCommand is _control_record_to_command: the dot-split token list the shared handler consumes, or nil when
// the command is unknown or a field it needs is absent. The duration token is str() of the JSON value, whatever its type.
func controlRecordToCommand(record *jsonObject) []string {
	cmd, _ := record.vals["cmd"].(string)
	if cmd != "disable" && cmd != "enable" && cmd != "addbypass" && cmd != "removebypass" {
		return nil
	}

	command := []string{"python_control", cmd}
	duration, hasDuration := record.vals["duration"]
	switch cmd {
	case "addbypass", "removebypass":
		ip, _ := record.vals["ip"].(string)
		if ip == "" {
			return nil
		}
		// The shared handler un-maps '-' to '.' (the DNS-TXT transport encoding); the channel carries the IP verbatim,
		// so a dotted IPv4 passes through unchanged.
		command = append(command, ip)
		// addbypass takes an optional duration as the 4th token.
		if cmd == "addbypass" && hasDuration {
			command = append(command, pyStr(duration))
		}
	case "disable":
		// disable carries an optional duration as the 3rd token (validated downstream).
		if hasDuration {
			command = append(command, pyStr(duration))
		}
	}
	return command
}

// controlWatcher is the state of pfb_control_watcher: the channel and the last sequence it consumed.
//
// pfb_apply_control_command has no failing path in Go, so Python's "control command failed" and "control watcher error"
// catches, which keep the daemon alive past an exception, have no counterpart.
type controlWatcher struct {
	m       *pfbUnbound
	channel string
	lastSeq *big.Int
}

// newControlWatcher adopts the seq of any record already on disk WITHOUT applying it (a record left by a prior run is
// not replayed) and publishes it as the applied baseline; the watcher only acts on a FUTURE advance. Python does this on
// the watcher thread; here it is done before the goroutine starts, so a record written right after init cannot be taken
// for the baseline.
func (m *pfbUnbound) newControlWatcher() *controlWatcher {
	w := &controlWatcher{m: m, channel: m.pfb.pfbPyControl, lastSeq: new(big.Int)}
	if record := controlReadRecord(w.channel); record != nil {
		if seq, ok := controlSeq(record); ok {
			w.lastSeq = seq
		}
	}
	m.controlWriteApplied(w.lastSeq)
	return w
}

func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

// drainAndApply reads the record and applies it iff its seq strictly advances, then republishes the applied seq: on
// every consumed record, whether it was applied or rejected, so the writer's wait never blocks on a record the reader
// already saw. A seq that does not advance is left alone, marker included.
func (w *controlWatcher) drainAndApply(stop <-chan struct{}) {
	for !stopped(stop) {
		record := controlReadRecord(w.channel)
		if record == nil || w.m.retired.Load() { // a record read after Close (the read was blocked) is not applied
			return
		}
		seq, ok := controlSeq(record)
		if !ok || seq.Cmp(w.lastSeq) <= 0 {
			return
		}
		w.lastSeq = seq
		controlHook("apply")
		if command := controlRecordToCommand(record); command != nil {
			if _, msg := w.m.pfbApplyControlCommand(command); msg != "" {
				logInfo("[pfBlockerNG]: " + msg)
			}
		}
		controlHook("marker")
		w.m.controlWriteApplied(seq)
	}
}

// controlHook is called by drainAndApply before it applies a record ("apply") and before it publishes the applied marker
// ("marker"); a variable so that a test can retire the module at exactly that point.
var controlHook = func(stage string) {}

// run is the daemon body: drain, then wait for the next tick, until stop is closed.
// shortcut: Python waits on a kqueue (EVFILT_VNODE on the channel's directory) on FreeBSD and polls elsewhere; Go polls
// on every tick, which only adds up to RELOAD_POLL_INTERVAL of latency to a command. Upgrade if that latency matters.
func (w *controlWatcher) run(stop <-chan struct{}, tick <-chan time.Time) {
	pollLoop(stop, tick, w.drainAndApply)
}

// pollLoop is a watcher's body: drain, then wait for the next tick, until stop is closed.
func pollLoop(stop <-chan struct{}, tick <-chan time.Time, drain func(stop <-chan struct{})) {
	for !stopped(stop) {
		drain(stop)
		select {
		case <-stop:
			return
		case <-tick:
		}
	}
}

// watcherStopWait is how long a stop waits for a watcher's goroutine: deinit's join(timeout=5). A variable so that a test
// can shorten it.
var watcherStopWait = 5 * time.Second

// startPoller runs the watcher `name`'s loop on its own goroutine, fed by the tick source tickFor makes (nil: a
// RELOAD_POLL_INTERVAL ticker), and returns what stops it and waits for its goroutine, the release of the tick source
// included, to end. The wait is bounded by watcherStopWait: a goroutine stuck in a drain is left to finish by itself, one
// line says so, and the stop returns. Call the stop once.
func startPoller(name string, tickFor func() (<-chan time.Time, func()), run func(stop <-chan struct{}, tick <-chan time.Time)) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	if tickFor == nil {
		tickFor = func() (<-chan time.Time, func()) {
			ticker := time.NewTicker(RELOAD_POLL_INTERVAL)
			return ticker.C, ticker.Stop
		}
	}
	tick, release := tickFor()
	go func() {
		defer close(done)
		defer release()
		run(stop, tick)
	}()
	return func() {
		close(stop)
		timer := time.NewTimer(watcherStopWait)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			logWarn(fmt.Sprintf("[pfBlockerNG]: %s watcher did not stop within %s, going on", name, watcherStopWait))
		}
	}
}

// startControlWatcher starts the watcher (pfb["control_watcher"] True: controlStop is set) unless it already runs.
func (m *pfbUnbound) startControlWatcher() {
	if m.controlStop != nil {
		return
	}
	m.controlStop = startPoller("control", m.controlTick, m.newControlWatcher().run)
}

// stopControlWatcher is deinit's stop of the watcher: it returns once the watcher has ended, or after watcherStopWait.
func (m *pfbUnbound) stopControlWatcher() {
	if m.controlStop != nil {
		m.controlStop()
		m.controlStop = nil
	}
}
