// Tests for the Go translation of pfb_unbound.py's DNSBL control channel: _control_read_record,
// _control_write_applied, _control_record_to_command and pfb_control_watcher. They mirror
// tests/test_pfbl03_control_channel.py (TestControlReadRecord, TestRecordToCommand, TestControlWriteApplied,
// TestControlWatcherLoop); the record rows replay testdata/pfb_unbound_control_oracle.json, which
// testdata/gen_pfb_unbound_control_oracle.py records from pfb_unbound.py on CPython 3.11. Python waits on a kqueue or a
// poll; here the watcher's tick is a channel the test sends on, so no test waits on a clock.
package decider

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chModule is a module whose control channel and applied marker live in its own directory; no watcher runs.
func chModule(t *testing.T) *pfbUnbound {
	t.Helper()
	m := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\n"))
	opInstall(t, m, func(s *pfbSettings) { opEnable(s) }, nil)
	m.afterFunc = (&ctlTimers{}).afterFunc
	return m
}

func chPublish(t *testing.T, m *pfbUnbound, text string) {
	t.Helper()
	if err := os.WriteFile(m.pfb.pfbPyControl, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// chApplied is the applied marker's text, "" if there is none.
func chApplied(t *testing.T, m *pfbUnbound) string {
	t.Helper()
	data, err := os.ReadFile(m.pfb.pfbPyControlApplied)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func chRecord(t *testing.T, text string) *jsonObject {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pfb_py_control")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return controlReadRecord(path)
}

// --- _control_read_record, the seq check and _control_record_to_command ---

func TestControlReadRecordMatchesPythonOnTheOracleRows(t *testing.T) {
	for _, row := range ctlOracle(t).Records {
		record := chRecord(t, row.Text)
		if (record != nil) != row.Record {
			t.Errorf("%.60q: record present = %v, want %v", row.Text, record != nil, row.Record)
			continue
		}
		if record == nil {
			continue
		}
		var seq *string
		if value, ok := controlSeq(record); ok {
			text := value.String()
			seq = &text
		}
		if (seq == nil) != (row.Seq == nil) || (seq != nil && *seq != *row.Seq) {
			t.Errorf("%.60q: seq = %v, want %v", row.Text, seq, row.Seq)
		}
		command := controlRecordToCommand(record)
		if !equalStrings(command, row.Command) || (command == nil) != (row.Command == nil) {
			t.Errorf("%.60q: command = %q, want %q", row.Text, command, row.Command)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestControlReadRecordIsNoneForAnAbsentFileOrADirectory(t *testing.T) {
	dir := t.TempDir()
	if record := controlReadRecord(filepath.Join(dir, "absent")); record != nil {
		t.Errorf("record of an absent file = %v, want none", record)
	}
	if record := controlReadRecord(dir); record != nil {
		t.Errorf("record of a directory = %v, want none", record)
	}
}

// The file is read as UTF-8 text: bytes that are not UTF-8 make open().read() raise, which is no record.
func TestControlReadRecordIsNoneForBytesThatAreNotUTF8(t *testing.T) {
	if record := chRecord(t, "{\"seq\": 1, \"cmd\": \"enable\", \"x\": \"\xff\"}"); record != nil {
		t.Errorf("record = %v, want none: the file is not valid UTF-8", record)
	}
	if record := chRecord(t, "{\"seq\": 1, \"cmd\": \"enable\", \"x\": \"\xed\xa0\x80\"}"); record != nil {
		t.Errorf("record = %v, want none: an encoded surrogate is not valid UTF-8", record)
	}
	if record := chRecord(t, "{\"seq\": 1, \"cmd\": \"enable\"}"); record == nil {
		t.Errorf("record = none for valid text, want the record")
	}
}

// shortcut: Python raises an uncaught RecursionError near nesting 1000, which ends its watcher thread; Go reads a
// runaway nesting as no record and the watcher goes on. A hand-written channel file never nests; upgrade if one does.
func TestControlReadRecordReadsRunawayNestingAsNoRecord(t *testing.T) {
	text := `{"seq": 1, "cmd": "enable", "deep": ` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + "}"
	if record := chRecord(t, text); record != nil {
		t.Errorf("record = %v, want none for a 200000-deep nesting", record)
	}
}

// --- _control_write_applied ---

func TestControlWriteAppliedWritesTheSeqAsOneLine(t *testing.T) {
	m := chModule(t)
	m.controlWriteApplied(big.NewInt(7))
	if got := chApplied(t, m); got != "7\n" {
		t.Errorf("applied marker = %q, want %q", got, "7\n")
	}
	m.controlWriteApplied(new(big.Int).Lsh(big.NewInt(1), 70))
	if got := chApplied(t, m); got != "1180591620717411303424\n" {
		t.Errorf("applied marker = %q, want 2**70 and a newline", got)
	}
	if _, err := os.Stat(m.pfb.pfbPyControlApplied + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temp file is left behind (stat error %v), want it renamed over the marker", err)
	}
}

func TestControlWriteAppliedFailureIsLoggedAndLeavesNoTempFile(t *testing.T) {
	m := chModule(t)
	logs := captureLog(t)
	// the directory of the marker is missing, so the temp file cannot be created
	m.pfb.pfbPyControlApplied = filepath.Join(t.TempDir(), "gone", "pfb_py_control.applied")
	m.controlWriteApplied(big.NewInt(3))
	want := "[pfBlockerNG]: failed to write control applied marker [ " + m.pfb.pfbPyControlApplied + " ]: "
	if !strings.HasPrefix(logs.String(), want) {
		t.Errorf("logged %q, want it to start with %q", logs.String(), want)
	}
}

func TestControlWriteAppliedWithoutAPathWritesNothing(t *testing.T) {
	m := chModule(t)
	logs := captureLog(t)
	m.pfb.pfbPyControlApplied = ""
	m.controlWriteApplied(big.NewInt(3))
	if logs.Len() != 0 {
		t.Errorf("logged %q, want nothing", logs.String())
	}
	dir := filepath.Dir(m.pfb.pfbPyControl)
	for _, name := range []string{"pfb_py_control.applied", "pfb_py_control.applied.tmp", ".tmp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s exists (stat error %v), want no marker written", name, err)
		}
	}
}

// --- the watcher: baseline ---

func TestWatcherBaselineAdoptsTheSeqOnDiskWithoutApplyingIt(t *testing.T) {
	m := chModule(t)
	chPublish(t, m, `{"seq": 9, "cmd": "disable"}`)
	if !ctlBlacklist(m) {
		t.Fatalf("python_blacklist = false before the watcher starts, want true")
	}
	w := m.newControlWatcher()
	if !ctlBlacklist(m) {
		t.Errorf("the record on disk at startup was replayed: python_blacklist = false")
	}
	if got := chApplied(t, m); got != "9\n" {
		t.Errorf("applied marker = %q, want the adopted baseline %q", got, "9\n")
	}
	stop := make(chan struct{})
	w.drainAndApply(stop)
	if !ctlBlacklist(m) {
		t.Errorf("the baseline record was applied by the first drain: python_blacklist = false")
	}
	chPublish(t, m, `{"seq": 10, "cmd": "wipe-everything"}`)
	w.drainAndApply(stop)
	if got := chApplied(t, m); got != "10\n" || !ctlBlacklist(m) {
		t.Errorf("after seq 10: (marker, python_blacklist) = (%q, %v), want (%q, true)", got, ctlBlacklist(m), "10\n")
	}
	chPublish(t, m, `{"seq": 11, "cmd": "disable"}`)
	w.drainAndApply(stop)
	if got := chApplied(t, m); got != "11\n" || ctlBlacklist(m) {
		t.Errorf("after seq 11: (marker, python_blacklist) = (%q, %v), want (%q, false)", got, ctlBlacklist(m), "11\n")
	}
}

func TestWatcherBaselineWithoutARecordPublishesSeqZero(t *testing.T) {
	m := chModule(t)
	m.newControlWatcher()
	if got := chApplied(t, m); got != "0\n" {
		t.Errorf("applied marker = %q, want %q", got, "0\n")
	}
}

func TestWatcherBaselineKeepsZeroForARecordWithoutAnIntegerSeq(t *testing.T) {
	for _, text := range []string{`{"seq": "9"}`, `{"seq": 9.0}`, `{"cmd": "disable"}`, `[9]`, `{`} {
		m := chModule(t)
		chPublish(t, m, text)
		m.newControlWatcher()
		if got := chApplied(t, m); got != "0\n" {
			t.Errorf("%s: applied marker = %q, want %q", text, got, "0\n")
		}
	}
}

// bool is int in Python: a JSON true is seq 1 and false is seq 0.
func TestWatcherBaselineAdoptsABooleanSeqAsAnInteger(t *testing.T) {
	for text, want := range map[string]string{`{"seq": true}`: "1\n", `{"seq": false}`: "0\n", `{"seq": -4}`: "-4\n"} {
		m := chModule(t)
		chPublish(t, m, text)
		m.newControlWatcher()
		if got := chApplied(t, m); got != want {
			t.Errorf("%s: applied marker = %q, want %q", text, got, want)
		}
	}
}

// --- the watcher: drain_and_apply ---

func TestWatcherAppliesAFreshCommandAndPublishesItsSeq(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	logs := captureLog(t)
	chPublish(t, m, `{"seq": 1, "cmd": "disable"}`)
	if !ctlBlacklist(m) {
		t.Fatalf("python_blacklist = false before the command")
	}
	w.drainAndApply(make(chan struct{}))
	if ctlBlacklist(m) {
		t.Errorf("python_blacklist = true after the disable record")
	}
	if got := chApplied(t, m); got != "1\n" {
		t.Errorf("applied marker = %q, want %q", got, "1\n")
	}
	if want := "pfb_dns_proxy info: [pfBlockerNG]: Python_control: DNSBL disabled\n"; logs.String() != want {
		t.Errorf("logged %q, want the handler's message %q", logs.String(), want)
	}
}

func TestWatcherAppliesAddbypassThenRemovebypassFromTheChannel(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	stop := make(chan struct{})
	if ctlGate(m) || len(ctlEntries(m)) != 0 {
		t.Fatalf("before: (gate, entries) = (%v, %v), want (false, none)", ctlGate(m), ctlEntries(m))
	}
	chPublish(t, m, `{"seq": 1, "cmd": "addbypass", "ip": "192.0.2.10"}`)
	w.drainAndApply(stop)
	if got := ctlEntries(m); len(got) != 1 || got[0] != "192.0.2.10" {
		t.Errorf("after addbypass gpListDB = %v, want [192.0.2.10]", got)
	}
	chPublish(t, m, `{"seq": 2, "cmd": "removebypass", "ip": "192.0.2.10"}`)
	w.drainAndApply(stop)
	if got := ctlEntries(m); len(got) != 0 {
		t.Errorf("after removebypass gpListDB = %v, want none", got)
	}
}

func TestWatcherIgnoresASeqThatDoesNotAdvanceAndLeavesTheMarker(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	stop := make(chan struct{})
	chPublish(t, m, `{"seq": 5, "cmd": "disable"}`)
	w.drainAndApply(stop)
	if got := chApplied(t, m); got != "5\n" || ctlBlacklist(m) {
		t.Fatalf("seq 5: (marker, python_blacklist) = (%q, %v), want (%q, false)", got, ctlBlacklist(m), "5\n")
	}
	ctlApply(m, "python_control", "enable")
	for _, text := range []string{`{"seq": 3, "cmd": "disable"}`, `{"seq": 5, "cmd": "disable"}`, `{"seq": -1, "cmd": "disable"}`} {
		chPublish(t, m, text)
		w.drainAndApply(stop)
		if !ctlBlacklist(m) {
			t.Errorf("%s: a stale record was applied, python_blacklist = false", text)
		}
		if got := chApplied(t, m); got != "5\n" {
			t.Errorf("%s: applied marker = %q, want it left at %q", text, got, "5\n")
		}
	}
	chPublish(t, m, `{"seq": 6, "cmd": "wipe-everything"}`)
	w.drainAndApply(stop)
	chPublish(t, m, `{"seq": 7, "cmd": "disable"}`)
	w.drainAndApply(stop)
	if got := chApplied(t, m); got != "7\n" || ctlBlacklist(m) {
		t.Errorf("seq 7: (marker, python_blacklist) = (%q, %v), want (%q, false)", got, ctlBlacklist(m), "7\n")
	}
}

// isinstance(seq, int): an integer of any size counts, a true counts as 1, a float or a string or a missing seq is no seq.
func TestWatcherOnlyAnIntegerSeqCounts(t *testing.T) {
	for _, tc := range []struct {
		record  string
		applied bool
		marker  string
	}{
		{`{"cmd": "disable"}`, false, "0\n"},
		{`{"seq": "1", "cmd": "disable"}`, false, "0\n"},
		{`{"seq": 2.0, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": 1e2, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": null, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": NaN, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": false, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": 0, "cmd": "disable"}`, false, "0\n"},
		{`{"seq": true, "cmd": "disable"}`, true, "1\n"},
		{`{"seq": 1, "cmd": "disable"}`, true, "1\n"},
		{`{"seq": 123456789012345678901234567890, "cmd": "disable"}`, true, "123456789012345678901234567890\n"},
	} {
		m := chModule(t)
		w := m.newControlWatcher()
		chPublish(t, m, tc.record)
		w.drainAndApply(make(chan struct{}))
		if applied := !ctlBlacklist(m); applied != tc.applied {
			t.Errorf("%s: applied = %v, want %v", tc.record, applied, tc.applied)
		}
		if got := chApplied(t, m); got != tc.marker {
			t.Errorf("%s: applied marker = %q, want %q", tc.record, got, tc.marker)
		}
	}
}

func TestWatcherConsumesAnUnknownOrMalformedCommandWithoutSideEffect(t *testing.T) {
	for _, record := range []string{
		`{"seq": 1, "cmd": "wipe-everything"}`,
		`{"seq": 1, "cmd": "ENABLE"}`,
		`{"seq": 1}`,
		`{"seq": 1, "cmd": 5}`,
		`{"seq": 1, "cmd": "addbypass"}`,
		`{"seq": 1, "cmd": "addbypass", "ip": ""}`,
		`{"seq": 1, "cmd": "removebypass", "ip": 7}`,
	} {
		m := chModule(t)
		w := m.newControlWatcher()
		live := m.snapshot.Load()
		chPublish(t, m, record)
		w.drainAndApply(make(chan struct{}))
		if m.snapshot.Load() != live {
			t.Errorf("%s: a snapshot was published, want no effect", record)
		}
		if got := chApplied(t, m); got != "1\n" {
			t.Errorf("%s: applied marker = %q, want the seq consumed (%q)", record, got, "1\n")
		}
	}
}

// "{}".format(record.get("duration")) is Python's str() of the JSON value, which the handler then validates.
func TestWatcherPassesADurationToTheHandlerAsPythonsStr(t *testing.T) {
	for _, tc := range []struct {
		duration string
		wantMsg  string
	}{
		{`30`, "Python_control: DNSBL disabled for 30 second(s)"},
		{`"30"`, "Python_control: DNSBL disabled for 30 second(s)"},
		{`"\u0663"`, "Python_control: DNSBL disabled for 3 second(s)"},
		{`30.0`, "Python_control: DNSBL disabled: duration [ 30.0 ] out of range (1-3600sec)"},
		{`1.5`, "Python_control: DNSBL disabled: duration [ 1.5 ] out of range (1-3600sec)"},
		{`true`, "Python_control: DNSBL disabled: duration [ True ] out of range (1-3600sec)"},
		{`false`, "Python_control: DNSBL disabled: duration [ False ] out of range (1-3600sec)"},
		{`null`, "Python_control: DNSBL disabled: duration [ None ] out of range (1-3600sec)"},
		{`"\u00b2"`, "Python_control: DNSBL disabled: duration [ ² ] out of range (1-3600sec)"},
		{`[1, "a"]`, "Python_control: DNSBL disabled: duration [ [1, 'a'] ] out of range (1-3600sec)"},
		{`{"k": [true, null]}`, "Python_control: DNSBL disabled: duration [ {'k': [True, None]} ] out of range (1-3600sec)"},
		{`1e16`, "Python_control: DNSBL disabled: duration [ 1e+16 ] out of range (1-3600sec)"},
		{`1e-5`, "Python_control: DNSBL disabled: duration [ 1e-05 ] out of range (1-3600sec)"},
		{`-5`, "Python_control: DNSBL disabled: duration [ -5 ] out of range (1-3600sec)"},
		{`3601`, "Python_control: DNSBL disabled: duration [ 3601 ] out of range (1-3600sec)"},
		{`123456789012345678901234567890`, "Python_control: DNSBL disabled: duration [ 123456789012345678901234567890 ] out of range (1-3600sec)"},
		{`""`, "Python_control: DNSBL disabled"},
	} {
		m := chModule(t)
		w := m.newControlWatcher()
		logs := captureLog(t)
		chPublish(t, m, `{"seq": 1, "cmd": "disable", "duration": `+tc.duration+`}`)
		w.drainAndApply(make(chan struct{}))
		// a numeric non-integer such as "²" logs python_control_duration's complaint first: the info line closes the log
		if want := "pfb_dns_proxy info: [pfBlockerNG]: " + tc.wantMsg + "\n"; !strings.HasSuffix(logs.String(), want) {
			t.Errorf("duration %s: logged %q, want it to end with %q", tc.duration, logs.String(), want)
		}
		if got := chApplied(t, m); got != "1\n" {
			t.Errorf("duration %s: applied marker = %q, want %q", tc.duration, got, "1\n")
		}
	}
}

func TestWatcherPassesAnAddbypassDurationAndDropsARemovebypassOne(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	timers := &ctlTimers{}
	m.afterFunc = timers.afterFunc
	chPublish(t, m, `{"seq": 1, "cmd": "addbypass", "ip": "10.0.0.5", "duration": "60"}`)
	w.drainAndApply(make(chan struct{}))
	if list := timers.all(); len(list) != 1 || list[0].delay != 60*time.Second {
		t.Fatalf("timers = %v, want one of 60s", list)
	}
	chPublish(t, m, `{"seq": 2, "cmd": "removebypass", "ip": "10.0.0.5", "duration": 60}`)
	w.drainAndApply(make(chan struct{}))
	if len(timers.all()) != 1 || len(ctlEntries(m)) != 0 {
		t.Errorf("after removebypass: (timers, entries) = (%d, %v), want (1, none)", len(timers.all()), ctlEntries(m))
	}
}

// A write failure is logged and the command still stands (Python: "the command still stands").
func TestWatcherWriteFailureIsLoggedAndTheCommandStillStands(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	logs := captureLog(t)
	m.pfb.pfbPyControlApplied = filepath.Join(t.TempDir(), "gone", "pfb_py_control.applied")
	chPublish(t, m, `{"seq": 1, "cmd": "disable"}`)
	w.drainAndApply(make(chan struct{}))
	if ctlBlacklist(m) {
		t.Errorf("python_blacklist = true: the failed marker write undid the command")
	}
	if !strings.Contains(logs.String(), "failed to write control applied marker") {
		t.Errorf("logged %q, want the marker failure", logs.String())
	}
	// the seq was consumed all the same: the next drain does not apply it again
	ctlApply(m, "python_control", "enable")
	w.drainAndApply(make(chan struct{}))
	if !ctlBlacklist(m) {
		t.Errorf("the record was applied twice")
	}
}

func TestWatcherDoesNotDrainOnceStopped(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	stop := make(chan struct{})
	close(stop)
	chPublish(t, m, `{"seq": 1, "cmd": "disable"}`)
	w.drainAndApply(stop)
	if !ctlBlacklist(m) || chApplied(t, m) != "0\n" {
		t.Errorf("a stopped watcher drained: (python_blacklist, marker) = (%v, %q), want (true, %q)", ctlBlacklist(m), chApplied(t, m), "0\n")
	}
}

// --- the watcher: the loop ---

func chWait(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("STUCK/ENVIRONMENT: %s did not happen", what)
	}
}

// Every tick is one poll. The loop takes a tick only when its previous drain is over, so the second send of a pair is the
// barrier that the first tick's drain finished.
func TestWatcherLoopDrainsOnEveryTickUntilStopped(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	stop, tick, done := make(chan struct{}), make(chan time.Time), make(chan struct{})
	go func() {
		defer close(done)
		w.run(stop, tick)
	}()
	tick <- time.Time{} // the startup drain is over
	chPublish(t, m, `{"seq": 1, "cmd": "disable"}`)
	tick <- time.Time{}
	tick <- time.Time{}
	if ctlBlacklist(m) || chApplied(t, m) != "1\n" {
		t.Errorf("after the tick: (python_blacklist, marker) = (%v, %q), want (false, %q)", ctlBlacklist(m), chApplied(t, m), "1\n")
	}
	chPublish(t, m, `{"seq": 2, "cmd": "enable"}`)
	tick <- time.Time{}
	tick <- time.Time{}
	if !ctlBlacklist(m) || chApplied(t, m) != "2\n" {
		t.Errorf("after the second tick: (python_blacklist, marker) = (%v, %q), want (true, %q)", ctlBlacklist(m), chApplied(t, m), "2\n")
	}
	close(stop)
	chWait(t, "the loop to end after stop", done)
}

func TestWatcherLoopStartupDrainAppliesNothingAlreadyOnDisk(t *testing.T) {
	m := chModule(t)
	chPublish(t, m, `{"seq": 4, "cmd": "disable"}`)
	w := m.newControlWatcher()
	stop, tick, done := make(chan struct{}), make(chan time.Time), make(chan struct{})
	go func() {
		defer close(done)
		w.run(stop, tick)
	}()
	tick <- time.Time{}
	close(stop)
	chWait(t, "the loop to end after stop", done)
	if !ctlBlacklist(m) {
		t.Errorf("the record already on disk at startup was applied by the loop")
	}
}

func TestWatcherLoopEndsAtOnceWhenAlreadyStopped(t *testing.T) {
	m := chModule(t)
	w := m.newControlWatcher()
	stop, done := make(chan struct{}), make(chan struct{})
	close(stop)
	chPublish(t, m, `{"seq": 1, "cmd": "disable"}`)
	go func() {
		defer close(done)
		w.run(stop, make(chan time.Time))
	}()
	chWait(t, "the loop to end", done)
	if !ctlBlacklist(m) {
		t.Errorf("a stopped loop applied a record")
	}
}

// --- init_standard starts the watcher ---

func TestInitStandardStartsTheControlWatcherOnlyWhenPythonControlIsOn(t *testing.T) {
	for _, tc := range []struct {
		ini     string
		running bool
	}{
		{"[MAIN]\npython_enable = true\npython_control = true\n", true},
		{"[MAIN]\npython_enable = true\npython_control = false\n", false},
		{"[MAIN]\npython_enable = true\npython_control_legacy = true\n", false},
	} {
		dir := modIniDir(t, tc.ini)
		if err := os.WriteFile(filepath.Join(dir, "pfb_py_control"), []byte(`{"seq": 4, "cmd": "disable"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		m := modMust(t, dir)
		t.Cleanup(m.stopControlWatcher)
		if got := m.controlStop != nil; got != tc.running {
			t.Errorf("%q: watcher running = %v, want %v", tc.ini, got, tc.running)
		}
		want := ""
		if tc.running {
			want = "4\n" // the baseline: adopted and published, never applied
		}
		if got := chApplied(t, m); got != want {
			t.Errorf("%q: applied marker = %q, want %q", tc.ini, got, want)
		}
	}
}

func TestStopControlWatcherEndsItAndAllowsARestart(t *testing.T) {
	m := modMust(t, modIniDir(t, "[MAIN]\npython_enable = true\npython_control = true\n"))
	t.Cleanup(m.stopControlWatcher)
	if m.controlStop == nil {
		t.Fatalf("the watcher is not running after init with python_control on")
	}
	m.stopControlWatcher()
	if m.controlStop != nil {
		t.Errorf("the watcher is still marked running after stopControlWatcher")
	}
	m.stopControlWatcher() // a second stop is harmless
	m.startControlWatcher()
	if m.controlStop == nil {
		t.Errorf("the watcher did not start again")
	}
	m.startControlWatcher() // already running: no second watcher
	m.stopControlWatcher()
}
