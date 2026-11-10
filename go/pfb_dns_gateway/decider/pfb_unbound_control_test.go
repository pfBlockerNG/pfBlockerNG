// Tests for the Go translation of pfb_unbound.py's DNSBL control surface: python_control_duration, the timer bodies
// (python_control_sleep, python_control_addbypass), pfb_apply_control_command and the legacy DNS-TXT branch of operate().
// They mirror tests/test_pfbl03_control_channel.py (TestSharedHandlerDisableEnable, TestSharedHandlerBypass),
// tests/test_pfbl03_txt_legacy_gate.py and the python_control tests of tests/test_pfb_unbound.py; the expectations are the
// Python source's, replayed from testdata/pfb_unbound_control_oracle.json, which testdata/gen_pfb_unbound_control_oracle.py
// records from pfb_unbound.py on CPython 3.11. Python runs a timer on a thread that sleeps; here a timer is the module's
// afterFunc seam, which these tests fire by hand, so no test waits on a clock.
package decider

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

type ctlTimer struct {
	delay time.Duration
	fn    func()
}

// ctlTimers is the afterFunc seam: it records a timer and runs it only when the test fires it.
type ctlTimers struct {
	mu   sync.Mutex
	list []ctlTimer
	// onSchedule runs inside every afterFunc call, i.e. while the handler that starts the timer is still running.
	onSchedule func()
}

func (c *ctlTimers) afterFunc(delay time.Duration, fn func()) {
	if c.onSchedule != nil {
		c.onSchedule()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, ctlTimer{delay, fn})
}

func (c *ctlTimers) all() []ctlTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.list)
}

func (c *ctlTimers) fire(t *testing.T, i int) {
	t.Helper()
	list := c.all()
	if i >= len(list) {
		t.Fatalf("timer %d: only %d timers were started", i, len(list))
	}
	list[i].fn()
}

func (c *ctlTimers) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = nil
}

// ctlModule is a module with DNSBL blocking on and the control transports allowed, its timers under the test's hand.
func ctlModule(t *testing.T) (*pfbUnbound, *ctlTimers) {
	t.Helper()
	m := modMust(t, t.TempDir())
	opInstall(t, m, func(s *pfbSettings) { opEnable(s); s.pythonControl, s.pythonControlLegacy = true, true }, func(s *snapshot) {
		opBlockData(s, "evil.com", "1", 0)
		opFeed(s, 0, "TestFeed", "TestGroup")
	})
	timers := &ctlTimers{}
	m.afterFunc = timers.afterFunc
	return m, timers
}

func ctlApply(m *pfbUnbound, command ...string) (bool, string) {
	return m.pfbApplyControlCommand(command)
}

func ctlBlacklist(m *pfbUnbound) bool { return m.snapshot.Load().settings.pythonBlacklist }

func ctlGate(m *pfbUnbound) bool { return m.snapshot.Load().settings.gpListDB }

func ctlEntries(m *pfbUnbound) []string {
	return slices.Sorted(maps.Keys(m.snapshot.Load().gpListDB))
}

func ctlWantResult(t *testing.T, what string, applied bool, msg string, wantApplied bool, wantMsg string) {
	t.Helper()
	if applied != wantApplied || msg != wantMsg {
		t.Errorf("%s: (applied, message) = (%v, %q), want (%v, %q)", what, applied, msg, wantApplied, wantMsg)
	}
}

// --- python_control_duration ---

func TestControlDurationAcceptsOneToThreeThousandSixHundredSeconds(t *testing.T) {
	for text, want := range map[string]int{"1": 1, "60": 60, "3600": 3600, "00060": 60} {
		if got := controlDuration(text); got != want {
			t.Errorf("controlDuration(%q) = %d, want %d", text, got, want)
		}
	}
	for _, text := range []string{"0", "3601", "-1", "+1", "abc", "", "12 ", "1_0", "99999999999999999999999999"} {
		if got := controlDuration(text); got != 0 {
			t.Errorf("controlDuration(%q) = %d, want 0 (Python's False)", text, got)
		}
	}
}

// str.isnumeric() is Unicode-wide, int() then converts the decimal digits and refuses the rest: "٣" is 3, "²" is not a
// duration.
func TestControlDurationFollowsPythonsUnicodeNumerics(t *testing.T) {
	logs := captureLog(t)
	for text, want := range map[string]int{"\u0663": 3, "\u0663\u0663": 33, "\uff11\uff10": 10, "\U0001d7d1": 3} {
		if got := controlDuration(text); got != want {
			t.Errorf("controlDuration(%q) = %d, want %d", text, got, want)
		}
	}
	if logs.Len() != 0 {
		t.Errorf("a decimal digit logged %q, want nothing", logs.String())
	}
	for _, text := range []string{"\u00b2", "\u2155"} {
		logs.Reset()
		if got := controlDuration(text); got != 0 {
			t.Errorf("controlDuration(%q) = %d, want 0: isnumeric() but not an int()", text, got)
		}
		if want := "[pfBlockerNG] python_control_duration: invalid literal for int() with base 10: '" + text + "'"; logs.String() != want {
			t.Errorf("controlDuration(%q) logged %q, want %q", text, logs.String(), want)
		}
	}
}

type ctlOracleFile struct {
	Handler []struct {
		ID  string `json:"id"`
		Pre struct {
			Blacklist bool     `json:"python_blacklist"`
			Gate      bool     `json:"gate"`
			Entries   []string `json:"entries"`
			Timers    []string `json:"timers"`
		} `json:"pre"`
		Commands [][]string `json:"commands"`
		Results  [][]any    `json:"results"`
		Post     struct {
			Blacklist bool     `json:"python_blacklist"`
			Gate      bool     `json:"gate"`
			Entries   []string `json:"entries"`
			Timers    [][]any  `json:"timers"`
		} `json:"post"`
	} `json:"handler"`
	SleepExpiry struct {
		Blacklist bool `json:"python_blacklist"`
	} `json:"sleep_expiry"`
	AddbypassExpiry struct {
		First   bool     `json:"first"`
		Second  bool     `json:"second"`
		Entries []string `json:"entries"`
	} `json:"addbypass_expiry"`
	Durations []struct {
		Text   string `json:"text"`
		Value  any    `json:"value"`
		Stderr string `json:"stderr"`
	} `json:"durations"`
	Records []struct {
		Text    string   `json:"text"`
		Record  bool     `json:"record"`
		Seq     *string  `json:"seq"`
		Command []string `json:"command"`
	} `json:"records"`
}

func ctlOracle(t *testing.T) *ctlOracleFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_control_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle ctlOracleFile
	if err := json.Unmarshal(data, &oracle); err != nil {
		t.Fatal(err)
	}
	return &oracle
}

func TestControlDurationMatchesPythonOnTheOracleRows(t *testing.T) {
	for _, row := range ctlOracle(t).Durations {
		logs := captureLog(t)
		want := 0
		if number, ok := row.Value.(float64); ok {
			want = int(number)
		}
		if got := controlDuration(row.Text); got != want {
			t.Errorf("controlDuration(%q) = %d, want %d", row.Text, got, want)
		}
		if logs.String() != row.Stderr {
			t.Errorf("controlDuration(%q) logged %q, want Python's %q", row.Text, logs.String(), row.Stderr)
		}
	}
}

// --- pfb_apply_control_command ---

// Every scenario of the oracle: the results, the state the commands leave and the timers they start match Python's.
func TestApplyControlCommandMatchesPythonOnTheOracleScenarios(t *testing.T) {
	for _, row := range ctlOracle(t).Handler {
		t.Run(row.ID, func(t *testing.T) {
			m, timers := ctlModule(t)
			opInstall(t, m, func(s *pfbSettings) { s.pythonBlacklist, s.gpListDB = row.Pre.Blacklist, row.Pre.Gate }, func(s *snapshot) {
				for _, ip := range row.Pre.Entries {
					s.gpListDB[ip] = 0
				}
			})
			for _, name := range row.Pre.Timers {
				m.controlStartThread(name, time.Second, func() {})
			}
			timers.reset()
			for i, command := range row.Commands {
				applied, msg := m.pfbApplyControlCommand(command)
				ctlWantResult(t, fmt.Sprintf("command %d %q", i, command), applied, msg, row.Results[i][0].(bool), row.Results[i][1].(string))
			}
			if got := ctlBlacklist(m); got != row.Post.Blacklist {
				t.Errorf("python_blacklist = %v, want %v", got, row.Post.Blacklist)
			}
			if got := ctlGate(m); got != row.Post.Gate {
				t.Errorf("gpListDB gate = %v, want %v", got, row.Post.Gate)
			}
			if got := ctlEntries(m); !slices.Equal(got, row.Post.Entries) {
				t.Errorf("gpListDB = %v, want %v", got, row.Post.Entries)
			}
			got := timers.all()
			if len(got) != len(row.Post.Timers) {
				t.Fatalf("timers started = %d, want %d (%v)", len(got), len(row.Post.Timers), row.Post.Timers)
			}
			for i, want := range row.Post.Timers {
				if delay := time.Duration(want[1].(float64)) * time.Second; got[i].delay != delay {
					t.Errorf("timer %d delay = %v, want %v", i, got[i].delay, delay)
				}
				if !m.controlThread(want[0].(string)) {
					t.Errorf("timer %d: no active timer named %q", i, want[0])
				}
			}
		})
	}
}

func TestDisableClearsTheGateAndEnableSetsIt(t *testing.T) {
	m, _ := ctlModule(t)
	if !ctlBlacklist(m) {
		t.Fatalf("python_blacklist = false before disable, want true")
	}
	applied, msg := ctlApply(m, "python_control", "disable")
	ctlWantResult(t, "disable", applied, msg, true, "Python_control: DNSBL disabled")
	if ctlBlacklist(m) {
		t.Errorf("python_blacklist = true after disable, want false")
	}
	applied, msg = ctlApply(m, "python_control", "enable")
	ctlWantResult(t, "enable", applied, msg, true, "Python_control: DNSBL enabled")
	if !ctlBlacklist(m) {
		t.Errorf("python_blacklist = false after enable, want true")
	}
}

func TestDisableWithADurationStartsATimerThatReEnablesBlocking(t *testing.T) {
	m, timers := ctlModule(t)
	applied, msg := ctlApply(m, "python_control", "disable", "30")
	ctlWantResult(t, "disable 30", applied, msg, true, "Python_control: DNSBL disabled for 30 second(s)")
	if list := timers.all(); len(list) != 1 || list[0].delay != 30*time.Second {
		t.Fatalf("timers = %v, want one of 30s", list)
	}
	if ctlBlacklist(m) || !m.controlThread("sleep") {
		t.Fatalf("before expiry: (python_blacklist, timer active) = (%v, %v), want (false, true)", ctlBlacklist(m), m.controlThread("sleep"))
	}
	timers.fire(t, 0)
	if !ctlBlacklist(m) {
		t.Errorf("python_blacklist = false after the timer expired, want true")
	}
	if m.controlThread("sleep") {
		t.Errorf("the sleep timer is still active after its body ended")
	}
	// the name is free again: a new disable with a duration is accepted
	applied, msg = ctlApply(m, "python_control", "disable", "40")
	ctlWantResult(t, "disable after expiry", applied, msg, true, "Python_control: DNSBL disabled for 40 second(s)")
}

func TestSecondDisableWhileTheTimerRunsIsRefused(t *testing.T) {
	m, timers := ctlModule(t)
	ctlApply(m, "python_control", "disable", "30")
	applied, msg := ctlApply(m, "python_control", "disable", "40")
	ctlWantResult(t, "second disable", applied, msg, false, "Python_control: DNSBL disabled: Previous call still in progress")
	if len(timers.all()) != 1 {
		t.Errorf("timers = %d, want the first one alone", len(timers.all()))
	}
}

// Python's timer thread sets python_blacklist at expiry whatever happened meanwhile.
func TestSleepExpiryEnablesBlockingEvenAfterAManualEnable(t *testing.T) {
	m, timers := ctlModule(t)
	ctlApply(m, "python_control", "disable", "30")
	ctlApply(m, "python_control", "enable")
	timers.fire(t, 0)
	if !ctlBlacklist(m) {
		t.Errorf("python_blacklist = false after expiry, want true")
	}
	oracle := ctlOracle(t)
	m.pfbApplyControlCommand([]string{"python_control", "disable"})
	m.controlSleep()
	if ctlBlacklist(m) != oracle.SleepExpiry.Blacklist {
		t.Errorf("controlSleep left python_blacklist = %v, want Python's %v", ctlBlacklist(m), oracle.SleepExpiry.Blacklist)
	}
}

func TestAddbypassThenRemovebypassListsAndUnlistsTheClient(t *testing.T) {
	m, _ := ctlModule(t)
	if ctlGate(m) || len(ctlEntries(m)) != 0 {
		t.Fatalf("before: (gate, entries) = (%v, %v), want (false, none)", ctlGate(m), ctlEntries(m))
	}
	applied, msg := ctlApply(m, "python_control", "addbypass", "10-0-0-5")
	ctlWantResult(t, "addbypass", applied, msg, true, "Python_control: Add bypass for IP: [ 10.0.0.5 ]")
	if !ctlGate(m) || !slices.Equal(ctlEntries(m), []string{"10.0.0.5"}) {
		t.Errorf("after addbypass: (gate, entries) = (%v, %v), want (true, [10.0.0.5])", ctlGate(m), ctlEntries(m))
	}
	applied, msg = ctlApply(m, "python_control", "removebypass", "10-0-0-5")
	ctlWantResult(t, "removebypass", applied, msg, true, "Python_control: Remove bypass for IP: [ 10.0.0.5 ]")
	if len(ctlEntries(m)) != 0 || !ctlGate(m) {
		t.Errorf("after removebypass: (gate, entries) = (%v, %v), want (true, none): the gate stays on", ctlGate(m), ctlEntries(m))
	}
	applied, msg = ctlApply(m, "python_control", "removebypass", "10-0-0-5")
	ctlWantResult(t, "removebypass of an absent IP", applied, msg, true, "Python_control: IP not in Group Policy: [ 10.0.0.5 ]")
}

func TestBypassCommandsRejectAMissingOrInvalidIP(t *testing.T) {
	m, _ := ctlModule(t)
	for _, cmd := range []string{"addbypass", "removebypass"} {
		for _, command := range [][]string{{"python_control", cmd}, {"python_control", cmd, ""}} {
			applied, msg := ctlApply(m, command...)
			ctlWantResult(t, fmt.Sprint(command), applied, msg, false, "Python_control: Missing bypass IP")
		}
		// the message shows the text after the '-' to '.' mapping
		applied, msg := ctlApply(m, "python_control", cmd, "1-2-3")
		ctlWantResult(t, cmd+" 1-2-3", applied, msg, false, "Python_control: Invalid IP: [ 1.2.3 ]")
	}
	if ctlGate(m) || len(ctlEntries(m)) != 0 {
		t.Errorf("(gate, entries) = (%v, %v) after rejected commands, want (false, none)", ctlGate(m), ctlEntries(m))
	}
}

func TestAddbypassWithADurationRemovesTheClientAtExpiry(t *testing.T) {
	m, timers := ctlModule(t)
	applied, msg := ctlApply(m, "python_control", "addbypass", "10-0-0-5", "60")
	ctlWantResult(t, "addbypass 60", applied, msg, true, "Python_control: Add bypass for IP: [ 10.0.0.5 ] for 60 second(s)")
	if list := timers.all(); len(list) != 1 || list[0].delay != 60*time.Second || !m.controlThread("addbypass10.0.0.5") {
		t.Fatalf("timers = %v, active = %v, want one 60s timer named addbypass10.0.0.5", timers.all(), m.controlThread("addbypass10.0.0.5"))
	}
	if !slices.Equal(ctlEntries(m), []string{"10.0.0.5"}) {
		t.Fatalf("before expiry gpListDB = %v, want [10.0.0.5]", ctlEntries(m))
	}
	timers.fire(t, 0)
	if len(ctlEntries(m)) != 0 {
		t.Errorf("after expiry gpListDB = %v, want none", ctlEntries(m))
	}
	if m.controlThread("addbypass10.0.0.5") {
		t.Errorf("the addbypass timer is still active after its body ended")
	}
}

func TestAddbypassExpiryOfAnIPAlreadyRemovedPublishesNothing(t *testing.T) {
	m, timers := ctlModule(t)
	ctlApply(m, "python_control", "addbypass", "10-0-0-5", "60")
	ctlApply(m, "python_control", "removebypass", "10-0-0-5")
	live := m.snapshot.Load()
	timers.fire(t, 0)
	if m.snapshot.Load() != live {
		t.Errorf("an expiry with nothing to pop published a new snapshot")
	}
}

func TestAddbypassExpiryMatchesPythonsAddbypassBody(t *testing.T) {
	m, _ := ctlModule(t)
	oracle := ctlOracle(t).AddbypassExpiry
	opInstall(t, m, func(s *pfbSettings) { s.gpListDB = true }, func(s *snapshot) { s.gpListDB["10.0.0.5"], s.gpListDB["10.0.0.6"] = 0, 0 })
	if got := m.controlAddbypass("10.0.0.5"); got != oracle.First {
		t.Errorf("first controlAddbypass = %v, want Python's %v", got, oracle.First)
	}
	if got := m.controlAddbypass("10.0.0.5"); got != oracle.Second {
		t.Errorf("second controlAddbypass = %v, want Python's %v", got, oracle.Second)
	}
	if got := ctlEntries(m); !slices.Equal(got, oracle.Entries) {
		t.Errorf("gpListDB = %v, want Python's %v", got, oracle.Entries)
	}
}

func TestAddbypassAndDisableTimersAreIndependent(t *testing.T) {
	m, timers := ctlModule(t)
	ctlApply(m, "python_control", "disable", "30")
	applied, msg := ctlApply(m, "python_control", "addbypass", "10-0-0-5", "60")
	ctlWantResult(t, "addbypass during a disable timer", applied, msg, true, "Python_control: Add bypass for IP: [ 10.0.0.5 ] for 60 second(s)")
	applied, msg = ctlApply(m, "python_control", "addbypass", "10-0-0-5", "90")
	ctlWantResult(t, "second addbypass of the same IP", applied, msg, false, "Python_control: Add bypass for IP: [ 10.0.0.5 ]: Previous call still in progress")
	applied, msg = ctlApply(m, "python_control", "addbypass", "10-0-0-6", "90")
	ctlWantResult(t, "addbypass of another IP", applied, msg, true, "Python_control: Add bypass for IP: [ 10.0.0.6 ] for 90 second(s)")
	if len(timers.all()) != 3 {
		t.Errorf("timers = %d, want 3", len(timers.all()))
	}
}

func TestUnknownOrShortCommandIsRefusedWithoutAMessage(t *testing.T) {
	m, _ := ctlModule(t)
	live := m.snapshot.Load()
	for _, command := range [][]string{{"python_control", "nosuchcommand"}, {"python_control"}, {}} {
		applied, msg := ctlApply(m, command...)
		ctlWantResult(t, fmt.Sprint(command), applied, msg, false, "")
	}
	if m.snapshot.Load() != live {
		t.Errorf("a refused command published a new snapshot")
	}
}

// --- the owner's one-snapshot rule (#3511): a published snapshot is never written ---

func TestControlCommandPublishesACopyAndLeavesThePublishedSnapshotUntouched(t *testing.T) {
	m, _ := ctlModule(t)
	opInstall(t, m, func(s *pfbSettings) { s.gpListDB = true }, func(s *snapshot) { s.gpListDB["10.0.0.9"] = 0 })
	before := m.snapshot.Load()
	settingsBefore, gpBefore := *before.settings, maps.Clone(before.gpListDB)
	settingsPtr := before.settings

	ctlApply(m, "python_control", "disable")
	ctlApply(m, "python_control", "addbypass", "10-0-0-5")
	ctlApply(m, "python_control", "removebypass", "10-0-0-9")

	after := m.snapshot.Load()
	if after == before {
		t.Fatalf("the commands changed state but the published snapshot is the same object")
	}
	if before.settings != settingsPtr || !reflect.DeepEqual(*before.settings, settingsBefore) {
		t.Errorf("the previous snapshot's settings were written: %+v, want %+v", *before.settings, settingsBefore)
	}
	if !maps.Equal(before.gpListDB, gpBefore) {
		t.Errorf("the previous snapshot's gpListDB was written: %v, want %v", before.gpListDB, gpBefore)
	}
	if after.gen != before.gen {
		t.Errorf("gen = %d after the commands, want the previous %d: a control command clears no memo", after.gen, before.gen)
	}
	if after.settings == before.settings || after.settings.pythonBlacklist || !slices.Equal(ctlEntries(m), []string{"10.0.0.5"}) {
		t.Errorf("after: settings shared = %v, python_blacklist = %v, gpListDB = %v; want a copy, false, [10.0.0.5]",
			after.settings == before.settings, after.settings.pythonBlacklist, ctlEntries(m))
	}
	// what the commands did not change is shared, not cloned
	if reflect.ValueOf(after.dataDB).Pointer() != reflect.ValueOf(before.dataDB).Pointer() {
		t.Errorf("dataDB was cloned by a control command, want it shared")
	}
}

func TestControlCommandWithoutAGroupPolicyChangeSharesTheMap(t *testing.T) {
	m, _ := ctlModule(t)
	before := m.snapshot.Load()
	ctlApply(m, "python_control", "disable")
	after := m.snapshot.Load()
	if reflect.ValueOf(after.gpListDB).Pointer() != reflect.ValueOf(before.gpListDB).Pointer() {
		t.Errorf("a disable cloned gpListDB, want it shared")
	}
}

func TestAQueryKeepsDecidingOnTheSnapshotItLoadedBeforeAControlCommand(t *testing.T) {
	m, _ := ctlModule(t)
	// a query's snapshot is bound on its first event: this one is mid-flight, on the snapshot live before the command
	inFlight := opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
	inFlight.snap = m.snapshot.Load()

	ctlApply(m, "python_control", "disable")

	opWantState(t, "the in-flight query after the disable", opOperate(m, MODULE_EVENT_PASS, inFlight), MODULE_FINISHED)
	fresh := opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "a new query after the disable", opOperate(m, MODULE_EVENT_NEW, fresh), MODULE_WAIT_MODULE)
	if fresh.snap != m.snapshot.Load() {
		t.Errorf("the new query's snapshot is not the live one")
	}
}

func TestABypassAddedByACommandAppliesToNewQueriesAndNotToInFlightOnes(t *testing.T) {
	m, _ := ctlModule(t)
	inFlight := opQstate("evil.com.", RR_TYPE_A, "10.0.0.5")
	inFlight.snap = m.snapshot.Load()

	ctlApply(m, "python_control", "addbypass", "10-0-0-5")

	opWantState(t, "the in-flight query", opOperate(m, MODULE_EVENT_PASS, inFlight), MODULE_FINISHED)
	fresh := opQstate("evil.com.", RR_TYPE_A, "10.0.0.5")
	opWantState(t, "a new query of the bypassed client", opOperate(m, MODULE_EVENT_NEW, fresh), MODULE_WAIT_MODULE)
	if fresh.noCacheStore != 1 {
		t.Errorf("noCacheStore = %d for a bypassed client, want 1", fresh.noCacheStore)
	}
}

// A control command is not memoized: the decision memo survives it, and the answer follows the new gate at once.
func TestControlCommandKeepsTheDecisionMemo(t *testing.T) {
	m, _ := ctlModule(t)
	q := opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
	opWantState(t, "blocked", opOperate(m, MODULE_EVENT_NEW, q), MODULE_FINISHED)
	if opMemo(t, m, "evil.com") == nil {
		t.Fatalf("no memo after the blocked query")
	}
	ctlApply(m, "python_control", "disable")
	if opMemo(t, m, "evil.com") == nil {
		t.Errorf("the control command cleared the decision memo")
	}
}

func TestControlCommandsRacingEachOtherLoseNoWrite(t *testing.T) {
	m, _ := ctlModule(t)
	const workers, perWorker = 8, 40
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				ctlApply(m, "python_control", "addbypass", fmt.Sprintf("10-%d-0-%d", w, i))
				// a query racing the commands reads whichever snapshot is live
				q := opQstate("evil.com.", RR_TYPE_A, "192.0.2.1")
				opOperate(m, MODULE_EVENT_NEW, q)
			}
		}()
	}
	wg.Wait()
	if got := len(ctlEntries(m)); got != workers*perWorker {
		t.Errorf("gpListDB has %d entries, want %d: a concurrent command lost its write", got, workers*perWorker)
	}
}

// The handler and the timer bodies write under the publisher mutex, rebuildAndSwap takes it too.
func TestControlCommandRunsUnderThePublisherMutex(t *testing.T) {
	m, timers := ctlModule(t)
	held := false
	timers.onSchedule = func() {
		if m.publishMu.TryLock() {
			m.publishMu.Unlock()
			return
		}
		held = true
	}
	ctlApply(m, "python_control", "disable", "30")
	if !held {
		t.Errorf("the command started its timer without holding publishMu")
	}
	if !m.publishMu.TryLock() {
		t.Fatalf("publishMu still held after the command returned")
	}
	m.publishMu.Unlock()
}

// A control write and rebuildAndSwap race: each one's change is in the final snapshot. The rebuild's builder leaves
// the settings to the swap (a reload), no lists are loaded so the swap leaves python_blacklist alone, and the last
// command of every round is a disable.
func TestControlWritesRacingARebuildAndSwapLoseNeitherChange(t *testing.T) {
	m, _ := ctlModule(t)
	for round := range 200 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 5 {
				m.rebuildAndSwap(func() (*snapshot, error) {
					s := newSnapshot()
					s.counts = round + 1
					return s, nil
				}, false)
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				ctlApply(m, "python_control", "enable")
				ctlApply(m, "python_control", "disable")
			}
		}()
		wg.Wait()
		live := m.snapshot.Load()
		if live.settings.pythonBlacklist {
			t.Fatalf("round %d: python_blacklist = true after the last command was a disable: the rebuild overwrote the control write", round)
		}
		if live.counts != round+1 {
			t.Fatalf("round %d: counts = %d, want %d: the control write overwrote the rebuild", round, live.counts, round+1)
		}
		ctlApply(m, "python_control", "enable")
	}
}

// A control write that lands while the builder runs is carried by the swap, which derives its settings from the live
// snapshot at publish time.
func TestControlWriteDuringTheBuildIsCarriedByTheSwap(t *testing.T) {
	m, _ := ctlModule(t)
	ok := m.rebuildAndSwap(func() (*snapshot, error) {
		ctlApply(m, "python_control", "addbypass", "10-0-0-5")
		ctlApply(m, "python_control", "disable")
		s := newSnapshot()
		s.counts = 3
		return s, nil
	}, false)
	if !ok {
		t.Fatalf("rebuildAndSwap = false")
	}
	live := m.snapshot.Load()
	if live.counts != 3 || live.settings.pythonBlacklist || !live.settings.gpListDB {
		t.Errorf("(counts, python_blacklist, gate) = (%d, %v, %v), want (3, false, true)", live.counts, live.settings.pythonBlacklist, live.settings.gpListDB)
	}
}

// --- the legacy DNS-TXT branch of operate() ---

func ctlTxt(t *testing.T, m *pfbUnbound, event int, name string, qtype uint16, client string) *moduleQstate {
	t.Helper()
	q := opQstate(name, qtype, client)
	m.operate(MODULE_ID, event, q, nil)
	return q
}

// ctlFallsThrough fails the test unless the query was left to the resolver and no command ran.
func ctlFallsThrough(t *testing.T, m *pfbUnbound, what string, q *moduleQstate) {
	t.Helper()
	if q.returnMsg != nil || q.extState[MODULE_ID] != MODULE_WAIT_MODULE {
		t.Errorf("%s: (reply, state) = (%v, %d), want no reply and %d (the resolver goes on)", what, q.returnMsg, q.extState[MODULE_ID], MODULE_WAIT_MODULE)
	}
	if !ctlBlacklist(m) {
		t.Errorf("%s: the disable command ran, python_blacklist = false", what)
	}
}

func TestTxtControlObeysALoopbackClientWhenBothGatesAreOn(t *testing.T) {
	for _, client := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		m, _ := ctlModule(t)
		q := ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.disable.", RR_TYPE_TXT, client)
		opWantState(t, client, q.extState[MODULE_ID], MODULE_FINISHED)
		opSections(t, client, q, []string{`python_control. 0 IN TXT "Python_control: DNSBL disabled"`}, nil)
		if ctlBlacklist(m) {
			t.Errorf("%s: python_blacklist = true after the disable, want false", client)
		}
		if q.returnRcode != RCODE_NOERROR || q.returnMsg.rep.security != secStatusIndeterminate {
			t.Errorf("%s: (rcode, security) = (%d, %d), want (NOERROR, indeterminate)", client, q.returnRcode, q.returnMsg.rep.security)
		}
	}
}

func TestTxtControlFallsThroughWhenTheLegacyTransportIsOff(t *testing.T) {
	m, _ := ctlModule(t)
	opInstall(t, m, func(s *pfbSettings) { s.pythonControlLegacy = false }, nil)
	ctlFallsThrough(t, m, "legacy off", ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.disable.", RR_TYPE_TXT, "127.0.0.1"))
}

func TestTxtControlFallsThroughWhenPythonControlIsOff(t *testing.T) {
	m, _ := ctlModule(t)
	opInstall(t, m, func(s *pfbSettings) { s.pythonControl = false }, nil)
	ctlFallsThrough(t, m, "python_control off", ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.disable.", RR_TYPE_TXT, "127.0.0.1"))
}

func TestTxtControlFallsThroughForANonLoopbackClient(t *testing.T) {
	m, _ := ctlModule(t)
	for _, client := range []string{"192.0.2.10", "127.0.0.2", "::2", "::ffff:127.0.0.2", "0:0:0:0:0:0:0:1", "Unknown"} {
		ctlFallsThrough(t, m, client, ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.disable.", RR_TYPE_TXT, client))
	}
}

func TestTxtControlFallsThroughForANonTxtQueryType(t *testing.T) {
	m, _ := ctlModule(t)
	for _, qtype := range []uint16{RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_MX} {
		ctlFallsThrough(t, m, fmt.Sprint("qtype ", qtype), ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.disable.", qtype, "127.0.0.1"))
	}
}

func TestTxtControlFallsThroughForANameThatDoesNotStartWithPythonControlDot(t *testing.T) {
	m, _ := ctlModule(t)
	for _, name := range []string{"python_control.", "xpython_control.disable.", "disable.python_control.", "python-control.disable.", "python_controlx.disable."} {
		ctlFallsThrough(t, m, name, ctlTxt(t, m, MODULE_EVENT_NEW, name, RR_TYPE_TXT, "127.0.0.1"))
	}
}

func TestTxtControlHandlesNewAndPassButNotModdone(t *testing.T) {
	for _, event := range []int{MODULE_EVENT_NEW, MODULE_EVENT_PASS} {
		m, _ := ctlModule(t)
		q := ctlTxt(t, m, event, "python_control.disable.", RR_TYPE_TXT, "127.0.0.1")
		opWantState(t, fmt.Sprint("event ", event), q.extState[MODULE_ID], MODULE_FINISHED)
		if q.returnMsg == nil || ctlBlacklist(m) {
			t.Errorf("event %d: (reply, python_blacklist) = (%v, %v), want a reply and false", event, q.returnMsg, ctlBlacklist(m))
		}
	}
	m, _ := ctlModule(t)
	q := ctlTxt(t, m, MODULE_EVENT_MODDONE, "python_control.disable.", RR_TYPE_TXT, "127.0.0.1")
	if q.returnMsg != nil || !ctlBlacklist(m) {
		t.Errorf("MODDONE: (reply, python_blacklist) = (%v, %v), want no reply and true", q.returnMsg, ctlBlacklist(m))
	}
}

func TestTxtControlLowercasesTheNameLikeEveryOtherBranch(t *testing.T) {
	m, _ := ctlModule(t)
	q := ctlTxt(t, m, MODULE_EVENT_NEW, "Python_Control.DISABLE.", RR_TYPE_TXT, "127.0.0.1")
	opWantState(t, "mixed-case name", q.extState[MODULE_ID], MODULE_FINISHED)
	if ctlBlacklist(m) {
		t.Errorf("python_blacklist = true after a mixed-case disable, want false")
	}
}

func TestTxtControlReplyTextSuccessAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer string
	}{
		{"python_control.enable.", `python_control. 0 IN TXT "Python_control: DNSBL enabled"`},
		{"python_control.nosuchcommand.", `python_control_fail. 0 IN TXT "Python_control: Command not authorized! [ python_control.nosuchcommand ]"`},
		{"python_control.addbypass.", `python_control_fail. 0 IN TXT "Python_control: Missing bypass IP"`},
		{"python_control.addbypass.1-2-3.", `python_control_fail. 0 IN TXT "Python_control: Invalid IP: [ 1.2.3 ]"`},
		{"python_control.disable.0.", `python_control_fail. 0 IN TXT "Python_control: DNSBL disabled: duration [ 0 ] out of range (1-3600sec)"`},
		{"python_control.addbypass.10-0-0-5.60.", `python_control. 0 IN TXT "Python_control: Add bypass for IP: [ 10.0.0.5 ] for 60 second(s)"`},
	} {
		m, _ := ctlModule(t)
		q := ctlTxt(t, m, MODULE_EVENT_NEW, tc.name, RR_TYPE_TXT, "127.0.0.1")
		opWantState(t, tc.name, q.extState[MODULE_ID], MODULE_FINISHED)
		opSections(t, tc.name, q, []string{tc.answer}, nil)
	}
}

// The command is the dot-split of the name: a refused command's message carries the whole name.
func TestTxtControlCommandNotAuthorizedNamesTheWholeQuery(t *testing.T) {
	m, _ := ctlModule(t)
	q := ctlTxt(t, m, MODULE_EVENT_NEW, "python_control.a.b.c.", RR_TYPE_TXT, "::1")
	opSections(t, "unknown command", q, []string{`python_control_fail. 0 IN TXT "Python_control: Command not authorized! [ python_control.a.b.c ]"`}, nil)
}
