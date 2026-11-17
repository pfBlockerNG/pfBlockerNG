package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// laneBackend answers the maintenance projection from values the test changes, counting every read of it.
type laneBackend struct {
	mu            sync.Mutex
	values        map[string]any
	reads         int
	err           error
	uninitialized bool
	onRead        func(ctx context.Context) error // called outside the lock, before the read answers; an error fails it
}

func (b *laneBackend) Read(ctx context.Context) (settings.Stored, error) {
	b.mu.Lock()
	hook := b.onRead
	b.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return settings.Stored{}, err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads++
	if b.err != nil {
		return settings.Stored{}, b.err
	}
	if b.uninitialized {
		return settings.Stored{}, nil
	}
	fields := map[string]json.RawMessage{}
	for name, v := range b.values {
		raw, _ := json.Marshal(v)
		fields[name] = raw
	}
	return settings.Stored{Initialized: true, Revision: uint64(b.reads), Projections: map[string]map[string]json.RawMessage{"maintenance": fields}}, nil
}

func (b *laneBackend) Write(context.Context, uint64, map[string]map[string]any) (uint64, error) {
	return 0, errors.New("not writable")
}

func (b *laneBackend) set(values map[string]any, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values, b.err = values, err
}

func (b *laneBackend) readCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reads
}

func laneStoreOver(t *testing.T, values map[string]any) (*settings.Store, *laneBackend) {
	t.Helper()
	b := &laneBackend{values: values}
	st, err := settings.Load(b, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return st, b
}

func laneSettingsOver(t *testing.T, values map[string]any, logf func(string, ...any)) *laneSettings {
	t.Helper()
	st, _ := laneStoreOver(t, values)
	return newLaneSettings(st, logf)
}

var (
	metricsOn          = map[string]any{"enabled": true, "metricsExport": true}
	dailyIPWeeklyDNSBL = map[string]any{"clearIpCounters": "daily", "clearDnsblCounters": "weekly"}
)

func ranTimes(n *int, mu *sync.Mutex) func(context.Context) error {
	return func(context.Context) error { mu.Lock(); *n++; mu.Unlock(); return nil }
}

// The maintenance lane runs only for an enabled package without the platform's off switch, whatever the settings were when
// Core last read them: the settings are read again before every decision.
func TestMaintenanceRunsOnlyWhenEnabledAndNotOffSwitchedAfterReloadingTheSettings(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, offSwitch := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%t offSwitch=%t", enabled, offSwitch), func(t *testing.T) {
				st, b := laneStoreOver(t, map[string]any{"enabled": !enabled, "scheduledWorkDisabled": !offSwitch})
				rec := &logRecorder{}
				var n int
				var mu sync.Mutex
				gate := gateMaintenance(ranTimes(&n, &mu), newLaneSettings(st, rec.logf), rec.logf)
				b.set(map[string]any{"enabled": enabled, "scheduledWorkDisabled": offSwitch}, nil)
				before := b.readCount()
				if err := gate(t.Context()); err != nil {
					t.Fatal(err)
				}
				if want := enabled && !offSwitch; (n == 1) != want || n > 1 {
					t.Errorf("the maintenance ran %d times, want it to run: %t", n, want)
				}
				if got := b.readCount(); got != before+1 {
					t.Errorf("the decision read the backend %d times, want once before it", got-before)
				}
			})
		}
	}
}

// The maintenance's own result is the lane's: an error of the run is returned as it is.
func TestMaintenanceGateReturnsTheRunsError(t *testing.T) {
	st, _ := laneStoreOver(t, map[string]any{"enabled": true})
	boom := errors.New("boom")
	gate := gateMaintenance(func(context.Context) error { return boom }, newLaneSettings(st, (&logRecorder{}).logf), (&logRecorder{}).logf)
	if err := gate(t.Context()); !errors.Is(err, boom) {
		t.Errorf("gate = %v, want the run's error", err)
	}
}

// A settings read that fails (or answers a value Core refuses) keeps the values read last, and is logged once per outage.
func TestMaintenanceKeepsTheLastSettingsWhenTheReloadFailsAndLogsOnce(t *testing.T) {
	for name, fault := range map[string]func(b *laneBackend){
		"backend error":  func(b *laneBackend) { b.set(map[string]any{"enabled": true}, errors.New("adapter failed")) },
		"refused value":  func(b *laneBackend) { b.set(map[string]any{"enabled": true, "clearIpCounters": "monthly"}, nil) },
		"enabled string": func(b *laneBackend) { b.set(map[string]any{"enabled": "on"}, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			st, b := laneStoreOver(t, map[string]any{"enabled": true})
			rec := &logRecorder{}
			var n int
			var mu sync.Mutex
			ls := newLaneSettings(st, rec.logf)
			gate := gateMaintenance(ranTimes(&n, &mu), ls, func(string, ...any) {})
			fault(b)
			for range 3 {
				if err := gate(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if n != 3 {
				t.Errorf("the maintenance ran %d times over the failing reads, want 3 on the last values", n)
			}
			if rec.count() != 1 {
				t.Fatalf("three failed reloads logged %d lines %q, want 1", rec.count(), rec.lines)
			}
			b.set(map[string]any{"enabled": true}, nil)
			_ = gate(t.Context())
			fault(b)
			_ = gate(t.Context())
			if rec.count() != 2 {
				t.Errorf("a failure after a good read logged %d lines %q in all, want 2", rec.count(), rec.lines)
			}
		})
	}
}

// The last values hold a lane that was off off, too.
func TestMaintenanceStaysSkippedOnTheLastSettingsWhenTheReloadFails(t *testing.T) {
	st, b := laneStoreOver(t, map[string]any{"enabled": false})
	var n int
	var mu sync.Mutex
	rec := &logRecorder{}
	gate := gateMaintenance(ranTimes(&n, &mu), newLaneSettings(st, rec.logf), rec.logf)
	b.set(nil, errors.New("adapter failed"))
	_ = gate(t.Context())
	if n != 0 {
		t.Errorf("the maintenance ran %d times on last values that say off, want 0", n)
	}
}

// One log line when the lane flips between running and skipping, none while it stays as it is.
func TestMaintenanceLogsOneLinePerFlipAndNoneWhileSteady(t *testing.T) {
	st, b := laneStoreOver(t, map[string]any{"enabled": true})
	rec := &logRecorder{}
	var n int
	var mu sync.Mutex
	gate := gateMaintenance(ranTimes(&n, &mu), newLaneSettings(st, func(string, ...any) {}), rec.logf)
	step := func(enabled bool) {
		t.Helper()
		b.set(map[string]any{"enabled": enabled}, nil)
		if err := gate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	step(true)
	step(true)
	if rec.count() != 0 {
		t.Fatalf("a lane that keeps running logged %q, want nothing", rec.lines)
	}
	step(false)
	step(false)
	step(false)
	if rec.count() != 1 || !strings.Contains(rec.lines[0], "skip") {
		t.Fatalf("running to skipping logged %q, want one line saying it skips", rec.lines)
	}
	step(true)
	step(true)
	if rec.count() != 2 || !strings.Contains(rec.lines[1], "run") {
		t.Errorf("skipping to running logged %q, want a second line saying it runs", rec.lines)
	}
	if n != 4 {
		t.Errorf("the maintenance ran %d times, want 4 (the running steps)", n)
	}
}

// The metrics lane starts only for an enabled package that exports metrics, ignores the platform's off switch, and never
// reads the backend again at a minute boundary.
func TestMetricsStartsOnlyWhenEnabledAndExportingAndNeverReloads(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, export := range []bool{true, false} {
			for _, offSwitch := range []bool{false, true} {
				t.Run(fmt.Sprintf("enabled=%t export=%t offSwitch=%t", enabled, export, offSwitch), func(t *testing.T) {
					st, b := laneStoreOver(t, map[string]any{"enabled": enabled, "metricsExport": export, "scheduledWorkDisabled": offSwitch})
					out := filepath.Join(t.TempDir(), "out")
					rec := &logRecorder{}
					metrics := &lane{name: "metrics", path: laneProgram(t, t.TempDir(), "prog", `echo run >> `+out), logf: rec.logf}
					start := time.Date(2024, 5, 6, 12, 0, 30, 0, time.UTC)
					drive(t, start, 3, func() *time.Location { return time.UTC }, metrics, &lane{}, newLaneSettings(st, rec.logf))
					got := len(lines(readFile(t, out)))
					if want := map[bool]int{true: 3, false: 0}[enabled && export]; got != want {
						t.Errorf("metrics started %d times over 3 boundaries, want %d", got, want)
					}
					if b.readCount() != 1 {
						t.Errorf("the backend was read %d times, want only the load: a minute boundary must not reload", b.readCount())
					}
				})
			}
		}
	}
}

// At a local day change the settings are read once, and the counters program gets the verbs due, clearip before cleardnsbl,
// whatever the package's enable and the off switch say.
func TestCountersGetTheVerbsDueAtADayChange(t *testing.T) {
	cadences := []string{"never", "daily", "weekly"}
	for _, day := range []struct {
		name   string
		start  time.Time
		sunday bool
	}{
		{"weekday to weekday", time.Date(2024, 3, 5, 23, 58, 30, 0, time.UTC), false},
		{"Saturday to Sunday", time.Date(2024, 3, 9, 23, 58, 30, 0, time.UTC), true},
	} {
		for _, ip := range cadences {
			for _, dnsbl := range cadences {
				t.Run(fmt.Sprintf("%s ip=%s dnsbl=%s", day.name, ip, dnsbl), func(t *testing.T) {
					st, b := laneStoreOver(t, map[string]any{}) // all never: the day change has to read them again
					out := filepath.Join(t.TempDir(), "out")
					rec := &logRecorder{}
					counters := &lane{name: "counters", path: laneProgram(t, t.TempDir(), "prog", `echo "$*" >> `+out), logf: rec.logf}
					b.set(map[string]any{"clearIpCounters": ip, "clearDnsblCounters": dnsbl}, nil)
					drive(t, day.start, 2, func() *time.Location { return time.UTC }, &lane{}, counters, newLaneSettings(st, rec.logf))
					due := func(setting string) bool { return setting == "daily" || (setting == "weekly" && day.sunday) }
					var verbs []string
					if due(ip) {
						verbs = append(verbs, "clearip")
					}
					if due(dnsbl) {
						verbs = append(verbs, "cleardnsbl")
					}
					var want []string
					if verbs != nil {
						want = []string{strings.Join(verbs, " ")}
					}
					if got := lines(readFile(t, out)); !reflect.DeepEqual(got, want) {
						t.Errorf("counters started with %q, want %q", got, want)
					}
					if b.readCount() != 2 {
						t.Errorf("the backend was read %d times, want the load and one reload at the day change", b.readCount())
					}
				})
			}
		}
	}
}

// Without a usable value (no settings yet) no lane starts, and the fault is logged once per outage, not at every boundary.
func TestLanesStartNothingWithoutUsableSettingsAndLogOnce(t *testing.T) {
	b := &laneBackend{uninitialized: true}
	st, err := settings.Load(b, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	rec := &logRecorder{}
	dir := t.TempDir()
	metrics := &lane{name: "metrics", path: laneProgram(t, dir, "metrics", `echo run >> `+filepath.Join(dir, "m")), logf: rec.logf}
	counters := &lane{name: "counters", path: laneProgram(t, dir, "counters", `echo run >> `+filepath.Join(dir, "c")), logf: rec.logf}
	start := time.Date(2024, 3, 9, 23, 58, 30, 0, time.UTC) // the second boundary is a day change
	drive(t, start, 4, func() *time.Location { return time.UTC }, metrics, counters, newLaneSettings(st, rec.logf))
	if readFile(t, filepath.Join(dir, "m")) != "" || readFile(t, filepath.Join(dir, "c")) != "" {
		t.Error("a lane started without usable settings")
	}
	if rec.count() != 1 {
		t.Errorf("the missing settings were logged %d times %q over 4 boundaries, want once", rec.count(), rec.lines)
	}
}

// A Core that is stopped while a day change reads the settings starts nothing after the read, and the loop returns.
func TestRunClockStartsNothingWhenCancelledDuringTheDayChangeReload(t *testing.T) {
	st, b := laneStoreOver(t, map[string]any{"enabled": true, "metricsExport": true, "clearIpCounters": "daily"})
	entered := make(chan struct{})
	b.mu.Lock()
	b.onRead = func(ctx context.Context) error {
		close(entered)
		<-ctx.Done() // the reload is blocked until Core is stopped
		return ctx.Err()
	}
	b.mu.Unlock()
	dir := t.TempDir()
	metricsOut, countersOut := filepath.Join(dir, "m"), filepath.Join(dir, "c")
	rec := &logRecorder{}
	metrics := &lane{name: "metrics", path: laneProgram(t, dir, "metrics", `echo run >> `+metricsOut), logf: rec.logf}
	counters := &lane{name: "counters", path: laneProgram(t, dir, "counters", `echo "$*" >> `+countersOut), logf: rec.logf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan time.Time, 1)
	first <- time.Time{}
	calls := 0
	after := func(time.Duration) <-chan time.Time {
		if calls++; calls == 1 {
			return first
		}
		return nil
	}
	ended := make(chan struct{})
	go func() {
		now := func() time.Time { return time.Date(2024, 3, 9, 23, 59, 30, 0, time.UTC) } // the boundary is a day change
		runClock(ctx, now, after, func() *time.Location { return time.UTC }, metrics, counters, newLaneSettings(st, rec.logf))
		close(ended)
	}()
	<-entered
	cancel()
	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("STUCK/ENVIRONMENT: runClock did not return after its context was cancelled during the reload")
	}
	within(t, "the lanes to be idle", func() bool { return !metrics.busy.Load() && !counters.busy.Load() })
	if got := readFile(t, metricsOut) + readFile(t, countersOut); got != "" {
		t.Errorf("a stopped Core still started programs after the reload: %q", got)
	}
}

// The metrics lane logs one line when it flips between starting and skipping its runs, none while it stays as it is, so an
// observer knows a minute boundary has decided against a run without waiting for a margin.
func TestMetricsLogsOneLinePerFlipAndNoneWhileSteady(t *testing.T) {
	on := map[string]any{"enabled": true, "metricsExport": true}
	st, b := laneStoreOver(t, on)
	rec := &logRecorder{}
	out := filepath.Join(t.TempDir(), "out")
	metrics := &lane{name: "metrics", path: laneProgram(t, t.TempDir(), "prog", `echo run >> `+out), logf: rec.logf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeClock{cur: time.Date(2024, 5, 6, 12, 0, 30, 0, time.UTC), ticks: 6, cancel: cancel, lanes: []*lane{metrics}}
	// before boundary 3 the export goes off, before boundary 5 it comes back
	plan := map[int]map[string]any{2: {"enabled": true, "metricsExport": false}, 4: on}
	after := func(d time.Duration) <-chan time.Time {
		if v, ok := plan[len(f.waits)]; ok {
			b.set(v, nil)
			if _, err := st.Reload(ctx); err != nil {
				t.Fatal(err)
			}
		}
		return f.after(d)
	}
	runClock(ctx, f.now, after, func() *time.Location { return time.UTC }, metrics, &lane{}, newLaneSettings(st, rec.logf))
	within(t, "the metrics lane to be reaped", idle(metrics))
	want := []string{
		"the metrics lane skips its runs: the package is disabled or the export is off",
		"the metrics lane runs again: the package is enabled and the export is on",
	}
	if !reflect.DeepEqual(rec.lines, want) {
		t.Errorf("logged %q, want %q", rec.lines, want)
	}
	if got := len(lines(readFile(t, out))); got != 4 {
		t.Errorf("metrics started %d times over 6 boundaries, want 4", got)
	}
}

// At each local day change the counters lane logs what it clears, or that nothing is due, so an observer knows the day change
// was decided; ordinary minute boundaries log nothing.
func TestCountersLogTheirDecisionAtEachDayChange(t *testing.T) {
	for _, c := range []struct {
		ip, dnsbl, want string
	}{
		{"never", "never", "the day changed: no counter is due to clear"},
		{"daily", "weekly", "the day changed: the counters lane clears clearip"},
		{"daily", "daily", "the day changed: the counters lane clears clearip cleardnsbl"},
	} {
		t.Run(c.ip+"-"+c.dnsbl, func(t *testing.T) {
			st, _ := laneStoreOver(t, map[string]any{"clearIpCounters": c.ip, "clearDnsblCounters": c.dnsbl})
			rec := &logRecorder{}
			counters := &lane{name: "counters", path: laneProgram(t, t.TempDir(), "prog", `:`), logf: rec.logf}
			start := time.Date(2024, 3, 5, 23, 58, 30, 0, time.UTC) // a weekday; the second of 3 boundaries is the day change
			drive(t, start, 3, func() *time.Location { return time.UTC }, &lane{}, counters, newLaneSettings(st, rec.logf))
			if want := []string{c.want}; !reflect.DeepEqual(rec.lines, want) {
				t.Errorf("logged %q, want %q", rec.lines, want)
			}
		})
	}
}
