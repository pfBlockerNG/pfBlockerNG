package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	_ "time/tzdata" // the zone rows do not depend on the host's zoneinfo
)

// logRecorder is a lane's logf that keeps what it was told.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRecorder) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logRecorder) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

// laneProgram writes an executable shell program named name into dir and returns its path.
func laneProgram(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// within polls cond until it holds, as the completion barrier of work that runs in another process.
func within(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("STUCK/ENVIRONMENT: %s did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func idle(l *lane) func() bool { return func() bool { return !l.busy.Load() } }

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func exists(path string) func() bool {
	return func() bool { _, err := os.Stat(path); return err == nil }
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// A lane runs its program once per start with exactly the given arguments, never through a shell: the path holds spaces and
// shell metacharacters, and an argument holds a space.
func TestLaneStartRunsTheProgramWithExactlyTheArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x y;$(z)")
	out := filepath.Join(t.TempDir(), "out")
	l := &lane{name: "counters", path: laneProgram(t, dir, "prog", `printf '%s\n' "$@" >> `+out), logf: (&logRecorder{}).logf}
	l.start("daily", "two words")
	within(t, "the lane to be reaped", idle(l))
	if got, want := readFile(t, out), "daily\ntwo words\n"; got != want {
		t.Errorf("the program recorded %q, want %q", got, want)
	}
}

// A lane whose previous run is alive skips the start, never queues it, and runs again once that run is reaped.
func TestLaneStartSkipsWhileBusyAndRunsAgainAfterTheReap(t *testing.T) {
	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	l := &lane{name: "metrics", path: laneProgram(t, dir, "prog", `echo run >> `+started+"\nwhile [ ! -e "+release+" ]; do sleep 0.005; done"), logf: (&logRecorder{}).logf}
	l.start()
	within(t, "the first run to start", exists(started))
	l.start()
	if !l.busy.Load() {
		t.Fatal("the lane is not busy while its program runs")
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, "the first run to be reaped", idle(l))
	if got := lines(readFile(t, started)); len(got) != 1 {
		t.Fatalf("the skipped start ran anyway or the first run did not: started lines %q, want exactly 1", got)
	}
	l.start()
	within(t, "the third start to run", func() bool { return len(lines(readFile(t, started))) == 2 })
	within(t, "the third run to be reaped", idle(l))
}

// The program is its own session leader (so, a group leader), so a signal aimed at Core's process group does not reach it.
func TestLaneChildIsItsOwnSessionLeader(t *testing.T) {
	dir := t.TempDir()
	pidFile, release := filepath.Join(dir, "pid"), filepath.Join(dir, "release")
	l := &lane{name: "metrics", path: laneProgram(t, dir, "prog", `echo $$ > `+pidFile+".tmp; mv "+pidFile+".tmp "+pidFile+"\nwhile [ ! -e "+release+" ]; do sleep 0.005; done"), logf: (&logRecorder{}).logf}
	l.start()
	within(t, "the program to record its pid", exists(pidFile))
	pid, err := strconv.Atoi(strings.TrimSpace(readFile(t, pidFile)))
	if err != nil {
		t.Fatal(err)
	}
	sid := sessionOf(t, pid)
	if own := sessionOf(t, os.Getpid()); sid == own || sid != pid {
		t.Errorf("child session %d (pid %d), want its own session, distinct from Core's %d", sid, pid, own)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, "the program to be reaped", idle(l))
}

// sessionOf is the session id of pid.
func sessionOf(t *testing.T, pid int) int {
	t.Helper()
	sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, uintptr(pid), 0, 0)
	if errno != 0 {
		t.Fatalf("getsid(%d): %v", pid, errno)
	}
	return int(sid)
}

// A failure is logged once per outage: a success ends the outage and the next failure is logged again.
func TestLaneLogsAFailureOncePerOutage(t *testing.T) {
	dir := t.TempDir()
	codeFile := filepath.Join(dir, "code")
	rec := &logRecorder{}
	l := &lane{name: "metrics", path: laneProgram(t, dir, "prog", `exit "$(cat `+codeFile+`)"`), logf: rec.logf}
	run := func(code string) {
		t.Helper()
		if err := os.WriteFile(codeFile, []byte(code), 0o600); err != nil {
			t.Fatal(err)
		}
		l.start()
		within(t, "the run to be reaped", idle(l))
	}
	for range 3 {
		run("1")
	}
	if n := rec.count(); n != 1 {
		t.Fatalf("three failures logged %d lines %q, want 1", n, rec.lines)
	}
	if !strings.Contains(rec.lines[0], "metrics") || !strings.Contains(rec.lines[0], "exit status 1") {
		t.Errorf("the log line %q names neither the lane nor the exit status", rec.lines[0])
	}
	run("0")
	if n := rec.count(); n != 1 {
		t.Fatalf("a success logged: %d lines %q, want still 1", n, rec.lines)
	}
	run("1")
	if n := rec.count(); n != 2 {
		t.Errorf("a failure after a success logged %d lines %q, want 2", n, rec.lines)
	}
}

// A path that cannot be started (missing, or not executable) is logged once per outage, leaves the lane usable, and a path
// that is made good runs on the next start.
func TestLaneStartErrorIsLoggedOnceAndLeavesTheLaneUsable(t *testing.T) {
	for _, kind := range []string{"missing", "not-executable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path, marker := filepath.Join(dir, "prog"), filepath.Join(dir, "marker")
			if kind == "not-executable" {
				if err := os.WriteFile(path, []byte("#!/bin/sh\necho ok > "+marker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rec := &logRecorder{}
			l := &lane{name: "counters", path: path, logf: rec.logf}
			l.start("daily")
			l.start("daily")
			if l.busy.Load() {
				t.Error("the lane is busy after a start that failed")
			}
			if n := rec.count(); n != 1 || !strings.Contains(rec.lines[0], "counters") {
				t.Fatalf("two failed starts logged %d lines %q, want 1 naming the lane", n, rec.lines)
			}
			if kind == "missing" {
				laneProgram(t, dir, "prog", "echo ok > "+marker)
			} else if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
			l.start("daily")
			within(t, "the repaired program to run", exists(marker))
			within(t, "the run to be reaped", idle(l))
		})
	}
}

// A lane without a path is off: it logs nothing and starts nothing.
func TestLaneWithoutAPathDoesNothing(t *testing.T) {
	rec := &logRecorder{}
	l := &lane{name: "metrics", logf: rec.logf}
	l.start("daily")
	if rec.count() != 0 || l.busy.Load() || l.failed.Load() {
		t.Errorf("an empty lane acted: logs %q busy %t failed %t", rec.lines, l.busy.Load(), l.failed.Load())
	}
}

// fakeClock drives runClock: now moves by exactly what runClock asked to wait, each wait ends at once after both lanes are
// idle, and the wait after the last tick never ends, so that the cancellation is what stops the loop.
type fakeClock struct {
	mu     sync.Mutex
	cur    time.Time
	ticks  int
	waits  []time.Duration
	cancel context.CancelFunc
	lanes  []*lane
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

func (f *fakeClock) after(d time.Duration) <-chan time.Time {
	for _, l := range f.lanes {
		for l.busy.Load() {
			time.Sleep(time.Millisecond)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.waits) == f.ticks {
		f.cancel()
		return nil
	}
	f.waits = append(f.waits, d)
	f.cur = f.cur.Add(d)
	ch := make(chan time.Time, 1)
	ch <- f.cur
	return ch
}

// drive runs runClock from start for ticks boundaries with the zone func and returns the waits it asked for.
func drive(t *testing.T, start time.Time, ticks int, zone func() *time.Location, metrics, counters *lane) []time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeClock{cur: start, ticks: ticks, cancel: cancel, lanes: []*lane{metrics, counters}}
	runClock(ctx, f.now, f.after, zone, metrics, counters)
	within(t, "the lanes to be reaped", func() bool { return !metrics.busy.Load() && !counters.busy.Load() })
	return f.waits
}

// The metrics lane starts at every minute boundary, and each wait is exactly the distance to the next multiple of 60 s: a
// clock exactly on a boundary waits a full minute for the next one.
func TestRunClockStartsMetricsAtEveryMinuteBoundary(t *testing.T) {
	for _, c := range []struct {
		name  string
		start time.Time
		waits []time.Duration
	}{
		{"mid-minute", time.Date(2024, 5, 6, 12, 0, 30, 250_000_000, time.UTC), []time.Duration{29*time.Second + 750*time.Millisecond, time.Minute, time.Minute}},
		{"on a boundary", time.Date(2024, 5, 6, 12, 1, 0, 0, time.UTC), []time.Duration{time.Minute, time.Minute, time.Minute}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			rec := &logRecorder{}
			metrics := &lane{name: "metrics", path: laneProgram(t, t.TempDir(), "prog", `date +%s >> `+out), logf: rec.logf}
			counters := &lane{name: "counters", logf: rec.logf}
			waits := drive(t, c.start, 3, func() *time.Location { return time.UTC }, metrics, counters)
			if !reflect.DeepEqual(waits, c.waits) {
				t.Errorf("runClock waited %v, want %v", waits, c.waits)
			}
			if got := lines(readFile(t, out)); len(got) != 3 {
				t.Errorf("metrics started %d times %q, want once per boundary (3)", len(got), got)
			}
			if rec.count() != 0 {
				t.Errorf("unexpected log lines %q", rec.lines)
			}
		})
	}
}

// Cancelling Core's context ends the loop at once and leaves a running child alone: it is neither signalled nor waited for and
// finishes its work.
func TestRunClockCancellationLeavesARunningChildAlone(t *testing.T) {
	dir := t.TempDir()
	pidFile, release, done := filepath.Join(dir, "pid"), filepath.Join(dir, "release"), filepath.Join(dir, "done")
	metrics := &lane{name: "metrics", path: laneProgram(t, dir, "prog", `echo $$ > `+pidFile+".tmp; mv "+pidFile+".tmp "+pidFile+"\nwhile [ ! -e "+release+" ]; do sleep 0.005; done\necho finished > "+done), logf: (&logRecorder{}).logf}
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
		runClock(ctx, func() time.Time { return time.Date(2024, 5, 6, 12, 0, 30, 0, time.UTC) }, after, nil, metrics, &lane{})
		close(ended)
	}()
	within(t, "the child to start", exists(pidFile))
	cancel()
	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("STUCK/ENVIRONMENT: runClock did not return after its context was cancelled")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(readFile(t, pidFile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the child is gone after runClock returned: %v", err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, "the child to finish its work", exists(done))
	within(t, "the child to be reaped", idle(metrics))
}

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestCadencesDue(t *testing.T) {
	sp, havana := mustZone(t, "America/Sao_Paulo"), mustZone(t, "America/Havana")
	utc := func(y int, m time.Month, d, h, mi int) time.Time { return time.Date(y, m, d, h, mi, 0, 0, time.UTC) }
	daily, weekly := []string{"daily"}, []string{"daily", "weekly"}
	// 2024-03-10 is a Sunday; 2024-03-09 a Saturday; 2024-03-11 a Monday.
	for _, c := range []struct {
		name string
		prev time.Time
		loc  *time.Location
		want []string
	}{
		{"UTC mid-day", utc(2024, 3, 6, 12, 0), time.UTC, nil},
		{"Saturday into Sunday", utc(2024, 3, 9, 23, 59), time.UTC, weekly},
		{"Sunday into Monday", utc(2024, 3, 10, 23, 59), time.UTC, daily},
		{"zone honoured: no change in UTC", utc(2024, 3, 10, 2, 59), time.UTC, nil},
		{"zone honoured: midnight in Sao Paulo", utc(2024, 3, 10, 2, 59), sp, weekly},
		{"Havana spring forward skips local midnight", utc(2024, 3, 10, 4, 59), havana, weekly},
		{"Havana fall back repeats local midnight", utc(2024, 11, 3, 4, 59), havana, nil},
		{"Havana ordinary midnight", utc(2024, 11, 3, 3, 59), havana, weekly},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := cadencesDue(c.prev, c.prev.Add(time.Minute), c.loc); !reflect.DeepEqual(got, c.want) {
				t.Errorf("cadencesDue(%s, +1m, %v) = %v, want %v", c.prev, c.loc, got, c.want)
			}
		})
	}
}

// The counters lane starts exactly once per local day change, with the cadences due as its arguments, and the zone is read
// again at every boundary.
func TestRunClockStartsCountersOncePerLocalDayChange(t *testing.T) {
	sp := mustZone(t, "America/Sao_Paulo")
	for _, c := range []struct {
		name  string
		start time.Time
		zones []*time.Location // the zone at each boundary; the last repeats
		want  []string
	}{
		{"Saturday into Sunday", time.Date(2024, 3, 9, 23, 58, 30, 0, time.UTC), []*time.Location{time.UTC}, []string{"daily weekly"}},
		{"Sunday into Monday", time.Date(2024, 3, 10, 23, 58, 30, 0, time.UTC), []*time.Location{time.UTC}, []string{"daily"}},
		{"mid-week day without a change", time.Date(2024, 3, 6, 12, 0, 30, 0, time.UTC), []*time.Location{time.UTC}, nil},
		{"zone changed between boundaries", time.Date(2024, 3, 10, 2, 58, 30, 0, time.UTC), []*time.Location{time.UTC, sp}, []string{"daily weekly"}},
		{"zone kept at UTC", time.Date(2024, 3, 10, 2, 58, 30, 0, time.UTC), []*time.Location{time.UTC, time.UTC}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			rec := &logRecorder{}
			metrics := &lane{name: "metrics", logf: rec.logf}
			counters := &lane{name: "counters", path: laneProgram(t, t.TempDir(), "prog", `echo "$*" >> `+out), logf: rec.logf}
			asked := 0
			zone := func() *time.Location {
				loc := c.zones[min(asked, len(c.zones)-1)]
				asked++
				return loc
			}
			drive(t, c.start, 3, zone, metrics, counters)
			if got := lines(readFile(t, out)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("counters started with %q, want %q", got, c.want)
			}
			if asked != 3 {
				t.Errorf("the zone was read %d times for 3 boundaries, want once per boundary", asked)
			}
		})
	}
}

// driveScript runs runClock over the clock readings in nows, one per boundary computed, with each wait ending at once once both
// lanes are idle. The loop is stopped when the readings run out, after the last boundary has fired.
func driveScript(t *testing.T, nows []time.Time, zone func() *time.Location, metrics, counters *lane) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	i := 0
	now := func() time.Time {
		if i >= len(nows) {
			cancel()
			return nows[len(nows)-1]
		}
		i++
		return nows[i-1]
	}
	after := func(time.Duration) <-chan time.Time {
		for _, l := range []*lane{metrics, counters} {
			for l.busy.Load() {
				time.Sleep(time.Millisecond)
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	runClock(ctx, now, after, zone, metrics, counters)
	within(t, "the lanes to be reaped", func() bool { return !metrics.busy.Load() && !counters.busy.Load() })
}

// A local day change is remembered across boundaries, so a clock that jumps or a gap of days still starts the counters once at
// the boundary that lands on a later local date, and a clock stepped back never does until a real later date.
func TestRunClockCountersSurviveClockJumpsAndNeverFireBackwards(t *testing.T) {
	at := func(d, h, m, s int) time.Time { return time.Date(2024, 3, d, h, m, s, 0, time.UTC) } // 2024-03-09 Sat, 10 Sun, 11 Mon
	for _, c := range []struct {
		name string
		nows []time.Time
		want []string
	}{
		{"a jump across midnight", []time.Time{at(9, 23, 58, 30), at(10, 0, 10, 10)}, []string{"daily weekly"}},
		{"a step back from Sunday into Saturday fires nothing, then the real change fires once",
			[]time.Time{at(10, 0, 4, 30), at(9, 23, 49, 30), at(9, 23, 58, 30), at(9, 23, 59, 30)}, []string{"daily weekly"}},
		{"a gap of days to a Monday", []time.Time{at(6, 12, 0, 30), at(11, 12, 0, 30)}, []string{"daily"}},
		{"a gap of days to a Sunday", []time.Time{at(6, 12, 0, 30), at(10, 12, 0, 30)}, []string{"daily weekly"}},
		{"a day change on every following day", []time.Time{at(9, 23, 59, 30), at(10, 23, 59, 30)}, []string{"daily weekly", "daily"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			rec := &logRecorder{}
			metrics := &lane{name: "metrics", logf: rec.logf}
			counters := &lane{name: "counters", path: laneProgram(t, t.TempDir(), "prog", `echo "$*" >> `+out), logf: rec.logf}
			driveScript(t, c.nows, func() *time.Location { return time.UTC }, metrics, counters)
			if got := lines(readFile(t, out)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("counters started with %q, want %q", got, c.want)
			}
		})
	}
}

// Cadences are due only when the boundary's local date is strictly after the previous boundary's: never for a clock stepped back,
// and a gap of several days is one start, weekly only when the boundary's own day is a Sunday.
func TestCadencesDueIsStrictlyForward(t *testing.T) {
	at := func(d, h, m int) time.Time { return time.Date(2024, 3, d, h, m, 0, 0, time.UTC) } // 9 Sat, 10 Sun, 11 Mon
	for _, c := range []struct {
		name           string
		prev, boundary time.Time
		want           []string
	}{
		{"a step back to the previous date", at(10, 0, 5), at(9, 23, 50), nil},
		{"a step back by days", at(11, 12, 0), at(6, 12, 0), nil},
		{"a gap of days ending on a Monday", at(6, 12, 0), at(11, 12, 1), []string{"daily"}},
		{"a gap of days ending on a Sunday", at(6, 12, 0), at(10, 12, 1), []string{"daily", "weekly"}},
		{"a jump across midnight", at(9, 23, 59), at(10, 0, 11), []string{"daily", "weekly"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := cadencesDue(c.prev, c.boundary, time.UTC); !reflect.DeepEqual(got, c.want) {
				t.Errorf("cadencesDue(%s, %s) = %v, want %v", c.prev, c.boundary, got, c.want)
			}
		})
	}
}

// run starts the --metrics-cmd and --counters-cmd programs at the clock's boundary, whose paths hold a space and shell
// metacharacters, and stops cleanly. The clock is the package's clockNow/clockAfter seam.
func TestRunStartsTheClockLanesAtTheBoundary(t *testing.T) {
	oldNow, oldAfter := clockNow, clockAfter
	t.Cleanup(func() { clockNow, clockAfter = oldNow, oldAfter })
	utc, err := os.ReadFile("/usr/share/zoneinfo/UTC")
	if err != nil {
		t.Skipf("the host has no zoneinfo to give --zoneinfo: %v", err)
	}
	clockNow = func() time.Time { return time.Date(2024, 3, 9, 23, 59, 30, 0, time.UTC) } // a Saturday: the next boundary is Sunday
	var calls sync.Mutex
	asked := 0
	ready := make(chan time.Time, 1)
	ready <- time.Time{}
	clockAfter = func(time.Duration) <-chan time.Time {
		calls.Lock()
		defer calls.Unlock()
		if asked++; asked == 1 {
			return ready
		}
		return nil
	}
	dir := scratchDir(t)
	zoneFile := filepath.Join(dir, "UTC")
	if err := os.WriteFile(zoneFile, utc, 0o600); err != nil {
		t.Fatal(err)
	}
	progs := filepath.Join(dir, "x y;$(z)")
	metricsOut, countersOut := filepath.Join(dir, "metrics"), filepath.Join(dir, "counters")
	metrics := laneProgram(t, progs, "metrics", `echo "metrics [$#]" > `+metricsOut)
	counters := laneProgram(t, progs, "counters", `echo "$*" > `+countersOut)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code := make(chan int, 1)
	go func() {
		var stderr strings.Builder
		code <- run(ctx, []string{"--socket", filepath.Join(dir, "run", "api.sock"), "--state-dir", filepath.Join(dir, "state"),
			"--zoneinfo", zoneFile, "--metrics-cmd", metrics, "--counters-cmd", counters}, &stderr)
	}()
	within(t, "the metrics program to start", exists(metricsOut))
	within(t, "the counters program to start", exists(countersOut))
	cancel()
	select {
	case c := <-code:
		if c != 0 {
			t.Errorf("run = %d, want 0", c)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("STUCK/ENVIRONMENT: run did not return after its context was cancelled")
	}
	within(t, "the programs to finish writing", func() bool {
		return readFile(t, metricsOut) != "" && readFile(t, countersOut) != ""
	})
	if got := readFile(t, metricsOut); got != "metrics [0]\n" {
		t.Errorf("the metrics program ran with %q, want no arguments", got)
	}
	if got := readFile(t, countersOut); got != "daily weekly\n" {
		t.Errorf("the counters program ran with %q, want \"daily weekly\"", got)
	}
}
