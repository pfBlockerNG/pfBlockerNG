package update

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stuck is the outer watchdog: it only salvages a hung test, no assertion rests on it.
const stuck = 30 * time.Second

func recv[T any](t *testing.T, ch <-chan T, what string) (v T) {
	t.Helper()
	select {
	case v = <-ch:
	case <-time.After(stuck):
		t.Fatalf("STUCK: %s", what)
	}
	return v
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// hold is a RunFunc a test steers: it writes the lines the test sends and ends with the error the test sends, or when
// its context ends.
type hold struct {
	lines   chan string
	wrote   chan struct{}
	release chan error
	runs    atomic.Int32
}

func newHold() *hold {
	return &hold{lines: make(chan string), wrote: make(chan struct{}, 1), release: make(chan error)}
}

func (h *hold) run(ctx context.Context, _ Request, log *os.File) (Result, error) {
	h.runs.Add(1)
	for {
		select {
		case s := <-h.lines:
			_, _ = log.WriteString(s)
			h.wrote <- struct{}{}
		case err := <-h.release:
			return Result{}, err
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
}

// write has the running Update append s to its log and returns once it is there.
func (h *hold) write(t *testing.T, s string) {
	t.Helper()
	select {
	case h.lines <- s:
	case <-time.After(stuck):
		t.Fatalf("STUCK: the run never took %q", s)
	}
	recv(t, h.wrote, "the run never wrote its line")
}

// finish ends the running Update with err.
func (h *hold) finish(t *testing.T, err error) {
	t.Helper()
	select {
	case h.release <- err:
	case <-time.After(stuck):
		t.Fatal("STUCK: the run never took its release")
	}
}

func newGate(t *testing.T, run RunFunc, done func(Request, Result, error)) *Gate {
	t.Helper()
	g := New(filepath.Join(t.TempDir(), "update.log"), run, done)
	t.Cleanup(g.Stop)
	return g
}

// settle returns once the Update Start admitted has finished and the gate is free again.
func settle(t *testing.T, g *Gate) {
	t.Helper()
	free := make(chan struct{})
	go func() { g.admit.Lock(); g.admit.Unlock(); close(free) }()
	recv(t, free, "the Update never released the gate")
}

func TestStartAdmitsAnUpdateAndAViewReadsItWhileItHoldsTheGate(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	before := time.Now().Unix()
	if err := g.Start(Request{Trigger: "manual", Scope: "ip", Force: "parse"}); err != nil {
		t.Fatalf("Start on an idle gate = %v, want it admitted", err)
	}
	h.write(t, "one\n")
	v := g.View(0, 0)
	if !v.Running || v.Update == nil {
		t.Fatalf("View = %s, want a running Update", jsonOf(t, v))
	}
	u := v.Update
	if u.Trigger != "manual" || u.Scope != "ip" || u.Force != "parse" || u.FinishedAt != nil || u.Result != "" {
		t.Errorf("the running Update = %s, want manual/ip/parse with no finish and no result", jsonOf(t, u))
	}
	if u.StartedAt < before || u.StartedAt > time.Now().Unix() {
		t.Errorf("startedAt = %d, want the Unix second Start ran in (from %d)", u.StartedAt, before)
	}
	if j := jsonOf(t, u); strings.Contains(j, "finishedAt") || strings.Contains(j, `"result"`) {
		t.Errorf("a running Update is %s, want no finishedAt and no result keys", j)
	}
	if v.Log != "one\n" || v.Next != 4 {
		t.Errorf("View(0) = log %q next %d, want %q and 4", v.Log, v.Next, "one\n")
	}
	h.write(t, "two\n")
	if v = g.View(v.Next, 0); v.Log != "two\n" || v.Next != 8 || !v.Running {
		t.Errorf("View(4) = %s, want only the new line, next 8, still running", jsonOf(t, v))
	}
	h.finish(t, nil)
}

func TestAStartWhileAnUpdateRunsIsRefusedAtOnceAndLeavesItAlone(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual", Scope: "dnsbl"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, "one\n")
	before := g.View(0, 0)
	for _, req := range []Request{{Trigger: "scheduled"}, {Trigger: "manual", Scope: "both", Force: "both"}} {
		if err := g.Start(req); !errors.Is(err, ErrRunning) {
			t.Errorf("Start(%+v) while an Update runs = %v, want ErrRunning", req, err)
		}
	}
	if after := g.View(0, 0); !reflect.DeepEqual(after, before) {
		t.Errorf("the refused Starts changed the running Update:\n before %s\n after  %s", jsonOf(t, before), jsonOf(t, after))
	}
	h.finish(t, nil)
	settle(t, g)
	if n := h.runs.Load(); n != 1 {
		t.Errorf("run was called %d times, want once: a refused Start must run nothing", n)
	}
}

func TestAnUpdateEndsSuccessfulWhenRunReturnsNilAndFailedOtherwise(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"run returns nil", nil, "success"},
		{"run returns an error", errors.New("the program failed"), "failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHold()
			g := newGate(t, h.run, nil)
			if err := g.Start(Request{Trigger: "retry"}); err != nil {
				t.Fatal(err)
			}
			h.write(t, "x\n")
			if v := g.View(0, 0); !v.Running || v.Update.FinishedAt != nil || v.Update.Result != "" {
				t.Fatalf("before run returns, View = %s, want a running Update with no result", jsonOf(t, v))
			}
			h.finish(t, c.err)
			settle(t, g)
			v := g.View(0, 0)
			if v.Running || v.Update == nil || v.Update.Result != c.want || v.Update.FinishedAt == nil || *v.Update.FinishedAt < v.Update.StartedAt {
				t.Fatalf("after run returns, View = %s, want not running, result %q and finishedAt set", jsonOf(t, v), c.want)
			}
			if j := jsonOf(t, v.Update); !strings.Contains(j, `"result":"`+c.want+`"`) || !strings.Contains(j, `"finishedAt":`) {
				t.Errorf("the finished Update is %s, want the keys result and finishedAt", j)
			}
			if v.Log != "x\n" {
				t.Errorf("the finished Update's log = %q, want it still readable: %q", v.Log, "x\n")
			}
		})
	}
}

func TestDoneSeesTheOutcomeWhileTheGateIsStillHeld(t *testing.T) {
	type seen struct {
		req     Request
		res     Result
		err     error
		restart error
		running bool
	}
	want := Result{Outcomes: map[string]string{"ipv4:a_v4": "success"}, Attempted: []string{"ipv4:a_v4"}}
	for _, c := range []struct {
		name string
		err  error
	}{
		{"a run that succeeds", nil},
		{"a run that fails", errors.New("the program failed")},
	} {
		t.Run(c.name, func(t *testing.T) {
			var g *Gate
			got := make(chan seen, 1)
			req := Request{Trigger: "apply", Feeds: []string{"ipv4:a_v4"}}
			run := func(context.Context, Request, *os.File) (Result, error) { return want, c.err }
			done := func(r Request, res Result, err error) {
				got <- seen{r, res, err, g.Start(Request{Trigger: "manual"}), g.View(0, 0).Running}
			}
			g = newGate(t, run, done)
			if err := g.Start(req); err != nil {
				t.Fatal(err)
			}
			s := recv(t, got, "done was never called")
			settle(t, g)
			if !reflect.DeepEqual(s.req, req) || !reflect.DeepEqual(s.res, want) || !errors.Is(s.err, c.err) {
				t.Errorf("done got (%+v, %+v, %v), want (%+v, %+v, %v)", s.req, s.res, s.err, req, want, c.err)
			}
			if !errors.Is(s.restart, ErrRunning) {
				t.Errorf("a Start inside done = %v, want ErrRunning: the gate is released only after done", s.restart)
			}
			if !s.running {
				t.Error("View inside done says the Update is not running, want it running until the gate is released")
			}
			if v := g.View(0, 0); v.Running || v.Update.FinishedAt == nil {
				t.Errorf("after the gate is released, View = %s, want a finished Update", jsonOf(t, v))
			}
		})
	}
}

func TestANewStartTruncatesTheLogAndReplacesTheStatus(t *testing.T) {
	const first = "first Update line\n"
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual", Scope: "ip"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, first)
	h.finish(t, nil)
	settle(t, g)
	old := g.View(0, 0)
	if old.Log != first || old.Next != int64(len(first)) || old.Update.Result != "success" {
		t.Fatalf("the first Update's View = %s, want its whole log and a finished status", jsonOf(t, old))
	}
	if err := g.Start(Request{Trigger: "apply"}); err != nil {
		t.Fatal(err)
	}
	v := g.View(old.Next, 0)
	if v.Log != "" || v.Next == old.Next {
		t.Errorf("View(%d) after the second Start = log %q next %d, want the truncated log read from its start, under a cursor of the new Update", old.Next, v.Log, v.Next)
	}
	if u := v.Update; !v.Running || u == nil || u.Trigger != "apply" || u.Scope != "" || u.Result != "" || u.FinishedAt != nil {
		t.Errorf("the status after the second Start = %s, want a running apply Update", jsonOf(t, v))
	}
	h.write(t, "new\n")
	if v = g.View(old.Next, 0); v.Log != "new\n" || g.View(v.Next, 0).Log != "" {
		t.Errorf("View(%d) = log %q next %d, want the new log from its start, then nothing from the cursor it returned", old.Next, v.Log, v.Next)
	}
	h.finish(t, nil)
}

func TestAViewBeforeAnyStartIsIdleWithNoUpdateAndNoLog(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "update.log")
	if err := os.WriteFile(left, []byte("left by a previous process\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, path string }{
		{"a log left by a previous process", left},
		{"no log file", filepath.Join(dir, "absent.log")},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := New(c.path, newHold().run, nil)
			t.Cleanup(g.Stop)
			for _, after := range []int64{0, 5, -1} {
				v := g.View(after, 3)
				if !reflect.DeepEqual(v, View{}) {
					t.Errorf("View(%d) before any Start = %s, want an idle View with no Update and no log", after, jsonOf(t, v))
				}
				if j := jsonOf(t, v); j != `{"running":false,"update":null,"log":"","next":"0"}` {
					t.Errorf("an idle View is %s, want running false and update null spelled out", j)
				}
			}
		})
	}
}

func TestAViewBoundsTheBytesAdvancesNextAndRestartsFromZeroOutOfRange(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, "0123456789")
	for _, c := range []struct {
		after     int64
		max       int
		log       string
		next      int64
		situation string
	}{
		{0, 4, "0123", 4, "the first chunk"},
		{4, 4, "4567", 8, "the next chunk"},
		{8, 4, "89", 10, "the last, short chunk"},
		{10, 4, "", 10, "an offset at the end: nothing new"},
		{11, 4, "0123", 4, "an offset beyond the end: the log was truncated"},
		{-1, 4, "0123", 4, "a negative offset"},
		{0, 0, "0123456789", 10, "max 0: the default bound"},
		{3, -5, "3456789", 10, "a negative max: the default bound"},
	} {
		if v := g.View(c.after, c.max); v.Log != c.log || v.Next != c.next {
			t.Errorf("View(%d, %d) [%s] = log %q next %d, want %q and %d", c.after, c.max, c.situation, v.Log, v.Next, c.log, c.next)
		}
	}
	h.write(t, strings.Repeat("a", 70000))
	if v := g.View(0, 0); len(v.Log) != 64<<10 || v.Next != 64<<10 {
		t.Errorf("View(0, 0) on a 70010 byte log = %d bytes next %d, want the default bound of 65536", len(v.Log), v.Next)
	}
	if v := g.View(0, math.MaxInt); len(v.Log) != 70010 || v.Next != 70010 {
		t.Errorf("View(0, MaxInt) = %d bytes next %d, want the whole 70010 byte log", len(v.Log), v.Next)
	}
	h.finish(t, nil)
}

func TestAViewNeverSplitsARuneAcrossItsBound(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, "a\u00e9\u20ac\U0001d11e") // 1, 2, 3 and 4 bytes
	for _, c := range []struct {
		after int64
		max   int
		log   string
		next  int64
	}{
		{0, 2, "a", 1},
		{1, 2, "\u00e9", 3},
		{3, 4, "\u20ac", 6},
		{6, 4, "\U0001d11e", 10},
		{1, 1, "\xc3", 2}, // a bound inside the first rune must still advance
	} {
		if v := g.View(c.after, c.max); v.Log != c.log || v.Next != c.next {
			t.Errorf("View(%d, %d) = log %q next %d, want %q and %d", c.after, c.max, v.Log, v.Next, c.log, c.next)
		}
	}
	h.finish(t, nil)
}

func TestStopCancelsTheRunningUpdateWaitsForItAndRefusesLaterStarts(t *testing.T) {
	h := newHold()
	ended := make(chan error, 1)
	g := newGate(t, h.run, func(_ Request, _ Result, err error) { ended <- err })
	if err := g.Start(Request{Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, "x\n")
	stopped := make(chan struct{})
	go func() { g.Stop(); close(stopped) }()
	recv(t, stopped, "Stop never returned")
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the Update ended with %v, want its context canceled", err)
		}
	default:
		t.Fatal("Stop returned before the Update had finished")
	}
	if v := g.View(0, 0); v.Running || v.Update.Result != "failed" || v.Update.FinishedAt == nil {
		t.Errorf("after Stop, View = %s, want a finished, failed Update", jsonOf(t, v))
	}
	if err := g.Start(Request{Trigger: "manual"}); !errors.Is(err, ErrStopped) {
		t.Errorf("Start after Stop = %v, want ErrStopped", err)
	}
	again := make(chan struct{})
	go func() { g.Stop(); close(again) }()
	recv(t, again, "a second Stop never returned")
	if n := h.runs.Load(); n != 1 {
		t.Errorf("run was called %d times, want once: Start after Stop must run nothing", n)
	}
}

func TestStopOnAnIdleGateRefusesLaterStarts(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	stopped := make(chan struct{})
	go func() { g.Stop(); close(stopped) }()
	recv(t, stopped, "Stop on an idle gate never returned")
	if err := g.Start(Request{Trigger: "manual"}); !errors.Is(err, ErrStopped) {
		t.Errorf("Start after Stop = %v, want ErrStopped", err)
	}
	if n := h.runs.Load(); n != 0 {
		t.Errorf("run was called %d times, want never", n)
	}
}

func TestConcurrentStartsAdmitExactlyOne(t *testing.T) {
	const n = 64
	h := newHold()
	g := newGate(t, h.run, nil)
	errs := make(chan error, n)
	begin := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			errs <- g.Start(Request{Trigger: "manual"})
		}()
	}
	close(begin)
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	recv(t, all, "the concurrent Starts never all returned")
	close(errs)
	admitted, refused := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrRunning):
			refused++
		default:
			t.Errorf("Start = %v, want nil or ErrRunning", err)
		}
	}
	if admitted != 1 || refused != n-1 {
		t.Errorf("%d concurrent Starts: %d admitted and %d refused, want exactly 1 and %d", n, admitted, refused, n-1)
	}
	h.finish(t, nil)
	settle(t, g)
	if got := h.runs.Load(); got != 1 {
		t.Errorf("run was called %d times, want once", got)
	}
}

func TestAnUnwritableLogPathFailsStartAndLeavesTheGateFree(t *testing.T) {
	h := newHold()
	g := New(filepath.Join(t.TempDir(), "missing", "update.log"), h.run, nil)
	t.Cleanup(g.Stop)
	for attempt := 1; attempt <= 2; attempt++ { // a second failure, not ErrRunning, proves the first released the gate
		if err := g.Start(Request{Trigger: "manual"}); err == nil || errors.Is(err, ErrRunning) || errors.Is(err, ErrStopped) {
			t.Errorf("Start #%d with a log in a missing directory = %v, want the error of creating the log", attempt, err)
		}
	}
	if v := g.View(0, 0); !reflect.DeepEqual(v, View{}) {
		t.Errorf("View after the failed Starts = %s, want an idle gate with no Update", jsonOf(t, v))
	}
	if n := h.runs.Load(); n != 0 {
		t.Errorf("run was called %d times, want never", n)
	}
}
