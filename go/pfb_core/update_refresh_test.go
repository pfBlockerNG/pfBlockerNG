package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// An Update starts on the platform as it is then (issue #3975): the interface addresses and the proxy change outside Core, and
// the tick that tells Core is up to 15 minutes away. Before each Update Core reads its backend again, as SettingsChanged does.

// readStep is one answer of a scriptedBackend: the proxy user of the ingest projection, or a failed read.
type readStep struct {
	user string
	err  error
}

// scriptedBackend answers its Nth read with step N (the last one again after that). It cannot be written.
type scriptedBackend struct {
	steps []readStep
	reads int
}

func (b *scriptedBackend) Read(context.Context) (settings.Stored, error) {
	step := b.steps[min(b.reads, len(b.steps)-1)]
	b.reads++
	if step.err != nil {
		return settings.Stored{}, step.err
	}
	return settings.Stored{Initialized: true, Revision: uint64(b.reads), Projections: map[string]map[string]json.RawMessage{
		"ingest": {"proxyUser": json.RawMessage(strconv.Quote(step.user))}}}, nil
}

func (b *scriptedBackend) Write(context.Context, uint64, map[string]map[string]any) (uint64, error) {
	return 0, errors.New("not writable")
}

func loadScripted(t *testing.T, steps ...readStep) (*settings.Store, *scriptedBackend) {
	t.Helper()
	b := &scriptedBackend{steps: steps}
	st, err := settings.Load(b, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return st, b
}

// recordingRun is the Update's own code: it records the proxy user it finds in the store and what it was called with.
type recordingRun struct {
	t    *testing.T
	st   *settings.Store
	seen []string
	req  update.Request
	ctx  context.Context
}

func (r *recordingRun) run(ctx context.Context, req update.Request, _ *os.File) (update.Result, error) {
	ingest, err := r.st.GetClear("ingest")
	if err != nil {
		r.t.Fatalf("GetClear: %v", err)
	}
	r.seen = append(r.seen, ingest["proxyUser"].(string))
	r.req, r.ctx = req, ctx
	return update.Result{Attempted: []string{"feed"}}, update.ErrDeferred
}

func TestAnUpdateStartsOnTheSettingsTheBackendHoldsThen(t *testing.T) {
	st, b := loadScripted(t, readStep{user: "before"}, readStep{user: "after"})
	inner := &recordingRun{t: t, st: st}
	run := refreshingRun(st, inner.run, t.Logf)
	if ingest, _ := st.GetClear("ingest"); ingest["proxyUser"] != "before" || b.reads != 1 {
		t.Fatalf("the store holds %v after %d reads, want what the first read gave", ingest["proxyUser"], b.reads)
	}

	ctx := context.WithValue(t.Context(), struct{}{}, "marker")
	req := update.Request{Trigger: "manual", Scope: "ip", Force: "parse"}
	res, err := run(ctx, req, nil)

	if !slices.Equal(inner.seen, []string{"after"}) || b.reads != 2 {
		t.Errorf("the Update saw proxy users %v after %d reads, want [after] after the second", inner.seen, b.reads)
	}
	if inner.ctx != ctx || inner.req.Trigger != "manual" || inner.req.Scope != "ip" || inner.req.Force != "parse" {
		t.Errorf("the Update was called with %v, %+v, want the request and context it was given", inner.ctx, inner.req)
	}
	if !errors.Is(err, update.ErrDeferred) || !slices.Equal(res.Attempted, []string{"feed"}) {
		t.Errorf("the Update answered %+v, %v, want what its own code answered", res, err)
	}
}

func TestAFailedReadAtUpdateStartKeepsTheValuesIsLoggedOncePerOutageAndTheUpdateRuns(t *testing.T) {
	boom := errors.New("config.xml is locked")
	st, b := loadScripted(t, readStep{user: "before"}, readStep{err: boom}, readStep{err: boom}, readStep{user: "later"}, readStep{err: boom})
	inner := &recordingRun{t: t, st: st}
	var logged []string
	run := refreshingRun(st, inner.run, func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) })

	for i := range 4 {
		if _, err := run(t.Context(), update.Request{Trigger: "manual"}, nil); !errors.Is(err, update.ErrDeferred) {
			t.Fatalf("Update %d answered %v, want its own code's answer: a failed read does not stop it", i+1, err)
		}
	}

	if want := []string{"before", "before", "later", "later"}; !slices.Equal(inner.seen, want) {
		t.Errorf("the Updates saw %v, want %v: a failed read keeps the values in memory", inner.seen, want)
	}
	if b.reads != 5 {
		t.Errorf("the backend was read %d times, want the Load and one read per Update", b.reads)
	}
	if len(logged) != 2 || !strings.Contains(logged[0], "config.xml is locked") {
		t.Errorf("%d lines logged %q, want one for the first outage (two failed reads), naming why, and one for the second", len(logged), logged)
	}
}

// A read cut short because the Update was cancelled is no outage of the backend: it is not logged, and does not use up the line
// the next failed read gets.
func TestAReadFailingUnderACancelledUpdateIsNotLoggedAsAnOutage(t *testing.T) {
	st, _ := loadScripted(t, readStep{user: "before"}, readStep{err: errors.New("config.xml is locked")})
	inner := &recordingRun{t: t, st: st}
	var logged []string
	run := refreshingRun(st, inner.run, func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) })
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	run(cancelled, update.Request{Trigger: "manual"}, nil)
	if len(logged) != 0 {
		t.Fatalf("a read failing under a cancelled Update logged %q, want nothing", logged)
	}
	run(t.Context(), update.Request{Trigger: "manual"}, nil)

	if len(logged) != 1 || !strings.Contains(logged[0], "config.xml is locked") {
		t.Errorf("the next failed read logged %q, want its one line: the cancelled one did not use it up", logged)
	}
}

// The Update the scheduler or a client starts through Core is the wrapped one: the adapter is run once more, before the program.
func TestAnUpdateStartedThroughCoreReadsTheSettingsBackendFirst(t *testing.T) {
	holdQuarters(t)
	adapter := newFakeAdapter(t, readReply(t, 1, nil))
	program := newFakeUpdate(t)
	core := startCore(t, scratchDir(t), "--settings-backend-cmd", adapter.path, "--update-cmd", program.path)
	if adapter.runs() != 1 {
		t.Fatalf("the adapter ran %d times by the time Core served, want only the read at start", adapter.runs())
	}

	if got := core.post("StartUpdate", `{"requestId":"m1","trigger":"manual"}`); got.status != 200 {
		t.Fatalf("StartUpdate = %d %s", got.status, got.body)
	}
	core.waitLog("", "update program started")
	if adapter.runs() != 2 || adapter.request() != `{"version":1,"op":"read"}` {
		t.Errorf("the adapter ran %d times, last asked %s: want a read of the settings before the Update's program started", adapter.runs(), adapter.request())
	}
	program.release()
	core.waitFinished("manual")
}
