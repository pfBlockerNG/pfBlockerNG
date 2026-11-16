package scheduler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

func TestMaintenanceCallbackRunsOnlyAtQuarterAndIsJoined(t *testing.T) {
	f := newFixture(t, model(false), "")
	cfg := f.config()
	var calls atomic.Int32
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	callback := func(ctx context.Context) error {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	}
	field := reflect.ValueOf(&cfg).Elem().FieldByName("Maintenance")
	if !field.IsValid() || field.Type() != reflect.TypeOf(callback) || !field.CanSet() {
		t.Fatalf("scheduler.Config.Maintenance must be optional %v; field present=%v", reflect.TypeOf(callback), field.IsValid())
	}
	field.Set(reflect.ValueOf(callback))
	f.s = New(cfg)
	f.s.Bind(f.start)
	f.setNow(time.Date(2026, 11, 13, 10, 50, 7, 500_000_000, time.UTC))
	h := startRun(t, f)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	if got := recv(t, h.asked, "first quarter boundary"); got != 9*time.Minute+52*time.Second+500*time.Millisecond {
		t.Fatalf("first boundary delay = %s", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("maintenance ran before a timer event: %d calls", got)
	}

	fire := func(at time.Time) {
		f.setNow(at)
		select {
		case h.fire <- time.Time{}:
		case <-time.After(stuck):
			t.Fatal("STUCK: scheduler did not consume quarter timer")
		}
	}
	fire(time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC))
	recv(t, entered, "maintenance callback at the quarter boundary")
	if got := recv(t, h.asked, "next boundary while maintenance is held"); got != 15*time.Minute {
		t.Fatalf("next boundary delay = %s, want 15m", got)
	}
	fire(time.Date(2026, 11, 13, 11, 15, 0, 0, time.UTC))
	recv(t, h.asked, "feed scheduler to continue while maintenance is held")
	if got := calls.Load(); got != 1 {
		t.Fatalf("busy maintenance overlapped or queued: %d calls", got)
	}
	if got := f.requests(); len(got) != 0 {
		t.Fatalf("maintenance created Updates: %+v", got)
	}

	h.cancel()
	recv(t, canceled, "maintenance cancellation")
	select {
	case <-h.finished:
		t.Fatal("Run returned before its canceled maintenance callback was released")
	default:
	}
	close(release)
	recv(t, h.finished, "Run to join its maintenance callback")
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Errorf("maintenance changed scheduler state: stat error = %v", err)
	}
}

func TestStalledMaintenanceDoesNotDelayDueFeedsOrOverlapAtNextBoundary(t *testing.T) {
	f := newFixture(t, model(true, hourly(feedA)), "")
	cfg := f.config()
	var calls atomic.Int32
	entered, canceled := make(chan struct{}, 2), make(chan struct{})
	callback := func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			defer close(canceled)
		}
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	field := reflect.ValueOf(&cfg).Elem().FieldByName("Maintenance")
	if !field.IsValid() || field.Type() != reflect.TypeOf(callback) || !field.CanSet() {
		t.Fatalf("scheduler.Config.Maintenance must be optional %v; field present=%v", reflect.TypeOf(callback), field.IsValid())
	}
	field.Set(reflect.ValueOf(callback))
	f.s = New(cfg)
	f.s.Bind(f.start)
	h := startRun(t, f)
	recv(t, h.asked, "initial boundary")
	fire := func() {
		select {
		case h.fire <- time.Time{}:
		case <-time.After(stuck):
			t.Fatal("STUCK: scheduler did not consume quarter timer")
		}
	}
	fire()
	recv(t, entered, "maintenance to enter")
	recv(t, h.asked, "due feed evaluation while maintenance is held")
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
	if got := f.items()[feedA].PendingOccurrence; got == nil || *got != occ10 {
		t.Fatalf("feed reservation while maintenance was held = %v, want occurrence %d", got, occ10)
	}

	f.setNow(f.now().Add(15 * time.Minute))
	fire()
	recv(t, h.asked, "next boundary while maintenance is still held")
	if got := calls.Load(); got != 1 {
		t.Errorf("busy maintenance overlapped or queued: %d callbacks", got)
	}
	if got := len(f.requests()); got != 2 {
		t.Errorf("feed evaluations while maintenance was held = %d, want 2", got)
	}
	h.stop(t)
	recv(t, canceled, "maintenance to observe cancellation")
	if got := calls.Load(); got != 1 {
		t.Errorf("busy maintenance trigger accumulated during shutdown: %d callbacks", got)
	}
}

func TestMaintenanceFailureIsLoggedWithoutBlockingFeedPlanning(t *testing.T) {
	f := newFixture(t, model(true, hourly(feedA)), "")
	cfg := f.config()
	called, logged := make(chan struct{}, 1), make(chan struct{}, 1)
	callback := func(context.Context) error {
		called <- struct{}{}
		return errors.New("maintenance fixture failure")
	}
	field := reflect.ValueOf(&cfg).Elem().FieldByName("Maintenance")
	if !field.IsValid() || field.Type() != reflect.TypeOf(callback) || !field.CanSet() {
		t.Fatalf("scheduler.Config.Maintenance must be optional %v; field present=%v", reflect.TypeOf(callback), field.IsValid())
	}
	field.Set(reflect.ValueOf(callback))
	cfg.Logf = func(format string, args ...any) {
		f.logf(format, args...)
		if strings.Contains(format, "maintenance failed:") {
			logged <- struct{}{}
		}
	}
	f.s = New(cfg)
	f.s.Bind(f.start)
	h := startRun(t, f)
	recv(t, h.asked, "initial boundary")
	select {
	case h.fire <- time.Time{}:
	case <-time.After(stuck):
		t.Fatal("STUCK: scheduler did not consume quarter timer")
	}
	recv(t, called, "failing maintenance callback")
	recv(t, logged, "maintenance error log")
	recv(t, h.asked, "feed scheduler after maintenance failure")
	wantRequest(t, f.last(), "scheduled", []string{feedA}, nil)
	h.stop(t)
}

func TestMaintenanceAndFeedGateAdmissionOrdersPreservePending(t *testing.T) {
	for _, trigger := range []string{"apply", "retry"} {
		for _, first := range []string{"maintenance", "feed"} {
			t.Run(trigger+"/"+first, func(t *testing.T) {
				seed := stateText(map[string]string{feedA: fmt.Sprintf(`{"pending_occurrence":%d}`, occ10)})
				f := newFixture(t, model(true, hourly(feedA)), seed)
				started := make(chan update.Request, 1)
				callbackResult := make(chan error, 1)
				modelEntered, modelRelease := make(chan struct{}), make(chan struct{})
				cfg := f.config()
				model := cfg.Model
				if first == "maintenance" {
					var firstModel atomic.Bool
					cfg.Model = func() (schedule.Model, error) {
						if firstModel.CompareAndSwap(false, true) {
							close(modelEntered)
							<-modelRelease
						}
						return model()
					}
				}
				callback := func(ctx context.Context) error {
					if first == "maintenance" {
						<-modelEntered
					} else {
						recv(t, started, "feed Update to enter the real gate")
					}
					err := f.s.Start(trigger, "", "")
					callbackResult <- err
					if first == "maintenance" {
						close(modelRelease)
					}
					<-ctx.Done()
					return ctx.Err()
				}
				field := reflect.ValueOf(&cfg).Elem().FieldByName("Maintenance")
				if !field.IsValid() || field.Type() != reflect.TypeOf(callback) || !field.CanSet() {
					t.Fatalf("scheduler.Config.Maintenance must be optional %v; field present=%v", reflect.TypeOf(callback), field.IsValid())
				}
				field.Set(reflect.ValueOf(callback))
				f.s = New(cfg)
				g := update.New(filepath.Join(t.TempDir(), "update.log"),
					func(ctx context.Context, req update.Request, _ *os.File) (update.Result, error) {
						started <- req
						<-ctx.Done()
						return update.Result{}, update.ErrDeferred
					}, f.s.Done)
				f.s.Bind(g.Start)
				t.Cleanup(g.Stop)

				h := startRun(t, f)
				recv(t, h.asked, "quarter boundary")
				select {
				case h.fire <- time.Time{}:
				case <-time.After(stuck):
					t.Fatal("STUCK: scheduler did not consume quarter timer")
				}
				err := recv(t, callbackResult, "maintenance StartUpdate result")
				if first == "maintenance" && err != nil {
					t.Errorf("maintenance %s first = %v, want admission", trigger, err)
				}
				if first == "feed" && !errors.Is(err, update.ErrRunning) {
					t.Errorf("maintenance %s after feed = %v, want ErrRunning", trigger, err)
				}
				recv(t, h.asked, "feed evaluation to finish under competing gate admission")
				view, err := g.View(0, 0)
				if err != nil {
					t.Fatal(err)
				}
				if !view.Running || view.Update == nil ||
					(first == "maintenance" && view.Update.Trigger != trigger) ||
					(first == "feed" && view.Update.Trigger != "scheduled") {
					t.Errorf("winning Update = %+v, first=%s trigger=%s", view, first, trigger)
				}
				h.stop(t)
				g.Stop()
				if got := f.items()[feedA].PendingOccurrence; got == nil || *got != occ10 {
					t.Errorf("refused competing Update settled the pending occurrence: %v", got)
				}
			})
		}
	}
}
