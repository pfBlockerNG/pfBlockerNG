package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateViewWaitsForLocalCompletionTeardown(t *testing.T) {
	for _, tc := range []struct {
		name       string
		exit       int
		wantResult string
	}{
		{name: "success", exit: 0, wantResult: "success"},
		{name: "deferred", exit: deferredStatus, wantResult: "skipped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command, dir := program(t, "echo run >> \"$D/runs\"\necho run-output\nexit "+strconv.Itoa(tc.exit))
			log := newLog(t)
			entered, release := make(chan struct{}), make(chan struct{})
			doneErrs, secondDone := make(chan error, 2), make(chan struct{})
			var doneCalls atomic.Int32
			var releaseOnce sync.Once
			gate := New(log.Name(), nil, func(_ Request, _ Result, _ error) {
				err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error { return nil })
				doneErrs <- err
				if doneCalls.Add(1) == 1 {
					close(entered)
					<-release
				} else {
					close(secondDone)
				}
			})
			gate.Admit = command.Admit
			gate.Launch = func(ctx context.Context, lease *Admission, req Request, log *os.File) (Result, error) {
				return lease.Launch(ctx, command, req, log)
			}
			t.Cleanup(gate.Stop)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			if err := gate.Start(Request{Trigger: "manual"}, nil); err != nil {
				t.Fatal(err)
			}
			recv(t, entered, "the worker completion callback never reached its held teardown")
			if err := recv(t, doneErrs, "the terminal receipt was not reconciled"); err != nil {
				t.Fatal(err)
			}
			lock, err := operationLock(log.Name())
			if err != nil {
				t.Fatalf("completed worker lifetime flock = %v; want free", err)
			}
			lock.Close()

			view := mustView(t, gate, 0, 0)
			if !view.Running || view.Update == nil || view.Update.FinishedAt != nil || view.Update.Result != "" {
				t.Errorf("View during local teardown = %+v; want a consistent running status", view)
			}
			concurrent := make(chan View, 1)
			go func() {
				v, _ := gate.View(0, 0)
				concurrent <- v
			}()
			if v := recv(t, concurrent, "concurrent View blocked during completion teardown"); !v.Running || v.Update == nil || v.Update.FinishedAt != nil {
				t.Errorf("concurrent View during local teardown = %+v; want a consistent running status", v)
			}
			before := logText(t, log)
			if err := gate.Start(Request{Trigger: "apply"}, nil); !errors.Is(err, ErrRunning) {
				t.Errorf("second Start during completion teardown = %v; want ErrRunning", err)
			}
			if after := logText(t, log); after != before {
				t.Errorf("rejected Start changed the log: before %q, after %q", before, after)
			}
			if runs, err := os.ReadFile(filepath.Join(dir, "runs")); err != nil || string(runs) != "run\n" {
				t.Errorf("program runs before local release = %q, %v; want one", runs, err)
			}

			releaseOnce.Do(func() { close(release) })
			awaitGateAdmission(t, gate)
			ended := mustView(t, gate, 0, 0)
			if ended.Running || ended.Update == nil || ended.Update.Result != tc.wantResult || ended.Update.FinishedAt == nil {
				t.Fatalf("View after local release = %+v; want terminal %s", ended, tc.wantResult)
			}
			restarted := New(log.Name(), nil, nil)
			restarted.Admit = command.Admit
			if recovered := mustView(t, restarted, 0, 0); recovered.Running || recovered.Update == nil || recovered.Update.Result != tc.wantResult {
				t.Errorf("new Gate view = %+v; want the retained terminal receipt", recovered)
			}
			if err := gate.Start(Request{Trigger: "manual"}, nil); err != nil {
				t.Fatalf("Start immediately after the completed view = %v; want admission", err)
			}
			if err := recv(t, doneErrs, "the next admission did not finish"); err != nil {
				t.Errorf("second admission completion = %v", err)
			}
			recv(t, secondDone, "the next completion callback did not run")
			awaitGateAdmission(t, gate)
			if runs, err := os.ReadFile(filepath.Join(dir, "runs")); err != nil || string(runs) != "run\nrun\n" {
				t.Errorf("program runs after the next admission = %q, %v; want two", runs, err)
			}
		})
	}
}

func awaitGateAdmission(t *testing.T, gate *Gate) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(time.Millisecond) {
		if gate.admit.TryLock() {
			gate.admit.Unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("STUCK: the gate did not release its local admission")
		}
	}
}
