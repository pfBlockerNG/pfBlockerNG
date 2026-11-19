package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// blackhole is a LAPI whose blocked path takes every request and never answers: the request ends only when the
// client gives up. The other paths answer at once. arrived receives each blocked request's path as it comes in.
type blackhole struct {
	srv     *httptest.Server
	arrived chan string
}

func newBlackhole(t *testing.T, blocked string) *blackhole {
	t.Helper()
	b := &blackhole{arrived: make(chan string, 16)}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == blocked {
			b.arrived <- r.URL.Path
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/decisions/stream":
			_, _ = io.WriteString(w, startupBody)
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// await returns once the blackhole has taken a request, failing at once if run returns first.
func (b *blackhole) await(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case <-b.arrived:
	case err := <-result:
		t.Fatalf("run returned %v before the LAPI request arrived", err)
	case <-time.After(time.Minute): // salvage watchdog only
		t.Fatal("STUCK/ENVIRONMENT: no LAPI request arrived within a minute")
	}
}

// send hands v to the run loop, failing at once if run returns first.
func send(t *testing.T, ch chan<- time.Time, what string, result <-chan error) {
	t.Helper()
	select {
	case ch <- testEpoch:
	case err := <-result:
		t.Fatalf("run returned %v before taking the %s tick", err, what)
	case <-time.After(time.Minute): // salvage watchdog only: a loop that blocks for a whole request takes it later
		t.Fatalf("STUCK/ENVIRONMENT: the run loop did not take the %s tick within a minute", what)
	}
}

// Scenario: the LAPI takes a request and never answers (a blackholed address). Given a running daemon whose pull or
// usage post is waiting on it, when the status ticker fires, then the status file is written at once, before the
// request ends, stamped with the current time, and its other fields are those from before the request: the request
// shows in no field until it has ended.
func TestTheStatusFileIsWrittenWhileALAPIRequestHangs(t *testing.T) {
	for _, tc := range []struct {
		name, blocked string
		before        map[string]any // status fields while the request hangs
	}{
		{
			name:    "pull",
			blocked: "/v1/decisions/stream",
			before: map[string]any{"last_pull": float64(0), "last_error_time": float64(0), "last_error": "",
				"lapi_requests": float64(0), "lapi_errors": float64(0)},
		},
		{
			name:    "usage post",
			blocked: "/v1/usage-metrics",
			before: map[string]any{"last_pull": float64(testEpoch.Unix()), "last_error_time": float64(0),
				"last_error": "", "lapi_requests": float64(1), "lapi_errors": float64(0)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			lapi := newBlackhole(t, tc.blocked)
			cfg := *h.cfg
			cfg.APIURL = lapi.srv.URL + "/"
			api, err := newLAPIClient(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			h.d.api = api
			var clock atomic.Int64
			clock.Store(testEpoch.Unix())
			h.d.now = func() time.Time { return time.Unix(clock.Load(), 0) }

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := h.d.setup(ctx); err != nil {
				t.Fatal(err)
			}
			usage, tick := make(chan time.Time), make(chan time.Time)
			events := make(chan string, 16)
			result := make(chan error, 1)
			go func() { h.d.run(ctx, nil, usage, tick, nil, func(e string) { events <- e }); result <- nil }()
			if tc.blocked == "/v1/usage-metrics" {
				if e := nextEvent(t, events, result); e != "pull" {
					t.Fatalf("first event = %q; want the start-up pull", e)
				}
				send(t, usage, "usage", result)
			}
			lapi.await(t, result)

			clock.Store(testEpoch.Unix() + 7)
			send(t, tick, "status", result)
			if e := nextEvent(t, events, result); e != "status" {
				t.Fatalf("event after the status tick = %q; want status, written while the %s hangs", e, tc.name)
			}
			st := readStatus(t, h)
			if st["updated_at"] != float64(testEpoch.Unix()+7) {
				t.Fatalf("updated_at = %v; want %d, the time of the status tick", st["updated_at"], testEpoch.Unix()+7)
			}
			for field, want := range tc.before {
				if st[field] != want {
					t.Errorf("%s while the %s hangs = %#v; want %#v", field, tc.name, st[field], want)
				}
			}
			info, err := os.Stat(h.cfg.StatusFile)
			if err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("status file = %v, %v; want mode 0644", info, err)
			}

			cancel()
			select {
			case <-result:
			case <-time.After(time.Minute): // salvage watchdog only: ctx ends the hanging request
				t.Fatal("STUCK/ENVIRONMENT: the run loop did not stop within a minute")
			}
			assertTable(t, h.pf, "crowdsec_v4")
			assertTable(t, h.pf, "crowdsec_v6")
		})
	}
}
