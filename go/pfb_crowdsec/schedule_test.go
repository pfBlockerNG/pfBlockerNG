package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// stopRun ends the run loop and waits for it to return.
func stopRun(t *testing.T, cancel context.CancelFunc, result <-chan error) {
	t.Helper()
	cancel()
	select {
	case <-result:
	case <-time.After(time.Minute): // salvage watchdog only: ctx ends any request in flight
		t.Fatal("STUCK/ENVIRONMENT: the run loop did not stop within a minute")
	}
}

// Scenario: ticks come while a LAPI request hangs (#4117 review round 1, finding 1: with every pull as slow as
// update_frequency, a pull tick was always due and a pull-first order never posted usage). Given a running daemon
// whose start-up pull hangs, when a pull tick, a usage tick and another pull tick come, then no second request starts
// while it hangs; once it ends, the due usage post runs before the due pull, one at a time.
func TestADueUsagePostRunsBeforeADuePull(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+"?startup="+r.URL.Query().Get("startup"))
		first := len(seen) == 1
		mu.Unlock()
		if first {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done(): // the client gave up: a failing test must not hang the server's Close
			}
		}
		if r.URL.Path == "/v1/usage-metrics" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusBadGateway) // no pull succeeds, so none is followed by a usage post of its own
	}))
	t.Cleanup(srv.Close)
	requests := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
	h := newHarness(t)
	cfg := *h.cfg
	cfg.APIURL = srv.URL + "/"
	api, err := newLAPIClient(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.d.api = api
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	ticks, usage, status := make(chan time.Time), make(chan time.Time), make(chan time.Time)
	events := make(chan string, 16)
	result := make(chan error, 1)
	go func() { h.d.run(ctx, ticks, usage, status, nil, func(e string) { events <- e }); result <- nil }()
	select {
	case <-arrived:
	case <-time.After(time.Minute): // salvage watchdog only
		t.Fatal("STUCK/ENVIRONMENT: the start-up pull did not arrive within a minute")
	}

	send(t, ticks, "pull", result)
	send(t, usage, "usage", result)
	send(t, ticks, "second pull", result)
	send(t, status, "status", result)
	if e := nextEvent(t, events, result); e != "status" { // the loop has handled every tick before it
		t.Fatalf("event = %q; want status", e)
	}
	if got := requests(); len(got) != 1 {
		t.Fatalf("requests while the start-up pull hung = %q; want only that pull", got)
	}

	close(release)
	var got []string
	for range 3 {
		got = append(got, nextEvent(t, events, result))
	}
	if want := []string{"pull", "usage", "pull"}; !slices.Equal(got, want) {
		t.Fatalf("events after the hung pull ended = %q; want %q: the due usage post first", got, want)
	}
	want := []string{"/v1/decisions/stream?startup=true", "/v1/usage-metrics?startup=", "/v1/decisions/stream?startup=true"}
	if got := requests(); !slices.Equal(got, want) {
		t.Fatalf("requests = %q; want %q", got, want)
	}
	stopRun(t, cancel, result)
	if h.d.requests != 3 || h.d.errors != 2 {
		t.Fatalf("lapi requests, errors = %d, %d; want 3, 2", h.d.requests, h.d.errors)
	}
}

// Scenario: the first usage post follows the first successful pull (owner decision on #4074, 2026-11-20). Given a
// daemon whose start-up pull fails, when the next pull succeeds, then a usage post follows it with no usage tick, its
// window the nominal 15 minutes as upstream's start-up posts report it; a later successful pull is followed by no post
// of its own.
func TestTheFirstSuccessfulPullIsFollowedByAUsagePost(t *testing.T) {
	h := newHarness(t, lapiReply{http.StatusBadGateway, `{}`}, ok(startupBody), ok(emptyDelta))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time)
	events := make(chan string, 16)
	result := make(chan error, 1)
	go func() { h.d.run(ctx, ticks, nil, nil, nil, func(e string) { events <- e }); result <- nil }()
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("first event = %q; want the failed start-up pull", e)
	}

	send(t, ticks, "pull", result)
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("event after the tick = %q; want the pull", e)
	}
	send(t, ticks, "pull", result)
	if e := nextEvent(t, events, result); e != "usage" {
		t.Fatalf("event after the first successful pull = %q; want usage, posted with no usage tick", e)
	}
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("event after the usage post = %q; want the pull ticked meanwhile", e)
	}
	send(t, ticks, "pull", result)
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("event after a later tick = %q; want only a pull", e)
	}
	stopRun(t, cancel, result)

	reqs, bodies := h.lapi.requests()
	var paths []string
	for _, r := range reqs {
		paths = append(paths, r.URL.Path)
	}
	want := []string{"/v1/decisions/stream", "/v1/decisions/stream", "/v1/usage-metrics", "/v1/decisions/stream",
		"/v1/decisions/stream"}
	if !slices.Equal(paths, want) {
		t.Fatalf("requests = %q; want %q", paths, want)
	}
	var top allMetrics
	if err := json.Unmarshal([]byte(bodies[2]), &top); err != nil {
		t.Fatal(err)
	}
	if meta := top.RemediationComponents[0].Metrics[0].Meta; meta.WindowSizeSeconds != 900 {
		t.Fatalf("first post's window = %d s; want 900, the usage interval", meta.WindowSizeSeconds)
	}
}
