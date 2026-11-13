package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/scheduler"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// newUpdates builds Core's scheduler and its Update gate for --update-cmd: the program at path runs each Update (an empty
// path: no scheduler, and both are nil). The scheduler's state and the Update's log live in stateDir.
func newUpdates(path, stateDir string, st *settings.Store, logf func(string, ...any)) (*scheduler.Scheduler, *update.Gate) {
	if path == "" {
		return nil, nil
	}
	sched := scheduler.New(scheduler.Config{Model: scheduleModel(st), StatePath: filepath.Join(stateDir, "schedule_state.json"),
		Loc: time.Local, Logf: logf})
	gate := update.New(filepath.Join(stateDir, "update.log"), (&update.Command{Path: path}).Run, sched.Done)
	sched.Bind(gate.Start)
	return sched, gate
}

// runUpdates starts the quarter-hour loop and returns the function that ends it: it stops the loop, then the Update
// running, whose program's process group is killed (an Update stopped this way is not resumed). It may be called again.
func runUpdates(ctx context.Context, sched *scheduler.Scheduler, gate *update.Gate) (stop func()) {
	if sched == nil {
		return func() {}
	}
	loop, endLoop := context.WithCancel(ctx)
	ended := make(chan struct{})
	go func() { sched.Run(loop, nil); close(ended) }()
	return func() { endLoop(); <-ended; gate.Stop() }
}

// scheduleModel is the schedule model over the settings as they are now: SettingsChanged and saves refresh the store the
// scheduler reads, so nothing is told to it.
func scheduleModel(st *settings.Store) func() (schedule.Model, error) {
	return func() (schedule.Model, error) {
		snap, err := st.Get([]string{"schedule", "feeds/ipv4", "feeds/ipv6", "feeds/dnsbl"})
		if err != nil {
			return schedule.Model{}, err
		}
		if !snap.Initialized {
			return schedule.Model{}, errors.New("the settings are not initialized")
		}
		var sched map[string]any
		feeds := map[string]map[string]any{}
		for _, p := range snap.Projections {
			if id := strings.TrimPrefix(p.ResourceID, "settings/"); id == "schedule" {
				sched = p.Value
			} else {
				feeds[id] = p.Value
			}
		}
		return schedule.ModelFromSettings(sched, feeds)
	}
}

// updateMethods are the three Update and schedule methods over sched and gate (docs/misc/core-api-protocol.md, "Update and
// schedule"). Without a scheduler (no --update-cmd) each answers unavailable.
func updateMethods(sched *scheduler.Scheduler, gate *update.Gate) map[string]method {
	methods := map[string]method{
		"StartUpdate": {mutating: true, call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				RequestID string  `json:"requestId"`
				Trigger   string  `json:"trigger"`
				Scope     *string `json:"scope"`
				Force     *string `json:"force"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			scope, force, bad := "both", "none", []fieldError(nil)
			switch p.Trigger {
			case "manual":
				var scopeErr, forceErr []fieldError
				scope, scopeErr = pick("scope", p.Scope, scope, "ip", "dnsbl", "both")
				force, forceErr = pick("force", p.Force, force, "none", "parse", "download", "both")
				bad = append(scopeErr, forceErr...)
			case "apply", "retry":
				if p.Scope != nil {
					bad = append(bad, fieldError{Field: "scope", Message: "only a manual Update takes a scope"})
				}
				if p.Force != nil {
					bad = append(bad, fieldError{Field: "force", Message: "only a manual Update takes a force"})
				}
			case "":
				bad = []fieldError{{Field: "trigger", Message: "required"}}
			default:
				bad = []fieldError{{Field: "trigger", Message: "must be one of manual, apply, retry"}}
			}
			if bad != nil {
				return nil, newError(codeInvalidArgument, "the Update request is not valid; nothing was started", bad...)
			}
			err := sched.Start(p.Trigger, scope, force)
			switch {
			case errors.Is(err, update.ErrRunning):
				return nil, newError(codeConflict, err.Error())
			case errors.Is(err, update.ErrStopped):
				return nil, newError(codeUnavailable, err.Error())
			}
			return struct{}{}, err
		}},
		"GetUpdate": {call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				After int64 `json:"after"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			if p.After < 0 {
				return nil, newError(codeInvalidArgument, "after is a log offset", fieldError{Field: "after", Message: "must not be negative"})
			}
			return gate.View(p.After, 0), nil
		}},
		"GetSchedule": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			view, err := sched.View()
			if err != nil {
				return nil, newError(codeUnavailable, "the schedule cannot be computed: "+err.Error())
			}
			return view, nil
		}},
	}
	if sched == nil {
		for name, m := range methods {
			m.call = func(context.Context, []byte) (any, error) {
				return nil, newError(codeUnavailable, "Core runs no scheduler: start it with --update-cmd")
			}
			methods[name] = m
		}
	}
	return methods
}

// pick is an optional parameter's value: def when it is absent, else one of allowed.
func pick(field string, v *string, def string, allowed ...string) (string, []fieldError) {
	switch {
	case v == nil:
		return def, nil
	case slices.Contains(allowed, *v):
		return *v, nil
	}
	return def, []fieldError{{Field: field, Message: "must be one of " + strings.Join(allowed, ", ")}}
}
