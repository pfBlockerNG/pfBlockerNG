package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/scheduler"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// newUpdates builds Core's scheduler and its Update gate for --update-cmd: the program at path runs each Update, after the
// settings are read again (refreshingRun); an empty path: no scheduler, and both are nil. The scheduler's state and the Update's
// log live in stateDir. The schedule is read in the zone of the file zoneinfo names (--zoneinfo; empty: the process's local zone).
func newUpdates(path, zoneinfo, stateDir string, st *settings.Store, logf func(string, ...any)) (*scheduler.Scheduler, *update.Gate) {
	if path == "" {
		return nil, nil
	}
	sched := scheduler.New(scheduler.Config{Model: scheduleModel(st), StatePath: filepath.Join(stateDir, "schedule_state.json"),
		Loc: time.Local, Zone: hostZone(zoneinfo, logf), Logf: logf})
	gate := update.New(filepath.Join(stateDir, "update.log"), refreshingRun(st, (&update.Command{Path: path}).Run, logf), sched.Done)
	sched.Bind(gate.Start)
	return sched, gate
}

// refreshingRun is run with the settings read again from their backend before each Update, as SettingsChanged reads them
// (issue #3975): the interface addresses and the proxy change outside Core, and the Outpost's tick that tells Core is up to 15
// minutes away. A failed read keeps the values in memory, is logged once per outage, and the Update runs on them.
func refreshingRun(st *settings.Store, run update.RunFunc, logf func(string, ...any)) update.RunFunc {
	var broken atomic.Bool
	return func(ctx context.Context, req update.Request, log *os.File) (update.Result, error) {
		switch _, err := st.Reload(ctx); {
		case err == nil:
			broken.Store(false)
		case ctx.Err() == nil && broken.CompareAndSwap(false, true):
			logf("the settings could not be read again before the Update, the values read last are used: %v", err)
		}
		return run(ctx, req, log)
	}
}

// hostZone is the scheduler's zone for --zoneinfo path (nil without one): the time zone file at path, read at every call, so
// that a change of the host's time zone is in effect at the next evaluation without a restart. A file that is missing or is not
// a time zone is the process's local zone, said once per outage in the log and again when it breaks anew.
func hostZone(path string, logf func(string, ...any)) func() *time.Location {
	if path == "" {
		return nil
	}
	var broken atomic.Bool
	return func() *time.Location {
		data, err := os.ReadFile(path)
		var loc *time.Location
		if err == nil {
			loc, err = time.LoadLocationFromTZData("host", data)
		}
		if err != nil {
			if broken.CompareAndSwap(false, true) {
				logf("the time zone file %s cannot be used, the local zone is used: %v", path, err)
			}
			return time.Local
		}
		broken.Store(false)
		return loc
	}
}

// quarterTimer is the timer the quarter-hour loop waits on: nil is time.After, the real clock. Only a test sets it, to keep a
// scheduled Update from starting under it (update_api_test.go).
var quarterTimer func(time.Duration) <-chan time.Time

// runUpdates starts the quarter-hour loop and returns the function that ends it: it stops the loop, then the Update
// running, whose program's process group is killed (an Update stopped this way is not resumed). It may be called again.
func runUpdates(ctx context.Context, sched *scheduler.Scheduler, gate *update.Gate) (stop func()) {
	if sched == nil {
		return func() {}
	}
	loop, endLoop := context.WithCancel(ctx)
	ended := make(chan struct{})
	go func() { sched.Run(loop, quarterTimer); close(ended) }()
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
			case errors.Is(err, update.ErrStopped), errors.Is(err, scheduler.ErrModel):
				return nil, newError(codeUnavailable, err.Error())
			}
			return struct{}{}, err
		}},
		"GetUpdate": {call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				After *string `json:"after"` // the cursor of an earlier reply, a decimal string
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			var after int64
			if p.After != nil {
				var ok bool
				if after, ok = cursor(*p.After); !ok {
					return nil, newError(codeInvalidArgument, "after is the next of an earlier GetUpdate, a string of decimal digits",
						fieldError{Field: "after", Message: "must be a string of decimal digits that fits 63 bits"})
				}
			}
			return gate.View(after, 0), nil
		}},
		"GetSchedule": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			view, err := sched.View()
			if errors.Is(err, scheduler.ErrModel) {
				return nil, newError(codeUnavailable, err.Error())
			}
			return view, err
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

// cursor reads a GetUpdate cursor: decimal digits only (no sign, space or point) within 63 bits.
func cursor(s string) (int64, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
