package main

import (
	"context"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
)

// clockNow and clockAfter are the clock runClock is given by run; only a test replaces them.
var (
	clockNow   = time.Now
	clockAfter = time.After
)

// lane is a program Core starts and observes but never controls: it runs in a session of its own with its output discarded,
// is never signalled, and outlives Core. Whatever bounds a run belongs to the program.
type lane struct {
	name, path   string
	logf         func(string, ...any)
	busy, failed atomic.Bool
}

// start runs the program with args unless the lane is off (empty path) or the previous run is still alive, which skips the
// start. A failure to start or a non-zero exit is logged once per outage, which a successful run ends.
func (l *lane) start(args ...string) {
	if l.path == "" || !l.busy.CompareAndSwap(false, true) {
		return
	}
	cmd := exec.Command(l.path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		l.busy.Store(false)
		l.report(err)
		return
	}
	go func() {
		err := cmd.Wait()
		l.report(err)
		l.busy.Store(false)
	}()
}

func (l *lane) report(err error) {
	switch {
	case err == nil:
		l.failed.Store(false)
	case l.failed.CompareAndSwap(false, true):
		l.logf("the %s command %s failed, said once until it succeeds: %v", l.name, l.path, err)
	}
}

// cadencesDue names the cadences boundary starts: none unless its local date in loc is strictly after prev's (so a clock stepped
// back never fires), otherwise daily, and weekly too when boundary's own day is a Sunday.
func cadencesDue(prev, boundary time.Time, loc *time.Location) []string {
	local, before := boundary.In(loc), prev.In(loc)
	py, pm, pd := before.Date()
	by, bm, bd := local.Date()
	if !time.Date(by, bm, bd, 0, 0, 0, 0, time.UTC).After(time.Date(py, pm, pd, 0, 0, 0, 0, time.UTC)) {
		return nil
	}
	if local.Weekday() == time.Sunday {
		return []string{"daily", "weekly"}
	}
	return []string{"daily"}
}

// runClock, until ctx ends, starts metrics at each Unix minute boundary when ls (from memory, never reloaded per minute) says the
// package is enabled and exports metrics, and counters at each boundary whose local date in zone() (nil func or result: the local
// zone) is later than the previous boundary's, kept in memory only, with the counter verbs due, after reading ls again. With
// no usable ls values nothing starts. It never touches a running child.
func runClock(ctx context.Context, now func() time.Time, after func(time.Duration) <-chan time.Time, zone func() *time.Location, metrics, counters *lane, ls *laneSettings) {
	var prev time.Time
	for {
		n := now()
		b := time.Unix((n.Unix()/60+1)*60, 0)
		select {
		case <-ctx.Done():
			return
		case <-after(b.Sub(n)):
		}
		loc := time.Local
		if zone != nil {
			if z := zone(); z != nil {
				loc = z
			}
		}
		if prev.IsZero() {
			prev = b.Add(-time.Minute)
		}
		due := cadencesDue(prev, b, loc)
		var cur maintenanceSettings
		var ok bool
		if len(due) > 0 {
			cur, ok = ls.reload(ctx)
		} else {
			cur, ok = ls.read()
		}
		if ok && cur.Enabled && cur.MetricsExport {
			metrics.start()
		}
		if verbs := counterVerbs(cur, due); ok && len(verbs) > 0 {
			counters.start(verbs...)
		}
		prev = b
	}
}
