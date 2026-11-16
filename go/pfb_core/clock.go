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

// cadencesDue names the cadences the boundary starts: none when prev, a minute before, is on the same calendar date in loc,
// otherwise daily, and weekly too when the new date is a Sunday.
func cadencesDue(prev, boundary time.Time, loc *time.Location) []string {
	py, pm, pd := prev.In(loc).Date()
	by, bm, bd := boundary.In(loc).Date()
	switch {
	case py == by && pm == bm && pd == bd:
		return nil
	case boundary.In(loc).Weekday() == time.Sunday:
		return []string{"daily", "weekly"}
	}
	return []string{"daily"}
}

// runClock starts metrics at every Unix minute boundary and counters at the first boundary of each local day in zone() (nil
// func or result: the local zone), until ctx ends. It never touches a running child.
func runClock(ctx context.Context, now func() time.Time, after func(time.Duration) <-chan time.Time, zone func() *time.Location, metrics, counters *lane) {
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
		metrics.start()
		if due := cadencesDue(b.Add(-time.Minute), b, loc); len(due) > 0 {
			counters.start(due...)
		}
	}
}
