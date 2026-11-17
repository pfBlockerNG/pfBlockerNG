package main

import (
	"context"
	"sync/atomic"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// maintenanceSettings is settings/maintenance as the timed lanes decide from it.
type maintenanceSettings struct {
	Enabled, ScheduledWorkDisabled, MetricsExport bool
	ClearIP, ClearDNSBL                           string // never, daily or weekly
}

// laneSettings reads settings/maintenance from the store: read answers from memory, reload reads the backend again first (a
// reload runs the Outpost's adapter, so never once per minute). A fault is logged once per outage and the last values stay.
type laneSettings struct {
	st                *settings.Store
	logf              func(string, ...any)
	unusable, stalled atomic.Bool
}

func newLaneSettings(st *settings.Store, logf func(string, ...any)) *laneSettings {
	return &laneSettings{st: st, logf: logf}
}

// read is the values in memory; false (logged once per outage) when there is none to read, so that no lane starts.
func (l *laneSettings) read() (maintenanceSettings, bool) {
	if l == nil || l.st == nil {
		return maintenanceSettings{}, false
	}
	v, err := l.st.GetClear("maintenance")
	if err != nil {
		if l.unusable.CompareAndSwap(false, true) {
			l.logf("the maintenance settings cannot be read, the timed lanes start nothing: %v", err)
		}
		return maintenanceSettings{}, false
	}
	l.unusable.Store(false)
	flag := func(name string) bool { b, _ := v[name].(bool); return b }
	cadence := func(name string) string { s, _ := v[name].(string); return s }
	return maintenanceSettings{Enabled: flag("enabled"), ScheduledWorkDisabled: flag("scheduledWorkDisabled"), MetricsExport: flag("metricsExport"),
		ClearIP: cadence("clearIpCounters"), ClearDNSBL: cadence("clearDnsblCounters")}, true
}

// reload reads the backend again, keeping the values read last when that fails (logged once per outage), then read.
func (l *laneSettings) reload(ctx context.Context) (maintenanceSettings, bool) {
	if l == nil || l.st == nil {
		return maintenanceSettings{}, false
	}
	switch _, err := l.st.Reload(ctx); {
	case err == nil:
		l.stalled.Store(false)
	case ctx.Err() == nil && l.stalled.CompareAndSwap(false, true):
		l.logf("the maintenance settings could not be read again, the values read last are used: %v", err)
	}
	return l.read()
}

// gateMaintenance runs run only for an enabled package without the platform's off switch, reading the settings again before
// each decision. It logs one line when the lane flips between running and skipping, none while it stays as it is.
func gateMaintenance(run func(context.Context) error, ls *laneSettings, logf func(string, ...any)) func(context.Context) error {
	if run == nil {
		return nil
	}
	var skipping atomic.Bool
	return func(ctx context.Context) error {
		cur, ok := ls.reload(ctx)
		due := ok && cur.Enabled && !cur.ScheduledWorkDisabled
		if skipping.Swap(!due) != !due {
			if due {
				logf("maintenance runs again: the package is enabled and scheduled work is not switched off")
			} else {
				logf("maintenance skips its runs: the package is disabled, scheduled work is switched off or the settings are unusable")
			}
		}
		if !due {
			return nil
		}
		return run(ctx)
	}
}

// counterVerbs are the counter programs due at a day change whose due cadences are due: clearip, then cleardnsbl.
func counterVerbs(s maintenanceSettings, due []string) []string {
	var verbs []string
	for _, c := range []struct{ verb, cadence string }{{"clearip", s.ClearIP}, {"cleardnsbl", s.ClearDNSBL}} {
		for _, d := range due {
			if c.cadence == d {
				verbs = append(verbs, c.verb)
				break
			}
		}
	}
	return verbs
}
