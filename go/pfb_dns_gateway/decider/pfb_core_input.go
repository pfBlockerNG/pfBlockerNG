// pfB-DNS on the Core input (issue #4036, sub-slice 7e): the DNSBL data comes from the Core API instead of the files PHP
// writes. coreinput.Sync writes Core's dnsbl/* resources into the module directory in today's file shapes, so init and
// the reload build from them unchanged; this file decides when.
//
// Boot never waits for Core (#3848): init builds from the cache the last Sync left, when coreinput.Load trusts it, and
// otherwise serves no DNSBL and reports it degraded. A poller takes the reload sentinel's place: on each tick it syncs,
// swaps a new generation in through the RAM-gated reload, and reports what the live snapshot serves to Core's
// ReportApplied, once after the start and after each swap.
package decider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
)

// coreSyncCap ends a Sync or a report that Core leaves hanging, so that the poller goes on; it orders nothing.
const coreSyncCap = 10 * time.Minute

// coreFeed is the poller's state. Only init, before the poller starts, and the poller touch it.
type coreFeed struct {
	m      *pfbUnbound
	client *coreinput.Client
	dir    string                            // the module directory
	tick   func() (<-chan time.Time, func()) // nil: a RELOAD_POLL_INTERVAL ticker
	disk   coreinput.State                   // what the module directory holds: the last Sync's state
	served map[string]coreinput.Cursor       // what the live snapshot was built from; nil: nothing
	// reported is whether Core has been told what is served; lastErr is the last Sync error logged, so that a Core that
	// stays down is logged once.
	reported bool
	lastErr  string
}

// bootCore boots the module in moduleDir on the Core API at socket. tick is the poller's tick source (nil: a ticker).
func bootCore(moduleDir, logDir, socket string, tick func() (<-chan time.Time, func())) (*pfbUnbound, error) {
	feed := &coreFeed{client: coreinput.New(socket), dir: moduleDir, tick: tick, disk: coreinput.Load(moduleDir)}
	if !feed.trusted() {
		if _, err := os.Lstat(filepath.Join(moduleDir, "pfb_py_sources.json")); err == nil {
			logWarn("[pfBlockerNG]: the DNSBL cache in " + moduleDir + " is not trusted and is not loaded; it is fetched from Core again")
		}
	}
	return initStandardWith(MODULE_ID, moduleDir, logDir, feed)
}

// trusted is whether init may build from the module directory: Load trusts what the last Sync left there.
func (f *coreFeed) trusted() bool { return f.disk.Manifest != (coreinput.Cursor{}) }

// run is the poller's body: drain, then wait for the next tick, until stop is closed. A panic ends only the poller, as
// one ends only the reload watcher.
func (f *coreFeed) run(stop <-chan struct{}, tick <-chan time.Time) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(logOutput, "[pfBlockerNG]: Core input poller error: %v\n", err)
		}
	}()
	pollLoop(stop, tick, f.drain)
}

// drain syncs with Core, swaps a new generation in, and reports what is served until Core has taken a report. A Sync that
// fails changes nothing served: the live snapshot stays, and so does the module directory's last good state.
func (f *coreFeed) drain(stop <-chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), coreSyncCap)
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	state, changed, err := coreinput.Sync(ctx, f.client, f.dir, f.disk)
	f.logSync(err)
	if err == nil && changed {
		f.disk = state
		build := f.m.reloadBuilder
		if build == nil {
			build = f.m.reloadBuildSnapshot
		}
		if f.m.reloadRunSwap(build) {
			f.served, f.reported = state.Resources, false
		}
	}
	if !f.reported {
		if err := f.client.ReportApplied(ctx, f.served); err != nil {
			logWarn("[pfBlockerNG]: DNSBL: reporting the generation served to Core failed: " + err.Error())
		} else {
			f.reported = true
		}
	}
}

// logSync logs a Sync error once until it changes, and that Core answers again.
func (f *coreFeed) logSync(err error) {
	msg := ""
	switch {
	case errors.Is(err, coreinput.ErrNoData):
		msg = "Core publishes no DNSBL data; serving what is loaded"
	case err != nil:
		msg = "fetching the DNSBL data from Core failed, serving what is loaded: " + err.Error()
	}
	if msg != f.lastErr {
		if msg != "" {
			logWarn("[pfBlockerNG]: " + msg)
		} else {
			logInfo("[pfBlockerNG]: DNSBL data from Core: Core answers again")
		}
		f.lastErr = msg
	}
}
