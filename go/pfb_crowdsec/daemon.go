package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// daemon keeps the two tables equal to the LAPI's active bans (spec D1). All of its state lives in one goroutine.
type daemon struct {
	cfg  *config
	log  *logger
	pf   *pfctl
	api  *lapiClient
	bans *banSet
	now  func() time.Time

	started   time.Time
	synced    bool    // the last pull succeeded; the next one is a delta, else a full pull (startup=true)
	dirty     [2]bool // a pfctl add or delete failed: the next reconcile replaces the table
	lastPull  time.Time
	lastErrAt time.Time
	lastErr   string
	dropped   [2]counter // the inbound rules' counters at the last read
	window    [2]counter // drops counted since the last usage post, across counter resets
}

func newDaemon(cfg *config, log *logger, pf *pfctl, api *lapiClient, now func() time.Time) *daemon {
	return &daemon{cfg: cfg, log: log, pf: pf, api: api, bans: newBanSet(), now: now, started: now()}
}

func (d *daemon) tables() [2]string { return [2]string{d.cfg.TableV4, d.cfg.TableV6} }

// setup creates both tables if missing and empties them.
func (d *daemon) setup(ctx context.Context) error {
	for _, table := range d.tables() {
		if err := d.pf.createTable(ctx, table); err != nil {
			return fmt.Errorf("creating table %s: %w", table, err)
		}
		if err := d.pf.flush(ctx, table); err != nil {
			return fmt.Errorf("flushing table %s: %w", table, err)
		}
	}
	return nil
}

// pull runs one tick: fetch and apply the stream, reconcile, read the counters, write the status file. A failed
// fetch changes nothing in pf; it is returned after the rest of the tick has run, and the next tick pulls the full
// set: the LAPI may have moved this bouncer's cursor past the delta it could not read (#4077).
func (d *daemon) pull(ctx context.Context) error {
	var fresh []netip.Addr
	full := !d.synced
	resp, err := d.api.pull(ctx, full)
	d.synced = err == nil
	switch {
	case err != nil:
		d.lastErr, d.lastErrAt = err.Error(), d.now()
		d.log.errorf("LAPI pull failed: %v", err)
	case full:
		d.lastPull = d.now()
		fresh = d.replace(ctx, resp)
	default:
		d.lastPull = d.now()
		fresh = d.apply(ctx, resp)
	}
	d.reconcile(ctx)
	d.killStates(ctx, fresh)
	d.readCounters(ctx)
	d.writeStatus()
	return err
}

// apply loads the pull's net change into pf and returns its new single addresses, whose states are to be killed once
// the tables are reconciled (so also when an add failed and the reconcile installed them).
func (d *daemon) apply(ctx context.Context, resp *streamResponse) []netip.Addr {
	res := d.bans.apply(resp)
	d.logUnused(res)
	tables := d.tables()
	for f, bans := range res.del {
		if len(bans) > 0 && d.load(ctx, family(f), "delete", bans) {
			d.log.infof("%s: %d values deleted", tables[f], len(bans))
		}
	}
	var fresh []netip.Addr
	for f, bans := range res.add {
		if len(bans) > 0 && d.load(ctx, family(f), "add", bans) {
			d.log.infof("%s: %d values added", tables[f], len(bans))
		}
		for _, b := range bans {
			if b.single {
				fresh = append(fresh, b.addr)
			}
		}
	}
	return fresh
}

// replace makes a full pull the whole in-memory set and replaces both tables with it. It returns the set's single
// addresses that were not banned before, whose states are to be killed.
func (d *daemon) replace(ctx context.Context, resp *streamResponse) []netip.Addr {
	old := d.bans
	d.bans = newBanSet()
	res := d.bans.apply(resp)
	d.logUnused(res)
	var fresh []netip.Addr
	for f, bans := range res.add {
		if d.load(ctx, family(f), "replace", bans) {
			d.log.infof("%s: replaced with the full set of %d values", d.tables()[f], len(bans))
		}
		for _, b := range bans {
			if _, was := old.entries[b.key]; b.single && !was {
				fresh = append(fresh, b.addr)
			}
		}
	}
	return fresh
}

func (d *daemon) logUnused(res applyResult) {
	if n := len(res.invalid); n > 0 {
		d.log.warnf("ignored %d invalid ban values (first: %s)", n, strings.Join(res.invalid[:min(n, 3)], ", "))
	}
	if res.skipped > 0 {
		d.log.debugf("skipped %d decisions that are not ip or range bans", res.skipped)
	}
}

// load feeds bans to `pfctl -T op`; a failure marks the table for replacement by the next reconcile.
func (d *daemon) load(ctx context.Context, f family, op string, bans []ban) bool {
	keys := make([]string, len(bans))
	for i, b := range bans {
		keys[i] = b.key
	}
	if err := d.pf.load(ctx, d.tables()[f], op, keys); err != nil {
		d.log.errorf("pfctl %s on %s: %v", op, d.tables()[f], err)
		d.dirty[f] = true
		return false
	}
	return true
}

// killStates cuts the existing connections of newly banned single addresses, reading the state list once.
func (d *daemon) killStates(ctx context.Context, fresh []netip.Addr) {
	if len(fresh) == 0 {
		return
	}
	states, err := d.pf.stateAddrs(ctx)
	if err != nil {
		d.log.errorf("pfctl reading states: %v", err)
		return
	}
	for _, addr := range fresh {
		if !states[addr] {
			continue
		}
		if err := d.pf.killStates(ctx, addr); err != nil {
			d.log.errorf("pfctl killing states of %s: %v", addr, err)
		} else {
			d.log.debugf("killed the states of %s", addr)
		}
	}
}

// reconcile re-creates a missing table and replaces a table whose count differs from the in-memory set, or whose
// last add or delete failed. A filter reload kills both tables; this is how they come back.
func (d *daemon) reconcile(ctx context.Context) {
	have, err := d.pf.tables(ctx)
	if err != nil {
		d.log.errorf("pfctl reading tables: %v", err)
		return
	}
	for f, table := range d.tables() {
		want := d.bans.keys(family(f))
		addresses, exists := have[table]
		missing := !exists
		if missing {
			if err := d.pf.createTable(ctx, table); err != nil {
				d.log.errorf("pfctl creating table %s: %v", table, err)
				continue
			}
		}
		if !missing && !d.dirty[f] && addresses == len(want) {
			continue
		}
		if err := d.pf.load(ctx, table, "replace", want); err != nil {
			d.log.errorf("pfctl replacing table %s: %v", table, err)
			continue
		}
		d.dirty[f] = false
		d.log.infof("%s: restored %d values (table was %s)", table, len(want), describe(missing, addresses))
	}
}

func describe(missing bool, addresses int) string {
	if missing {
		return "missing"
	}
	return fmt.Sprintf("holding %d", addresses)
}

func (d *daemon) readCounters(ctx context.Context) {
	tables := d.tables()
	sums, err := d.pf.counters(ctx, tables[:])
	if err != nil {
		d.log.warnf("pfctl reading rule counters: %v", err)
		return
	}
	for f, table := range tables {
		cur := sums[table]
		d.window[f].Packets += since(cur.Packets, d.dropped[f].Packets)
		d.window[f].Bytes += since(cur.Bytes, d.dropped[f].Bytes)
		d.dropped[f] = cur
	}
}

// origins counts the family's values per origin as published (status file, usage labels): an origin that repeats the
// API key is shown as "(hidden)".
func (d *daemon) origins(f family) map[string]int {
	out := map[string]int{}
	for origin, n := range d.bans.origins(f) {
		if strings.Contains(origin, d.cfg.APIKey) {
			origin = "(hidden)"
		}
		out[origin] += n
	}
	return out
}

func (d *daemon) writeStatus() {
	st := &status{
		Version:                version,
		StartTime:              d.started.Unix(),
		UpdateFrequencySeconds: int64(d.cfg.interval / time.Second),
		UpdatedAt:              d.now().Unix(),
		LastPull:               unixOrZero(d.lastPull),
		LastErrorTime:          unixOrZero(d.lastErrAt),
		LastError:              d.lastErr,
		LAPIRequests:           d.api.requests,
		LAPIErrors:             d.api.errors,
		Banned:                 map[string]familyBans{},
		Dropped:                map[string]counter{},
	}
	for f := range 2 {
		st.Banned[ipTypes[f]] = familyBans{Total: len(d.bans.keys(family(f))), Origins: d.origins(family(f))}
		st.Dropped[ipTypes[f]] = d.dropped[f]
	}
	if err := writeStatus(d.cfg.StatusFile, st); err != nil {
		d.log.warnf("writing %s: %v", d.cfg.StatusFile, err)
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// sendUsage closes the usage window: reads the counters, then posts the window. A failed post is logged and the
// window dropped.
func (d *daemon) sendUsage(ctx context.Context) {
	d.readCounters(ctx)
	in := usageInput{start: d.started, now: d.now(), window: usageInterval, dropped: d.window}
	for f := range 2 {
		in.origins[f] = d.origins(family(f))
	}
	d.window = [2]counter{}
	body, err := usagePayload(in)
	if err == nil {
		err = d.api.postUsage(ctx, body)
	}
	if err != nil {
		d.log.warnf("usage metrics not sent: %v", err)
		return
	}
	d.log.debugf("usage metrics sent")
}

// since is cur's growth over prev; a counter below prev was reset by a filter reload and counted from zero.
func since(cur, prev uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// shutdown flushes both tables: a stopped bouncer enforces nothing.
func (d *daemon) shutdown(ctx context.Context) {
	for _, table := range d.tables() {
		if err := d.pf.flush(ctx, table); err != nil {
			d.log.errorf("pfctl flushing %s: %v", table, err)
		}
	}
	d.log.infof("tables flushed")
}

// run pulls at once, then on every tick; reconciles on SIGUSR1; posts usage on its ticker; and flushes the tables
// and returns when ctx ends. done, when set, is told of each handled event (tests synchronise on it).
func (d *daemon) run(ctx context.Context, ticks, usage <-chan time.Time, usr1 <-chan os.Signal, done func(string)) {
	notify := func(event string) {
		if done != nil {
			done(event)
		}
	}
	_ = d.pull(ctx)
	notify("pull")
	for {
		select {
		case <-ctx.Done():
			d.shutdown(context.WithoutCancel(ctx))
			return
		case <-ticks:
			_ = d.pull(ctx)
			notify("pull")
		case <-usr1:
			d.log.infof("SIGUSR1: checking the tables")
			d.reconcile(ctx)
			notify("reconcile")
		case <-usage:
			d.sendUsage(ctx)
			notify("usage")
		}
	}
}
