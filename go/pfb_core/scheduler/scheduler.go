package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const (
	quarter     = 900 // seconds
	extraPrefix = "extra:"
	cronKey     = "cron"
)

// extraOrder is the order the PHP tick ran the Extras in, whatever order they are due in.
var extraOrder = []string{extraPrefix + "dcc", extraPrefix + "bl"}

// ErrModel marks an error that means the schedule model cannot be built from the settings (Config.Model failed): a caller tells
// it from the gate's refusal, which is update.ErrRunning or update.ErrStopped. The model's own error is wrapped with it.
var ErrModel = errors.New("the schedule model cannot be built")

var (
	scopes = []string{"ip", "dnsbl", "both"}
	forces = []string{"none", "parse", "download", "both"}
)

// Config: Model returns the current model (built from the settings elsewhere), called without the scheduler's lock and
// possibly by several goroutines at once; StatePath is the file the scheduler owns; Loc is the zone the schedule is read in
// (nil: time.Local), unless Zone, which is called once per evaluation and per View (before the scheduler's lock, as Model is),
// returns one: so that a change of the host's time zone is read without a restart. Now is the clock (nil: time.Now); Logf is
// the logger (nil: discard).
type Config struct {
	Model     func() (schedule.Model, error)
	StatePath string
	Loc       *time.Location
	Zone      func() *time.Location
	Now       func() time.Time
	Logf      func(format string, args ...any)
}

type Scheduler struct {
	cfg Config

	mu         sync.Mutex // everything below; held while start runs, so a result waits for its own reservation
	st         schedule.State
	geoipReady bool // the Outpost's last report; true until it makes one
	start      func(update.Request) error
}

// New loads the state file: absent is an empty state; unreadable or invalid is logged and an empty state too, because the
// cutover imports configuration only, so the next evaluation recomputes what is due.
func New(c Config) *Scheduler {
	if c.Loc == nil {
		c.Loc = time.Local
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	s := &Scheduler{cfg: c, st: schedule.State{}, geoipReady: true}
	raw, err := os.ReadFile(c.StatePath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		c.Logf("scheduler: the state file cannot be read, starting with an empty state: %v", err)
	default:
		if st, err := schedule.ParseState(raw); err != nil {
			c.Logf("scheduler: %s is invalid, starting with an empty state: %v", c.StatePath, err)
		} else {
			s.st = st
		}
	}
	return s
}

// Bind sets the gate Start uses; the gate must be created with s.Done as its done callback.
func (s *Scheduler) Bind(start func(update.Request) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.start = start
}

// zone is the zone of this evaluation or view: Zone's, else Loc.
func (s *Scheduler) zone() *time.Location {
	if s.cfg.Zone != nil {
		if loc := s.cfg.Zone(); loc != nil {
			return loc
		}
	}
	return s.cfg.Loc
}

// Tick is one quarter-hour evaluation. It starts nothing and writes nothing when nothing is due, and an Update already
// running skips it without an error.
func (s *Scheduler) Tick() error {
	if err := s.evaluate("scheduled", false); !errors.Is(err, update.ErrRunning) {
		return err
	}
	return nil
}

// evaluate plans what is due and asks for an Update with it (always: force), reserving the occurrences only if the gate
// admits the request. It returns the gate's error unchanged.
func (s *Scheduler) evaluate(trigger string, force bool) error {
	cfg := s.cfg
	m, err := cfg.Model() // before the lock: it needs none of the state, and a slow read must not hold up Done
	if err != nil {
		cfg.Logf("scheduler: the schedule model is unavailable, nothing started: %v", err)
		return fmt.Errorf("%w: %w", ErrModel, err)
	}
	loc := s.zone()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := cfg.Now().Unix()
	// The cache is recomputed first, as the PHP tick refreshed its own before planning.
	nextDue := map[string]int64{}
	for id, e := range schedule.CacheEntries(m, s.st, now, loc) {
		nextDue[id] = e.NextDue
	}
	extraDue, extraOcc := schedule.ExtraPlan(m, s.st, now, loc, nextDue, s.geoipReady)
	occ := schedule.FeedPlan(m, s.st, now, loc).Occurrences
	maps.Copy(occ, extraOcc) // an Extra wins a clash, as PHP's array union does
	st, err := schedule.Reserve(s.st, occ)
	if err != nil {
		cfg.Logf("scheduler: the reservation was rejected, nothing started: %v", err)
		return err
	}
	req := update.Request{Trigger: trigger, Scope: "both", Force: "none"}
	if m.Scheduled {
		for _, e := range m.Entries {
			if e.Enabled && !strings.HasPrefix(e.ID, extraPrefix) && st[e.ID].PendingOccurrence != nil {
				req.Feeds = append(req.Feeds, e.ID)
			}
		}
	}
	for _, id := range extraOrder {
		if slices.Contains(extraDue, id) {
			req.Extras = append(req.Extras, id)
		}
	}
	if len(req.Feeds) == 0 && len(req.Extras) == 0 && !force {
		return nil
	}
	if err := s.launch(req); err != nil {
		if errors.Is(err, update.ErrRunning) {
			cfg.Logf("scheduler: the %s Update was skipped: %v", trigger, err)
		} else {
			cfg.Logf("scheduler: the %s Update was not started: %v", trigger, err)
		}
		return err
	}
	s.st = st
	s.save()
	return nil
}

// launch passes req to the bound gate. The caller holds s.mu.
func (s *Scheduler) launch(req update.Request) error {
	if s.start == nil {
		return errors.New("scheduler: no Update gate is bound")
	}
	return s.start(req)
}

// Start asks for an Update. Trigger "manual" runs scope (ip, dnsbl or both) with force (none, parse, download or both);
// "apply" runs without feeds or Extras; "retry" is a quarter-hour evaluation that starts even when nothing is due. Scope
// and force are the Core's own (both, none) for apply and retry. The gate's refusal, update.ErrRunning, is returned as is.
func (s *Scheduler) Start(trigger, scope, force string) error {
	req := update.Request{Trigger: trigger, Scope: "both", Force: "none"}
	switch trigger {
	case "retry":
		return s.evaluate(trigger, true)
	case "apply":
	case "manual":
		if !slices.Contains(scopes, scope) || !slices.Contains(forces, force) {
			return fmt.Errorf("scheduler: a manual Update takes a scope of %v and a force of %v, not %q and %q", scopes, forces, scope, force)
		}
		req.Scope, req.Force = scope, force
	default:
		return fmt.Errorf("scheduler: %q is not a trigger an Update can be asked for", trigger)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.launch(req)
}

// Done records what an Update reported: all its outcomes in one pass over the state, the Extras among the attempted ids that
// are still pending, and the GeoIP readiness the Outpost saw. A success for an id with no pending occurrence only stamps
// its last_successful_check. The state is written once; a failed run's outcomes still count.
func (s *Scheduler) Done(req update.Request, res update.Result, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if errors.Is(err, update.ErrDeferred) { // it ran nothing: what it reported, if anything, is not recorded
		s.cfg.Logf("scheduler: the %s Update was deferred by the update program; nothing is recorded", req.Trigger)
		return
	}
	if err != nil {
		s.cfg.Logf("scheduler: the %s Update failed: %v", req.Trigger, err)
	}
	outcomes := make(map[string]schedule.Outcome, len(res.Outcomes))
	for id, outcome := range res.Outcomes {
		outcomes[id] = schedule.Outcome(outcome)
	}
	st, rejected := schedule.RecordOutcomes(s.st, outcomes, s.cfg.Now().Unix())
	for _, id := range slices.Sorted(maps.Keys(rejected)) {
		s.cfg.Logf("scheduler: the outcome %q of %q was rejected: %v", outcomes[id], id, rejected[id])
	}
	s.st = st
	for _, id := range res.Attempted {
		// A failed Extra waits for its next occurrence; a failed feed is retried through its pending occurrence alone.
		if it := s.st[id]; strings.HasPrefix(id, extraPrefix) && it.PendingOccurrence != nil {
			it.PendingAttempted = true
			s.st[id] = it
		}
	}
	if res.GeoIPReady != nil {
		s.geoipReady = *res.GeoIPReady
	}
	s.save()
}

// Entry is a ledger entry as the schedule view reports it.
type Entry struct {
	LastRun int64 `json:"lastRun"`
	NextDue int64 `json:"nextDue"`
}

// View is what GetSchedule answers: the feeds' entry (nil when none is or will be due), the Extras' by id, and the time of
// the last successful check of every item that has had one (the metrics export's per-feed gauge).
type View struct {
	Scheduled           bool             `json:"scheduled"`
	Feeds               *Entry           `json:"feeds"`
	Extras              map[string]Entry `json:"extras"`
	LastSuccessfulCheck map[string]int64 `json:"lastSuccessfulCheck"`
}

// View computes the schedule view now from the model and the state.
func (s *Scheduler) View() (View, error) {
	m, err := s.cfg.Model() // before the lock, as in evaluate
	if err != nil {
		return View{}, fmt.Errorf("%w: %w", ErrModel, err)
	}
	loc := s.zone()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{Scheduled: m.Scheduled, Extras: map[string]Entry{}, LastSuccessfulCheck: map[string]int64{}}
	for id, it := range s.st {
		if it.LastSuccessfulCheck != nil {
			v.LastSuccessfulCheck[id] = *it.LastSuccessfulCheck
		}
	}
	for id, e := range schedule.CacheEntries(m, s.st, s.cfg.Now().Unix(), loc) {
		if id == cronKey {
			v.Feeds = &Entry{e.LastRun, e.NextDue}
		} else {
			v.Extras[id] = Entry{e.LastRun, e.NextDue}
		}
	}
	return v, nil
}

// Run calls Tick at every quarter-hour boundary (a Unix time that is a multiple of 900 s) until ctx is done. after is the
// timer (nil: time.After). A failed Tick has logged itself, and the next boundary comes anyway.
func (s *Scheduler) Run(ctx context.Context, after func(time.Duration) <-chan time.Time) {
	if after == nil {
		after = time.After
	}
	for {
		now := s.cfg.Now()
		boundary := time.Unix((now.Unix()/quarter+1)*quarter, 0)
		select {
		case <-ctx.Done():
			return
		case <-after(boundary.Sub(now)):
			_ = s.Tick()
		}
	}
}

// itemFile is a state item as the file holds it; it converts from schedule.Item, which has the same fields.
type itemFile struct {
	LastSuccessfulCheck     *int64           `json:"last_successful_check,omitempty"`
	LastCompletedOccurrence *int64           `json:"last_completed_occurrence,omitempty"`
	PendingOccurrence       *int64           `json:"pending_occurrence,omitempty"`
	CompletionOutcome       schedule.Outcome `json:"completion_outcome,omitempty"`
	PendingAttempted        bool             `json:"pending_attempted,omitempty"`
}

// save writes the state; a failed write is logged and the next write retries, because the state stays in memory.
func (s *Scheduler) save() {
	if err := writeState(s.cfg.StatePath, s.st); err != nil {
		s.cfg.Logf("scheduler: the state file was not written: %v", err)
	}
}

// writeState replaces path with the state in schedule.ParseState's format: the new file written whole and synced, renamed
// over the old one, and the directory synced.
func writeState(path string, st schedule.State) error {
	doc := struct {
		Schema int                 `json:"schema"`
		Items  map[string]itemFile `json:"items"`
	}{1, make(map[string]itemFile, len(st))}
	for id, it := range st {
		doc.Items[id] = itemFile(it)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	// A new file, never an existing one: CreateTemp makes it 0600, where reusing a file would keep that file's mode.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, path)
	}
	if err != nil {
		_ = os.Remove(tmpPath) // a leftover is never read as state, but nothing would remove it
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
