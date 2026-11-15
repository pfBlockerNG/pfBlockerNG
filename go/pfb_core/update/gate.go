package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultMax = 64 << 10    // the bytes of log a View returns when asked for none in particular
	maxLog     = 8 << 20     // the bytes a running Update's log may hold before it keeps only its newest half (boundLog)
	logCheck   = time.Second // how often a running Update's log is held to maxLog
	offsetBits = 40          // a cursor is the Update's generation above the log offset in its low bits
	offsetMask = 1<<offsetBits - 1
	genMask    = 1<<(63-offsetBits) - 1
)

var (
	ErrRunning = errors.New("an Update is running")
	ErrStopped = errors.New("Core is stopping")
	// ErrRecoveryRequired means a finished worker receipt is not yet in the schedule. The caller records it and retries once.
	ErrRecoveryRequired = errors.New("an Update result is waiting to be recorded")
	// ErrDeferred is what a RunFunc returns when the Update chose not to run now (Command.Run: the program's exit status 75): it
	// is not a failure, and it reported nothing. The gate ends such an Update with the result "skipped".
	ErrDeferred = errors.New("the Update was deferred")
)

// Request is what an Update runs; the JSON is the program's stdin (with "version":1 added).
type Request struct {
	Trigger string   `json:"trigger"`         // "scheduled", "manual", "apply" or "retry"
	Scope   string   `json:"scope,omitempty"` // "ip", "dnsbl", "both"
	Force   string   `json:"force,omitempty"` // "none", "parse", "download", "both"
	Feeds   []string `json:"feeds,omitempty"`
	Extras  []string `json:"extras,omitempty"`
}

// Result is what the program reports on fd 3.
type Result struct {
	Outcomes   map[string]string `json:"outcomes"` // id -> "success" | "retry-cap-reached"
	Attempted  []string          `json:"attempted"`
	GeoIPReady *bool             `json:"geoipReady"` // nil: not reported
}

// RunFunc runs one Update, writing its progress to log (a regular file, opened for append, truncated at Start).
type RunFunc func(ctx context.Context, req Request, log *os.File) (Result, error)

// View is the state of the current or the last Update, and a chunk of its log. Next is a JSON string: a cursor passes 2^53,
// which a browser or a PHP float cannot hold exactly, at generation 8192.
type View struct {
	Running bool    `json:"running"`
	Update  *Status `json:"update"`
	Log     string  `json:"log"`
	Next    int64   `json:"next,string"`
}

// Status is an Update's own record: it is set at Start and completed when the Update ends.
type Status struct {
	Trigger    string `json:"trigger"`
	Scope      string `json:"scope,omitempty"`
	Force      string `json:"force,omitempty"`
	StartedAt  int64  `json:"startedAt"`
	FinishedAt *int64 `json:"finishedAt,omitempty"`
	Result     string `json:"result,omitempty"` // "success" when run returned nil, "skipped" for ErrDeferred, else "failed"
}

// Gate admits one Update at a time.
type Gate struct {
	logPath string
	run     RunFunc
	Admit   func(string) (*Admission, error) // nil only for a Gate whose run does not own a worker
	Launch  func(context.Context, *Admission, Request, *os.File) (Result, error)
	done    func(Request, Result, error)
	admit   sync.Mutex // taken by Start's TryLock and released when the Update ends; nothing ever waits on it but Stop
	mu      sync.Mutex // everything below, and the log's truncation
	status  *Status    // replaced when the Update ends, never changed in place: View hands it out
	gen     int64      // bumped by every Start but the first and by every trim of the log: a cursor from before reads from the start
	cancel  context.CancelFunc
	stopped bool
}

// New returns an idle Gate. Start creates logPath (0600) if it is missing; run executes an Update; done (may be nil) is
// called with the outcome after run returns and BEFORE the gate is released, so a scheduler can record outcomes before the
// next Start. Calling Stop from done deadlocks.
func New(logPath string, run RunFunc, done func(Request, Result, error)) *Gate {
	return &Gate{logPath: logPath, run: run, done: done}
}

// Start admits req (TryLock) or returns ErrRunning at once. commit, when set, runs once after the
// admission lease is held and before the worker is released. It also refuses after Stop with ErrStopped.
func (g *Gate) Start(req Request, commit func() (map[string]int64, error)) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return ErrStopped
	}
	if !g.admit.TryLock() {
		return ErrRunning
	}
	var lease *Admission
	var err error
	if g.Admit != nil {
		lease, err = g.Admit(g.logPath)
		if err != nil {
			g.admit.Unlock()
			return err
		}
	}
	if err := salvageUnfinished(g.logPath); err != nil {
		if lease != nil {
			lease.Close()
		}
		g.admit.Unlock()
		return err
	}
	if receipt, readErr := readWorkerState(g.logPath + ".status"); readErr == nil && receipt.FinishedAt != nil && !receipt.Settled {
		if lease != nil {
			lease.Close()
		}
		g.admit.Unlock()
		return ErrRecoveryRequired
	}
	if commit != nil {
		snap, err := commit()
		if err != nil {
			if lease != nil {
				lease.Close()
			}
			g.admit.Unlock()
			return err
		}
		if lease != nil {
			lease.occurrences = snap
		}
	}
	fresh, err := replaceRegular(g.logPath)
	if err != nil {
		if lease != nil {
			lease.Close()
		}
		g.admit.Unlock()
		return fmt.Errorf("the Update log cannot be opened: %w", err)
	}
	fresh.Close()
	log, err := os.OpenFile(g.logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		if lease != nil {
			lease.Close()
		}
		g.admit.Unlock()
		return fmt.Errorf("the Update log cannot be opened: %w", err)
	}
	if g.status != nil {
		g.gen = (g.gen + 1) & genMask
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.status = &Status{Trigger: req.Trigger, Scope: req.Scope, Force: req.Force, StartedAt: time.Now().Unix()}
	go g.execute(ctx, cancel, lease, req, log)
	return nil
}

func (g *Gate) execute(ctx context.Context, cancel context.CancelFunc, lease *Admission, req Request, log *os.File) {
	bounded := make(chan struct{})
	go g.boundLog(ctx, log, bounded)
	var res Result
	var err error
	if g.Launch != nil {
		res, err = g.Launch(ctx, lease, req, log)
	} else {
		res, err = g.run(ctx, req, log)
	}
	if lease != nil {
		lease.Close()
	}
	finished := time.Now().Unix()
	cancel()
	<-bounded
	_ = log.Close()
	if g.done != nil {
		g.done(req, res, err)
	}
	outcome := "success"
	switch {
	case errors.Is(err, ErrDeferred):
		outcome = "skipped"
	case err != nil:
		outcome = "failed"
	}
	g.mu.Lock()
	ended := *g.status
	ended.FinishedAt, ended.Result = &finished, outcome
	g.status = &ended
	g.admit.Unlock() // under mu: no Start can see the gate free while the status still says running
	g.mu.Unlock()
}

// BoundLog periodically trims log above 8 MiB to its newest whole lines (at most 4 MiB). Call the returned function after the
// writer exits, before closing log: it joins the periodic worker and bounds even output written during cancellation.
func BoundLog(ctx context.Context, log *os.File) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		boundLog(ctx, log, func(log *os.File, size int64) { trimLog(log, size) })
	}()
	return func() {
		cancel()
		<-done
		if info, err := log.Stat(); err == nil && info.Size() > maxLog {
			trimLog(log, info.Size())
		}
	}
}

func (g *Gate) boundLog(ctx context.Context, log *os.File, done chan<- struct{}) {
	defer close(done)
	boundLog(ctx, log, g.trimLog)
}

// boundLog holds a running command's log to maxLog until ctx ends: the root filesystem must not fill while a command prints.
// A log past it keeps its newest whole lines, at most half of maxLog, as pfb_log_mgmt() trims the package's other logs.
func boundLog(ctx context.Context, log *os.File, trim func(*os.File, int64)) {
	tick := time.NewTicker(logCheck)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if info, err := log.Stat(); err == nil && info.Size() > maxLog {
			trim(log, info.Size())
		}
	}
}

func (g *Gate) trimLog(log *os.File, size int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if trimLog(log, size) {
		g.gen = (g.gen + 1) & genMask
	}
}

// trimLog keeps the newest whole lines of the first size bytes of log, at most maxLog/2 of them.
// shortcut: what the program appends between the read and the truncation is lost, and what it appends between the truncation
// and the write lands before the kept lines (pfb_log_mgmt()'s trim has the same window); fine for a log already past maxLog.
func trimLog(log *os.File, size int64) bool {
	r, err := os.Open(log.Name())
	if err != nil {
		return false
	}
	defer r.Close()
	tail := make([]byte, maxLog/2)
	if _, err := r.ReadAt(tail, size-int64(len(tail))); err != nil {
		return false
	}
	if i := bytes.IndexByte(tail, '\n'); i >= 0 {
		tail = tail[i+1:]
	}
	if log.Truncate(0) == nil {
		_, _ = log.Write(tail)
		publishLogGen(log.Name() + ".status")
		return true
	}
	return false
}

// View: Running; Update (nil until the first Start of this process; the last one stays readable after it finishes);
// Log: the log bytes from the cursor after (0: the start), at most max bytes (max<=0: 64 KiB); Next: the cursor after Log.
// A cursor is opaque. One from another Update, a negative one or one past the log's end reads from the start.
func (g *Gate) View(after int64, max int) View {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := View{Update: g.status}
	if g.status != nil {
		v.Running = g.status.FinishedAt == nil
		v.Log, v.Next = g.readLog(after, max, v.Running)
	}
	return v
}

// readLog is the log from the cursor, bounded to limit bytes and never ending inside a rune that is whole in the log, so the
// next read starts on one. A rune cut at the end of a running Update's log waits for its rest; once it ends, nothing waits.
func (g *Gate) readLog(cursor int64, limit int, running bool) (string, int64) {
	gen := g.gen << offsetBits
	if state, err := readWorkerState(g.logPath + ".status"); err == nil {
		gen = state.LogGen << offsetBits
	}
	var after int64
	if cursor >= 0 && cursor&^offsetMask == gen {
		after = cursor & offsetMask
	}
	f, err := os.Open(g.logPath)
	if err != nil {
		return "", gen
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", gen
	}
	if after > info.Size() {
		after = 0
	}
	if limit <= 0 {
		limit = defaultMax
	}
	buf := make([]byte, min(info.Size()-after, int64(limit)))
	n, err := f.ReadAt(buf, after)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", gen | after
	}
	buf = buf[:n]
	atEnd := after+int64(n) >= info.Size()
	if i := partialRune(buf); i >= 0 && (running || !atEnd) {
		switch {
		case i > 0:
			buf = buf[:i]
		case atEnd:
			return "", gen | after
		} // else the bound is inside the very first rune: advance anyway
	}
	return string(buf), gen | (after + int64(len(buf)))
}

// partialRune is where the incomplete rune that ends b starts, or -1.
func partialRune(b []byte) int {
	for i := max(0, len(b)-utf8.UTFMax+1); i < len(b); i++ {
		if utf8.RuneStart(b[i]) && !utf8.FullRune(b[i:]) {
			return i
		}
	}
	return -1
}

// Stop cancels a running Update's context and waits for it to finish; later Starts return ErrStopped.
func (g *Gate) Stop() {
	g.mu.Lock()
	g.stopped = true
	cancel := g.cancel
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	g.admit.Lock()
	g.admit.Unlock()
}
