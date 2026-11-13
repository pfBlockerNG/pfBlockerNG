package update

import (
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
	defaultMax = 64 << 10 // the bytes of log a View returns when asked for none in particular
	offsetBits = 40       // a cursor is the Update's generation above the log offset in its low bits
	offsetMask = 1<<offsetBits - 1
	genMask    = 1<<(63-offsetBits) - 1
)

var (
	ErrRunning = errors.New("an Update is running")
	ErrStopped = errors.New("Core is stopping")
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
	Result     string `json:"result,omitempty"` // "success" when run returned nil, else "failed"
}

// Gate admits one Update at a time.
type Gate struct {
	logPath string
	run     RunFunc
	done    func(Request, Result, error)

	admit sync.Mutex // taken by Start's TryLock and released when the Update ends; nothing ever waits on it but Stop

	mu      sync.Mutex // everything below, and the log's truncation
	status  *Status    // replaced when the Update ends, never changed in place: View hands it out
	gen     int64      // the number of Starts before the current Update: its cursors differ from every earlier Update's
	cancel  context.CancelFunc
	stopped bool
}

// New returns an idle Gate. Start creates logPath (0600) if it is missing; run executes an Update; done (may be nil) is
// called with the outcome after run returns and BEFORE the gate is released, so a scheduler can record outcomes before the
// next Start. Calling Stop from done deadlocks.
func New(logPath string, run RunFunc, done func(Request, Result, error)) *Gate {
	return &Gate{logPath: logPath, run: run, done: done}
}

// Start admits req (TryLock) or returns ErrRunning at once; on admission it truncates the log, records the status
// (startedAt = time.Now().Unix()) and runs in a goroutine. It also refuses after Stop with ErrStopped.
func (g *Gate) Start(req Request) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return ErrStopped
	}
	if !g.admit.TryLock() {
		return ErrRunning
	}
	log, err := os.OpenFile(g.logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		g.admit.Unlock()
		return fmt.Errorf("the Update log cannot be opened: %w", err)
	}
	if g.status != nil {
		g.gen = (g.gen + 1) & genMask
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.status = &Status{Trigger: req.Trigger, Scope: req.Scope, Force: req.Force, StartedAt: time.Now().Unix()}
	go g.execute(ctx, cancel, req, log)
	return nil
}

func (g *Gate) execute(ctx context.Context, cancel context.CancelFunc, req Request, log *os.File) {
	res, err := g.run(ctx, req, log)
	finished := time.Now().Unix()
	cancel()
	_ = log.Close()
	if g.done != nil {
		g.done(req, res, err)
	}
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	g.mu.Lock()
	ended := *g.status
	ended.FinishedAt, ended.Result = &finished, outcome
	g.status = &ended
	g.admit.Unlock() // under mu: no Start can see the gate free while the status still says running
	g.mu.Unlock()
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
