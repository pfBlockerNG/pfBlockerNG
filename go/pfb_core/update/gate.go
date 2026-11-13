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

const defaultMax = 64 << 10 // the bytes of log a View returns when asked for none in particular

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

// View is the state of the current or the last Update, and a chunk of its log.
type View struct {
	Running bool    `json:"running"`
	Update  *Status `json:"update"`
	Log     string  `json:"log"`
	Next    int64   `json:"next"`
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
// Log: the log bytes from offset after, at most max bytes (max<=0: 64 KiB); Next: after + len(Log).
// after < 0 or beyond the file size reads from 0 (the log was truncated by a new Update).
func (g *Gate) View(after int64, max int) View {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := View{Update: g.status}
	if g.status != nil {
		v.Running = g.status.FinishedAt == nil
		v.Log, v.Next = g.readLog(after, max)
	}
	return v
}

// readLog is the log from after, which is bounded to limit bytes and never ends inside a rune, so the next View starts on one.
func (g *Gate) readLog(after int64, limit int) (string, int64) {
	f, err := os.Open(g.logPath)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", 0
	}
	if after < 0 || after > info.Size() {
		after = 0
	}
	if limit <= 0 {
		limit = defaultMax
	}
	buf := make([]byte, min(info.Size()-after, int64(limit)))
	n, err := f.ReadAt(buf, after)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", after
	}
	buf = buf[:n]
	for i := max(0, len(buf)-utf8.UTFMax+1); i < len(buf); i++ {
		if utf8.RuneStart(buf[i]) && !utf8.FullRune(buf[i:]) {
			if i > 0 { // a bound inside the very first rune still has to advance
				buf = buf[:i]
			}
			break
		}
	}
	return string(buf), after + int64(len(buf))
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
