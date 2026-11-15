package update

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	protocolVersion = 1
	maxResult       = 1 << 20 // the bytes of result the program may report
	deferredStatus  = 75 // EX_TEMPFAIL: the program chose not to run now (a lock held, the schedule switched off)
)

// killGrace is how long the program's whole group has to end on TERM, and again after KILL, before Run goes on. It ends a second
// (the rc script's poll) before the rc script KILLs Core 5 s after its TERM, so Core's KILL reaches the group first (issue #4003).
var killGrace = 3 * time.Second

// leaderExited reports whether the program has exited, when the context ends; replaced only by tests.
var leaderExited = exitedUnreaped

// reap waits for the program and reaps it; replaced only by tests, to hold the window between its exit and its reap open.
var reap = (*exec.Cmd).Wait

// Command runs the platform Update in an independent worker. Context cancellation stops observation, not a launched
// settings transaction; downloads and scripts retain their own operation-level bounds.
type Command struct {
	Path string
}

// Run returns the result the program reported (readResult), with the error of a failed run: a non-zero exit (the result still
// counts when the program wrote a valid one), a kill, or a result line that is not exactly one object of the shape above. Exit
// status 75 is not a failure: Run returns ErrDeferred and no result, whatever the program wrote on fd 3.
func (c *Command) Run(ctx context.Context, req Request, log *os.File) (Result, error) {
	return c.runIndependent(ctx, req, log)
}

// isDeferral reports whether err, from cmd.Wait, is the program's exit with status 75.
func isDeferral(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == deferredStatus
}

// scratch is a temp file in dir, with the func that closes and removes it.
func scratch(dir, pattern string) (*os.File, func(), error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close(); _ = os.Remove(f.Name()) }, nil
}

// groupGone reports whether the process group has no member within grace, polling every 10 ms (docs/misc/external-process-waits.md).
func groupGone(group int, grace time.Duration) bool {
	for deadline := time.Now().Add(grace); ; time.Sleep(10 * time.Millisecond) {
		if errors.Is(syscall.Kill(group, 0), syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// readResult is what the program wrote to f: nothing, or result lines, each exactly one JSON object of protocol version 1. The
// lines add up: every line's outcomes (the first for an id stands), and the attempted ids and GeoIP readiness of the last line
// that has them. A bad unterminated last line (one the program's death cut short) leaves the lines before it, with the error;
// any other error returns a zero Result.
func readResult(f *os.File) (Result, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, maxResult+1))
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("the update program's result cannot be read: %w", err)
	case len(b) > maxResult:
		return Result{}, errors.New("the update program's result is over 1 MiB")
	}
	var res Result
	lines := bytes.Split(b, []byte("\n"))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		r, err := resultLine(line)
		if err != nil {
			if i < len(lines)-1 {
				res = Result{}
			}
			return res, err
		}
		if res.Outcomes == nil {
			res.Outcomes = r.Outcomes
		} else {
			for id, outcome := range r.Outcomes {
				if _, seen := res.Outcomes[id]; !seen {
					res.Outcomes[id] = outcome
				}
			}
		}
		if r.Attempted != nil {
			res.Attempted = r.Attempted
		}
		res.GeoIPReady = cmp.Or(r.GeoIPReady, res.GeoIPReady)
	}
	return res, nil
}

// resultLine is one line of a result: exactly one JSON object of protocol version 1 and nothing after it.
func resultLine(line []byte) (Result, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var r struct {
		Version int `json:"version"`
		Result
	}
	if err := dec.Decode(&r); err != nil {
		return Result{}, fmt.Errorf("the update program's result is not one JSON object: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Result{}, errors.New("the update program's result is not one JSON object: it has data after the first")
	}
	if r.Version != protocolVersion {
		return Result{}, fmt.Errorf("the update program's result speaks version %d, not %d", r.Version, protocolVersion)
	}
	for id, outcome := range r.Outcomes {
		if outcome != "success" && outcome != "retry-cap-reached" {
			return Result{}, fmt.Errorf("the update program's result has the outcome %q for %q, not success or retry-cap-reached", outcome, id)
		}
	}
	return r.Result, nil
}
