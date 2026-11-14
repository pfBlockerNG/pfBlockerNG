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
	"path/filepath"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

const (
	protocolVersion = 1
	maxResult       = 1 << 20 // the bytes of result the program may report
	defaultCap      = 4 * time.Hour
	deferredStatus  = 75 // EX_TEMPFAIL: the program chose not to run now (a lock held, the schedule switched off)
)

// killGrace is how long the program's whole group has to end on TERM, and again after KILL, before Run goes on. It ends a second
// (the rc script's poll) before the rc script KILLs Core 5 s after its TERM, so Core's KILL reaches the group first (issue #4003).
var killGrace = 3 * time.Second

// Command runs the update program at Path once per Update: stdin is {"version":1,<Request>}, stdout and stderr are the log, and
// fd 3 is the result, lines of {"version":1,"outcomes":{id:"success"|"retry-cap-reached"},"attempted":[ids],"geoipReady":bool};
// all four are regular files, never pipes (a daemon an Update restarts would hold one open). The program's group gets TERM when
// ctx ends or Cap (0: 4 hours) passes, and KILL if a member is left after 3 s; a program that has exited leaves its group alone.
// Core owns the program directly; a re-executed watchdog kills its group if Core dies before committing completion.
type Command struct {
	Path string
	Cap  time.Duration
}

// limit is how long the program may run: Cap, or four hours when Cap is 0.
func (c *Command) limit() time.Duration { return cmp.Or(c.Cap, defaultCap) }

// Run returns the result the program reported (readResult), with the error of a failed run: a non-zero exit (the result still
// counts when the program wrote a valid one), a kill, or a result line that is not exactly one object of the shape above. Exit
// status 75 is not a failure: Run returns ErrDeferred and no result, whatever the program wrote on fd 3.
func (c *Command) Run(ctx context.Context, req Request, log *os.File) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	body, err := json.Marshal(struct {
		Version int `json:"version"`
		Request
	}{protocolVersion, req})
	if err != nil {
		return Result{}, err
	}
	dir := filepath.Dir(log.Name())
	in, rmIn, err := scratch(dir, ".request-*")
	if err != nil {
		return Result{}, err
	}
	defer rmIn()
	if _, err = in.Write(body); err == nil {
		_, err = in.Seek(0, io.SeekStart)
	}
	if err != nil {
		return Result{}, err
	}
	fd3, rmResult, err := scratch(dir, ".result-*")
	if err != nil {
		return Result{}, err
	}
	defer rmResult()

	limit := c.limit()
	ctx, cancel := context.WithTimeoutCause(ctx, limit, fmt.Errorf("it ran past its %s cap", limit))
	defer cancel()
	cmd := exec.Command(c.Path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, log, log
	cmd.ExtraFiles = []*os.File{fd3}
	outcome := process.Run(ctx, cmd, process.Policy{Grace: killGrace})
	watchErr := outcome.WatchdogErr
	if watchErr != nil {
		watchErr = fmt.Errorf("the update %w", watchErr)
	}
	if cmd.Process == nil {
		return Result{}, errors.Join(outcome.CommandErr, watchErr)
	}
	err = outcome.CommandErr
	var killed error
	if outcome.Interrupted != nil {
		killed = fmt.Errorf("the update %w", outcome.Interrupted)
	}
	switch {
	case killed != nil:
		err = killed
	case isDeferral(err):
		if watchErr != nil {
			return Result{}, watchErr
		}
		return Result{}, fmt.Errorf("the update program deferred the Update (exit status %d): %w", deferredStatus, ErrDeferred)
	case err != nil:
		err = fmt.Errorf("the update program failed: %w", err)
	}
	err = cmp.Or(err, watchErr)
	res, resErr := readResult(fd3)
	return res, cmp.Or(err, resErr)
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
