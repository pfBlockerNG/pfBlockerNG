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
	"syscall"
	"time"
)

const (
	protocolVersion = 1
	maxResult       = 1 << 20 // the bytes of result the program may report
	defaultCap      = 4 * time.Hour
	deferredStatus  = 75 // EX_TEMPFAIL: the program chose not to run now (a lock held, the schedule switched off)
)

var killGrace = 5 * time.Second // how long the program's whole group has to end on TERM, and again after KILL, before Run goes on

// leaderExited reports whether the program has exited, when the context ends; replaced only by tests.
var leaderExited = exitedUnreaped

// reap waits for the program and reaps it; replaced only by tests, to hold the window between its exit and its reap open.
var reap = (*exec.Cmd).Wait

// Command runs the update program at Path once per Update: stdin is {"version":1,<Request>}, stdout and stderr are the log, and
// fd 3 is the result {"version":1,"outcomes":{id:"success"|"retry-cap-reached"},"attempted":[ids],"geoipReady":bool}; all four
// are regular files, never pipes (a daemon an Update restarts would hold one open). The program's group gets TERM when ctx ends
// or Cap (0: 4 hours) passes, and KILL if a member is left after 5 s; a program that has exited leaves its group alone.
type Command struct {
	Path string
	Cap  time.Duration
}

// limit is how long the program may run: Cap, or four hours when Cap is 0.
func (c *Command) limit() time.Duration { return cmp.Or(c.Cap, defaultCap) }

// Run returns the result the program reported, with the error of a failed run: a non-zero exit (the result still counts
// when the program wrote a valid one), a kill, or a result that is not exactly one object of the shape above. Exit status 75
// is not a failure: Run returns ErrDeferred and no result, whatever the program wrote on fd 3.
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	exited, killed := make(chan struct{}), make(chan bool, 1)
	go func() {
		select {
		case <-exited:
			killed <- false
		case <-ctx.Done():
			pid := cmd.Process.Pid
			if leaderExited(pid) {
				killed <- false // the program has exited, reaped or not: what it left running is not Run's to kill
				return
			}
			group := -pid
			_ = syscall.Kill(group, syscall.SIGTERM)
			if !groupGone(group, killGrace) {
				_ = syscall.Kill(group, syscall.SIGKILL)
				groupGone(group, killGrace) // KILL only queues: a member leaves the group once it has exited and been reaped
			}
			killed <- true
		}
	}()
	err = reap(cmd)
	close(exited)
	switch wasKilled := <-killed; {
	case wasKilled:
		err = fmt.Errorf("the update program was killed: %w", context.Cause(ctx))
	case isDeferral(err):
		return Result{}, fmt.Errorf("the update program deferred the Update (exit status %d): %w", deferredStatus, ErrDeferred)
	case err != nil:
		err = fmt.Errorf("the update program failed: %w", err)
	}
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

// readResult is what the program wrote to f: nothing, or exactly one JSON object of protocol version 1 and nothing after it.
// It returns a zero Result with every error.
func readResult(f *os.File) (Result, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, maxResult+1))
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("the update program's result cannot be read: %w", err)
	case len(b) == 0:
		return Result{}, nil
	case len(b) > maxResult:
		return Result{}, errors.New("the update program's result is over 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
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
