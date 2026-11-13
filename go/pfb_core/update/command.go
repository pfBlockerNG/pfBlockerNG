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
	waitDelay       = time.Second // how long a descendant holding the program's stdin may keep Run waiting
)

var killGrace = 5 * time.Second // how long the program's group has to end on TERM before it is killed

// Command runs the Outpost's update program at Path once per Update.
//
//	stdin   {"version":1,<Request>}
//	stdout and stderr   the progress log itself, a regular file: an Update restarts daemons, and one that inherited a pipe would hold it open
//	fd 3    a regular file next to the log: {"version":1,"outcomes":{id:"success"|"retry-cap-reached"},"attempted":[ids],"geoipReady":bool}
//	exit    0 is success
//
// The program leads its own process group. The group is killed (TERM, then KILL after 5 s) when ctx ends or Cap passes
// (0: 4 hours), never when the program exits on its own: a reload it started in the background must survive.
type Command struct {
	Path string
	Cap  time.Duration
}

// Run returns the result the program reported, with the error of a failed run: a non-zero exit (the result still counts
// when the program wrote a valid one), a kill, or a result that is not exactly one object of the shape above.
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
	fd3, err := os.CreateTemp(filepath.Dir(log.Name()), ".result-*")
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = fd3.Close(); _ = os.Remove(fd3.Name()) }()

	limit := cmp.Or(c.Cap, defaultCap)
	ctx, cancel := context.WithTimeoutCause(ctx, limit, fmt.Errorf("it ran past its %s cap", limit))
	defer cancel()
	cmd := exec.Command(c.Path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(body), log, log
	cmd.ExtraFiles = []*os.File{fd3}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	exited, killed := make(chan struct{}), make(chan bool, 1)
	go func() {
		select {
		case <-exited:
			killed <- false
		case <-ctx.Done():
			group := -cmd.Process.Pid
			_ = syscall.Kill(group, syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(killGrace):
			}
			_ = syscall.Kill(group, syscall.SIGKILL) // ESRCH: nothing is left
			killed <- true
		}
	}()
	err = cmd.Wait()
	close(exited)
	switch wasKilled := <-killed; {
	case wasKilled:
		err = fmt.Errorf("the update program was killed: %w", context.Cause(ctx))
	case errors.Is(err, exec.ErrWaitDelay):
		err = nil // exit 0, and a descendant still holds the stdin pipe
	case err != nil:
		err = fmt.Errorf("the update program failed: %w", err)
	}
	res, resErr := readResult(fd3)
	return res, cmp.Or(err, resErr)
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
