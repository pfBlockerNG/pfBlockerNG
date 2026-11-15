package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const workerArg = "--update-worker"
const workerVersion = 1
const maxWorkerState = 4 << 20 // request plus bounded result and private disposition

// workerState is private to this binary; the nonce pairs admission and completion, never a PID.
type workerState struct {
	Version     int              `json:"version"`
	Nonce       string           `json:"nonce"`
	Path        string           `json:"path"`
	Request     Request          `json:"request"`
	StartedAt   int64            `json:"startedAt"`
	LogGen      int64            `json:"logGen,omitempty"`
	Occurrences map[string]int64 `json:"occurrences,omitempty"`
	Settled     bool             `json:"settled,omitempty"`
	FinishedAt  *int64           `json:"finishedAt,omitempty"`
	ExitCode    *int             `json:"exitCode,omitempty"`
	Signal      int              `json:"signal,omitempty"`
	CoreDumped  bool             `json:"coreDumped,omitempty"`
	Failure     string           `json:"failure,omitempty"`
	Result      Result           `json:"result"`
}

type workerObservation struct {
	state   *workerState
	running bool
}

func init() {
	if len(os.Args) == 3 && os.Args[1] == workerArg {
		os.Exit(runWorker(os.Args[2]))
	}
}

// operationFile refuses symlinks, devices, FIFOs and shared/foreign files before any IO.
func operationFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
			err = fmt.Errorf("%s is not a private owned regular file", path)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func operationLock(logPath string) (*os.File, error) {
	absolute, err := filepath.Abs(logPath)
	if err != nil || absolute != logPath {
		return nil, fmt.Errorf("the operation log must be an absolute path")
	}
	dir := filepath.Dir(logPath)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return nil, fmt.Errorf("the operation directory is not a real directory: %s", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0o027 != 0 || !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("the operation directory is not private and owned: %s", dir)
	}
	lock, err := operationFile(logPath+".lock", syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	return lock, nil
}

// replaceRegular puts a new empty inode at path. A descriptor opened before the
// replacement keeps the old inode, so a live program cannot write the next admission.
func replaceRegular(path string) (*os.File, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".replace-*")
	if err != nil {
		return nil, err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

func readWorkerState(path string) (workerState, error) {
	f, err := operationFile(path, syscall.O_RDONLY)
	if err != nil {
		return workerState{}, err
	}
	defer f.Close()
	return decodeWorkerState(f)
}

func noWorkerState(logPath string) error {
	for _, suffix := range []string{".request", ".result"} {
		f, err := operationFile(logPath+suffix, syscall.O_RDONLY)
		if err == nil {
			f.Close()
			return fmt.Errorf("%s exists without worker status", logPath+suffix)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// observeWorker derives presentation from the validated receipt and lifetime lock without changing either.
func observeWorker(logPath string) (workerObservation, error) {
	lock, err := operationLock(logPath)
	if errors.Is(err, ErrRunning) {
		state, readErr := readWorkerState(logPath + ".status")
		if readErr != nil {
			return workerObservation{}, fmt.Errorf("the running Update has no usable worker status: %w", readErr)
		}
		if state.FinishedAt != nil {
			return workerObservation{}, errors.New("the Update published completion before releasing its lifetime lock")
		}
		return workerObservation{state: &state, running: true}, nil
	}
	if err != nil {
		return workerObservation{}, err
	}
	defer lock.Close()
	state, err := readWorkerState(logPath + ".status")
	if errors.Is(err, os.ErrNotExist) {
		return workerObservation{}, noWorkerState(logPath)
	}
	if err != nil {
		return workerObservation{}, err
	}
	if state.FinishedAt == nil {
		return workerObservation{}, errors.New("the worker released its lifetime lock without publishing completion")
	}
	if !state.Settled {
		return workerObservation{}, errors.New("the worker completion is waiting to be reconciled")
	}
	return workerObservation{state: &state}, nil
}

func decodeWorkerState(r io.Reader) (workerState, error) {
	var state workerState
	body, err := io.ReadAll(io.LimitReader(r, maxWorkerState+1))
	if err != nil {
		return state, err
	}
	if len(body) > maxWorkerState || !utf8.Valid(body) {
		return state, errors.New("the worker state is oversized or not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return state, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return state, errors.New("the worker state has trailing data")
	}
	nonce, err := hex.DecodeString(state.Nonce)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != state.Nonce || state.Version != workerVersion || state.StartedAt <= 0 || state.Path == "" || strings.IndexFunc(state.Path, unicode.IsControl) >= 0 {
		return state, errors.New("the worker state has an invalid identity or version")
	}
	for id, outcome := range state.Result.Outcomes {
		if id == "" || outcome != "success" && outcome != "retry-cap-reached" {
			return state, errors.New("the worker state contains an invalid outcome")
		}
	}
	if state.FinishedAt == nil {
		if state.Settled || state.ExitCode != nil || state.Signal != 0 || state.CoreDumped || state.Failure != "" || len(state.Result.Outcomes) != 0 || len(state.Result.Attempted) != 0 || state.Result.GeoIPReady != nil {
			return state, errors.New("the unfinished worker state contains a terminal result")
		}
	} else if *state.FinishedAt < state.StartedAt || state.Signal < 0 || state.Signal > 255 ||
		state.ExitCode != nil && (*state.ExitCode < 0 || *state.ExitCode > 255 || state.Signal != 0) ||
		state.CoreDumped && state.Signal == 0 ||
		state.ExitCode == nil && state.Signal == 0 && state.Failure == "" {
		return state, errors.New("the worker state contains an inconsistent terminal disposition")
	}
	return state, nil
}

func writeWorkerState(path string, state workerState) error {
	if old, err := operationFile(path, syscall.O_RDONLY); err == nil {
		old.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".worker-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(state)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func publishLogGen(path string) {
	state, err := readWorkerState(path)
	if err != nil {
		return
	}
	state.LogGen = (state.LogGen + 1) & genMask
	_ = writeWorkerState(path, state)
}

func salvageUnfinished(logPath string) error {
	state, err := readWorkerState(logPath + ".status")
	if errors.Is(err, os.ErrNotExist) || err == nil && (state.FinishedAt != nil || state.Settled) {
		return nil
	}
	if err != nil {
		return err
	}
	f, err := operationFile(logPath+".result", syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	res, readErr := readResult(f)
	if len(res.Outcomes) == 0 && len(res.Attempted) == 0 && res.GeoIPReady == nil {
		return nil
	}
	state.Result = res
	if readErr != nil {
		state.Failure = readErr.Error()
	} else {
		state.Failure = "the worker was interrupted before publishing completion"
	}
	finished := time.Now().Unix()
	state.FinishedAt = &finished
	return writeWorkerState(logPath+".status", state)
}

// Recover records one finished receipt. apply runs while the lifetime lock is held; a write error leaves the receipt unsettled.
func Recover(logPath string, apply func(int64, map[string]int64, Result, error) error) error {
	lock, err := operationLock(logPath)
	if errors.Is(err, ErrRunning) {
		state, readErr := readWorkerState(logPath + ".status")
		switch {
		case errors.Is(readErr, os.ErrNotExist):
			return nil
		case readErr != nil:
			return readErr
		case state.FinishedAt != nil:
			return ErrRecoveryRequired
		default:
			return nil
		}
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := readWorkerState(logPath + ".status")
	if errors.Is(err, os.ErrNotExist) {
		return noWorkerState(logPath)
	}
	if err != nil {
		return err
	}
	if state.Settled {
		return nil
	}
	if state.FinishedAt == nil {
		if err := salvageUnfinished(logPath); err != nil {
			return err
		}
		state, err = readWorkerState(logPath + ".status")
		if err != nil || state.FinishedAt == nil || state.Settled {
			return nil
		}
	}
	res, runErr := state.outcome()
	if err := apply(*state.FinishedAt, state.Occurrences, res, runErr); err != nil {
		return err
	}
	state.Settled = true
	return writeWorkerState(logPath+".status", state)
}

func (s workerState) outcome() (Result, error) {
	if s.FinishedAt == nil {
		return s.Result, errors.New("the worker was interrupted before publishing completion")
	}
	if s.ExitCode != nil && *s.ExitCode == deferredStatus {
		return Result{}, ErrDeferred
	}
	if s.Signal != 0 {
		dump := ""
		if s.CoreDumped {
			dump = " (core dumped)"
		}
		return s.Result, fmt.Errorf("the update program failed: signal: %s%s", syscall.Signal(s.Signal), dump)
	}
	if s.ExitCode != nil && *s.ExitCode != 0 {
		return s.Result, fmt.Errorf("the update program failed: exit status %d", *s.ExitCode)
	}
	if s.Failure != "" {
		return s.Result, errors.New(s.Failure)
	}
	if s.ExitCode == nil {
		return s.Result, errors.New("the worker published no program exit status")
	}
	return s.Result, nil
}

// Admission owns the operation lock until Close or a successful launch transfers it.
type Admission struct {
	lock        *os.File
	logGen      int64
	occurrences map[string]int64
	published   func()
}

func (a *Admission) Close() error {
	if a == nil || a.lock == nil {
		return nil
	}
	return a.lock.Close()
}

func (c *Command) Admit(logPath string) (*Admission, error) {
	lock, err := operationLock(logPath)
	if errors.Is(err, ErrRunning) {
		state, readErr := readWorkerState(logPath + ".status")
		switch {
		case errors.Is(readErr, os.ErrNotExist), readErr == nil && state.FinishedAt != nil:
			return nil, ErrRecoveryRequired
		case readErr != nil:
			return nil, fmt.Errorf("cannot observe running worker state: %w", readErr)
		default:
			return nil, ErrRunning
		}
	}
	if err != nil {
		return nil, err
	}
	a := &Admission{lock: lock}
	state, err := readWorkerState(logPath + ".status")
	if errors.Is(err, os.ErrNotExist) {
		if err := noWorkerState(logPath); err != nil {
			a.Close()
			return nil, fmt.Errorf("cannot recover worker state: %w", err)
		}
	} else if err != nil {
		a.Close()
		return nil, fmt.Errorf("cannot recover worker state: %w", err)
	} else {
		a.logGen = (state.LogGen + 1) & genMask
	}
	return a, nil
}

func (c *Command) Run(ctx context.Context, req Request, log *os.File) (Result, error) {
	a, err := c.Admit(log.Name())
	if err != nil {
		return Result{}, err
	}
	defer a.Close()
	return a.Launch(ctx, c, req, log)
}

func (a *Admission) Launch(ctx context.Context, c *Command, req Request, log *os.File) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	lock := a.lock
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, err
	}
	state := workerState{
		Version: workerVersion, Nonce: hex.EncodeToString(nonce[:]), Path: c.Path, Request: req, StartedAt: time.Now().Unix(),
		LogGen: a.logGen, Occurrences: a.occurrences,
	}
	if err := writeWorkerState(log.Name()+".request", state); err != nil {
		return Result{}, err
	}
	request, err := operationFile(log.Name()+".request", syscall.O_RDONLY)
	if err != nil {
		return Result{}, err
	}
	defer request.Close()
	result, err := replaceRegular(log.Name() + ".result")
	if err != nil {
		return Result{}, err
	}
	if err := result.Sync(); err != nil {
		return Result{}, err
	}
	if err := writeWorkerState(log.Name()+".status", state); err != nil {
		return Result{}, err
	}
	if a.published != nil {
		a.published()
	}
	ready, readyW, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	defer ready.Close()
	defer readyW.Close()
	release, releaseW, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	defer release.Close()
	defer releaseW.Close()
	self, err := os.Executable()
	if err != nil {
		return Result{}, err
	}
	cmd := exec.Command(self, workerArg, log.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, log, log
	cmd.ExtraFiles = []*os.File{request, lock, log, result, readyW, release}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	readyW.Close()
	release.Close()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return Result{}, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(ready, ack[:]); err != nil {
		return Result{}, fmt.Errorf("the worker did not acknowledge ownership: %w", err)
	}
	if ack[0] != 1 {
		return Result{}, fmt.Errorf("the worker sent invalid ownership acknowledgement %d", ack[0])
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := releaseW.Write([]byte{1}); err != nil {
		return Result{}, err
	}
	releaseW.Close()
	lock.Close()
	a.lock = nil
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case waitErr := <-done:
		terminal, err := readWorkerState(log.Name() + ".status")
		if err != nil {
			return Result{}, fmt.Errorf("the worker completion cannot be read: %w", err)
		}
		if terminal.Nonce != state.Nonce {
			return Result{}, errors.New("the worker completion does not match admission")
		}
		if terminal.FinishedAt == nil {
			partial, parseErr := readResult(result)
			return partial, errors.Join(errors.New("the worker was interrupted before publishing completion"), waitErr, parseErr)
		}
		return terminal.outcome()
	}
}

func runWorker(logPath string) int {
	request, lock := os.NewFile(3, "request"), os.NewFile(4, "lock")
	log, result := os.NewFile(5, logPath), os.NewFile(6, "result")
	ready, release := os.NewFile(7, "ready"), os.NewFile(8, "release")
	for fd := 3; fd <= 8; fd++ {
		syscall.CloseOnExec(fd)
	}
	defer func() {
		if lock != nil {
			_ = lock.Close()
		}
	}()
	defer request.Close()
	defer log.Close()
	defer result.Close()
	defer ready.Close()
	defer release.Close()
	state, err := decodeWorkerState(request)
	if err != nil {
		return 1
	}
	if _, err := ready.Write([]byte{1}); err != nil {
		return 1
	}
	ready.Close()
	var commit [1]byte
	if _, err := io.ReadFull(release, commit[:]); err != nil || commit[0] != 1 {
		return 1
	}
	release.Close()
	in, remove, err := scratch(filepath.Dir(logPath), ".stdin-*")
	if err == nil {
		defer remove()
		err = json.NewEncoder(in).Encode(struct {
			Version int `json:"version"`
			Request
		}{protocolVersion, state.Request})
		if err == nil {
			_, err = in.Seek(0, io.SeekStart)
		}
	}
	if err == nil {
		cmd := exec.Command(state.Path)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = in, log, log
		cmd.ExtraFiles = []*os.File{result}
		finish := BoundLog(context.Background(), log)
		err = cmd.Run()
		finish()
		if cmd.ProcessState != nil {
			status := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if status.Signaled() {
				state.Signal = int(status.Signal())
				state.CoreDumped = status.CoreDump()
			} else {
				exit := status.ExitStatus()
				state.ExitCode = &exit
			}
		} else if err != nil {
			state.Failure = err.Error()
		}
		state.Result, err = readResult(result)
		if published, readErr := readWorkerState(logPath + ".status"); readErr == nil {
			state.LogGen = published.LogGen
		}
	}
	if err != nil {
		state.Failure = err.Error()
	}
	if state.ExitCode != nil && *state.ExitCode == deferredStatus {
		state.Result = Result{}
	}
	finished := time.Now().Unix()
	state.FinishedAt = &finished
	if err := writeWorkerState(logPath+".status", state); err != nil {
		fmt.Fprintf(log, "worker completion could not be published: %v\n", err)
		return 1
	}
	_ = lock.Close()
	lock = nil
	return 0
}
