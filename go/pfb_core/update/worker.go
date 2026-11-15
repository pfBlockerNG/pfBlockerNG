package update

import (
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
	"syscall"
	"time"
)

const workerArg = "--update-worker"
const workerVersion = 1

// workerState is private to this binary; the nonce pairs admission and completion, never a PID.
type workerState struct {
	Version    int     `json:"version"`
	Nonce      string  `json:"nonce"`
	Path       string  `json:"path"`
	Request    Request `json:"request"`
	StartedAt  int64   `json:"startedAt"`
	FinishedAt *int64  `json:"finishedAt,omitempty"`
	ExitCode   *int    `json:"exitCode,omitempty"`
	Signal     int     `json:"signal,omitempty"`
	Failure    string  `json:"failure,omitempty"`
	Result     Result  `json:"result"`
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

func readWorkerState(path string) (workerState, error) {
	f, err := operationFile(path, syscall.O_RDONLY)
	if err != nil {
		return workerState{}, err
	}
	defer f.Close()
	return decodeWorkerState(f)
}

func decodeWorkerState(r io.Reader) (workerState, error) {
	var state workerState
	dec := json.NewDecoder(io.LimitReader(r, maxResult+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return state, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return state, errors.New("the worker state has trailing data")
	}
	nonce, err := hex.DecodeString(state.Nonce)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != state.Nonce || state.Version != workerVersion || state.StartedAt <= 0 || state.Path == "" {
		return state, errors.New("the worker state has an invalid identity or version")
	}
	if state.FinishedAt == nil && (state.ExitCode != nil || state.Signal != 0 || state.Failure != "") {
		return state, errors.New("the unfinished worker state contains a terminal result")
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

func (s workerState) outcome() (Result, error) {
	if s.FinishedAt == nil {
		return s.Result, errors.New("the worker was interrupted before publishing completion")
	}
	if s.ExitCode != nil && *s.ExitCode == deferredStatus {
		return Result{}, ErrDeferred
	}
	if s.Failure != "" {
		return s.Result, errors.New(s.Failure)
	}
	if s.Signal != 0 {
		return s.Result, fmt.Errorf("the update program failed: signal: %s", syscall.Signal(s.Signal))
	}
	if s.ExitCode == nil {
		return s.Result, errors.New("the worker published no program exit status")
	}
	if *s.ExitCode != 0 {
		return s.Result, fmt.Errorf("the update program failed: exit status %d", *s.ExitCode)
	}
	return s.Result, nil
}

func (c *Command) runIndependent(ctx context.Context, req Request, log *os.File) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	lock, err := operationLock(log.Name())
	if err != nil {
		return Result{}, err
	}
	defer lock.Close() // Never LOCK_UN: the worker inherits this same open description.
	if _, err := readWorkerState(log.Name()+".status"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("cannot recover worker state: %w", err)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, err
	}
	state := workerState{Version: workerVersion, Nonce: hex.EncodeToString(nonce[:]), Path: c.Path, Request: req, StartedAt: time.Now().Unix()}
	if err := writeWorkerState(log.Name()+".status", state); err != nil {
		return Result{}, err
	}
	if err := writeWorkerState(log.Name()+".request", state); err != nil {
		return Result{}, err
	}
	request, err := operationFile(log.Name()+".request", syscall.O_RDONLY)
	if err != nil {
		return Result{}, err
	}
	defer request.Close()
	result, err := operationFile(log.Name()+".result", syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return Result{}, err
	}
	defer result.Close()
	if err := result.Truncate(0); err != nil {
		return Result{}, err
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
	if _, err := io.ReadFull(ready, ack[:]); err != nil || ack[0] != 1 {
		return Result{}, fmt.Errorf("the worker did not acknowledge ownership: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := releaseW.Write([]byte{1}); err != nil {
		return Result{}, err
	}
	releaseW.Close()
	lock.Close()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case waitErr := <-done:
		terminal, err := readWorkerState(log.Name()+".status")
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
	defer lock.Close()
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
			} else {
				exit := status.ExitStatus()
				state.ExitCode = &exit
			}
		} else if err != nil {
			state.Failure = err.Error()
		}
		state.Result, err = readResult(result)
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
	return 0
}
