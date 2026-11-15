package feedparse

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

var (
	preScriptTimeout = 300 * time.Second // PFB_LIST_SCRIPT_TIMEOUT: a script that runs longer is killed
	preScriptGrace   = 5 * time.Second   // PFB_HOOK_KILL_GRACE: how long its group has to end on TERM before KILL
)

// bourneShell runs a script that is no executable format, as execvp() does for the old path.
const bourneShell = "/bin/sh"

// PreScriptResult is the outcome of RunPreScript (pfb_list_pre_script_run()): whether the transform ran, the file to parse, and
// why it did not.
type PreScriptResult struct {
	OK     bool
	Path   string // the staged copy when OK, else the normalized feed: what a failed transform leaves the caller to keep
	Reason string // when not OK: one of the PreScript constants
	Status int    // the exit status when Reason is PreScriptExit: 126 for a script that cannot be run, 127 for one that is missing or is no path, 128+n when signal n ended it
}

// Reasons a pre-script did not run to the end.
const (
	PreScriptStage   = "stage"   // the staged copy could not be made
	PreScriptExit    = "exit"    // the script exited non-zero, or could not be started
	PreScriptTimeout = "timeout" // the script was killed: it ran past its limit, or ctx ended
	PreScriptDeleted = "deleted" // the script removed its staged input
)

// RunPreScript is pfb_list_pre_script_run(): a copy of norm is staged at staged and script is run on it, with args after the
// staged path, so that neither the downloaded feed nor its .norm is touched. The script runs as the program named, never
// through a shell, except that a file that is no executable format (no #! line) is run by /bin/sh, as execvp() does; its output
// goes to log (nil discards it). It runs for at most 300 seconds: TERM reaches its whole process group at the limit or when ctx
// ends, and KILL follows after 5 seconds if the leader remains. Attached descendants are killed before the runner returns.
//
// script is a path: one without a '/' is refused (exit 127) instead of being looked up on PATH. Finding the list's script, and
// containing it in the script directory (pfb_resolve_list_script()), is the caller's.
//
// OK is true when the script succeeded and left its staged copy (an emptied copy is a valid transform); Path is then the copy
// to parse, and Cleanup removes it afterwards. Any failure removes the staged copy and keeps the caller on norm, its last
// known-good feed.
func RunPreScript(ctx context.Context, script, norm, staged string, log io.Writer, args ...string) PreScriptResult {
	failed := func(reason string, status int) PreScriptResult {
		os.Remove(staged)
		return PreScriptResult{Path: norm, Reason: reason, Status: status}
	}
	if !strings.Contains(script, "/") {
		return failed(PreScriptExit, 127)
	}
	if err := copyFile(norm, staged); err != nil {
		return failed(PreScriptStage, 0)
	}
	ctx, cancel := context.WithTimeout(ctx, preScriptTimeout)
	defer cancel()
	argv := append([]string{staged}, args...)
	outcome := runProcessGroup(ctx, log, script, argv)
	if outcome.WatchdogErr == nil && errors.Is(outcome.CommandErr, syscall.ENOEXEC) {
		outcome = runProcessGroup(ctx, log, bourneShell, append([]string{script}, argv...))
	}
	err := errors.Join(outcome.CommandErr, outcome.Interrupted, outcome.WatchdogErr)
	var exit *exec.ExitError
	switch {
	case outcome.Interrupted == nil && outcome.WatchdogErr == nil && (outcome.CommandErr == nil || errors.Is(outcome.CommandErr, exec.ErrWaitDelay)):
	case ctx.Err() != nil:
		return failed(PreScriptTimeout, 0)
	case errors.As(err, &exit):
		status := exit.ExitCode()
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			status = 128 + int(ws.Signal())
		}
		return failed(PreScriptExit, status)
	case errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.ENOEXEC):
		return failed(PreScriptExit, 126)
	default:
		return failed(PreScriptExit, 127)
	}
	if _, err := os.Stat(staged); err != nil {
		return failed(PreScriptDeleted, 0)
	}
	return PreScriptResult{OK: true, Path: staged}
}

// runProcessGroup delegates group ownership while retaining the pre-script's argv, log and IO-drain budget.
func runProcessGroup(ctx context.Context, log io.Writer, name string, args []string) process.Outcome {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.WaitDelay = preScriptGrace + time.Second // a detached descendant holding the output pipe open does not hold the run
	return process.Run(ctx, cmd, preScriptGrace)
}

// Cleanup removes the staged copy once the feed is parsed (pfb_list_script_cleanup_staged()). A failed run has none.
func (p PreScriptResult) Cleanup() {
	if p.OK {
		os.Remove(p.Path)
	}
}

// copyFile copies src over dst, creating or truncating it: a copy left by an earlier run is replaced. The copy is 0644, as the old
// path's copy() leaves it under the usual umask, so that a script that drops privileges reads its input.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
