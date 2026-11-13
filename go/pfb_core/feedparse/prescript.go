package feedparse

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
	"time"
)

var (
	preScriptTimeout = 300 * time.Second // PFB_LIST_SCRIPT_TIMEOUT: a script that runs longer is killed
	preScriptGrace   = 5 * time.Second   // PFB_HOOK_KILL_GRACE: how long its group has to end on TERM before KILL
)

// PreScript is the outcome of RunPreScript (pfb_list_pre_script_run()): whether the transform ran, the file to parse, and why
// it did not.
type PreScript struct {
	OK     bool
	Path   string // the staged copy when OK, else the normalized feed: what a failed transform leaves the caller to keep
	Reason string // when not OK: one of the PreScript constants
	Status int    // the exit status when Reason is PreScriptExit: 126 for a script that cannot be run, 127 for one that is missing, 128+n when signal n ended it
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
// through a shell; its output goes to log (nil discards it). It is held to 300 seconds: TERM to its whole process group at the
// limit or when ctx ends, KILL if a member is left after 5 seconds. A script that has exited leaves its group alone.
//
// OK is true when the script succeeded and left its staged copy (an emptied copy is a valid transform); Path is then the copy
// to parse, and Cleanup removes it afterwards. Any failure removes the staged copy and keeps the caller on norm, its last
// known-good feed.
func RunPreScript(ctx context.Context, script, norm, staged string, log io.Writer, args ...string) PreScript {
	failed := func(reason string, status int) PreScript {
		os.Remove(staged)
		return PreScript{Path: norm, Reason: reason, Status: status}
	}
	if err := copyFile(norm, staged); err != nil {
		return failed(PreScriptStage, 0)
	}
	ctx, cancel := context.WithTimeout(ctx, preScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, append([]string{staged}, args...)...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var kill *time.Timer
	cmd.Cancel = func() error {
		group := -cmd.Process.Pid
		kill = time.AfterFunc(preScriptGrace, func() { syscall.Kill(group, syscall.SIGKILL) })
		return syscall.Kill(group, syscall.SIGTERM)
	}
	cmd.WaitDelay = preScriptGrace + time.Second // a descendant holding the output pipe open does not hold the run
	err := cmd.Run()
	if kill != nil {
		kill.Stop() // the group is gone; never signal a reused pgid
	}
	var exit *exec.ExitError
	switch {
	case err == nil || errors.Is(err, exec.ErrWaitDelay):
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
	return PreScript{OK: true, Path: staged}
}

// Cleanup removes the staged copy once the feed is parsed (pfb_list_script_cleanup_staged()). A failed run has none.
func (p PreScript) Cleanup() {
	if p.OK {
		os.Remove(p.Path)
	}
}

// copyFile copies src over dst, creating or truncating it: a copy left by an earlier run is replaced.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
