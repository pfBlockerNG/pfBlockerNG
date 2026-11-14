//go:build !linux && !freebsd

package update

import (
	"os/exec"
	"os/signal"
	"syscall"
)

// awaitExit waits for the program to exit and returns its exit status, or the signal that ended it.
// shortcut: it reaps the program, so a cancel between the reap and the supervisor's exit kills the group (as exited_other.go).
func awaitExit(cmd *exec.Cmd) (int, syscall.Signal) {
	_ = cmd.Wait()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ws.Signaled() {
		return 0, ws.Signal()
	}
	return ws.ExitStatus(), 0
}

// defaultAction hands sig back to the Go runtime.
// shortcut: the runtime's action differs from the default for some signals (SEGV, ABRT, PIPE); no system here runs Core.
func defaultAction(sig syscall.Signal) { signal.Reset(sig) }
