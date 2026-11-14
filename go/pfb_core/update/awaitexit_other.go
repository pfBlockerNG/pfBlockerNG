//go:build !linux && !freebsd

package update

import (
	"os/exec"
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
