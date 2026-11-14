package update

import (
	"os/exec"
	"syscall"
)

// awaitExit waits for the program to exit and returns its exit status, or the signal that ended it, and reaps nothing: the
// supervisor ends while the program is still its zombie, so Core never sees the program gone and its supervisor still there.
func awaitExit(cmd *exec.Cmd) (int, syscall.Signal) {
	var ws syscall.WaitStatus
	for {
		if _, err := syscall.Wait4(cmd.Process.Pid, &ws, syscall.WNOWAIT, nil); err != syscall.EINTR {
			break
		}
	}
	if ws.Signaled() {
		return 0, ws.Signal()
	}
	return ws.ExitStatus(), 0
}
