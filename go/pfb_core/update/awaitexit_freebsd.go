package update

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// awaitExit waits for the program to exit and returns its exit status, or the signal that ended it, and reaps nothing: the
// supervisor ends while the program is still its zombie, so Core never sees the program gone and its supervisor still there.
// A wait that fails is status 1.
func awaitExit(cmd *exec.Cmd) (int, syscall.Signal) {
	var ws syscall.WaitStatus
	for {
		_, err := syscall.Wait4(cmd.Process.Pid, &ws, syscall.WNOWAIT, nil)
		if err == nil {
			break
		}
		if err != syscall.EINTR {
			return 1, 0
		}
	}
	if ws.Signaled() {
		return 0, ws.Signal()
	}
	return ws.ExitStatus(), 0
}

// defaultAction sets sig's action to the default (sigaction with a zeroed action: SIG_DFL, no flags, no mask).
func defaultAction(sig syscall.Signal) {
	var act [4]uint64
	_, _, _ = syscall.RawSyscall(syscall.SYS_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&act[0])), 0)
}
