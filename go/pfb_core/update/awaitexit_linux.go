package update

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// awaitExit waits for the program to exit and returns its exit status, or the signal that ended it, and reaps nothing: the
// supervisor ends while the program is still its zombie, so Core never sees the program gone and its supervisor still there.
func awaitExit(cmd *exec.Cmd) (int, syscall.Signal) {
	var info [16]uint64 // a 128-byte siginfo_t: si_code at byte 8, si_status at byte 24
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(cmd.Process.Pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno != syscall.EINTR {
			break
		}
	}
	code := *(*int32)(unsafe.Pointer(&info[1]))
	status := int(*(*int32)(unsafe.Pointer(&info[3])))
	if code == 1 { // CLD_EXITED
		return status, 0
	}
	return 0, syscall.Signal(status) // CLD_KILLED, CLD_DUMPED
}
