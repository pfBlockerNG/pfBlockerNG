package update

import (
	"syscall"
	"unsafe"
)

// exitedUnreaped reports whether the child pid has exited, reaped or not, and reaps nothing: kill(pid, 0) succeeds on a zombie.
func exitedUnreaped(pid int) bool {
	var info [16]uint64 // a 128-byte siginfo_t
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG, 0, 0)
		switch errno {
		case 0:
			return *(*int32)(unsafe.Pointer(&info[0])) != 0 // si_signo stays 0 while the child runs
		case syscall.EINTR:
		case syscall.ECHILD: // reaped, or never the caller's child: no group of the caller's to kill either
			return true
		default:
			return false
		}
	}
}
