package update

import (
	"syscall"
	"testing"
	"unsafe"
)

// awaitZombie returns once pid has exited, leaving it unreaped.
func awaitZombie(t *testing.T, pid int) {
	t.Helper()
	var info [16]uint64 // a 128-byte siginfo_t
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			t.Fatalf("ENVIRONMENT: waitid(%d): %v", pid, errno)
		}
		return
	}
}
