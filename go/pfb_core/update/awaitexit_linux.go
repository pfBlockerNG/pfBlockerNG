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
	var info [16]uint64 // a 128-byte siginfo_t
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(cmd.Process.Pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno == 0 {
			break
		}
		if errno != syscall.EINTR {
			return 1, 0
		}
	}
	// si_code is the third int; the union holding si_pid, si_uid and si_status starts after it, aligned to a pointer
	base := uintptr(12)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		base = 16
	}
	raw := unsafe.Pointer(&info[0])
	code := *(*int32)(unsafe.Add(raw, 8))
	status := int(*(*int32)(unsafe.Add(raw, base+8)))
	if code == 1 { // CLD_EXITED
		return status, 0
	}
	return 0, syscall.Signal(status) // CLD_KILLED, CLD_DUMPED
}

// defaultAction sets sig's action to the default (rt_sigaction with a zeroed action: SIG_DFL, no flags, no mask).
func defaultAction(sig syscall.Signal) {
	var act [4]uint64
	_, _, _ = syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&act[0])), 0, 8, 0, 0)
}

// noCoreDump keeps the supervisor's own death from dumping core: RLIMIT_CORE 0 does not stop a dump into a core_pattern pipe
// (core(5); systemd-coredump, apport), an undumpable process never dumps.
func noCoreDump() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
}
