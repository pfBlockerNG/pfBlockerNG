package update

import "syscall"

// exitedUnreaped reports whether the child pid has exited, reaped or not, and reaps nothing: kill(pid, 0) succeeds on a zombie.
func exitedUnreaped(pid int) bool {
	wpid, err := syscall.Wait4(pid, nil, syscall.WNOHANG|syscall.WNOWAIT, nil)
	switch err {
	case nil:
		return wpid == pid
	case syscall.ECHILD: // reaped, or never the caller's child: no group of the caller's to kill either
		return true
	}
	return false
}
