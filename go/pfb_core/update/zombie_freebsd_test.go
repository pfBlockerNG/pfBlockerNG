package update

import (
	"syscall"
	"testing"
)

// awaitZombie returns once pid has exited, leaving it unreaped: FreeBSD's wait4 takes WNOWAIT and adds WEXITED.
func awaitZombie(t *testing.T, pid int) {
	t.Helper()
	for {
		_, err := syscall.Wait4(pid, nil, syscall.WNOWAIT, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("ENVIRONMENT: wait4(%d): %v", pid, err)
		}
		return
	}
}
