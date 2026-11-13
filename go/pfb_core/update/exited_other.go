//go:build !linux && !freebsd

package update

import (
	"errors"
	"syscall"
)

// exitedUnreaped reports whether the child pid has been reaped.
// shortcut: a zombie leader passes kill(pid, 0), so a cancel between its exit and its reap kills its group; pfSense (FreeBSD) and CI (Linux) never use this, upgrade when another OS runs Core.
func exitedUnreaped(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }
