//go:build linux || freebsd

package update

import "syscall"

// procAttr puts the program in a process group of its own, and has the kernel KILL it when Core dies (issue #4003; FreeBSD:
// procctl PROC_PDEATHSIG_CTL): a Core killed outright cannot stop it, and the next Core must not find it running.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
