//go:build linux || freebsd

package update

import "syscall"

// procAttr puts the supervisor in a process group of its own, the Update's, and has the kernel send it coreDied when Core dies
// (issue #4003; FreeBSD: procctl PROC_PDEATHSIG_CTL): the supervisor then kills the whole group, which a Core killed outright
// cannot do, and the next Core finds none of it running.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: coreDied}
}
