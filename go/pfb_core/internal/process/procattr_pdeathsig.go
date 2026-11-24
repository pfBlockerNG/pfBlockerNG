//go:build linux || freebsd

package process

import "syscall"

// procAttr puts the strict command's watchdog in its own process group and has the kernel send it coreDied when Core dies
// (FreeBSD: procctl PROC_PDEATHSIG_CTL), so the watchdog can clean the transient group after an abrupt Core exit.
// The command joins this group before it starts.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: coreDied}
}

// DieWithParent has the kernel KILL the command when the process that started it dies, so that it does not run on as an
// orphan of a killed Core.
func DieWithParent(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGKILL }
