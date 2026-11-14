//go:build !linux && !freebsd

package update

import "syscall"

// procAttr puts the supervisor in a process group of its own, the Update's; this system has no parent-death signal.
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
