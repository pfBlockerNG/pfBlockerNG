//go:build !linux && !freebsd

package update

import "syscall"

// procAttr puts the program in a process group of its own; this system has no parent-death signal.
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
