//go:build !linux && !freebsd

package process

import "syscall"

// procAttr puts the watchdog in its own process group; this system has no parent-death signal.
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// DieWithParent does nothing: this system has no parent-death signal.
func DieWithParent(*syscall.SysProcAttr) {}
