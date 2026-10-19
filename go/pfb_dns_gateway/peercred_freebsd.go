//go:build freebsd

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const xucredVersion = 0 // XUCRED_VERSION of <sys/ucred.h>

// peerUID is the user id the kernel recorded for the process that connected c: LOCAL_PEERCRED.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		switch {
		case e != nil:
			credErr = e
		case cred.Version != xucredVersion:
			credErr = fmt.Errorf("credential of version %d, want %d", cred.Version, xucredVersion)
		default:
			uid = cred.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, credErr
}
