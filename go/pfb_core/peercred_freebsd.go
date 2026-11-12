//go:build freebsd

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// The LOCAL_PEERCRED option of <sys/un.h> at level SOL_LOCAL (0), and struct xucred of <sys/ucred.h> (XU_NGROUPS 16, then a
// pointer-sized union): the standard library has no wrapper for it.
const (
	solLocal      = 0
	localPeercred = 1
	xucredVersion = 0
)

type xucred struct {
	version uint32
	uid     uint32
	ngroups int16
	_       int16
	groups  [16]uint32
	_       uint64
}

// peerUID is the user id the kernel recorded for the process that connected c: LOCAL_PEERCRED.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(cred))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeercred,
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			credErr = errno
		}
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if cred.version != xucredVersion {
		return 0, fmt.Errorf("credential of version %d, want %d", cred.version, xucredVersion)
	}
	return cred.uid, nil
}
