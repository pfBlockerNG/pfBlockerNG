//go:build !linux && !freebsd

package main

import (
	"errors"
	"net"
)

// peerUID has no kernel credential to read here, so nobody is root: every connection is refused.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("no peer credential on this platform")
}
