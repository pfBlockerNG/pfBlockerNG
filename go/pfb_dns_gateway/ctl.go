package main

import (
	"errors"
	"net"
	"time"
)

// ctlMaxPEM is the longest message the control socket takes: a chain of a few certificates and a key are a few KiB.
const ctlMaxPEM = 64 << 10

// ctlServer is the control socket: root pushes the TLS certificate over it.
type ctlServer struct {
	ln       *net.UnixListener
	path     string
	certs    *certStore
	logf     func(format string, args ...any)
	peerUID  func(*net.UnixConn) (uint32, error) // the kernel's credential of the peer; a test replaces it
	deadline time.Duration
}

func bindCtl(path string, certs *certStore, logf func(format string, args ...any)) (*ctlServer, error) {
	return nil, errors.New("not implemented")
}

func (c *ctlServer) serve(g *gateway) {}

func peerUID(*net.UnixConn) (uint32, error) { return 1, nil }
