package main

import (
	"crypto/tls"
	"net"
)

// serveDoT answers DNS over TLS on ln until stop() or the returned closeNow. A DoT connection is a TCP connection that
// speaks TLS first: it takes a slot of the shared TCP cap at accept, before any handshake byte is read, and then runs the
// same framing, ACL, decider and upstream path as plain TCP, with the TLS peer as the client.
func (g *gateway) serveDoT(ln *net.TCPListener, conf *tls.Config) (closeNow func()) {
	closeNow = g.closeOnStop(func() { _ = ln.Close() })
	g.wg.Add(1)
	go g.serveTCP(ln, conf)
	return closeNow
}
