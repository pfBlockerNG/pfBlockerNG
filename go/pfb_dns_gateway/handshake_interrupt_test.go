package main

import (
	"net"
	"testing"
	"time"
)

// A client that opens a DoT connection and says nothing holds a connection in its TLS handshake for as long as the
// handshake limit allows. stop() must end that handshake itself, at once: not wait out the bound it gives serving
// goroutines and then cut the connection, which is what a shutdown that has to fit the rc script's stop limit cannot afford.
// The bound and the handshake limit here are an hour, so only the stop can end the handshake. The event waited for is the
// connection being closed under the client; the stop returning follows from it. Closing our end in the cleanup ends the
// handshake as well, so the stop goroutine of a run that failed does not outlive the test.
func TestAStopEndsATLSHandshakeThatIsStillGoing(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.stopBound, r.g.handshake = time.Hour, time.Hour
	addr := r.serveDoT(m)
	raw, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	eventually(t, "the gateway to hold the connection in its handshake", func() bool { return r.g.tcpConns.Load() == 1 })

	stopped := make(chan struct{})
	go func() {
		r.g.stop()
		close(stopped)
	}()
	t.Cleanup(func() {
		_ = raw.Close()
		waitClosed(t, stopped, "stop() to return once the connection was closed")
	})
	requireTCPClosed(t, raw)
	waitClosed(t, stopped, "stop() to return after it ended the TLS handshake")
}
