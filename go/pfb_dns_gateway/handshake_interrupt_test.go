package main

import (
	"net"
	"testing"
	"time"
)

// A client that opens a DoT connection and says nothing holds a connection in its TLS handshake for as long as the
// handshake limit allows. stop() must end that handshake itself, at once: not wait out the bound it gives serving
// goroutines and then cut the connection, which is what a shutdown that has to fit the rc script's stop limit cannot afford.
// The bound and the handshake limit here are an hour, so the only thing that lets stop() return inside the watchdog is the
// handshake being ended by the stop.
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
	select {
	case <-stopped:
	case <-time.After(watchdog):
		t.Fatal("STUCK: stop() did not end a TLS handshake that is still going")
	}
	requireTCPClosed(t, raw)
}
