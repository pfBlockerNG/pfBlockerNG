package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// holdDoQAccept makes the gateway's DoQ accept loop stop, with the connection it just took in hand, until the
// returned release runs (it also runs at the end of the test, so no goroutine is left behind). entered closes when
// the loop first holds a connection. Set it before serveDoQ: the loop reads the hook.
func holdDoQAccept(t *testing.T, g *gateway) (entered <-chan struct{}, release func()) {
	t.Helper()
	in, held := make(chan struct{}), make(chan struct{})
	var once sync.Once
	g.doqAccepted = func() {
		once.Do(func() { close(in) })
		<-held
	}
	release = sync.OnceFunc(func() { close(held) })
	t.Cleanup(release)
	return in, release
}

// doqAnswersWithin reports whether a new DoQ client completes its handshake inside d: a listener that was closed
// drops the Initial without an answer, which is how the tests below tell that stop() got past ln.Close().
func doqAnswersWithin(t *testing.T, addr netip.AddrPort, m tlsMaterial, d time.Duration) bool {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(clientAllowed)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(addr), doqConfig(m), nil)
	if err == nil {
		_ = conn.CloseWithError(0, "probe")
	}
	return err == nil
}

// stop() sends every DoQ connection its close only after the accept loop has handed out what the listener had queued:
// a handshake that completed just before the listener closed is registered late, and a closer that did not wait for
// the loop would miss it and tear the transport down under it, leaving the client to find out at its idle timeout.
func TestStopClosesADoQConnectionTheAcceptLoopRegistersAfterTheListenerClosed(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.stopBound = time.Hour // only the release below may let the closer go on
	m := newTLSMaterial(t)
	entered, release := holdDoQAccept(t, r.g)
	addr := r.serveDoQ(m)

	late := dialDoQ(t, addr, m, clientAllowed) // its handshake is done: the loop holds it, unregistered
	waitClosed(t, entered, "the accept loop to take the connection")
	stopped := make(chan struct{})
	go func() { r.g.stop(); close(stopped) }()
	eventually(t, "the DoQ listener to be closed", func() bool { return !doqAnswersWithin(t, addr, m, 300*time.Millisecond) })

	release()
	waitClosed(t, stopped, "stop() to return once the accept loop was released")
	requireConnClosed(t, late.conn, rfcDoQNoError)
}

// A closer that cannot finish (here: the accept loop never comes back) is given stopBound, then it says what it left
// and closes the socket; stop() still returns.
func TestStopClosesTheDoQSocketAndSaysSoWhenItsClosersWaitRunsOut(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.stopBound = 50 * time.Millisecond
	m := newTLSMaterial(t)
	entered, _ := holdDoQAccept(t, r.g)
	addr := r.serveDoQ(m)

	_ = dialDoQ(t, addr, m, clientAllowed)
	waitClosed(t, entered, "the accept loop to take the connection")
	stopped := make(chan struct{})
	go func() { r.g.stop(); close(stopped) }()
	waitClosed(t, stopped, "stop() to return with the accept loop still held")

	if log := r.logs.joined(); !strings.Contains(log, "connections still open after 50ms; closing the socket") {
		t.Fatalf("stop() must say that the DoQ closer ran out of time:\n%s", log)
	}
}
