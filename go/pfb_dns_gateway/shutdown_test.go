package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// rc stops the gateway with SIGTERM, but a terminal or a supervisor may send SIGHUP: it must end the same way (exit
// 0, ready file removed), not by the default action that kills the process and leaves a stale ready file.
func TestGatewaySIGHUPStopsLikeSIGTERMAndRemovesTheReadyFile(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("no ready file while the gateway serves: %v", err)
	}
	if err := gw.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGHUP, want 0; log:\n%s", code, gw.logText())
	}
	if _, err := os.Stat(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the ready file is still there after SIGHUP (stat: %v)", err)
	}
}

// Stopping cancels, it does not drain: a query in flight is answered with the SERVFAIL the gateway builds, and the
// reply Unbound sends afterwards, which the decider never approved, reaches nobody.
func TestStopAnswersWhatIsInFlightWithServfailNeverWithUnboundsReply(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			held := make(chan struct{})
			release := sync.OnceFunc(func() { close(held) })
			t.Cleanup(release)
			r := newRig(t, rigConfig{acl: aclMixed, upstream: []upstreamOption{answering(func(q seenQuery) [][]byte {
				<-held
				return echoWithQR(q)
			})}})
			r.autoForward()
			c := k.dial(t, r)
			query := buildQuery(t, 7, "inflight.example.", true)
			tcpSend(t, c, query)
			r.up.next() // Unbound has the query and holds its answer
			r.g.dec.Close()
			r.g.stop()
			release() // too late: nobody is waiting for it

			reply := tcpReply(t, c)
			servfailFor(t, reply)
			if queryID(reply) != 7 {
				t.Fatalf("SERVFAIL is for query %d, want 7", queryID(reply))
			}
			if bytes.Equal(reply, echoWithQR(seenQuery{wire: query})[0]) {
				t.Fatal("the client got Unbound's reply, which the decider never approved")
			}
			requireTCPClosed(t, c)
		})
	}
}

// stop() waits for the DoH requests still being served, not only for the listener's goroutine: an http.Server does not
// wait for its handlers when it is closed. The handler here is held in its QUERY write by a wedged decision socket,
// so it can only finish when the test lets it.
func TestStopWaitsForADoHHandlerThatIsStillRunning(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	r.g.stopBound = time.Hour // this test lets the handler go itself
	addr := r.serveDoH(m)
	c := newDoHClient(t, addr, m, dohOptions{})
	d := r.g.dec
	d.wmu.Lock()
	var unlock = sync.OnceFunc(d.wmu.Unlock)
	t.Cleanup(unlock) // before the rig's own cleanup: its stop() must not wait for this handler forever

	req := c.post(dohPath, dohMediaType, buildQuery(t, 1, "held.example.", true))
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		if resp, err := c.http.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	eventually(t, "the DoH query to be in flight", func() bool { return r.g.muxInflight.Load() == 1 })
	stopped := make(chan struct{})
	go func() { r.g.stop(); close(stopped) }()
	select {
	case <-gone: // stop() closed the connection, so it is past its listeners and is waiting for what still runs
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: stop() never closed the DoH connection")
	}
	select {
	case <-stopped:
		t.Fatal("stop() returned while a DoH handler was still running")
	default:
	}
	unlock()
	waitClosed(t, stopped, "stop() to return once the handler finished")
	if n := r.g.muxInflight.Load(); n != 0 {
		t.Fatalf("stop() returned with %d DoH handlers still running", n)
	}
}
