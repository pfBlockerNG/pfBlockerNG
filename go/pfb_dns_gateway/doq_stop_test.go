package main

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// RFC 9250 4.3: DOQ_NO_ERROR, the code of a graceful close.
const rfcDoQNoError = 0x0

// stopModes are the two ways the tests below end a gateway. stop() cancels the gateway's context first, so the
// goroutine of each connection also notices and closes it, and which close reaches the client first is a race.
// "listeners only" runs just what serveDoQ registered to close on stop, with nothing cancelled: the connection
// goroutines stay where they are, so a client gets a CONNECTION_CLOSE only if that closer sends it.
var stopModes = []struct {
	name string
	stop func(g *gateway)
}{
	{"stop", func(g *gateway) { g.stop() }},
	{"listeners only", func(g *gateway) {
		g.mu.Lock()
		closers := slices.Clone(g.closers)
		g.mu.Unlock()
		for _, closeFn := range closers {
			closeFn()
		}
	}},
}

// A stopping gateway tells every DoQ client that it is going: quic-go's Transport.Close ends connections without a
// CONNECTION_CLOSE and Listener.Close leaves accepted ones open, so a connection nobody closed first stays open at
// the client until its idle timeout (30 s) while the gateway is gone. Each connection here has a query in flight.
func TestStopClosesEveryDoQConnectionWithDoQNoError(t *testing.T) {
	const conns = 100 // under the cap of 128 connections: more of them, more chances for a close to be lost
	for _, mode := range stopModes {
		t.Run(mode.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{perAddr: noAddrCap})
			held := make(chan struct{})
			release := sync.OnceFunc(func() { close(held) })
			t.Cleanup(release)
			r.autoAnswer(func(q decidedQuery) []byte { <-held; return echoAnswer(q) })
			clients := make([]*doqClient, conns)
			for i := range clients {
				clients[i] = dialDoQ(t, addr, m, clientAllowed)
				sendDoQ(t, clients[i].stream(), doqQuery(t, "held.example."))
			}
			for range conns {
				r.nextQuery() // every connection is accepted and served, its stream in flight
			}

			mode.stop(r.g)
			for _, c := range clients {
				requireConnClosed(t, c.conn, rfcDoQNoError)
			}
		})
	}
}

// requireEndedByTheServer asserts that the server ended the connection on the wire, with an application close or a
// transport close such as CONNECTION_REFUSED, not by going silent until an idle timeout.
func requireEndedByTheServer(t *testing.T, conn *quic.Conn) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK: the server never ended the connection")
	}
	var app *quic.ApplicationError
	var transport *quic.TransportError
	cause := context.Cause(conn.Context())
	if remote := (errors.As(cause, &app) && app.Remote) || (errors.As(cause, &transport) && transport.Remote); !remote {
		t.Fatalf("the connection ended with %v, want a close sent by the server", cause)
	}
}

// Connections that the gateway has not served yet when it stops, still handshaking or waiting to be accepted, are
// ended on the wire as well.
func TestStopEndsDoQConnectionsThatAreNotServedYetOnTheWire(t *testing.T) {
	const conns = 100
	for _, mode := range stopModes {
		t.Run(mode.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{perAddr: noAddrCap})
			clients := make([]*doqClient, conns)
			for i := range clients {
				clients[i] = dialDoQ(t, addr, m, clientAllowed) // returns when the client's handshake is done, not the server's accept
			}
			mode.stop(r.g)
			for _, c := range clients {
				requireEndedByTheServer(t, c.conn)
			}
		})
	}
}
