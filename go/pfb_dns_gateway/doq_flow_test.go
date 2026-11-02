package main

import (
	"context"
	"testing"
	"time"
)

// The DoQ listener sizes each stream's receive window to one DNS message and the connection window to every
// stream that connection may hold. The stream cap and the idle timeout stay as they are. A zero window is not
// that size: quic-go substitutes its own default.
func TestDoQListenerSetsReceiveWindowsForOneMessagePerStream(t *testing.T) {
	cfg := newGateway(nil, nil, nil, time.Second, nil).doqQUICConfig()
	if cfg.MaxIncomingStreams != maxDoQStreams || cfg.MaxIncomingUniStreams != -1 || cfg.MaxIdleTimeout != doqIdleTimeout {
		t.Fatalf("DoQ stream cap or idle timeout changed: streams=%d uni=%d idle=%s; want %d, -1, %s",
			cfg.MaxIncomingStreams, cfg.MaxIncomingUniStreams, cfg.MaxIdleTimeout, int64(maxDoQStreams), doqIdleTimeout)
	}
	// Literals, not the constants the config is built from: maxWire-1 or a connection window of one message must fail.
	const wantStream uint64 = 65535
	const wantConn uint64 = 100 * 65535
	if cfg.InitialStreamReceiveWindow != wantStream || cfg.MaxStreamReceiveWindow != wantStream ||
		cfg.InitialConnectionReceiveWindow != wantConn || cfg.MaxConnectionReceiveWindow != wantConn {
		t.Fatalf("DoQ receive windows are stream initial=%d max=%d conn initial=%d max=%d; want stream %d and connection %d",
			cfg.InitialStreamReceiveWindow, cfg.MaxStreamReceiveWindow,
			cfg.InitialConnectionReceiveWindow, cfg.MaxConnectionReceiveWindow,
			wantStream, wantConn)
	}
}

// A DoQ query's context ends when the connection's does, including while the gateway context is still active,
// and still ends when the gateway stops while the connection is up.
func TestDoQQueryContextEndsWhenTheConnectionDoes(t *testing.T) {
	gateway, stopGateway := context.WithCancel(context.Background())
	t.Cleanup(stopGateway)
	conn, stopConn := context.WithCancel(context.Background())
	qctx, stopQuery := doqQueryContext(gateway, conn)
	t.Cleanup(stopQuery)
	if err := qctx.Err(); err != nil {
		t.Fatalf("query context ended before the connection did: %v", err)
	}

	stopConn()
	// testing.md: the watchdog reports STUCK/ENVIRONMENT. On this wait that label is the regression, a query
	// context that stays live after the connection ends, not an environment failure.
	select {
	case <-qctx.Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: cancelling the connection context left the DoQ query context active while the gateway context is still live")
	}
	if err := gateway.Err(); err != nil {
		t.Fatalf("the gateway context ended with the connection: %v", err)
	}

	gateway2, stopGateway2 := context.WithCancel(context.Background())
	conn2, stopConn2 := context.WithCancel(context.Background())
	t.Cleanup(stopConn2)
	qctx2, stopQuery2 := doqQueryContext(gateway2, conn2)
	t.Cleanup(stopQuery2)
	stopGateway2()
	// Same watchdog contract: STUCK/ENVIRONMENT here means the query context survived gateway stop.
	select {
	case <-qctx2.Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: stopping the gateway left the DoQ query context active")
	}
	if err := conn2.Err(); err != nil {
		t.Fatalf("the connection context ended with the gateway: %v", err)
	}

	// Stopping the query itself must end its context while both parents stay live. AfterFunc only
	// runs when the connection ends, so a cleanup that forgets cancel() leaves this context active.
	gateway3, stopGateway3 := context.WithCancel(context.Background())
	t.Cleanup(stopGateway3)
	conn3, stopConn3 := context.WithCancel(context.Background())
	t.Cleanup(stopConn3)
	qctx3, stopQuery3 := doqQueryContext(gateway3, conn3)
	t.Cleanup(stopQuery3)
	stopQuery3()
	select {
	case <-qctx3.Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: stopping the query left its context active while the gateway and the connection are still live")
	}
	if err := gateway3.Err(); err != nil {
		t.Fatalf("the gateway context ended when the query stopped: %v", err)
	}
	if err := conn3.Err(); err != nil {
		t.Fatalf("the connection context ended when the query stopped: %v", err)
	}
}

// A dropped DoQ connection releases the shared in-flight slot while the gateway is still serving. The decider
// never answers, so only the connection ending can free the slot before gateway shutdown.
func TestDroppedDoQConnectionReleasesTheSharedInFlightSlot(t *testing.T) {
	r, m, addr := newDoQRig(t, rigConfig{timeout: time.Hour})
	c := dialDoQ(t, addr, m, clientAllowed)
	sendDoQ(t, c.stream(), doqQuery(t, "held.example."))
	if q := r.recvQuery(); q.ip != clientAllowed {
		t.Fatalf("the decider saw the query from %s, want %s", q.ip, clientAllowed)
	}
	if n := r.g.muxInflight.Load(); n != 1 {
		t.Fatalf("in flight before the drop: %d, want 1", n)
	}
	if err := r.g.ctx.Err(); err != nil {
		t.Fatalf("the gateway context ended before the drop: %v", err)
	}

	_ = c.conn.CloseWithError(0, "dropped")
	// eventually reports STUCK/ENVIRONMENT. That is the regression if the slot is still held, not a stuck machine.
	eventually(t, "the dropped DoQ connection to release its shared in-flight slot while the gateway is still serving", func() bool {
		return r.g.muxInflight.Load() == 0 && r.g.ctx.Err() == nil
	})
}
