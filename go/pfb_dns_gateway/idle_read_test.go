package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// A query budget under the idle timeout keeps MaxIdleTimeout at 30s and sets no keepalive. The listener has one
// config, so a keepalive would also hold a connection that has finished and gone quiet.
func TestDoQShortBudgetKeepsTheIdleTimeoutAndSetsNoKeepalive(t *testing.T) {
	cfg := newGateway(nil, nil, nil, 5*time.Second, nil).doqQUICConfig()
	if cfg.MaxIdleTimeout != doqIdleTimeout || cfg.KeepAlivePeriod != 0 {
		t.Fatalf("idle timeout %s keepalive %s, want %s and no keepalive", cfg.MaxIdleTimeout, cfg.KeepAlivePeriod, doqIdleTimeout)
	}
}

// The resolve budget is longer than the 30s connection idle timeout. The query is held past that idle timeout and
// must still come back as the decider's answer. A keepalive is not what keeps it: the listener config is shared,
// and a keepalive would also keep a finished connection up.
func TestDoQQueryBudgetLongerThanTheIdleTimeoutIsNotAborted(t *testing.T) {
	const timeout = 20 * time.Second
	r, m, addr := newDoQRig(t, rigConfig{timeout: timeout, grace: time.Second})
	budget := 2*r.g.timeout + r.g.grace
	if budget <= doqIdleTimeout {
		t.Fatalf("budget %s is not longer than the DoQ idle timeout %s", budget, doqIdleTimeout)
	}
	cfg := r.g.doqQUICConfig()
	if cfg.KeepAlivePeriod != 0 {
		t.Fatalf("KeepAlivePeriod %s would keep a finished quiet connection up", cfg.KeepAlivePeriod)
	}

	release := make(chan struct{})
	r.autoAnswer(func(q decidedQuery) []byte {
		<-release
		return echoAnswer(q)
	})
	c := dialDoQ(t, addr, m, clientAllowed)
	query := doqQuery(t, "slow.example.")
	s := c.stream()
	sendDoQ(t, s, query)
	_ = s.SetReadDeadline(time.Now().Add(budget))
	got := make(chan doqRead, 1)
	go func() {
		data, err := io.ReadAll(s)
		got <- doqRead{data: data, err: err}
	}()
	_ = r.nextQuery()

	// Past doqIdleTimeout the connection used to die. The extra second lets that timer win against this wait;
	// the budget is what the reply is checked against, not the clock.
	select {
	case <-c.conn.Context().Done():
		t.Fatalf("DoQ idle timeout aborted a query whose budget is %s: %v", budget, context.Cause(c.conn.Context()))
	case res := <-got:
		t.Fatalf("in-flight DoQ query ended before the decider answered: %v (%d bytes)", res.err, len(res.data))
	case <-time.After(doqIdleTimeout + time.Second):
	}
	close(release)

	var res doqRead
	select {
	case res = <-got:
	case <-c.conn.Context().Done():
		t.Fatalf("connection ended after the idle timeout, before the answer: %v", context.Cause(c.conn.Context()))
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: the decider's answer never reached the DoQ client")
	}
	if res.err != nil && !errors.Is(res.err, io.EOF) {
		t.Fatalf("DoQ query whose budget is %s failed after the idle timeout: %v", budget, res.err)
	}
	if got := unframe(t, res.data); !bytes.Equal(got, withID0(echoWithQR(seenQuery{wire: query})[0])) {
		t.Fatalf("reply %x, want the decider's answer: the idle timeout aborted the query", got)
	}
}

type doqRead struct {
	data []byte
	err  error
}

// The next-frame read hits tcpIdle while a query is still at the decider. That timeout must not cancel the query.
// The client sends nothing else, so the read is the idle one, and the reply is the decider's once it is released.
func TestInFlightQuerySurvivesTheNextFrameIdleRead(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			const idle = 50 * time.Millisecond
			r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: idle, timeout: time.Second})
			release := make(chan struct{})
			r.autoAnswer(func(q decidedQuery) []byte {
				<-release
				return echoAnswer(q)
			})
			c := k.dial(t, r)
			query := buildQuery(t, 7, "held.example.", true)
			tcpSend(t, c, query)
			_ = r.nextQuery()

			// The idle read was armed before the decider saw the query. Well past it, a cancelled handler has
			// already written SERVFAIL or closed the connection. One that is still running has written nothing.
			_ = c.SetReadDeadline(time.Now().Add(10 * idle))
			var size [2]byte
			n, err := io.ReadFull(c, size[:])
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("in-flight %s query ended when the next-frame read hit tcpIdle: read %d bytes %x, err=%v", k.name, n, size[:min(n, 2)], err)
			}
			close(release)
			if got := tcpReply(t, c); !bytes.Equal(got, echoWithQR(seenQuery{wire: query})[0]) {
				t.Fatalf("reply %x, want the decider's answer: the next-frame idle read cancelled the query", got)
			}
		})
	}
}
