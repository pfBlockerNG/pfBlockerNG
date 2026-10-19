package main

import (
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// eventually waits for a state change the test cannot observe through a channel; it returns as soon as cond holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(watchdog)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: %s never became true", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// G17: 128 TCP connections at once; the 129th is closed at accept and the others are untouched.
func TestTCPConnectionsOverTheCapAreClosedAtAccept(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	conns := make([]net.Conn, maxTCPConns)
	for i := range conns {
		conns[i] = r.tcpClient("")
	}
	over := r.tcpClient("")
	requireTCPClosed(t, over) // connections are accepted in order: once this one is shut, the first 128 hold their slots
	requireTCPClosed(t, r.tcpClient(""))

	for _, i := range []int{0, maxTCPConns - 1} {
		query := buildQuery(t, uint16(i+1), "example.", true)
		tcpSend(t, conns[i], query)
		if got := tcpReply(t, conns[i]); len(got) == 0 {
			t.Fatalf("connection %d, inside the cap, got an empty reply", i)
		}
	}
	if n := strings.Count(r.logs.joined(), "TCP client limit"); n != 1 {
		t.Fatalf("two connections turned away in one burst must log once, got %d lines: %s", n, r.logs.joined())
	}

	_ = conns[5].Close()
	eventually(t, "the closed connection's slot to be freed", func() bool { return r.g.tcpConns.Load() == maxTCPConns-1 })
	again := r.tcpClient("")
	tcpSend(t, again, buildQuery(t, 999, "example.", true))
	if got := tcpReply(t, again); len(got) == 0 {
		t.Fatal("a connection that arrives after a slot was freed must be served")
	}

	for _, c := range conns {
		_ = c.Close()
	}
	_ = again.Close()
	eventually(t, "every connection to drain", func() bool { return r.g.tcpConns.Load() == 0 })
	if r.g.tcpOverload.Load() {
		t.Fatal("the over-limit log latch must reset once the clients have drained")
	}
}

// G17: 512 UDP queries in flight; more are dropped without a trace, one log line per flood.
func TestUDPQueriesOverTheInflightCapAreDropped(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	releaseFirst, releaseRest := make(chan struct{}), make(chan struct{})
	r.autoAnswer(func(q decidedQuery) []byte {
		if binary.BigEndian.Uint16(q.wire) == 1 {
			<-releaseFirst
		} else {
			<-releaseRest
		}
		return echoAnswer(q)
	})
	c := r.udpClient("")
	send := func(id uint16) {
		if _, err := c.Write(buildQuery(t, id, "example.", true)); err != nil {
			t.Fatal(err)
		}
	}
	for batch := 0; batch < maxUDPInflight; batch += 8 { // paced, so the kernel's socket buffer never drops one
		for i := 1; i <= 8; i++ {
			send(uint16(batch + i))
		}
		for range 8 {
			r.nextQuery()
		}
	}
	for id := maxUDPInflight + 1; id <= maxUDPInflight+100; id++ {
		send(uint16(id))
	}

	// A refused client is answered by the read loop itself, so once its REFUSED arrives, the flood above (read
	// earlier, in order) has been judged and none of it can take the slot freed next.
	refused := r.udpClient(clientRefused)
	if _, err := refused.Write(buildQuery(t, 1, "example.", true)); err != nil {
		t.Fatal(err)
	}
	udpReply(t, refused)

	close(releaseFirst) // frees one slot; its reply is sent after the slot is released
	if got := udpReply(t, c); binary.BigEndian.Uint16(got) != 1 {
		t.Fatalf("the first reply is for id %d, want 1", binary.BigEndian.Uint16(got))
	}
	send(uint16(maxUDPInflight + 101)) // datagrams are read in order: the 100 above were handled before this one
	if q := r.nextQuery(); binary.BigEndian.Uint16(q.wire) != maxUDPInflight+101 {
		t.Fatalf("the next query the decider saw has id %d, want %d: a query over the cap was not dropped", binary.BigEndian.Uint16(q.wire), maxUDPInflight+101)
	}
	r.requireNoOtherQuery()
	if n := strings.Count(r.logs.joined(), "UDP queries in flight"); n != 1 {
		t.Fatalf("a flood must log once, got %d lines: %s", n, r.logs.joined())
	}

	close(releaseRest)
	eventually(t, "every query to finish", func() bool { return r.g.udpInflight.Load() == 0 })
	if r.g.udpOverload.Load() {
		t.Fatal("the over-limit log latch must reset once the queries have drained")
	}
}

// G17: the over-limit line is one per flood, however many queries the flood loses, and the next flood logs again.
func TestUDPOverloadIsLoggedAgainForTheNextFlood(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	var gate atomic.Pointer[chan struct{}] // what the decider's queries wait for: one channel per flood
	r.autoAnswer(func(q decidedQuery) []byte {
		<-*gate.Load()
		return echoAnswer(q)
	})
	c := r.udpClient("")
	send := func(id int) {
		if _, err := c.Write(buildQuery(t, uint16(id), "example.", true)); err != nil {
			t.Fatal(err)
		}
	}
	refused := r.udpClient(clientRefused)
	for flood := 1; flood <= 2; flood++ {
		hold := make(chan struct{})
		gate.Store(&hold)
		for batch := 0; batch < maxUDPInflight; batch += 8 { // paced, so the kernel's socket buffer never drops one
			for i := 1; i <= 8; i++ {
				send(batch + i)
			}
			for range 8 {
				r.nextQuery()
			}
		}
		for id := maxUDPInflight + 1; id <= maxUDPInflight+3; id++ { // over the cap: three dropped, one line
			send(id)
		}
		// A refused client is answered by the read loop itself: once its REFUSED arrives, the datagrams above (read
		// earlier, in order) have been judged.
		if _, err := refused.Write(buildQuery(t, 1, "example.", true)); err != nil {
			t.Fatal(err)
		}
		udpReply(t, refused)
		if n := strings.Count(r.logs.joined(), "UDP queries in flight"); n != flood {
			t.Fatalf("flood %d: %d over-limit lines so far, want %d (one per flood, three queries lost in each): %s", flood, n, flood, r.logs.joined())
		}
		r.requireNoOtherQuery()

		close(hold)
		eventually(t, "the flood to drain", func() bool { return r.g.udpInflight.Load() == 0 && !r.g.udpOverload.Load() })
	}
}
