package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// udpJudged resends its probe until one of this call's own is answered; a reply that an earlier call left on the socket
// (its probe was sent twice and both replies came, or the reply came late) is not an answer. The server below answers the
// call's only probe with the reply to an earlier probe, one id lower than the call's first, and then with the proper
// reply: a udpJudged that took the stale reply for its own would return with the proper one still waiting on the socket.
// No retry is ever injected, so nothing here depends on how long anything takes: the probe is sent once, and the
// call returns when it has read the proper reply.
func TestUDPJudgedDoesNotTakeAReplyToAnEarlierProbeForItsOwn(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	var probes atomic.Int32
	answered := make(chan struct{}) // closed once both replies are on the probe's socket
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if probes.Add(1) != 1 {
				continue
			}
			stale := bytes.Clone(buf[:n])
			binary.BigEndian.PutUint16(stale, binary.BigEndian.Uint16(stale)-1)
			_, _ = server.WriteToUDP(stale, from)
			_, _ = server.WriteToUDP(buf[:n], from)
			close(answered)
		}
	}()
	probe, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })

	udpJudgedOn(t, probe, nil)

	waitClosed(t, answered, "the server to answer the probe")
	if got := probes.Load(); got != 1 {
		t.Fatalf("the server saw %d probes, want 1: no retry was injected", got)
	}
	requireNoUDPReply(t, probe) // after the server's barrier: the proper reply was read, not left behind
}

// The retry is what answers a probe the kernel dropped: when it fires, the probe goes out again and the reply to the second
// one is the answer. The server never answers the first probe, and the test fires the retry once the server has it, so
// the retry is an event that follows the probe, not a time: a udpJudged that ignored the retry would wait for a reply that
// never comes and end at the watchdog.
func TestUDPJudgedSendsTheProbeAgainWhenTheRetryFiresAndTakesTheReplyToTheSecond(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	var probes atomic.Int32
	first := make(chan struct{}) // closed when the server has the first probe, which it leaves unanswered
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if probes.Add(1) == 1 {
				close(first)
				continue
			}
			_, _ = server.WriteToUDP(buf[:n], from)
		}
	}()
	probe, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	retry := make(chan time.Time, 1)
	go func() {
		select {
		case <-first:
			retry <- time.Now()
		case <-t.Context().Done():
		}
	}()

	udpJudgedOn(t, probe, retry)

	if got := probes.Load(); got != 2 {
		t.Fatalf("the server saw %d probes, want 2: the retry fired once, after the first probe", got)
	}
	requireNoUDPReply(t, probe)
}
