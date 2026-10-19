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
// first probe it gets with the reply to an earlier probe, one id lower than the call's first, and answers the next one
// properly: a udpJudged that took the stale reply for its own would return after one probe, and with none left over it
// returns after the second.
func TestUDPJudgedDoesNotTakeAReplyToAnEarlierProbeForItsOwn(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	var probes atomic.Int32
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := bytes.Clone(buf[:n])
			if probes.Add(1) == 1 {
				binary.BigEndian.PutUint16(reply, binary.BigEndian.Uint16(reply)-1)
			}
			_, _ = server.WriteToUDP(reply, from)
		}
	}()
	probe, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })

	udpJudgedEvery(t, probe, 20*time.Millisecond)

	if got := probes.Load(); got != 2 {
		t.Fatalf("udpJudged returned after %d probes, want 2: the reply to an earlier probe was taken for the answer to its own", got)
	}
}
