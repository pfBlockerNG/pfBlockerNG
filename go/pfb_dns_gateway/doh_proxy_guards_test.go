package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A LOCAL command that still carries a TCPv4 address block: go-proxyproto decodes the block, but Conn.RemoteAddr
// ignores it for a LOCAL command. Only the !IsLocal conjunct of namedByProxy keeps the X-Forwarded-For fallback.
func TestDoHLocalCommandWithAnAddressBlockFallsBackToXFF(t *testing.T) {
	r, m, addr := newDoHRig(t, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	block := append(netip.MustParseAddr("192.0.2.7").AsSlice(), netip.MustParseAddr("192.0.2.1").AsSlice()...)
	block = binary.BigEndian.AppendUint16(block, 51000)
	block = binary.BigEndian.AppendUint16(block, 443)
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed, prefix: pp2(0, 0x11, block)})
	c.do(c.get(dnsParam(buildQuery(t, 0, "example.", true)), "X-Forwarded-For", "203.0.113.9"))
	if q := r.nextQuery(); q.ip != "203.0.113.9" {
		t.Fatalf("client %s, want the X-Forwarded-For address 203.0.113.9: a LOCAL header names no client", q.ip)
	}
}

// A silent connection from a trusted peer sends no header and no request. The next connection must still be accepted
// and answered: the PROXY header is read per connection, never by the accept loop. The silent peer is held past the
// client's watchdog, so an accept loop that waits for it fails this test.
func TestDoHSilentTrustedPeerDoesNotBlockTheAcceptLoop(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.g.handshake = time.Hour
	m := newTLSMaterial(t)
	addr := r.serveDoH(m, "127.0.0.0/8")
	r.autoAnswer(echoAnswer)
	silent, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	c := newDoHClient(t, addr, m, dohOptions{source: clientAllowed})
	resp, err := c.http.Do(c.get(dnsParam(buildQuery(t, 0, "example.", true))))
	if err != nil {
		t.Fatalf("the next connection was not answered while a silent trusted peer held no header: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}
