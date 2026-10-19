package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// cancelOnFinished is a server's connection whose owner is told, the moment the last flight of a TLS 1.2 handshake (the
// server's ChangeCipherSpec and Finished) is on the wire: the cancel lands while the server's handshake call has not yet
// returned, which a stop right after the client's Handshake returns only hits sometimes.
type cancelOnFinished struct {
	net.Conn
	cancel func()
}

func (c *cancelOnFinished) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil && carriesChangeCipherSpec(p[:n]) {
		c.cancel()
	}
	return n, err
}

// carriesChangeCipherSpec reports whether one of the TLS records in b is a ChangeCipherSpec (content type 20).
func carriesChangeCipherSpec(b []byte) bool {
	for len(b) >= 5 {
		if b[0] == 20 {
			return true
		}
		n := 5 + int(b[3])<<8 + int(b[4])
		if len(b) < n {
			return false
		}
		b = b[n:]
	}
	return false
}

// A stop that lands as a connection's handshake completes is still a stop of a connection that has a TLS session: it ends
// with close_notify like every other (RFC 8446 6.1). crypto/tls closes the raw connection when the context it was given
// is cancelled before HandshakeContext returns, even if the handshake finished first, so a gateway that handed it its own
// context sent no alert to that connection, and said the handshake had failed.
func TestAStopThatLandsAsTheHandshakeCompletesStillEndsTheConnectionWithCloseNotify(t *testing.T) {
	m := newTLSMaterial(t)
	r := newRig(t, rigConfig{acl: aclMixed})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	completed := make(chan bool, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			completed <- false
			return
		}
		defer raw.Close()
		tc := tls.Server(&cancelOnFinished{Conn: raw, cancel: r.g.cancel}, m.certs.dot())
		ok := r.g.handshakeTLS(tc)
		completed <- ok
		if ok {
			closeTLS(tc, raw, r.g.closeBound)
		}
	}()

	raw, err := net.DialTimeout("tcp4", ln.Addr().String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tap := &tapConn{Conn: raw}
	conf := m.clientConfig()
	conf.MaxVersion = tls.VersionTLS12
	c := tls.Client(tap, conf)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-completed:
		if !ok {
			t.Fatal("the gateway reported a failed handshake for a client that completed it: the stop closed the connection under the TLS session")
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK: the server's handshake never returned")
	}
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("the connection ended with %v, want a clean close", err)
	}
	types := recordTypes(t, tap.bytes())
	if len(types) == 0 || types[len(types)-1] != tlsAlertRecord {
		t.Fatalf("the connection ended after TLS records of types %v with no alert (content type %d) last: close_notify was not sent", types, tlsAlertRecord)
	}
}
