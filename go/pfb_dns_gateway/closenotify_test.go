package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// tapConn records every byte its owner reads from the connection.
type tapConn struct {
	net.Conn
	mu  sync.Mutex
	got []byte
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.got = append(c.got, p[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *tapConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.got...)
}

// recordTypes is the content type of each TLS record in b.
func recordTypes(t *testing.T, b []byte) []byte {
	t.Helper()
	var types []byte
	for len(b) > 0 {
		if len(b) < 5 {
			t.Fatalf("a TLS record header is cut short: %x", b)
		}
		n := 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < n {
			t.Fatalf("a TLS record of %d bytes is cut short at %d", n, len(b))
		}
		types = append(types, b[0])
		b = b[n:]
	}
	return types
}

const tlsAlertRecord = 21 // RFC 5246 6.2.1: the content type of an alert

// RFC 8446 6.1: each party MUST send close_notify before it closes its write side. A TLS 1.2 alert keeps its content
// type in the clear in the record header, so a tap on the client's connection tells an alert from a bare TCP close
// (a TLS client library reports both as a plain EOF).
func TestDoTConnectionEndsWithCloseNotify(t *testing.T) {
	for _, how := range []struct {
		name string
		idle time.Duration // 0 = the gateway's own
		end  func(r *rig)
	}{
		{"the idle timeout", 100 * time.Millisecond, func(*rig) {}},
		{"the gateway stopping", 0, func(r *rig) { r.g.stop() }},
	} {
		t.Run(how.name, func(t *testing.T) {
			m := newTLSMaterial(t)
			r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: how.idle})
			addr := r.serveDoT(m)
			raw, err := net.DialTimeout("tcp4", addr.String(), watchdog)
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
			handshake := len(tap.bytes())

			how.end(r)
			_ = c.SetReadDeadline(time.Now().Add(watchdog))
			if _, err := io.Copy(io.Discard, c); err != nil {
				t.Fatalf("the connection ended with %v, want a clean close", err)
			}
			types := recordTypes(t, tap.bytes()[handshake:])
			if len(types) == 0 || types[len(types)-1] != tlsAlertRecord {
				t.Fatalf("the gateway closed the connection after %v TLS records with no alert (content type %d) last: close_notify was not sent", types, tlsAlertRecord)
			}
		})
	}
}
