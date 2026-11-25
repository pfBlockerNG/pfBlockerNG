package coreinput

import (
	"net/http"
	"testing"
)

// The client New makes cuts no call to Core for taking long (owner, 2026-11-25): only its caller's context ends one.
func TestTheClientCutsNoCallForTakingLong(t *testing.T) {
	c := New("/nonexistent/api.sock")
	if c.http.Timeout != 0 {
		t.Errorf("the client's Timeout is %v", c.http.Timeout)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the transport is a %T", c.http.Transport)
	}
	if tr.ResponseHeaderTimeout != 0 || tr.ExpectContinueTimeout != 0 || tr.TLSHandshakeTimeout != 0 {
		t.Errorf("the transport has a timeout: header %v, continue %v, handshake %v", tr.ResponseHeaderTimeout,
			tr.ExpectContinueTimeout, tr.TLSHandshakeTimeout)
	}
}
