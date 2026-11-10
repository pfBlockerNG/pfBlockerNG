package main

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The control socket exists in every mode, TLS or not. FF FF FF FF was once the verb that restarted the decider process; the
// decider is part of the gateway now, and those 4 bytes are what any message longer than a certificate is: a length.

var ctlRestartFrame = []byte{0xff, 0xff, 0xff, 0xff} // the retired restart verb

// send writes one frame on a connection of its own and returns the reply.
func (k *ctlRig) send(t *testing.T, frame []byte) string {
	t.Helper()
	c := dialCtl(t, k.path)
	_, _ = c.Write(frame) // a server that refuses the peer has closed already: the reply is what tells
	return ctlReply(t, c)
}

// The retired restart frame is refused as a length over the limit, like any other, and the control socket goes on taking
// pushes.
func TestTheRetiredRestartFrameIsRefusedAsALengthAndThePushesGoOn(t *testing.T) {
	k := newCtlRig(t)
	for name, n := range map[string]uint32{"the retired restart verb": 0xffffffff, "zero": 0, "one over the limit": ctlMaxPEM + 1} {
		if got := k.send(t, binary.BigEndian.AppendUint32(nil, n)); got != "error: a message of "+strconv.Itoa(int(n))+" bytes is not between 1 and 65536" {
			t.Fatalf("%s: reply %q, want the length error", name, got)
		}
	}
	k.requireEmpty(t, "after the refused lengths")

	leaf := k.leaf(t)
	if got := k.push(t, chainPEM(t, leaf)); got != "ok" {
		t.Fatalf("certificate push after the retired restart frame: reply %q, want ok", got)
	}
	k.requireServing(t, leaf, "after a push that followed the retired restart frame")
	if got := k.send(t, ctlFrame([]byte("x"))); !strings.HasPrefix(got, "error: ") || strings.Contains(got, "not between") {
		t.Fatalf("a 1-byte push: reply %q, want the certificate store's error, not the length's", got)
	}
}

// The control socket is there without TLS (listeners and the address table are pushed on it in every mode); a certificate
// pushed to a gateway with no TLS transport has nowhere to go and is answered with an error.
func TestTheControlSocketIsBoundWithoutATLSTransportAndRefusesACertificate(t *testing.T) {
	cfg, logs, sock := ctlConfig(t)
	cfg.dotListen = nil
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if info, err := os.Lstat(sock); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control socket of a gateway with no TLS: %v (err %v), want a socket", info, err)
	}
	pem, err := os.ReadFile(cfg.tlsPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := dialCtl(t, sock)
	_, _ = c.Write(ctlFrame(pem))
	if got := ctlReply(t, c); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("certificate pushed to a gateway with no TLS: reply %q, want an error", got)
	}
}
