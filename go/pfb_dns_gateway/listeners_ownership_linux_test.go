package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
)

// A taken add hands the received descriptors to the listeners that wrap them. The handler closes whatever is still in
// in.fds when it ends, so a taken add must leave none there: closing a number that a listener owns now, or that a later
// socket has reused, would take someone else's descriptor.
func TestATakenAddLeavesNoDescriptorWithTheInputForTheHandlerToClose(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(liveFreePorts(t, 1)[0]))
	s := newListenerSet(r.g, config{port: int(ap.Port())}, nil)

	parent, child := unixPair(t)
	body := "udp+tcp " + ap.String()
	if _, err := child.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)); err != nil {
		t.Fatal(err)
	}
	in := &ctlInput{conn: parent.(*net.UnixConn), oob: make([]byte, syscall.CmsgSpace(4*ctlRightsRoom)), fds: liveSockets(t, "udp+tcp", ap)}

	if got := s.change(true, in); got != "ok" {
		t.Fatalf("add udp+tcp %s: reply %q, want ok", ap, got)
	}
	if len(in.fds) != 0 {
		t.Fatalf("after a taken add in.fds is %v, want none: the handler would close descriptors the listeners own", in.fds)
	}
}

// unixPair is an AF_UNIX stream pair as two connections.
func unixPair(t *testing.T) (parent, child net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	ends := make([]net.Conn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "unixpair")
		if ends[i], err = net.FileConn(f); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		t.Cleanup(func() { _ = ends[i].Close() })
	}
	return ends[0], ends[1]
}
