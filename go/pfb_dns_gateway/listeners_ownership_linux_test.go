package main

import (
	"encoding/binary"
	"net"
	"net/netip"
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

	parent, child, err := newSocketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	defer child.Close()
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
