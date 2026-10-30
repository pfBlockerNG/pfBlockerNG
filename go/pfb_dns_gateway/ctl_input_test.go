package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// A message cut off at the deadline is answered with how many of its bytes arrived: the count of a read that failed is 0,
// never the -1 that recvmsg reports (a reader that returned it would take bytes off the count of the bytes before it).
func TestAMessageCutOffAtTheDeadlineSaysHowManyBytesArrived(t *testing.T) {
	k := newCtlRig(t, withDeadline(100*time.Millisecond))
	c := dialCtl(t, k.path)
	if _, err := c.Write(append(binary.BigEndian.AppendUint32(nil, 40), "abc"...)); err != nil { // 40 bytes announced, 3 sent
		t.Fatal(err)
	}
	const want = "error: the message ended after 3 of 40 bytes: "
	if reply := ctlReply(t, c); !strings.HasPrefix(reply, want) {
		t.Fatalf("reply %q, want one that starts %q", reply, want)
	}
}
