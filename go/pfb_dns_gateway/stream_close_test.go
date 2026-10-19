package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// closeWrite is the client's half-close: *net.TCPConn sends a FIN, *tls.Conn a close_notify.
func closeWrite(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}
}

// A client that sends its queries and half-closes (a FIN at a frame boundary) is still owed every answer: RFC 7766
// 6.2.1 lets a client close its sending side once it has sent what it wants, and a one-shot client (dig +tcp piped
// from a script, a stub resolver that closes after writing) does exactly that. The gateway answers what it was
// asked, then closes. The FIN races the decider's answers, so a gateway that cancels on EOF fails some round.
func TestAClientThatHalfClosesAfterItsQueriesStillGetsEveryAnswer(t *testing.T) {
	const rounds, queries = 20, 3
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			for round := 1; round <= rounds; round++ {
				r := newRig(t, rigConfig{acl: aclMixed})
				held := make(chan struct{})
				release := sync.OnceFunc(func() { close(held) })
				t.Cleanup(release)
				r.autoAnswer(func(q decidedQuery) []byte { <-held; return append(echoAnswer(q), "answer"...) })
				c := k.dial(t, r)
				for id := uint16(1); id <= queries; id++ {
					tcpSend(t, c, buildQuery(t, id, "example.", true))
				}
				for range queries {
					r.nextQuery() // all of them are held at the decider
				}
				closeWrite(t, c)
				release()
				answered := map[uint16]bool{}
				for range queries {
					reply := tcpReply(t, c)
					if !bytes.HasSuffix(reply, []byte("answer")) {
						t.Fatalf("round %d: query %d was answered %x, want the decider's answer: the half-close cancelled it", round, queryID(reply), reply)
					}
					answered[queryID(reply)] = true
				}
				if len(answered) != queries {
					t.Fatalf("round %d: answers for queries %v, want all %d", round, answered, queries)
				}
				requireTCPClosed(t, c) // and then the gateway closes
			}
		})
	}
}

// Only a clean EOF at a frame boundary is a half-close. EOF anywhere inside a frame is a client that broke off: what
// it asked is abandoned and its slot freed while its query is still undecided.
func TestAClientThatHangsUpInsideAFrameAbandonsWhatItAsked(t *testing.T) {
	for _, k := range streamKinds {
		for _, cut := range []struct {
			name string
			wire []byte
		}{
			{"inside the length prefix", []byte{0}},
			{"after the length prefix", []byte{0, 40}},
			{"inside the query", []byte{0, 40, 0xab}},
		} {
			t.Run(k.name+"/"+cut.name, func(t *testing.T) {
				r := newRig(t, rigConfig{acl: aclMixed})
				held := make(chan struct{})
				release := sync.OnceFunc(func() { close(held) })
				t.Cleanup(release)
				r.autoAnswer(func(q decidedQuery) []byte { <-held; return echoAnswer(q) })
				c := k.dial(t, r)
				tcpSend(t, c, buildQuery(t, 1, "held.example.", true))
				r.nextQuery()
				if _, err := c.Write(cut.wire); err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
				eventually(t, "the slot of a client that broke off a frame to be freed while its query is undecided", func() bool { return r.g.tcpConns.Load() == 0 })
			})
		}
	}
}

// A client that keeps sending but never reads cannot be written to: once a reply fails to go out its connection is
// closed, though the client is still sending. Otherwise it holds its slot for as long as it keeps the idle timeout
// from firing, with every later reply thrown away. The wait is for the client's own write to fail, not for a time.
func TestAClientThatKeepsSendingButNeverReadsIsClosedWhenAReplyCannotBeWritten(t *testing.T) {
	for _, k := range streamKinds {
		t.Run(k.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, tcpIdle: 100 * time.Millisecond})
			r.autoAnswer(answerWith(make([]byte, 60000))) // a few hundred of these overflow every socket buffer on the path
			go func() {                                   // the decider's record of queries is not what this test reads
				for {
					select {
					case <-r.queries:
					case <-t.Context().Done():
						return
					}
				}
			}()
			c := k.dial(t, r)
			query := framed(buildQuery(t, 1, "a.", true)[:12])
			_ = c.SetWriteDeadline(time.Now().Add(watchdog))
			for {
				_, err := c.Write(query)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("STUCK: the client kept sending and the gateway never closed the connection of a client it cannot write to")
				}
				if err != nil {
					break // closed by the gateway, while the client was still sending
				}
			}
			eventually(t, "the unwritable client's slot to be freed", func() bool { return r.g.tcpConns.Load() == 0 })
		})
	}
}
