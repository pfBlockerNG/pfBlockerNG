package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// After the query is read, the shared in-flight slot used to stay until 2*timeout+grace unless the gateway or
// the connection ended. STOP_SENDING, and a stream reset that also stops the server sending, end the stream
// while the connection stays up. The decider never answers the cancelled query, so only that can free the slot.
// A later query on the same connection still gets its answer. timeout is an hour: waiting it out is the bug.
func TestDoQCancelledStreamReleasesTheSharedInFlightSlot(t *testing.T) {
	cases := []struct {
		name string
		end  func(*quic.Stream)
	}{
		{"STOP_SENDING", func(s *quic.Stream) { s.CancelRead(rfcDoQRequestCancelled) }},
		{"stream reset", func(s *quic.Stream) {
			s.CancelRead(rfcDoQRequestCancelled)
			s.CancelWrite(rfcDoQRequestCancelled)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{timeout: time.Hour})
			c := dialDoQ(t, addr, m, clientAllowed)
			s := c.stream()
			sendDoQ(t, s, doqQuery(t, "held.example."))
			if q := r.recvQuery(); q.ip != clientAllowed {
				t.Fatalf("the decider saw the query from %s, want %s", q.ip, clientAllowed)
			}
			if n := r.g.muxInflight.Load(); n != 1 {
				t.Fatalf("in flight before the stream ended: %d, want 1", n)
			}
			if err := r.g.ctx.Err(); err != nil {
				t.Fatalf("the gateway context ended before the stream did: %v", err)
			}
			if err := c.conn.Context().Err(); err != nil {
				t.Fatalf("the connection context ended before the stream did: %v", err)
			}

			tc.end(s)
			// eventually reports STUCK/ENVIRONMENT. That is the regression if the slot is still held, not a stuck machine.
			eventually(t, "the cancelled DoQ stream to release its shared in-flight slot while the gateway and the connection stay up", func() bool {
				return r.g.muxInflight.Load() == 0 && r.g.ctx.Err() == nil && c.conn.Context().Err() == nil
			})

			done := doqQuery(t, "done.example.")
			s2 := c.stream()
			sendDoQ(t, s2, done)
			q2 := r.recvQuery()
			if q2.ip != clientAllowed || !bytes.Equal(q2.wire[2:], done[2:]) {
				t.Fatalf("the decider saw client=%s wire=%x; want %s and %x", q2.ip, q2.wire, clientAllowed, done)
			}
			r.p.send(tAnswer, q2.id, echoAnswer(q2))
			data, err := readDoQ(t, s2)
			if !errors.Is(err, io.EOF) {
				t.Fatalf("completed query ended with %v, want a FIN after the answer", err)
			}
			if got, want := unframe(t, data), withID0(echoAnswer(q2)); !bytes.Equal(got, want) {
				t.Fatalf("reply %x, want the decider's answer with Message ID 0: %x", got, want)
			}
			if n := r.g.muxInflight.Load(); n != 0 {
				t.Fatalf("in flight after the completed query: %d, want 0", n)
			}
		})
	}
}

// A read that only hits its deadline is DOQ_REQUEST_CANCELLED. A short message, a long one, or a missing FIN
// stays DOQ_PROTOCOL_ERROR. The deadline here is the query timeout, well under the handshake budget.
func TestDoQReadDeadlineIsRequestCancelledAndAMalformedStreamStaysProtocolError(t *testing.T) {
	good := doqQuery(t, "example.")
	cases := []struct {
		name string
		code quic.StreamErrorCode
		send func(t *testing.T, s *quic.Stream)
	}{
		{"one byte of the length, then the deadline", rfcDoQRequestCancelled, func(t *testing.T, s *quic.Stream) {
			put(t, s, []byte{0})
		}},
		{"a few bytes then the deadline", rfcDoQRequestCancelled, func(t *testing.T, s *quic.Stream) {
			put(t, s, []byte{0, 32})
		}},
		{"FIN before the length is complete", rfcDoQProtocolError, func(t *testing.T, s *quic.Stream) {
			put(t, s, []byte{0})
			_ = s.Close()
		}},
		{"one byte more than the length says", rfcDoQProtocolError, func(t *testing.T, s *quic.Stream) {
			put(t, s, append(framed(good), 'x'))
			_ = s.Close()
		}},
		{"a complete query that never gets its FIN", rfcDoQProtocolError, func(t *testing.T, s *quic.Stream) {
			put(t, s, framed(good))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, m, addr := newDoQRig(t, rigConfig{timeout: 200 * time.Millisecond})
			r.autoAnswer(echoAnswer)
			c := dialDoQ(t, addr, m, clientAllowed)
			bad := c.stream()
			tc.send(t, bad)
			requireStreamReset(t, bad, tc.code)

			barrier := doqQuery(t, "barrier.example.")
			if got := c.query(barrier); !bytes.Equal(got[2:], echoWithQR(seenQuery{wire: barrier})[0][2:]) {
				t.Fatalf("the next stream on the same connection was not answered correctly: %x", got)
			}
			if q := r.nextQuery(); !bytes.Equal(q.wire[2:], barrier[2:]) {
				t.Fatalf("the decider's first query is %x: the bad stream reached it", q.wire)
			}
			r.requireNoOtherQuery()
		})
	}
}
