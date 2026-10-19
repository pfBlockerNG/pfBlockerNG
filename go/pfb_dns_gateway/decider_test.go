package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const watchdog = 10 * time.Second // stuck-run guard for waits; never asserted on

const (
	tQuery, tForward, tReply, tAnswer, tDrop, tReady byte = 1, 2, 3, 4, 5, 6
	maxFrameBytes                                         = 5 + 1 + 1 + 255 + 65535
)

// pack builds a frame from the protocol document alone: u32 len | u8 type | u32 id | payload.
func pack(typ byte, id uint32, payload []byte) []byte {
	b := make([]byte, 9, 9+len(payload))
	binary.BigEndian.PutUint32(b, uint32(5+len(payload)))
	b[4] = typ
	binary.BigEndian.PutUint32(b[5:], id)
	return append(b, payload...)
}

// queryPayload is a QUERY payload by the documented layout: u8 transport, u8 n, n bytes of IP text, the DNS wire.
func queryPayload(transport byte, ip string, wire []byte) []byte {
	return append(append([]byte{transport, byte(len(ip))}, ip...), wire...)
}

// peer plays the decider (the Python side) on the other end of the socketpair.
type peer struct {
	t    *testing.T
	conn net.Conn
}

func (p *peer) sendRaw(b []byte) {
	p.t.Helper()
	if _, err := p.conn.Write(b); err != nil {
		p.t.Fatalf("peer write: %v", err)
	}
}

func (p *peer) send(typ byte, id uint32, payload []byte) {
	p.t.Helper()
	p.sendRaw(pack(typ, id, payload))
}

func (p *peer) recv() (typ byte, id uint32, payload []byte) {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(watchdog))
	var head [4]byte
	if _, err := io.ReadFull(p.conn, head[:]); err != nil {
		p.t.Fatalf("peer read length: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(p.conn, body); err != nil {
		p.t.Fatalf("peer read body: %v", err)
	}
	return body[0], binary.BigEndian.Uint32(body[1:5]), body[5:]
}

// expect reads one frame and fails unless it is exactly (typ, id, payload).
func (p *peer) expect(typ byte, id uint32, payload []byte) {
	p.t.Helper()
	gt, gid, gp := p.recv()
	if gt != typ || gid != id || !bytes.Equal(gp, payload) {
		p.t.Fatalf("frame from the gateway: got type=%d id=%d payload=%x, want type=%d id=%d payload=%x", gt, gid, gp, typ, id, payload)
	}
}

// newPeer returns a Decider over one end of a socketpair and the peer on the other; READY is not yet sent.
func newPeer(t *testing.T) (*Decider, *peer, *capturedLog) {
	t.Helper()
	parent, child, err := newSocketpair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.FileConn(child)
	if err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	logs := &capturedLog{}
	d := NewDecider(parent, logs.logf)
	p := &peer{t: t, conn: other}
	t.Cleanup(func() { d.Close(); _ = other.Close() })
	return d, p, logs
}

func readyPeer(t *testing.T) (*Decider, *peer, *capturedLog) {
	t.Helper()
	d, p, logs := newPeer(t)
	p.send(tReady, 0, nil)
	waitClosed(t, d.Ready(), "READY")
	return d, p, logs
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(watchdog):
		t.Fatalf("STUCK: %s never happened", what)
	}
}

type decided struct {
	answer []byte
	err    error
}

// decide runs Decide in the background so the test can play the decider meanwhile.
func decide(d *Decider, ctx context.Context, ip string, wire []byte, fwd forwarder) <-chan decided {
	out := make(chan decided, 1)
	go func() {
		a, err := d.Decide(ctx, netip.MustParseAddr(ip), false, wire, fwd)
		out <- decided{a, err}
	}()
	return out
}

func result(t *testing.T, ch <-chan decided) decided {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(watchdog):
		t.Fatal("STUCK: Decide never returned")
		return decided{}
	}
}

func noForward(t *testing.T) forwarder {
	return func(context.Context, []byte) []byte { t.Error("the gateway must not forward here"); return nil }
}

// G1: the codec writes and reads exactly the layout of docs/misc/dns-gateway-protocol.md.
func TestFrameCodecMatchesTheDocumentedLayout(t *testing.T) {
	wire := []byte{0xab, 0xcd, 0x01, 0x00}
	cases := []struct {
		name    string
		typ     byte
		id      uint32
		payload []byte
		golden  string
	}{
		{"QUERY", tQuery, 7, queryPayload(1, "192.0.2.10", wire), "0000001501" + "00000007" + "01" + "0a" + hex.EncodeToString([]byte("192.0.2.10")) + "abcd0100"},
		{"FORWARD", tForward, 7, wire, "0000000902" + "00000007" + "abcd0100"},
		{"REPLY", tReply, 258, wire, "0000000903" + "00000102" + "abcd0100"},
		{"REPLY empty", tReply, 7, nil, "0000000503" + "00000007"},
		{"ANSWER", tAnswer, 0xfffffffe, wire, "0000000904" + "fffffffe" + "abcd0100"},
		{"DROP", tDrop, 9, nil, "0000000505" + "00000009"},
		{"READY", tReady, 0, nil, "0000000506" + "00000000"},
	}
	var stream bytes.Buffer
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeFrame(&out, c.typ, c.id, c.payload); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(out.Bytes()); got != c.golden {
				t.Fatalf("writeFrame bytes:\n got  %s\n want %s", got, c.golden)
			}
			typ, id, payload, err := readFrame(bytes.NewReader(out.Bytes()))
			if err != nil || typ != c.typ || id != c.id || !bytes.Equal(payload, c.payload) {
				t.Fatalf("readFrame: got type=%d id=%d payload=%x err=%v, want type=%d id=%d payload=%x", typ, id, payload, err, c.typ, c.id, c.payload)
			}
		})
		stream.Write(pack(c.typ, c.id, c.payload))
	}
	for _, c := range cases { // the frames also read back to back from one stream, then a clean EOF
		typ, id, payload, err := readFrame(&stream)
		if err != nil || typ != c.typ || id != c.id || !bytes.Equal(payload, c.payload) {
			t.Fatalf("stream read of %s: got type=%d id=%d payload=%x err=%v", c.name, typ, id, payload, err)
		}
	}
	if _, _, _, err := readFrame(&stream); err != io.EOF {
		t.Fatalf("readFrame at the end of the stream: got %v, want io.EOF", err)
	}
}

func TestFrameReaderBoundariesAndTruncation(t *testing.T) {
	var protoErr protocolError
	big := pack(tAnswer, 1, make([]byte, maxFrameBytes-5))
	if _, _, payload, err := readFrame(bytes.NewReader(big)); err != nil || len(payload) != maxFrameBytes-5 {
		t.Fatalf("a frame of exactly the maximum length must be accepted: len=%d err=%v", len(payload), err)
	}
	for name, input := range map[string][]byte{
		"length 4, below the 5 bytes of type+id":   {0, 0, 0, 4},
		"length 0":                                 {0, 0, 0, 0},
		"length one over the maximum, header only": binary.BigEndian.AppendUint32(nil, maxFrameBytes+1),
		"unknown type 0x00":                        pack(0, 1, nil),
		"unknown type 0x07":                        pack(7, 1, nil),
		"unknown type 0xff":                        pack(0xff, 1, nil),
	} {
		t.Run(name, func(t *testing.T) {
			// The reader holds only the 4 length bytes in the over-max case: an io.ErrUnexpectedEOF here would mean
			// the payload was read before the length was checked.
			if _, _, _, err := readFrame(bytes.NewReader(input)); !errors.As(err, &protoErr) {
				t.Fatalf("got %v, want a protocolError", err)
			}
		})
	}
	whole := pack(tForward, 3, []byte("0123456789"))
	for _, cut := range []int{1, 3, 4, 8, 9, len(whole) - 1} {
		if _, _, _, err := readFrame(bytes.NewReader(whole[:cut])); err != io.ErrUnexpectedEOF {
			t.Errorf("frame cut after %d of %d bytes: got %v, want io.ErrUnexpectedEOF", cut, len(whole), err)
		}
	}
}

// G2: a decider that answers by itself (block answer, FORMERR) needs no upstream exchange.
func TestDeciderAnswerReachesTheCaller(t *testing.T) {
	d, p, _ := newPeer(t)
	select {
	case <-d.Ready():
		t.Fatal("Ready() closed before the decider sent READY")
	default:
	}
	p.send(tReady, 0, nil)
	waitClosed(t, d.Ready(), "READY")

	wire := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	out := decide(d, context.Background(), "2001:db8::1", wire, noForward(t))
	typ, id, payload := p.recv()
	if typ != tQuery || !bytes.Equal(payload, queryPayload(0, "2001:db8::1", wire)) {
		t.Fatalf("QUERY frame: got type=%d payload=%x, want type=%d payload=%x", typ, payload, tQuery, queryPayload(0, "2001:db8::1", wire))
	}
	if id == 0 {
		t.Fatal("QUERY id 0 is reserved for READY")
	}
	p.send(tAnswer, id, []byte("block answer"))
	if r := result(t, out); r.err != nil || string(r.answer) != "block answer" {
		t.Fatalf("Decide: got answer=%q err=%v, want %q", r.answer, r.err, "block answer")
	}
}

// G5 (decider half): DROP ends the query with neither an answer nor an error.
func TestDeciderDropMeansSendNothing(t *testing.T) {
	d, p, _ := readyPeer(t)
	out := decide(d, context.Background(), "192.0.2.10", []byte("x"), noForward(t))
	_, id, _ := p.recv()
	p.send(tDrop, id, nil)
	if r := result(t, out); r.err != nil || r.answer != nil {
		t.Fatalf("Decide after DROP: got answer=%q err=%v, want nil, nil", r.answer, r.err)
	}
}

// G3: FORWARD hands the decider's bytes to the exchange and REPLY carries what it returned.
func TestForwardThenReplyThenAnswer(t *testing.T) {
	d, p, _ := readyPeer(t)
	var asked [][]byte
	fwd := func(_ context.Context, wire []byte) []byte {
		asked = append(asked, wire)
		return []byte("unbound says")
	}
	out := decide(d, context.Background(), "192.0.2.10", []byte("client wire"), fwd)
	_, id, _ := p.recv()
	p.send(tForward, id, []byte("client wire"))
	p.expect(tReply, id, []byte("unbound says"))
	p.send(tAnswer, id, []byte("final"))
	if r := result(t, out); r.err != nil || string(r.answer) != "final" {
		t.Fatalf("Decide: got answer=%q err=%v, want %q", r.answer, r.err, "final")
	}
	if len(asked) != 1 || string(asked[0]) != "client wire" {
		t.Fatalf("exchange saw %q, want exactly [client wire]", asked)
	}
}

func TestEmptyExchangeResultIsAnEmptyReply(t *testing.T) {
	d, p, _ := readyPeer(t)
	out := decide(d, context.Background(), "192.0.2.10", []byte("q"), func(context.Context, []byte) []byte { return nil })
	_, id, _ := p.recv()
	p.send(tForward, id, []byte("q"))
	p.expect(tReply, id, nil)
	p.send(tDrop, id, nil)
	result(t, out)
}

// G4: the SafeSearch chase is a second FORWARD of the same id, answered by its own REPLY, in order.
func TestSecondForwardOfOneIdGetsItsOwnReply(t *testing.T) {
	d, p, _ := readyPeer(t)
	var asked [][]byte
	fwd := func(_ context.Context, wire []byte) []byte {
		asked = append(asked, wire)
		return append([]byte("reply to "), wire...)
	}
	out := decide(d, context.Background(), "192.0.2.10", []byte("orig"), fwd)
	_, id, _ := p.recv()
	p.send(tForward, id, []byte("orig"))
	p.expect(tReply, id, []byte("reply to orig"))
	p.send(tForward, id, []byte("chase"))
	p.expect(tReply, id, []byte("reply to chase"))
	p.send(tAnswer, id, []byte("cname+target"))
	if r := result(t, out); r.err != nil || string(r.answer) != "cname+target" {
		t.Fatalf("Decide: got answer=%q err=%v", r.answer, r.err)
	}
	if len(asked) != 2 || string(asked[0]) != "orig" || string(asked[1]) != "chase" {
		t.Fatalf("exchange order: got %q, want [orig chase]", asked)
	}
}

func TestQueriesInterleaveAndFinishInAnyOrder(t *testing.T) {
	d, p, _ := readyPeer(t)
	first := decide(d, context.Background(), "192.0.2.1", []byte("one"), noForward(t))
	_, id1, _ := p.recv()
	second := decide(d, context.Background(), "192.0.2.2", []byte("two"), noForward(t))
	_, id2, _ := p.recv()
	if id1 == id2 {
		t.Fatalf("two in-flight queries share id %d", id1)
	}
	p.send(tAnswer, id2, []byte("answer two"))
	p.send(tAnswer, id1, []byte("answer one"))
	if r := result(t, first); string(r.answer) != "answer one" {
		t.Fatalf("first query got %q, want %q", r.answer, "answer one")
	}
	if r := result(t, second); string(r.answer) != "answer two" {
		t.Fatalf("second query got %q, want %q", r.answer, "answer two")
	}
}

// G6b: a query the gateway gave up on keeps its id until the decider's final frame arrives.
func TestAbandonedIdStaysReservedAndItsLateForwardGetsAnEmptyReply(t *testing.T) {
	d, p, _ := readyPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	var exchanged int
	out := decide(d, ctx, "192.0.2.10", []byte("slow"), func(context.Context, []byte) []byte { exchanged++; return []byte("x") })
	_, abandoned, _ := p.recv()
	cancel() // the gateway's own deadline, driven by the test rather than the clock
	if r := result(t, out); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("Decide after the deadline: got err=%v, want context.Canceled", r.err)
	}

	p.send(tForward, abandoned, []byte("late forward"))
	p.expect(tReply, abandoned, nil) // immediate and empty: nobody is waiting for a real answer
	if exchanged != 0 {
		t.Fatalf("the exchange with Unbound ran %d times for an abandoned id, want 0", exchanged)
	}

	d.mu.Lock()
	d.nextID = abandoned - 1 // the id counter has wrapped around to the abandoned id
	d.mu.Unlock()
	next := decide(d, context.Background(), "192.0.2.11", []byte("fresh"), noForward(t))
	_, fresh, _ := p.recv()
	if fresh == abandoned {
		t.Fatalf("a new QUERY reused id %d while the decider still owes its ANSWER/DROP", abandoned)
	}
	p.send(tAnswer, fresh, []byte("fresh answer"))
	result(t, next)
}

func TestLateFinalFrameFreesTheAbandonedIdAndIsDiscarded(t *testing.T) {
	d, p, logs := readyPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := decide(d, ctx, "192.0.2.10", []byte("slow"), noForward(t))
	_, abandoned, _ := p.recv()
	cancel()
	result(t, out)

	// A second query is the ordering barrier: the reader handles frames in order, so once it has finished,
	// it has already handled the late ANSWER sent before it.
	barrier := decide(d, context.Background(), "192.0.2.12", []byte("barrier"), noForward(t))
	_, barrierID, _ := p.recv()
	p.send(tAnswer, abandoned, []byte("late answer, nobody waits"))
	p.send(tAnswer, barrierID, []byte("barrier answer"))
	if r := result(t, barrier); string(r.answer) != "barrier answer" {
		t.Fatalf("barrier query got %q", r.answer)
	}

	d.mu.Lock()
	d.nextID = abandoned - 1
	d.mu.Unlock()
	again := decide(d, context.Background(), "192.0.2.13", []byte("again"), noForward(t))
	_, reused, _ := p.recv()
	if reused != abandoned {
		t.Fatalf("after the late final frame the id %d must be free again, got a QUERY with id %d", abandoned, reused)
	}
	p.send(tDrop, reused, nil)
	result(t, again)
	if logs.count() != 0 {
		t.Fatalf("a late final frame is not an error, but the gateway logged: %s", logs.joined())
	}
}

// G7: frames for an id the gateway does not track are ignored and the session goes on.
func TestFramesForUnknownIdsAreIgnored(t *testing.T) {
	d, p, logs := readyPeer(t)
	held := decide(d, context.Background(), "192.0.2.10", []byte("held"), noForward(t))
	_, heldID, _ := p.recv()

	p.send(tForward, 424242, []byte("forward for nobody"))
	p.send(tAnswer, 424242, []byte("answer for nobody"))
	p.send(tDrop, 424242, nil)
	p.send(tAnswer, heldID, []byte("held answer")) // the reader has handled everything before this once Decide returns
	if r := result(t, held); string(r.answer) != "held answer" {
		t.Fatalf("held query got %q", r.answer)
	}

	next := decide(d, context.Background(), "192.0.2.11", []byte("next"), noForward(t))
	typ, id, _ := p.recv() // a stray REPLY for the unknown FORWARD would be read here instead of the QUERY
	if typ != tQuery {
		t.Fatalf("the next frame from the gateway has type %d, want QUERY: it answered a FORWARD for an unknown id", typ)
	}
	p.send(tAnswer, id, []byte("still serving"))
	if r := result(t, next); r.err != nil || string(r.answer) != "still serving" {
		t.Fatalf("session after unknown-id frames: got answer=%q err=%v", r.answer, r.err)
	}
	if logs.count() != 0 {
		t.Fatalf("unknown ids are not an error, but the gateway logged: %s", logs.joined())
	}
}

// A FORWARD that arrives while the previous one is unanswered breaks "one REPLY before the next FORWARD": it is
// ignored, never queued behind the first.
func TestForwardBeforeThePreviousReplyIsIgnored(t *testing.T) {
	d, p, _ := readyPeer(t)
	release := make(chan struct{})
	var mu sync.Mutex
	var asked []string
	fwd := func(_ context.Context, wire []byte) []byte {
		mu.Lock()
		asked = append(asked, string(wire))
		mu.Unlock()
		<-release
		return append([]byte("r:"), wire...)
	}
	out := decide(d, context.Background(), "192.0.2.10", []byte("q"), fwd)
	_, id, _ := p.recv()
	other := decide(d, context.Background(), "192.0.2.11", []byte("o"), noForward(t))
	_, otherID, _ := p.recv()
	p.send(tForward, id, []byte("one"))
	p.send(tForward, id, []byte("two"))
	p.send(tForward, id, []byte("three"))
	p.send(tAnswer, otherID, []byte("barrier")) // once this query returns, the reader has handled the FORWARDs above
	result(t, other)
	close(release)
	p.expect(tReply, id, []byte("r:one"))
	p.send(tDrop, id, nil)
	result(t, out)

	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != "one" {
		t.Fatalf("exchanges run: got %q, want only [one]", asked)
	}
	next := decide(d, context.Background(), "192.0.2.12", []byte("n"), noForward(t))
	if typ, _, _ := p.recv(); typ != tQuery { // a second REPLY for the ignored FORWARDs would be read here
		t.Fatalf("the next frame from the gateway has type %d, want QUERY: it answered an ignored FORWARD", typ)
	}
	_ = next
}

// G6c: the decider going away is a failure of the whole session, for waiting and later queries alike.
func TestDeciderEOFEndsTheSessionWithAnError(t *testing.T) {
	d, p, logs := readyPeer(t)
	waiting := decide(d, context.Background(), "192.0.2.10", []byte("q"), noForward(t))
	p.recv()
	_ = p.conn.Close()
	waitClosed(t, d.Done(), "session end after EOF")
	if r := result(t, waiting); r.err == nil {
		t.Fatal("a query in flight when the decider exited must fail, got no error")
	}
	var protoErr protocolError
	if err := d.Err(); err == nil || errors.As(err, &protoErr) {
		t.Fatalf("EOF is a failure but not a protocol error: got %v", err)
	}
	if r := result(t, decide(d, context.Background(), "192.0.2.11", []byte("q"), noForward(t))); r.err == nil {
		t.Fatal("Decide after the session ended must fail at once, got no error")
	}
	if !strings.Contains(logs.joined(), "decider") {
		t.Fatalf("EOF must be logged, got %q", logs.joined())
	}
}

func TestDeciderResetEndsTheSessionWithAnError(t *testing.T) {
	d, p, _ := readyPeer(t)
	waiting := decide(d, context.Background(), "192.0.2.10", []byte("q"), noForward(t))
	// The peer closes with the QUERY unread: an AF_UNIX stream then reports a reset (not EOF) to the other end.
	_ = p.conn.Close()
	waitClosed(t, d.Done(), "session end after the peer closed")
	if d.Err() == nil {
		t.Fatal("Err() is nil after the decider closed the socket")
	}
	if r := result(t, waiting); r.err == nil {
		t.Fatal("a query in flight when the decider vanished must fail, got no error")
	}
}

func TestCloseEndsTheSessionQuietlyAndTheDeciderSeesEOF(t *testing.T) {
	d, p, logs := readyPeer(t)
	d.Close()
	_ = p.conn.SetReadDeadline(time.Now().Add(watchdog))
	if n, err := p.conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the decider's end after Close: read %d bytes, err=%v, want io.EOF", n, err)
	}
	waitClosed(t, d.Done(), "session end after Close")
	if logs.count() != 0 {
		t.Fatalf("a requested close is not an error, but the gateway logged: %s", logs.joined())
	}
}

// G8 (in-process): malformed framing from the decider is fatal for the session.
func TestProtocolViolationsFromTheDeciderAreFatal(t *testing.T) {
	over := make([]byte, 65536)
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"length below 5", []byte{0, 0, 0, 4}, "length"},
		{"length above the maximum", binary.BigEndian.AppendUint32(nil, maxFrameBytes+1), "length"},
		{"unknown type 0x00", pack(0, 1, nil), "type"},
		{"unknown type 0x07", pack(7, 1, nil), "type"},
		{"unknown type 0xff", pack(0xff, 1, nil), "type"},
		{"QUERY from the decider", pack(tQuery, 1, queryPayload(0, "192.0.2.1", nil)), "not valid from the decider"},
		{"REPLY from the decider", pack(tReply, 1, nil), "not valid from the decider"},
		{"ANSWER with an empty payload", pack(tAnswer, 1, nil), "empty"},
		{"ANSWER larger than a DNS message", pack(tAnswer, 1, over), "65535"},
		{"FORWARD larger than a DNS message", pack(tForward, 1, over), "65535"},
		{"READY with an id", pack(tReady, 5, nil), "READY"},
		{"READY with a payload", pack(tReady, 0, []byte("x")), "READY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p, logs := readyPeer(t)
			waiting := decide(d, context.Background(), "192.0.2.10", []byte("q"), noForward(t))
			p.recv()
			p.sendRaw(c.raw)
			waitClosed(t, d.Done(), "session end after a protocol error")
			var protoErr protocolError
			if err := d.Err(); !errors.As(err, &protoErr) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Err(): got %v, want a protocolError mentioning %q", err, c.want)
			}
			if !strings.Contains(logs.joined(), "decision protocol error:") {
				t.Fatalf("log must start the line with %q, got %q", "decision protocol error:", logs.joined())
			}
			if r := result(t, waiting); r.err == nil {
				t.Fatal("the query in flight must fail with the session")
			}
			_ = p.conn.SetReadDeadline(time.Now().Add(watchdog))
			if _, err := io.Copy(io.Discard, p.conn); err != nil { // the gateway closed the socket: the decider reads EOF
				t.Fatalf("the gateway must close the socket after a protocol error: %v", err)
			}
		})
	}
}

func TestSecondReadyIsAProtocolError(t *testing.T) {
	d, p, _ := readyPeer(t)
	p.send(tReady, 0, nil)
	waitClosed(t, d.Done(), "session end after a second READY")
	var protoErr protocolError
	if err := d.Err(); !errors.As(err, &protoErr) || !strings.Contains(err.Error(), "READY") {
		t.Fatalf("Err(): got %v, want a protocolError mentioning READY", err)
	}
}

// A decider that stops reading must not wedge every query behind one blocked write.
func TestWriteThatCannotCompleteEndsTheSession(t *testing.T) {
	d, _, logs := readyPeer(t)
	d.writeTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	big := make([]byte, 65535)
	var wg sync.WaitGroup
	for range 64 { // far more than the socket buffer holds; the peer never reads
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = d.Decide(ctx, netip.MustParseAddr("192.0.2.10"), false, big, noForward(t))
		}()
	}
	waitClosed(t, d.Done(), "session end after a write timeout")
	wg.Wait()
	if d.Err() == nil || !strings.Contains(logs.joined(), "decider") {
		t.Fatalf("a stuck write must fail the session and be logged: err=%v log=%q", d.Err(), logs.joined())
	}
}
