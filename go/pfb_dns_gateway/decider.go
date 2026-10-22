package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// issue #3513: the decision protocol of docs/misc/dns-gateway-protocol.md (gateway side).
const (
	frameQuery byte = 1 + iota
	frameForward
	frameReply
	frameAnswer
	frameDrop
	frameReady
)

const (
	maxFrameLen         = 5 + 1 + 1 + 255 + 65535 // type + id, then transport + n + IP text + DNS wire
	maxWire             = 65535
	defaultWriteTimeout = 10 * time.Second
	// Ids reserved at once, in flight or abandoned until the decider's final frame. Live queries top out at 1536 (512 UDP,
	// 512 DoH and DoQ, 4 for each of 128 TCP and DoT connections); the rest is room for abandoned ones.
	maxOutstanding = 4096
)

// protocolError is a framing violation: the session cannot be trusted any further.
type protocolError string

func (e protocolError) Error() string { return string(e) }

var errDeciderClosed = errors.New("decision socket closed by the gateway")
var errDeciderBusy = errors.New("decider has too many queries outstanding")
var errDeciderRetired = errors.New("decider replaced by a restart")

// writeFrame sends the frame with one Write, so concurrent callers cannot interleave bytes.
func writeFrame(w io.Writer, typ byte, id uint32, payload []byte) error {
	buf := make([]byte, 9+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(5+len(payload)))
	buf[4] = typ
	binary.BigEndian.PutUint32(buf[5:], id)
	copy(buf[9:], payload)
	_, err := w.Write(buf)
	return err
}

// readFrame returns io.EOF at a frame boundary, io.ErrUnexpectedEOF inside a frame, and a protocolError for a bad
// length (checked before any payload is read) or an unknown type.
func readFrame(r io.Reader) (typ byte, id uint32, payload []byte, err error) {
	var head [9]byte
	if _, err = io.ReadFull(r, head[:4]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:4])
	if n < 5 || n > maxFrameLen {
		return 0, 0, nil, protocolError(fmt.Sprintf("frame length %d outside 5..%d", n, maxFrameLen))
	}
	if _, err = io.ReadFull(r, head[4:]); err != nil {
		return 0, 0, nil, unexpected(err)
	}
	typ, id = head[4], binary.BigEndian.Uint32(head[5:])
	if typ < frameQuery || typ > frameReady {
		return 0, 0, nil, protocolError(fmt.Sprintf("unknown frame type 0x%02x", typ))
	}
	payload = make([]byte, n-5)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, unexpected(err)
	}
	return typ, id, payload, nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// newSocketpair returns an AF_UNIX stream pair: the gateway's end as a net.Conn and the decider's as the file to
// hand to the child as fd 3.
func newSocketpair() (parent net.Conn, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentFile, childFile := os.NewFile(uintptr(fds[0]), "decision-gateway"), os.NewFile(uintptr(fds[1]), "decision-decider")
	parent, err = net.FileConn(parentFile) // FileConn dups the descriptor
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		return nil, nil, fmt.Errorf("decision socket: %w", err)
	}
	return parent, childFile, nil
}

// forwarder sends one wire to Unbound as the client and returns Unbound's reply; nil means none.
type forwarder func(ctx context.Context, wire []byte) []byte

// call is one query between its QUERY and the decider's ANSWER or DROP.
type call struct {
	forward chan []byte // at most one FORWARD is outstanding, so one slot never blocks the reader
	final   chan []byte // the ANSWER wire, nil for DROP; written once, by the reader

	mu        sync.Mutex
	busy      bool // a FORWARD was accepted and its REPLY not yet sent
	abandoned bool // the gateway stopped waiting; the id stays reserved until the final frame
}

// deliver hands a FORWARD to the waiting query. A FORWARD that arrives while the previous one is unanswered
// is ignored; for an abandoned query the caller answers with an empty REPLY.
func (c *call) deliver(wire []byte) (abandoned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.abandoned {
		return true
	}
	if !c.busy {
		c.busy = true
		c.forward <- wire
	}
	return false
}

func (c *call) answered() { c.mu.Lock(); c.busy = false; c.mu.Unlock() }

// abandon marks the query as given up and reports whether a delivered FORWARD was never picked up.
func (c *call) abandon() (unanswered bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.abandoned = true
	select {
	case <-c.forward:
		return true
	default:
		return false
	}
}

// abandon gives the query up: a FORWARD that reached it but was never picked up gets its empty REPLY at once, or
// the decider would wait for it until its own timeout.
func (d *Decider) abandon(id uint32, c *call) {
	if c.abandon() {
		_ = d.send(frameReply, id, nil)
	}
}

// Decider is the gateway's end of the decision socket: one reader goroutine multiplexes the queries in flight.
type Decider struct {
	conn         net.Conn
	logf         func(format string, args ...any)
	writeTimeout time.Duration
	ready, done  chan struct{}

	wmu sync.Mutex // serialises frame writes and their deadlines

	mu       sync.Mutex
	calls    map[uint32]*call
	nextID   uint32
	err      error
	closing  bool
	retired  bool          // a restart replaced it: the queries it holds finish, no new one registers
	capHit   bool          // the burst over maxOutstanding is logged; cleared when the table drains
	idle     chan struct{} // see drained; made by its first caller
	finished func()        // test seam, read under mu: finish calls it once it has updated the table and released mu
}

// NewDecider starts reading conn; READY, failure and queries are observed through the methods below.
func NewDecider(conn net.Conn, logf func(format string, args ...any)) *Decider {
	d := &Decider{
		conn: conn, logf: logf, writeTimeout: defaultWriteTimeout,
		ready: make(chan struct{}), done: make(chan struct{}), calls: map[uint32]*call{},
	}
	go d.read()
	return d
}

// Ready is closed when the decider has sent READY.
func (d *Decider) Ready() <-chan struct{} { return d.ready }

// Done is closed when the session ended: EOF, a reset, a protocol error, a stuck write, or Close.
func (d *Decider) Done() <-chan struct{} { return d.done }

// Err says why the session ended; nil until Done is closed.
func (d *Decider) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// Close ends the session; the decider reads EOF and exits.
func (d *Decider) Close() {
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()
	_ = d.conn.Close()
}

// fail ends the session with err, once. The reason is logged before Done is closed, so whoever sees Done has
// the log line too.
func (d *Decider) fail(err error) {
	d.mu.Lock()
	if d.err == nil {
		if d.closing {
			err = errDeciderClosed
		} else {
			d.logFailure(err)
		}
		d.err = err
		close(d.done)
	}
	d.mu.Unlock()
	_ = d.conn.Close()
}

func (d *Decider) logFailure(err error) {
	var protoErr protocolError
	switch {
	case errors.As(err, &protoErr):
		d.logf("decision protocol error: %v", err)
	case errors.Is(err, io.EOF):
		d.logf("decider closed the decision socket")
	default:
		d.logf("decider socket: %v", err)
	}
}

func (d *Decider) send(typ byte, id uint32, payload []byte) error {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	_ = d.conn.SetWriteDeadline(time.Now().Add(d.writeTimeout))
	if err := writeFrame(d.conn, typ, id, payload); err != nil {
		d.fail(fmt.Errorf("write: %w", err))
		return err
	}
	return nil
}

func (d *Decider) lookup(id uint32) *call {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[id]
}

// finish hands the call its final frame before it leaves the table: an empty table lets the retirement close the session,
// and the answer must be in the call by then. final holds one and is sent to once, so the send under mu never blocks.
func (d *Decider) finish(id uint32, answer []byte) {
	d.mu.Lock()
	if c := d.calls[id]; c != nil {
		c.final <- answer
		delete(d.calls, id)
	}
	if len(d.calls) == 0 {
		d.capHit = false
		d.closeIdle()
	}
	hook := d.finished
	d.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// markRetired makes every later register fail with errDeciderRetired, so the drain waits only for what it holds.
func (d *Decider) markRetired() {
	d.mu.Lock()
	d.retired = true
	d.mu.Unlock()
}

// drained is closed once no query is outstanding (at once when none is); only a retired decider waits on it.
func (d *Decider) drained() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.idle == nil {
		d.idle = make(chan struct{})
		if len(d.calls) == 0 {
			d.closeIdle()
		}
	}
	return d.idle
}

// closeIdle closes idle, once, if drained was asked for; d.mu is held.
func (d *Decider) closeIdle() {
	if d.idle == nil {
		return
	}
	select {
	case <-d.idle:
	default:
		close(d.idle)
	}
}

func (d *Decider) read() {
	readySeen := false
	for {
		typ, id, payload, err := readFrame(d.conn)
		if err != nil {
			d.fail(err)
			return
		}
		switch typ {
		case frameReady:
			if readySeen || id != 0 || len(payload) != 0 {
				d.fail(protocolError("READY must be sent once, with id 0 and no payload"))
				return
			}
			readySeen = true
			close(d.ready)
		case frameForward:
			if len(payload) > maxWire {
				d.fail(protocolError(fmt.Sprintf("FORWARD wire of %d bytes exceeds %d", len(payload), maxWire)))
				return
			}
			if c := d.lookup(id); c != nil && c.deliver(payload) {
				_ = d.send(frameReply, id, nil)
			}
		case frameAnswer:
			if len(payload) == 0 {
				d.fail(protocolError("ANSWER with an empty payload (a decider that sends nothing sends DROP)"))
				return
			}
			if len(payload) > maxWire {
				d.fail(protocolError(fmt.Sprintf("ANSWER wire of %d bytes exceeds %d", len(payload), maxWire)))
				return
			}
			d.finish(id, payload)
		case frameDrop:
			d.finish(id, nil)
		default:
			d.fail(protocolError(fmt.Sprintf("frame type 0x%02x is not valid from the decider", typ)))
			return
		}
	}
}

// register reserves an id no unfinished query holds, 0 (READY's) excepted.
func (d *Decider) register(c *call) (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.retired { // before done: the retirement closes it, and the query belongs to the active decider either way
		return 0, errDeciderRetired
	}
	select {
	case <-d.done:
		return 0, d.err
	default:
	}
	if len(d.calls) >= maxOutstanding {
		if !d.capHit {
			d.capHit = true
			d.logf("%d decider queries outstanding: answering new ones SERVFAIL until they finish", maxOutstanding)
		}
		return 0, errDeciderBusy
	}
	for {
		d.nextID++
		if _, busy := d.calls[d.nextID]; d.nextID != 0 && !busy {
			break
		}
	}
	d.calls[d.nextID] = c
	return d.nextID, nil
}

// Transport byte of a QUERY: what kind of client asked. A datagram client (plain UDP) has a size limit the decider
// holds its own answers to; every other client (TCP, DoT, DoH, DoQ) has none.
const (
	clientStream   byte = 0
	clientDatagram byte = 1
)

// Decide sends the query to the decider and serves its FORWARDs through fwd until it answers: the ANSWER wire,
// or nil for DROP. datagram says the client is a plain-UDP one. ctx ending abandons the query; the id stays reserved
// until the decider's final frame.
func (d *Decider) Decide(ctx context.Context, client netip.Addr, datagram bool, wire []byte, fwd forwarder) ([]byte, error) {
	c := &call{forward: make(chan []byte, 1), final: make(chan []byte, 1)}
	id, err := d.register(c)
	if err != nil {
		return nil, err
	}
	ip := client.String()
	transport := clientStream
	if datagram {
		transport = clientDatagram
	}
	if err := d.send(frameQuery, id, append(append([]byte{transport, byte(len(ip))}, ip...), wire...)); err != nil {
		return nil, err
	}
	for {
		select {
		case request := <-c.forward:
			reply := fwd(ctx, request)
			c.answered()
			if err := d.send(frameReply, id, reply); err != nil {
				return c.delivered(err)
			}
		case answer := <-c.final:
			return answer, nil
		case <-ctx.Done():
			d.abandon(id, c)
			return nil, ctx.Err()
		case <-d.done:
			return c.delivered(d.Err())
		}
	}
}

// delivered is the answer the decider already gave, else err: a session that ends after the final frame (a retired decider
// is closed as its last answer lands) does not take the answer with it.
func (c *call) delivered(err error) ([]byte, error) {
	select {
	case answer := <-c.final:
		return answer, nil
	default:
		return nil, err
	}
}
