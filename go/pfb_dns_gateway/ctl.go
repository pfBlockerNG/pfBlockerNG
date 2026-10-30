package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// The control socket is how root reaches the gateway once the gateway no longer is root: a Unix stream socket in a
// directory only root can enter, bound before the privilege drop and kept after it, in every mode. One message per
// connection, starting with 4 bytes: FF FF FF FF (nothing after it) restarts the decider; FF FF FF FE adds and FF FF FF FD
// removes a listener, each followed by a 4-byte big-endian length (1 to 256) and `<kind> <host:port>`, an add carrying
// its sockets as SCM_RIGHTS (see listeners.go); anything else is the big-endian length of the PEM that follows (the
// certificate, the CAs after it, the key), which replaces the TLS certificate. One reply line, `ok` or `error: <reason>`.
// Whoever is not root, by the kernel's credential of the peer, is closed on without a byte read from it. Descriptors that
// come with anything but an add that is taken are closed.

const (
	defaultCtlSocket   = "/var/run/pfb_dns/ctl.sock"
	ctlMaxPEM          = 64 << 10 // a chain of a few certificates and a key are a few KiB
	ctlMaxListener     = 256      // `<kind> <host:port>`: the longest is 7 + 1 + 47 bytes
	ctlRestart         = 0xffffffff
	ctlAdd             = 0xfffffffe // above ctlMaxPEM, so that no certificate's length is one
	ctlRemove          = 0xfffffffd
	ctlRightsRoom      = 8 // descriptors one read takes: an add carries 2
	defaultCtlDeadline = 5 * time.Second
)

// ctlUID is the only user whose pushes are taken. A test that runs the gateway as the user running the tests sets it.
var ctlUID uint32

type ctlServer struct {
	ln        *net.UnixListener
	path      string
	certs     *certStore // nil when no TLS transport is served: a push is refused
	logf      func(format string, args ...any)
	peerUID   func(*net.UnixConn) (uint32, error) // the kernel's credential of the peer; a test replaces it
	deadline  time.Duration                       // for reading the message, and again for writing the reply
	refusing  atomic.Bool                         // set when a burst of refusals is logged, cleared by the next push taken
	restart   func() error                        // the decider restart; start() sets it
	listeners *listenerSet                        // what an add or remove changes; start() sets it. nil in a test of the PEM alone: no add or remove may be sent to it (a nil set would panic)
}

// bindCtl makes path's directory private to the user running the gateway (root), replaces what an earlier gateway left at
// path, and listens there: the directory 0700 and the socket 0600, so that nobody else can even connect.
func bindCtl(path string, certs *certStore, logf func(format string, args ...any)) (*ctlServer, error) {
	if err := privateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return nil, fmt.Errorf("control socket %s is a directory", path)
		}
		if err := os.Remove(path); err != nil { // an earlier gateway could not remove it after its privilege drop
			return nil, fmt.Errorf("cannot replace the old control socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("control socket %s: %w", path, reason(err))
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("cannot listen on the control socket: %w", reason(err))
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("cannot make the control socket private: %w", reason(err))
	}
	return &ctlServer{ln: ln, path: path, certs: certs, logf: logf, peerUID: peerUID, deadline: defaultCtlDeadline}, nil
}

// privateDir creates dir 0700 or checks the one that is there: a real directory of the user running the gateway, closed to
// 0700 when it was left open. A key must not go through a directory that someone else owns or can replace.
func privateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("cannot create %s: %w", dir, reason(err))
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, reason(err))
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by the user running the gateway", dir)
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("cannot make %s private: %w", dir, reason(err))
		}
	}
	return nil
}

// serve takes pushes until stop(). One connection at a time: each is bounded by the deadline, and only root is let in.
func (c *ctlServer) serve(g *gateway) {
	g.closeOnStop(func() { _ = c.ln.Close() })
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := c.ln.AcceptUnix()
			if err != nil {
				if g.shuttingDown(err) {
					return
				}
				c.logf("control socket: accept: %v", err)
				g.pause()
				continue
			}
			c.handle(conn)
		}
	}()
}

func (c *ctlServer) handle(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(c.deadline))
	uid, err := c.peerUID(conn)
	if err != nil || uid != ctlUID {
		if c.refusing.CompareAndSwap(false, true) {
			if err != nil {
				c.logf("control socket: refused a connection whose credential cannot be read: %v", err)
			} else {
				c.logf("control socket: refused a connection from uid %d: only uid %d may push", uid, ctlUID)
			}
		}
		return
	}
	c.refusing.Store(false)
	in := &ctlInput{conn: conn, oob: make([]byte, syscall.CmsgSpace(4*ctlRightsRoom))}
	defer in.closeRights()      // before the connection is closed: the sender sees its sockets go
	reply := func(msg string) { // its own deadline: the read that failed may have used up the first
		_ = conn.SetWriteDeadline(time.Now().Add(c.deadline))
		_, _ = conn.Write([]byte(strings.ReplaceAll(msg, "\n", " ") + "\n"))
	}
	var head [4]byte
	if _, err := io.ReadFull(in, head[:]); err != nil {
		reply("error: no message: " + reason(err).Error())
		return
	}
	n := binary.BigEndian.Uint32(head[:])
	switch n {
	case ctlRestart:
		if err := c.restart(); err != nil {
			reply("error: " + err.Error())
			return
		}
		reply("ok")
		return
	case ctlAdd, ctlRemove:
		reply(c.listeners.change(n == ctlAdd, in))
		return
	}
	if n == 0 || n > ctlMaxPEM {
		reply(fmt.Sprintf("error: a message of %d bytes is not between 1 and %d", n, ctlMaxPEM))
		return
	}
	pem := make([]byte, n)
	if got, err := io.ReadFull(in, pem); err != nil {
		reply(fmt.Sprintf("error: the message ended after %d of %d bytes: %v", got, n, reason(err)))
		return
	}
	if c.certs == nil {
		reply("error: no TLS transport is served, so there is no certificate to replace")
		return
	}
	if err := c.certs.push(pem); err != nil {
		reply("error: " + err.Error())
		return
	}
	reply("ok")
}

// ctlInput is the connection read with recvmsg, so that a descriptor riding with any byte of the message is found and
// owned here: whatever no verb takes is closed when the handler ends. Descriptors on bytes never read are the kernel's.
type ctlInput struct {
	conn *net.UnixConn
	oob  []byte
	fds  []int // received and neither taken nor closed yet
	cut  bool  // the kernel dropped control data that did not fit oob, or it did not parse
}

func (in *ctlInput) Read(p []byte) (int, error) {
	n, oobn, flags, _, err := in.conn.ReadMsgUnix(p, in.oob)
	in.cut = in.cut || flags&syscall.MSG_CTRUNC != 0
	msgs, perr := syscall.ParseSocketControlMessage(in.oob[:oobn])
	in.cut = in.cut || perr != nil
	for i := range msgs {
		if fds, err := syscall.ParseUnixRights(&msgs[i]); err == nil {
			in.fds = append(in.fds, fds...)
		}
	}
	return max(n, 0), err // recvmsg's n is -1 on a timeout: an io.Reader's is not
}

func (in *ctlInput) closeRights() {
	for _, fd := range in.fds {
		_ = syscall.Close(fd)
	}
	in.fds = nil
}
