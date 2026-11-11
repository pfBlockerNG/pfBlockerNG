// Ported from Frontend.serve_observer, Frontend.stop (its observer half) and _serve_observer of
// src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py (removed in #3791): the Unix datagram socket pfb_upstream_observer.py reports
// Unbound's upstream blocks on. What a datagram means is pfb_dns_proxy_observer.go's.
package decider

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	observerSocketName = "pfb_upstream.sock" // in the module directory; pfb_upstream_observer.py SOCKET
	observerRcvbuf     = 256 * 1024          // OBSERVER_RCVBUF: bytes asked for the socket, so a burst queues in it
	// observerReadBuffer is far over maxReportBytes, so that a datagram is read whole and an oversize report is refused
	// by its real length, as Python's is (asyncio reads up to 256 KiB).
	observerReadBuffer = 64 * 1024
)

// observerPublish gives the bound socket its final name: a hard link, which fails with EEXIST rather than replace what is
// there. A variable so that a test can look at what it publishes, or act between the lstat and the publish.
var observerPublish = os.Link

// observerSocket is the listening socket and the goroutine reading it.
type observerSocket struct {
	conn *net.UnixConn
	path string
	done chan struct{} // closed when the reader has ended
}

// listenObserver listens on <dir>/pfb_upstream.sock with mode 0600, so that only its owner (the user Unbound runs as) can
// report. A socket left by a previous proxy is replaced; anything else at the path (a symlink is not a socket: lstat) is an
// error and is left alone.
//
// The socket is never reachable with a wider mode: it is bound in a fresh 0700 directory inside dir, restricted there, and
// published onto its path by a hard link (#3511). A bind followed by a chmod would leave it open for the time between; a
// process-wide umask would change the mode of what every other goroutine creates. The link, unlike a rename, never
// replaces: whatever appears at the path after the lstat (EEXIST) is an error naming the path, and is left alone. The
// temporary name is then removed with its directory; the socket stays reachable through the final name, the same inode.
func (f *Frontend) listenObserver(dir string) (*observerSocket, error) {
	path := filepath.Join(dir, observerSocketName)
	switch info, err := os.Lstat(path); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case info.Mode().Type() != fs.ModeSocket:
		return nil, fmt.Errorf("%s exists and is not a socket", observerSocketName)
	default:
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}

	private, err := os.MkdirTemp(dir, ".pfb_upstream-") // mode 0700
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(private) // the temporary name goes, and with it the directory; the final name is the same inode
	bound := filepath.Join(private, "s")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: bound, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	for _, step := range []func() error{
		func() error { return os.Chmod(bound, 0o600) }, // still private: nobody else can reach the directory
		func() error { return conn.SetReadBuffer(observerRcvbuf) },
		func() error { return observerPublish(bound, path) },
	} {
		if err := step(); err != nil {
			conn.Close()
			return nil, err
		}
	}

	o := &observerSocket{conn: conn, path: path, done: make(chan struct{})}
	go func() {
		defer close(o.done)
		buf := make([]byte, observerReadBuffer)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					logErr(fmt.Sprintf("upstream-block detection stopped: %v", err))
				}
				return
			}
			f.relaySafely(buf[:n])
		}
	}()
	return o, nil
}

// relaySafely is relayUpstreamResponse that a datagram cannot take the process down through: Python's asyncio logs an
// exception of datagram_received and reads on.
func (f *Frontend) relaySafely(data []byte) {
	defer func() {
		if v := recover(); v != nil {
			logErr(fmt.Sprintf("upstream report handler failed: %v", v))
		}
	}()
	f.relayUpstreamResponse(data)
}

// close stops listening: the socket closes, its reader is waited for (at most watcherStopWait, as a watcher is), and its
// path is unlinked.
// shortcut: a reader still running past the bound may relay one more report while the module deinits (relaySafely
// contains a panic from that), wait for it without a bound if a report ever has to be kept out of a closing module.
func (o *observerSocket) close() {
	o.conn.Close()
	timer := time.NewTimer(watcherStopWait)
	defer timer.Stop()
	select {
	case <-o.done:
	case <-timer.C:
		logWarn(fmt.Sprintf("[pfBlockerNG]: observer socket reader did not stop within %s, going on", watcherStopWait))
	}
	os.Remove(o.path) // a path that is gone already is no error
}
