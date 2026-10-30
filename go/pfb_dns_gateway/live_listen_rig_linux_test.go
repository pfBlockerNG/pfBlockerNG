package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// Root hands the running gateway a listener it bound itself: `FF FF FF FE` adds one, `FF FF FF FD` removes one, each then a
// 4-byte big-endian length (1 to 256) and `<kind> <host:port>`; an add carries its sockets as SCM_RIGHTS in the same sendmsg.
// Linux only: the rows count the process's descriptors in /proc/self/fd and make raw sockets.

var (
	liveAdd    = []byte{0xff, 0xff, 0xff, 0xfe}
	liveRemove = []byte{0xff, 0xff, 0xff, 0xfd}
)

const liveFront = "127.0.0.9" // a DoH front end the rig's start trusts

func liveFrame(verb []byte, body string) []byte {
	return append(append(slices.Clone(verb), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...), body...)
}

func liveNet(proto string, ap netip.AddrPort) string {
	if ap.Addr().Is4() {
		return proto + "4"
	}
	return proto + "6"
}

func liveHasV6() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		_ = l.Close()
	}
	return err == nil
}

// liveNeedAddr skips a row on an address the host cannot bind (no IPv6 loopback), as the readiness test does.
func liveNeedAddr(t *testing.T, host string) netip.Addr {
	t.Helper()
	addr := netip.MustParseAddr(host)
	if addr.Is6() && !liveHasV6() {
		t.Skip("no IPv6 loopback on this host")
	}
	return addr
}

// liveFreePorts returns n ports that are free for TCP and UDP on every address the rows bind, and differ from each other.
func liveFreePorts(t *testing.T, n int) []int {
	t.Helper()
	hosts := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	if liveHasV6() {
		hosts = append(hosts, "::1")
	}
	var held []io.Closer
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	var ports []int
	for attempt := 0; len(ports) < n; attempt++ {
		if attempt == 500 {
			t.Fatal("no port is free on every address the rows bind")
		}
		probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()
		var got []io.Closer
		ok := true
		for _, h := range hosts {
			hp := net.JoinHostPort(h, strconv.Itoa(port))
			l, errTCP := net.Listen("tcp", hp)
			p, errUDP := net.ListenPacket("udp", hp)
			if errTCP == nil {
				got = append(got, l)
			}
			if errUDP == nil {
				got = append(got, p)
			}
			ok = ok && errTCP == nil && errUDP == nil
		}
		if ok {
			held, ports = append(held, got...), append(ports, port)
		} else {
			for _, c := range got {
				_ = c.Close()
			}
		}
	}
	return ports
}

// Raw sockets: a row has to be able to hand over a socket that is unbound, bound elsewhere or not listening.

func liveSockaddr(ap netip.AddrPort) (int, syscall.Sockaddr) {
	if ap.Addr().Is4() {
		return syscall.AF_INET, &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	return syscall.AF_INET6, &syscall.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
}

// liveSocket is a socket of typ bound to ap (unbound and IPv4 when ap is the zero value), listening when listen is set.
// Reuse is on, so that a row can hand over a second socket on an address that one is already serving.
func liveSocket(t *testing.T, typ int, ap netip.AddrPort, listen bool) int {
	t.Helper()
	family, sa := syscall.AF_INET, syscall.Sockaddr(nil)
	if ap.IsValid() {
		family, sa = liveSockaddr(ap)
	}
	fd, err := syscall.Socket(family, typ|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []int{syscall.SO_REUSEADDR, unix.SO_REUSEPORT} {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, opt, 1); err != nil {
			t.Fatal(err)
		}
	}
	if sa != nil {
		if err := syscall.Bind(fd, sa); err != nil {
			t.Fatalf("bind %s: %v", ap, err)
		}
	}
	if listen {
		if err := syscall.Listen(fd, 16); err != nil {
			t.Fatal(err)
		}
	}
	return fd
}

func liveUDP(t *testing.T, ap netip.AddrPort) int {
	return liveSocket(t, syscall.SOCK_DGRAM, ap, false)
}
func liveTCP(t *testing.T, ap netip.AddrPort) int {
	return liveSocket(t, syscall.SOCK_STREAM, ap, true)
}

// liveSockets are the sockets root would send for kind on ap: UDP then listening TCP for udp+tcp, one listening TCP socket
// for dot and doh, one UDP socket for doq.
func liveSockets(t *testing.T, kind string, ap netip.AddrPort) []int {
	t.Helper()
	switch kind {
	case "udp+tcp":
		return []int{liveUDP(t, ap), liveTCP(t, ap)}
	case "dot", "doh":
		return []int{liveTCP(t, ap)}
	case "doq":
		return []int{liveUDP(t, ap)}
	}
	t.Fatalf("no sockets for kind %q", kind)
	return nil
}

func liveDevNull(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func livePipe(t *testing.T) []int {
	t.Helper()
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	return p[:]
}

// liveUnixListener is a listening stream socket whose address is not an IP address.
func liveUnixListener(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: filepath.Join(shortTempDir(t), "s")}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	return fd
}

func liveClose(fds ...int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

func liveOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// liveRequireFDs waits for the process's descriptor count to be want: the gateway closes what it was sent, and its end of
// the connection, as the handler ends.
func liveRequireFDs(t *testing.T, want int, when string) {
	t.Helper()
	deadline := time.Now().Add(watchdog)
	for {
		got := liveOpenFDs(t)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the process holds %d descriptors, want %d: one that came over the control socket was not closed", when, got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// liveRefused requires the reply of a gateway that read the verb and said no. A gateway older than the verbs reads the
// first 4 bytes as the length of a certificate and answers with that length's error.
func liveRefused(t *testing.T, reply, row string) {
	t.Helper()
	if !strings.HasPrefix(reply, "error: ") || strings.Contains(reply, "is not between 1 and 65536") {
		t.Fatalf("%s: reply %q, want an `error: ` that gives the reason of the add or the remove, not the certificate length's", row, reply)
	}
}

// liveRig is an in-process gateway started as main starts it: every kind on 127.0.0.1 at a port of its own, the certificate
// from a file, a control socket, and liveFront trusted as a DoH front end. The ACL lets 127.0.0.0/8 and ::1 in.
type liveRig struct {
	t        *testing.T
	srv      *server
	logs     *capture
	sock     string
	cfg      config
	m        tlsMaterial // the store the clients' view of the certificate is read from, and the pool they trust
	port     map[string]int
	stranger int // a port that no kind is configured on
}

type liveOpt func(t *testing.T, cfg *config)

// liveOnly keeps the TLS kinds named and drops the others from the start's flags: a kind not given is not served.
func liveOnly(kinds ...string) liveOpt {
	return func(_ *testing.T, cfg *config) {
		if !slices.Contains(kinds, "dot") {
			cfg.dotListen = nil
		}
		if !slices.Contains(kinds, "doh") {
			cfg.dohListen = nil
		}
		if !slices.Contains(kinds, "doq") {
			cfg.doqListen = nil
		}
	}
}

// liveStranger makes the control socket's one allowed user someone else than this process: every peer here is refused.
func liveStranger() liveOpt {
	return func(t *testing.T, _ *config) {
		was := ctlUID
		ctlUID = was + 1001
		t.Cleanup(func() { ctlUID = was })
	}
}

func newLiveRig(t *testing.T, opts ...liveOpt) *liveRig {
	t.Helper()
	ports := liveFreePorts(t, 5)
	pem, m := goodPEM(t)
	cfg, logs := lifecycleConfig(t, "serve")
	conf := filepath.Join(t.TempDir(), "unbound.conf")
	if err := os.WriteFile(conf, []byte("access-control: 127.0.0.0/8 allow\naccess-control: ::1 allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.unboundConf, cfg.tlsPEM = conf, pem
	cfg.port, cfg.dotPort, cfg.dohPort, cfg.doqPort = ports[0], ports[1], ports[2], ports[3]
	cfg.dotListen, cfg.dohListen, cfg.doqListen = []string{"127.0.0.1"}, []string{"127.0.0.1"}, []string{"127.0.0.1"}
	cfg.dohTrusted = []string{liveFront + "/32"}
	cfg.ctlSocket = filepath.Join(shortTempDir(t), "run", "ctl.sock")
	for _, o := range opts {
		o(t, &cfg)
	}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.shutdown)
	return &liveRig{t: t, srv: srv, logs: logs, sock: cfg.ctlSocket, cfg: cfg, m: m, stranger: ports[4],
		port: map[string]int{"udp+tcp": ports[0], "dot": ports[1], "doh": ports[2], "doq": ports[3]}}
}

// at is host on kind's configured port.
func (r *liveRig) at(kind, host string) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(r.port[kind]))
}

func (r *liveRig) hasLine(line string) bool {
	return slices.Contains(strings.Split(r.logs.text(), "\n"), line)
}

func (r *liveRig) waitLine(line string) {
	r.t.Helper()
	eventually(r.t, "the log line "+strconv.Quote(line), func() bool { return r.hasLine(line) })
}

func (r *liveRig) countLines(prefix string) int {
	n := 0
	for _, l := range strings.Split(r.logs.text(), "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// closers is how many closers the gateway holds for stop().
func (r *liveRig) closers() int {
	r.srv.g.mu.Lock()
	defer r.srv.g.mu.Unlock()
	return len(r.srv.g.closers)
}

// countDoQClosers counts how often DoQ's closer gets as far as closing its listener. The hook is published under the
// lock the closers are registered under.
func (r *liveRig) countDoQClosers() *atomic.Int32 {
	var n atomic.Int32
	r.srv.g.mu.Lock()
	r.srv.g.doqListenerClosed = func() { n.Add(1) }
	r.srv.g.mu.Unlock()
	return &n
}

// livePart is one sendmsg: bytes and the descriptors that ride with them.
type livePart struct {
	data []byte
	fds  []int
}

// exchange writes the parts on a connection of its own, shuts the write side when eof is set, returns the reply line and
// closes the test's copies of every descriptor sent.
func (r *liveRig) exchange(eof bool, parts ...livePart) string {
	t := r.t
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: r.sock, Net: "unix"})
	if err != nil {
		t.Fatalf("dial %s: %v", r.sock, err)
	}
	defer c.Close()
	for _, p := range parts {
		defer liveClose(p.fds...)
		var oob []byte
		if len(p.fds) > 0 {
			oob = syscall.UnixRights(p.fds...)
		}
		_, _, _ = c.WriteMsgUnix(p.data, oob, nil) // a gateway that has answered and closed already is told by the reply
	}
	if eof {
		_ = c.CloseWrite()
	}
	reply := ctlReply(t, c)
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	_, _ = io.Copy(io.Discard, c) // the gateway ends the connection after its reply: its end is closed before the caller counts descriptors
	return reply
}

func (r *liveRig) send(frame []byte, fds ...int) string {
	return r.exchange(false, livePart{frame, fds})
}

func (r *liveRig) addFrame(kind string, ap netip.AddrPort) []byte {
	return liveFrame(liveAdd, kind+" "+ap.String())
}

func (r *liveRig) removeFrame(kind string, ap netip.AddrPort) []byte {
	return liveFrame(liveRemove, kind+" "+ap.String())
}

// add sends fresh sockets for kind on ap and requires the gateway to take them and say so in its log.
func (r *liveRig) add(kind string, ap netip.AddrPort) {
	t := r.t
	t.Helper()
	if got := r.send(r.addFrame(kind, ap), liveSockets(t, kind, ap)...); got != "ok" {
		t.Fatalf("add %s %s: reply %q, want ok; log:\n%s", kind, ap, got, r.logs.text())
	}
	r.waitLine("listening " + kind + " " + ap.String())
}

func (r *liveRig) remove(kind string, ap netip.AddrPort) {
	t := r.t
	t.Helper()
	if got := r.send(r.removeFrame(kind, ap)); got != "ok" {
		t.Fatalf("remove %s %s: reply %q, want ok; log:\n%s", kind, ap, got, r.logs.text())
	}
	r.waitLine("stopped listening " + kind + " " + ap.String())
}

// refuse runs one request that must be refused: the reply is an add or remove error (returned, for a row that pins the
// reason), every descriptor the row made is closed again, and the gateway reports nothing new as listening.
func (r *liveRig) refuse(row string, eof bool, build func() []livePart) string {
	t := r.t
	t.Helper()
	base, listening := liveOpenFDs(t), r.countLines("listening ")
	reply := r.exchange(eof, build()...)
	liveRefused(t, reply, row)
	liveRequireFDs(t, base, row)
	if n := r.countLines("listening "); n != listening {
		t.Fatalf("%s: %d `listening` lines before, %d after; log:\n%s", row, listening, n, r.logs.text())
	}
	return reply
}

// Probes -------------------------------------------------------------------------------------------------------------------

func liveEcho(wire []byte) []byte { return echoWithQR(seenQuery{wire: wire})[0] }

func (r *liveRig) certDER() []byte {
	r.t.Helper()
	cert, err := r.m.certs.getCertificate(nil)
	if err != nil {
		r.t.Fatal(err)
	}
	return cert.Certificate[0]
}

func (r *liveRig) requireStoreCert(who string, got []byte) {
	r.t.Helper()
	if !bytes.Equal(got, r.certDER()) {
		r.t.Fatalf("%s presented a certificate that is not the store's", who)
	}
}

// ask runs one query over kind on ap and requires the decider's echo of it, and the store's certificate for a TLS kind.
func (r *liveRig) ask(kind string, ap netip.AddrPort) {
	t := r.t
	t.Helper()
	q := buildQuery(t, 0, "example.", true)
	switch kind {
	case "udp+tcp":
		c, err := net.DialUDP(liveNet("udp", ap), nil, net.UDPAddrFromAddrPort(ap))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(q); err != nil {
			t.Fatal(err)
		}
		if got := udpReply(t, c); !bytes.Equal(got, liveEcho(q)) {
			t.Fatalf("UDP on %s: got %x, want %x", ap, got, liveEcho(q))
		}
		tc, err := net.DialTimeout(liveNet("tcp", ap), ap.String(), watchdog)
		if err != nil {
			t.Fatalf("TCP on %s: %v", ap, err)
		}
		defer tc.Close()
		tcpSend(t, tc, q)
		if got := tcpReply(t, tc); !bytes.Equal(got, liveEcho(q)) {
			t.Fatalf("TCP on %s: got %x, want %x", ap, got, liveEcho(q))
		}
	case "dot":
		c, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: watchdog}, Config: r.m.clientConfig()}).Dial(liveNet("tcp", ap), ap.String())
		if err != nil {
			t.Fatalf("DoT on %s: %v", ap, err)
		}
		defer c.Close()
		tcpSend(t, c, q)
		if got := tcpReply(t, c); !bytes.Equal(got, liveEcho(q)) {
			t.Fatalf("DoT on %s: got %x, want %x", ap, got, liveEcho(q))
		}
		r.requireStoreCert("DoT on "+ap.String(), c.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw)
	case "doh":
		c := r.doh(ap, "")
		resp, body := c.do(c.get(dnsParam(q)))
		if resp.StatusCode != 200 || !bytes.Equal(body, liveEcho(q)) {
			t.Fatalf("DoH on %s: status %d body %x, want 200 and %x", ap, resp.StatusCode, body, liveEcho(q))
		}
		r.requireStoreCert("DoH on "+ap.String(), resp.TLS.PeerCertificates[0].Raw)
	case "doq":
		c := r.doq(ap)
		if got := c.query(q); !bytes.Equal(got, withID0(liveEcho(q))) {
			t.Fatalf("DoQ on %s: got %x, want %x", ap, got, withID0(liveEcho(q)))
		}
		r.requireStoreCert("DoQ on "+ap.String(), c.conn.ConnectionState().TLS.PeerCertificates[0].Raw)
	default:
		t.Fatalf("no probe for kind %q", kind)
	}
}

// doh is a DoH client of ap, from source when given; it holds no connection after a request.
func (r *liveRig) doh(ap netip.AddrPort, source string) *dohClient {
	d := net.Dialer{Timeout: watchdog}
	if source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	tr := &http.Transport{
		TLSClientConfig:   r.m.clientConfig(),
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, liveNet("tcp", ap), ap.String())
		},
	}
	r.t.Cleanup(tr.CloseIdleConnections)
	return &dohClient{t: r.t, addr: ap, m: r.m, http: &http.Client{Transport: tr, Timeout: watchdog}}
}

func (r *liveRig) doq(ap netip.AddrPort) *doqClient {
	t := r.t
	t.Helper()
	udp, err := net.ListenUDP(liveNet("udp", ap), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(ap), doqConfig(r.m), &quic.Config{MaxIdleTimeout: time.Minute})
	if err != nil {
		t.Fatalf("DoQ connect to %s: %v", ap, err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test over") })
	return &doqClient{t: t, conn: conn}
}

// requireGone waits until nothing answers on ap for kind any more: a connection is refused, a datagram is answered with an
// ICMP error. The listener's descriptor is released when the goroutine blocked on it returns, so the first look may be early.
func (r *liveRig) requireGone(kind string, ap netip.AddrPort) {
	r.t.Helper()
	eventually(r.t, kind+" on "+ap.String()+" to stop answering", func() bool {
		switch kind {
		case "udp+tcp":
			return liveTCPRefused(ap) && liveUDPRefused(ap)
		case "dot", "doh":
			return liveTCPRefused(ap)
		}
		return liveUDPRefused(ap)
	})
}

func liveTCPRefused(ap netip.AddrPort) bool {
	c, err := net.DialTimeout(liveNet("tcp", ap), ap.String(), watchdog)
	if err == nil {
		_ = c.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func liveUDPRefused(ap netip.AddrPort) bool {
	c, err := net.DialUDP(liveNet("udp", ap), nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return false
	}
	defer c.Close()
	if _, err := c.Write(make([]byte, 12)); err != nil { // a bare DNS header: plain DNS answers it, DoQ ignores it
		return false
	}
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = c.Read(make([]byte, 512))
	return errors.Is(err, syscall.ECONNREFUSED)
}
