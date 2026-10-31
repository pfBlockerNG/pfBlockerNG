package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
)

// listenerKinds are the kinds an add or remove names, in the spelling of the readiness lines.
var listenerKinds = []string{"udp+tcp", "dot", "doh", "doq"}

// listenerSet is every listener the gateway serves, by `<kind> <host:port>`, with what an add needs to serve one more.
// start() fills it before the control socket serves; after that the control socket's goroutine is its only user.
type listenerSet struct {
	g       *gateway
	cfg     config
	certs   *certStore // nil when no TLS kind is served
	trusted []netip.Prefix
	served  map[string]func() // closeNow of each
	refused map[string]string // start-time bind refusals by key, cleared by track when the key is served
}

func newListenerSet(g *gateway, cfg config, secure *tlsListeners) *listenerSet {
	s := &listenerSet{g: g, cfg: cfg, served: map[string]func(){}}
	if secure != nil {
		s.certs = secure.certs
	}
	if len(cfg.dohListen) > 0 {
		s.trusted = parseTrusted(cfg.dohTrusted, g.logf)
	}
	return s
}

func (s *listenerSet) track(kind string, ap netip.AddrPort, closeNow func()) {
	key := kind + " " + ap.String()
	s.served[key] = closeNow
	delete(s.refused, key) // served now: the refusal the start made of key no longer stands
}

// list is the reply to the list verb: served listeners, then refusals standing, each group in key order, then ok.
func (s *listenerSet) list() string {
	var b strings.Builder
	for _, key := range slices.Sorted(maps.Keys(s.served)) {
		b.WriteString("listening " + key + "\n")
	}
	for _, key := range slices.Sorted(maps.Keys(s.refused)) {
		b.WriteString("refused " + key + " " + strings.ReplaceAll(s.refused[key], "\n", " ") + "\n")
	}
	b.WriteString("ok\n")
	return b.String()
}

// refuse records why the start's bind of kind on host:port was refused, under the key track gives that listener.
// A host that is not an IP address has no key: the start's log line says why.
func refuse(refused map[string]string, kind, host string, port int, err error) {
	ap, aerr := bindAddr(host, port)
	if aerr != nil {
		return
	}
	refused[kind+" "+ap.String()] = errors.Unwrap(err).Error() // listenError wraps the bind's own error
}

// port is the port kind is configured on, and whether this gateway serves kind at all: a TLS kind only when its listen
// address was given at start.
func (s *listenerSet) port(kind string) (port int, served bool) {
	switch kind {
	case "udp+tcp":
		return s.cfg.port, true
	case "dot":
		return s.cfg.dotPort, len(s.cfg.dotListen) > 0
	case "doh":
		return s.cfg.dohPort, len(s.cfg.dohListen) > 0
	}
	return s.cfg.doqPort, len(s.cfg.doqListen) > 0
}

// parseListener reads `<kind> <host:port>` in its one canonical spelling: netip's, with no zone, no IPv4-mapped IPv6 and
// no port 0.
func parseListener(body []byte) (kind string, ap netip.AddrPort, err error) {
	kind, hostPort, ok := strings.Cut(string(body), " ")
	if !ok || !slices.Contains(listenerKinds, kind) {
		return "", ap, fmt.Errorf("%q is not `<kind> <host:port>` with a kind of %s", body, strings.Join(listenerKinds, ", "))
	}
	ap, err = netip.ParseAddrPort(hostPort)
	if err != nil || ap.Addr().Zone() != "" || ap.Addr().Is4In6() || ap.Port() == 0 || ap.String() != hostPort {
		return "", ap, fmt.Errorf("%q is not a host:port of an IP address, in its canonical spelling, without a zone, IPv4-mapped form or port 0", hostPort)
	}
	return kind, ap, nil
}

// change takes an add (add set, the descriptors of in) or a remove and returns its reply. An add that is not taken leaves
// its descriptors with in, which closes them.
func (s *listenerSet) change(add bool, in *ctlInput) string {
	var size [4]byte
	if _, err := io.ReadFull(in, size[:]); err != nil {
		return "error: no message: " + reason(err).Error()
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 1 || n > ctlMaxListener {
		return fmt.Sprintf("error: a listener of %d bytes is not between 1 and %d", n, ctlMaxListener)
	}
	body := make([]byte, n)
	if got, err := io.ReadFull(in, body); err != nil {
		return fmt.Sprintf("error: the message ended after %d of %d bytes: %v", got, n, reason(err))
	}
	kind, ap, err := parseListener(body)
	if err != nil {
		return "error: " + err.Error()
	}
	key := kind + " " + ap.String()
	closeNow, isServed := s.served[key]
	if !add {
		if !isServed {
			return "error: " + key + " is not served"
		}
		delete(s.served, key)
		s.g.ddr.change(false, kind, ap) // before the close: a client is never sent to a listener that is closing
		closeNow()
		s.g.logf("stopped listening %s", key)
		return "ok"
	}
	if err := s.admit(kind, ap, isServed, in); err != nil {
		return "error: " + err.Error()
	}
	closeNow, err = s.serve(kind, ap, in)
	if err != nil {
		return "error: " + err.Error()
	}
	s.track(kind, ap, closeNow)
	s.g.ddr.change(true, kind, ap)
	s.g.logf("listening %s", key)
	return "ok"
}

// admit says why an add is not taken: the kind or port is not this gateway's, the listener is served already, the gateway is
// stopping, or what came with the frame is not the sockets of kind on ap.
func (s *listenerSet) admit(kind string, ap netip.AddrPort, isServed bool, in *ctlInput) error {
	port, serves := s.port(kind)
	switch {
	case !serves:
		return fmt.Errorf("%s is not served by this gateway: it was started without a %s listen address", kind, kind)
	case int(ap.Port()) != port:
		return fmt.Errorf("port %d is not the port %d of %s", ap.Port(), port, kind)
	case isServed:
		return fmt.Errorf("%s %s is served already", kind, ap)
	case s.g.ctx.Err() != nil:
		return errors.New("the gateway is stopping")
	case in.cut:
		return errors.New("more descriptors came than the control socket takes")
	}
	types := []int{syscall.SOCK_STREAM}
	switch kind {
	case "udp+tcp":
		types = []int{syscall.SOCK_DGRAM, syscall.SOCK_STREAM}
	case "doq":
		types = []int{syscall.SOCK_DGRAM}
	}
	if len(in.fds) != len(types) {
		return fmt.Errorf("%s takes %d descriptors, %d came", kind, len(types), len(in.fds))
	}
	for i, fd := range in.fds {
		if err := checkSocket(fd, types[i], ap); err != nil {
			return fmt.Errorf("descriptor %d %w", i, err)
		}
	}
	return nil
}

// checkSocket requires fd to be a socket of type typ, listening when it is a stream, bound to ap in ap's family.
func checkSocket(fd, typ int, ap netip.AddrPort) error {
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return fmt.Errorf("is not a socket: %w", reason(err))
	}
	if got != typ {
		return fmt.Errorf("is a socket of type %d, want %d", got, typ)
	}
	if typ == syscall.SOCK_STREAM {
		if n, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN); err != nil || n == 0 {
			return errors.New("is not listening")
		}
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("has no address: %w", reason(err))
	}
	var bound netip.AddrPort
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		bound = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port))
	case *syscall.SockaddrInet6:
		bound = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port))
	default:
		return errors.New("is not bound to an IP address")
	}
	if bound != ap {
		return fmt.Errorf("is bound to %s, not %s", bound, ap)
	}
	return nil
}

// serve takes over the descriptors of in, which admit has checked, and serves them as start serves a listener of kind.
func (s *listenerSet) serve(kind string, ap netip.AddrPort, in *ctlInput) (closeNow func(), err error) {
	files := make([]*os.File, len(in.fds))
	for i, fd := range in.fds {
		files[i] = os.NewFile(uintptr(fd), "listener")
	}
	in.fds = nil
	defer func() { // net.FileListener and net.FilePacketConn dup: the originals are not needed once they have
		for _, f := range files {
			_ = f.Close()
		}
	}()
	udp := func(f *os.File) (*net.UDPConn, error) {
		pc, err := net.FilePacketConn(f)
		if err != nil {
			return nil, err
		}
		return pc.(*net.UDPConn), nil
	}
	tcp := func(f *os.File) (*net.TCPListener, error) {
		ln, err := net.FileListener(f)
		if err != nil {
			return nil, err
		}
		return ln.(*net.TCPListener), nil
	}
	switch kind {
	case "udp+tcp":
		u, err := udp(files[0])
		if err != nil {
			return nil, err
		}
		t, err := tcp(files[1])
		if err != nil {
			_ = u.Close()
			return nil, err
		}
		return s.g.serve(&plainListener{udp: u, tcp: t}), nil
	case "dot", "doh":
		t, err := tcp(files[0])
		if err != nil {
			return nil, err
		}
		if kind == "dot" {
			return s.g.serveDoT(t, s.certs.dot()), nil
		}
		return s.g.serveDoH(t, s.certs.doh(), s.trusted), nil
	}
	u, err := udp(files[0])
	if err != nil {
		return nil, err
	}
	return s.g.serveDoQ(u, s.certs.doq())
}
