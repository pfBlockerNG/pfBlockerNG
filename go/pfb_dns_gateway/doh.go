package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	proxyproto "github.com/pires/go-proxyproto"
)

// DNS over HTTPS (RFC 8484) behind TLS, with an optional trusted front end (HAProxy and the like) that tells us
// the real client by a PROXY protocol header and/or X-Forwarded-For.

const (
	dohPath       = "/dns-query"
	dohMediaType  = "application/dns-message"
	maxDoHParam   = 87380 // 65535 bytes in unpadded base64url: ceil(65535 * 4 / 3)
	maxDoHStreams = 100   // concurrent HTTP/2 streams per connection, as DoQ's
)

// parseTrusted turns --doh-trusted values into prefixes: a prefix is masked, a bare address is /32 or /128. A value
// that is neither is logged and dropped, never fatal: a stored setting must not crash-loop the only :53 listener.
func parseTrusted(values []string, logf func(format string, args ...any)) []netip.Prefix {
	var trusted []netip.Prefix
	for _, v := range values {
		if p, err := netip.ParsePrefix(v); err == nil {
			trusted = append(trusted, p.Masked())
		} else if a, err := netip.ParseAddr(v); err == nil {
			a = a.Unmap().WithZone("")
			trusted = append(trusted, netip.PrefixFrom(a, a.BitLen()))
		} else {
			logf("ignoring --doh-trusted %q: not an IP address or an address/length prefix", v)
		}
	}
	return trusted
}

func trusts(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

func addrPortOf(a net.Addr) netip.AddrPort {
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// limitedListener closes the connections over the cap at accept, so a flood cannot queue up in the backlog.
type limitedListener struct {
	net.Listener
	limit *connLimit
	logf  func(format string, args ...any)
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.limit.take(l.logf) {
			return &countedConn{Conn: conn, release: sync.OnceFunc(l.limit.release)}, nil
		}
		_ = conn.Close()
	}
}

type countedConn struct {
	net.Conn
	release func()
}

func (c *countedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// connInfo is the TCP connection as the kernel sees it, whatever a PROXY header says.
type connInfo struct{ peer, local netip.AddrPort }

type connInfoKey struct{}

func rawConnInfo(c net.Conn) connInfo {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	if p, ok := c.(*proxyproto.Conn); ok {
		c = p.Raw()
	}
	return connInfo{peer: addrPortOf(c.RemoteAddr()), local: addrPortOf(c.LocalAddr())}
}

// serveDoH answers DoH on ln until stop(). Connections: TCP, the cap, PROXY header parsing for trusted peers only
// (everyone else's bytes are never parsed as one), TLS, HTTP.
func (g *gateway) serveDoH(ln *net.TCPListener, conf *tls.Config, trusted []netip.Prefix) {
	limited := &limitedListener{Listener: ln, limit: g.dohConns, logf: g.logf}
	proxied := &proxyproto.Listener{
		Listener:          limited,
		ReadHeaderTimeout: g.handshake,
		ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if trusts(trusted, addrPortOf(o.Upstream).Addr()) {
				return proxyproto.USE, nil
			}
			return proxyproto.SKIP, nil
		},
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.serveDoHRequest(w, r, trusted) }),
		ReadHeaderTimeout: g.handshake,
		ReadTimeout:       g.tcpIdle,
		WriteTimeout:      2*g.timeout + g.grace + g.tcpIdle,
		IdleTimeout:       g.tcpIdle,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: maxDoHStreams},
		ErrorLog:          log.New(io.Discard, "", 0), // handshake failures of hostile clients are not events
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connInfoKey{}, rawConnInfo(c))
		},
	}
	g.closeOnStop(func() { _ = srv.Close() })
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		_ = srv.Serve(tls.NewListener(proxied, conf))
	}()
}

func (g *gateway) serveDoHRequest(w http.ResponseWriter, r *http.Request, trusted []netip.Prefix) {
	if r.URL.Path != dohPath {
		http.NotFound(w, r)
		return
	}
	wire, status := dohWire(w, r)
	if status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", "GET, POST")
	}
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	info := r.Context().Value(connInfoKey{}).(connInfo)
	src, dst := proxyEndpoints(requestClient(r, info, trusted), info.local)
	disp, reply := g.screen(src.Addr(), wire)
	switch disp {
	case discard:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	case hangUp:
		panic(http.ErrAbortHandler) // nothing may be sent: the client sees the request reset
	case toDecider:
		fwd := func(ctx context.Context, q []byte) []byte { return g.up.exchangeUDPThenTCP(ctx, src, dst, q) }
		var ok bool
		if reply, ok = g.resolveShared(r.Context(), src.Addr(), wire, fwd); !ok {
			w.Header().Set("Retry-After", "1") // HTTP's own overload signal: a front end or client can try another server
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if reply == nil {
			panic(http.ErrAbortHandler) // the decider dropped the query
		}
	}
	w.Header().Set("Content-Type", dohMediaType)
	w.Header().Set("Cache-Control", "max-age=0") // RFC 8484 5.1: the answer depends on who asks
	_, _ = w.Write(reply)
}

// dohWire is the DNS query of the request (RFC 8484 4.1: GET with dns=base64url, POST with the message as body) or
// the status that refuses it. A body over 65535 bytes is refused from its Content-Length, unread.
func dohWire(w http.ResponseWriter, r *http.Request) ([]byte, int) {
	switch r.Method {
	case http.MethodGet:
		param := strings.TrimRight(r.URL.Query().Get("dns"), "=") // padding is tolerated
		if param == "" {
			return nil, http.StatusBadRequest
		}
		if len(param) > maxDoHParam {
			return nil, http.StatusRequestEntityTooLarge
		}
		wire, err := base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		return wire, 0
	case http.MethodPost:
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != dohMediaType {
			return nil, http.StatusUnsupportedMediaType
		}
		if r.ContentLength > maxWire {
			return nil, http.StatusRequestEntityTooLarge
		}
		wire, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWire))
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			return nil, http.StatusRequestEntityTooLarge
		case err != nil:
			return nil, http.StatusBadRequest
		}
		return wire, 0
	}
	return nil, http.StatusMethodNotAllowed
}

// requestClient is the client of a request: the PROXY source of a trusted peer that sent a header, else the TCP peer;
// then, for a trusted peer, the rightmost entry of the last X-Forwarded-For header when it is an address (HAProxy's
// `option forwardfor` appends its own header line, so only the last one is the front end's).
func requestClient(r *http.Request, info connInfo, trusted []netip.Prefix) netip.AddrPort {
	client := info.peer
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil { // a PROXY header with no IP source leaves the peer
		client = ap
	}
	if !trusts(trusted, info.peer.Addr()) {
		return client
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		return client
	}
	last := forwarded[len(forwarded)-1]
	if ip, err := netip.ParseAddr(strings.TrimSpace(last[strings.LastIndexByte(last, ',')+1:])); err == nil {
		return netip.AddrPortFrom(ip, 0)
	}
	return client
}
