package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Numbers from RFC 9250 section 4.3, written out so no test trusts the constants of the code under test.
const (
	rfcDoQProtocolError     = 0x2
	rfcDoQRequestCancelled  = 0x3
	rfcMaxIncomingDoQStream = 100
)

// autoForward plays a decider that forwards every query to Unbound unchanged and answers the client with Unbound's
// reply (the path of an allowed name). Queries are recorded like autoAnswer's. Use it instead of recv()/send().
func (r *rig) autoForward() {
	go func() {
		for {
			typ, id, payload, err := readFrame(r.p.conn)
			if err != nil {
				return
			}
			switch typ {
			case tQuery:
				n := int(payload[0])
				q := decidedQuery{id: id, ip: string(payload[1 : 1+n]), wire: payload[1+n:]}
				r.queries <- q
				_ = writeFrame(r.p.conn, tForward, id, q.wire)
			case tReply:
				if len(payload) == 0 {
					_ = writeFrame(r.p.conn, tDrop, id, nil)
				} else {
					_ = writeFrame(r.p.conn, tAnswer, id, payload)
				}
			}
		}
	}()
}

func (r *rig) serveDoT(m tlsMaterial) netip.AddrPort {
	r.t.Helper()
	ln, err := bindTCP("127.0.0.1", 0)
	if err != nil {
		r.t.Fatal(err)
	}
	r.g.serveDoT(ln, m.settings.dot())
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func (r *rig) serveDoH(m tlsMaterial, trusted ...string) netip.AddrPort {
	r.t.Helper()
	ln, err := bindTCP("127.0.0.1", 0)
	if err != nil {
		r.t.Fatal(err)
	}
	r.g.serveDoH(ln, m.settings.doh(), parseTrusted(trusted, r.logs.logf))
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func (r *rig) serveDoQ(m tlsMaterial) netip.AddrPort {
	r.t.Helper()
	udp, err := bindUDP("127.0.0.1", 0)
	if err != nil {
		r.t.Fatal(err)
	}
	r.g.serveDoQ(udp, m.settings.doq())
	return udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// dialDoT connects as `source` (empty = the default) and completes the TLS handshake.
func dialDoT(t *testing.T, addr netip.AddrPort, m tlsMaterial, source string) *tls.Conn {
	t.Helper()
	d := net.Dialer{Timeout: watchdog}
	if source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	c, err := (&tls.Dialer{NetDialer: &d, Config: m.clientConfig()}).Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("DoT connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*tls.Conn)
}

// PROXYv2 headers built from the specification alone (section 2.2): signature, version+command, family+protocol,
// length, addresses.
const pp2Signature = "\r\n\r\n\x00\r\nQUIT\n"

func pp2(command, familyProtocol byte, addresses []byte) []byte {
	b := append([]byte(pp2Signature), 0x20|command, familyProtocol)
	b = binary.BigEndian.AppendUint16(b, uint16(len(addresses)))
	return append(b, addresses...)
}

// pp2TCP is a PROXY command for src -> dst over TCP in the family of the addresses.
func pp2TCP(src, dst string) []byte {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	family, addrs := byte(0x11), append(s.Addr().AsSlice(), d.Addr().AsSlice()...)
	if s.Addr().Is6() {
		family = 0x21
	}
	addrs = binary.BigEndian.AppendUint16(addrs, s.Port())
	return pp2(1, family, binary.BigEndian.AppendUint16(addrs, d.Port()))
}

// pp1 is the version 1 text header.
func pp1(src, dst string) []byte {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	proto := "TCP4"
	if s.Addr().Is6() {
		proto = "TCP6"
	}
	return []byte("PROXY " + proto + " " + s.Addr().String() + " " + d.Addr().String() + " " + strconv.Itoa(int(s.Port())) + " " + strconv.Itoa(int(d.Port())) + "\r\n")
}

// dohOptions describe one DoH test client.
type dohOptions struct {
	source string // local address; empty = the default
	h2     bool   // negotiate HTTP/2
	prefix []byte // written to the TCP connection before the TLS handshake (a PROXY header)
	split  bool   // write the prefix one byte at a time
}

type dohClient struct {
	t    *testing.T
	addr netip.AddrPort
	m    tlsMaterial
	http *http.Client
}

func newDoHClient(t *testing.T, addr netip.AddrPort, m tlsMaterial, o dohOptions) *dohClient {
	t.Helper()
	d := net.Dialer{Timeout: watchdog}
	if o.source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(o.source)}
	}
	tr := &http.Transport{
		TLSClientConfig:   m.clientConfig(),
		ForceAttemptHTTP2: o.h2,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, err := d.DialContext(ctx, "tcp4", addr.String())
			if err != nil {
				return nil, err
			}
			if o.split {
				c.(*net.TCPConn).SetNoDelay(true) //nolint:errcheck // loopback test helper
				for i := range o.prefix {
					if _, err := c.Write(o.prefix[i : i+1]); err != nil {
						return nil, err
					}
				}
			} else if _, err := c.Write(o.prefix); err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &dohClient{t: t, addr: addr, m: m, http: &http.Client{Transport: tr, Timeout: watchdog, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *dohClient) url(path string) string {
	return "https://localhost:" + strconv.Itoa(int(c.addr.Port())) + path
}

// do sends the request and returns the status, the headers and the whole body; a transport error fails the test.
func (c *dohClient) do(req *http.Request) (*http.Response, []byte) {
	c.t.Helper()
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("reading the body of %s %s: %v", req.Method, req.URL, err)
	}
	return resp, body
}

func (c *dohClient) get(path string, headers ...string) *http.Request {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodGet, c.url(path), nil)
	if err != nil {
		c.t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	return req
}

func (c *dohClient) post(path, contentType string, body []byte, headers ...string) *http.Request {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.url(path), strings.NewReader(string(body)))
	if err != nil {
		c.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	return req
}

// rawDoH is a TLS connection to the DoH listener for requests the HTTP client would not send.
func rawDoH(t *testing.T, addr netip.AddrPort, m tlsMaterial, prefix []byte) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", addr.String(), watchdog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if len(prefix) > 0 {
		if _, err := raw.Write(prefix); err != nil {
			t.Fatal(err)
		}
	}
	c := tls.Client(raw, m.clientConfig("http/1.1"))
	_ = c.SetDeadline(time.Now().Add(watchdog))
	if err := c.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	return c
}

func readHTTPResponse(t *testing.T, c net.Conn) (*http.Response, []byte, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// DoQ client -----------------------------------------------------------------------------------------------------

type doqClient struct {
	t    *testing.T
	conn *quic.Conn
}

func doqConfig(m tlsMaterial) *tls.Config { return m.clientConfig("doq") }

// dialDoQ connects as `source` (empty = the default) with ALPN doq.
func dialDoQ(t *testing.T, addr netip.AddrPort, m tlsMaterial, source string) *doqClient {
	t.Helper()
	conn, err := tryDialDoQ(t, addr, doqConfig(m), source)
	if err != nil {
		t.Fatalf("DoQ connect: %v", err)
	}
	return &doqClient{t: t, conn: conn}
}

func tryDialDoQ(t *testing.T, addr netip.AddrPort, conf *tls.Config, source string) (*quic.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	local := &net.UDPAddr{IP: net.IPv4zero}
	if source != "" {
		local.IP = net.ParseIP(source)
	}
	udp, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(addr), conf, &quic.Config{MaxIdleTimeout: time.Minute})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test over") })
	return conn, nil
}

// stream opens a query stream.
func (c *doqClient) stream() *quic.Stream {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		c.t.Fatalf("open stream: %v", err)
	}
	return s
}

func framed(wire []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
}

// send writes one framed query and FIN.
func sendDoQ(t *testing.T, s *quic.Stream, wire []byte) {
	t.Helper()
	if _, err := s.Write(framed(wire)); err != nil {
		t.Fatalf("DoQ write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("DoQ FIN: %v", err)
	}
}

// readDoQ reads the whole response stream: the data and the error that ended it (io.EOF for a FIN).
func readDoQ(t *testing.T, s *quic.Stream) ([]byte, error) {
	t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(watchdog))
	data, err := io.ReadAll(s)
	if err == nil {
		err = io.EOF
	}
	return data, err
}

// query is one complete exchange on a stream of its own; the reply is the DNS message without its length prefix.
func (c *doqClient) query(wire []byte) []byte {
	c.t.Helper()
	s := c.stream()
	sendDoQ(c.t, s, wire)
	data, err := readDoQ(c.t, s)
	if !errors.Is(err, io.EOF) {
		c.t.Fatalf("DoQ response stream ended with %v, want a FIN after the response", err)
	}
	return unframe(c.t, data)
}

// unframe checks the 2-byte length prefix and returns the message; nothing may follow it.
func unframe(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		t.Fatalf("DoQ response is not one length-prefixed message: %d bytes, prefix %x", len(data), data[:min(2, len(data))])
	}
	return data[2:]
}

// requireStreamReset asserts that the response stream was reset by the peer with the RFC 9250 error code.
func requireStreamReset(t *testing.T, s *quic.Stream, code quic.StreamErrorCode) {
	t.Helper()
	_, err := readDoQ(t, s)
	var se *quic.StreamError
	if !errors.As(err, &se) || !se.Remote || se.ErrorCode != code {
		t.Fatalf("response stream ended with %v, want a stream reset by the server with error code %#x", err, code)
	}
}

// requireConnClosed asserts that the server closed the connection with the RFC 9250 application error code.
func requireConnClosed(t *testing.T, conn *quic.Conn, code quic.ApplicationErrorCode) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(watchdog):
		t.Fatal("STUCK: the server did not close the connection")
	}
	var ae *quic.ApplicationError
	if err := context.Cause(conn.Context()); !errors.As(err, &ae) || !ae.Remote || ae.ErrorCode != code {
		t.Fatalf("connection closed with %v, want an application close by the server with error code %#x", err, code)
	}
}

// tlsClientHandshake runs a TLS client handshake on c (HTTP/1.1 ALPN) and reports how it ended.
func tlsClientHandshake(c net.Conn, m tlsMaterial) error {
	return tls.Client(c, m.clientConfig("http/1.1")).Handshake()
}
