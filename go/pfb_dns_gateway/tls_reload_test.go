package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// A certificate renewal never restarts the gateway, never fails a handshake and never drops a connection: root pushes
// the new certificate chain and key over the gateway's control socket and new handshakes get it from then on. These tests
// run the gateway as its own process with the three TLS transports on and a client of each; the decider echoes queries.

// reloadRig is a gateway serving every TLS transport, with the control socket at ctl.
type reloadRig struct {
	t             *testing.T
	file          string
	ctl           string
	plain         netip.AddrPort
	root          *pki
	m             tlsMaterial
	gw            *gatewayProcess
	dot, doh, doq netip.AddrPort
}

// chainPEM is what a PEM message or file holds: the certificate, the CAs after it, then the key.
func chainPEM(t *testing.T, leaf *pki, cas ...*pki) []byte {
	t.Helper()
	out := leaf.certPEM()
	for _, ca := range cas {
		out = append(out, ca.certPEM()...)
	}
	return append(out, leaf.keyPEM(t)...)
}

func newReloadRig(t *testing.T) (*reloadRig, *pki) {
	t.Helper()
	root := newPKI(t, nil, "reload root", true)
	first := newPKI(t, root, "localhost", false)
	file := filepath.Join(shortTempDir(t), "tls.pem")
	if err := os.WriteFile(file, chainPEM(t, first), 0o600); err != nil {
		t.Fatal(err)
	}
	return startReloadRig(t, file, root), first
}

// startReloadRig is a gateway process that reads file at start (as root, before the privilege drop) and takes pushes on a
// control socket of its own; the clients trust root.
func startReloadRig(t *testing.T, file string, root *pki) *reloadRig {
	t.Helper()
	ctl := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf",
		"--dot", "--dot-port", "0", "--tls-pem", file, "--ctl-socket", ctl,
		"--doh-listen", "127.0.0.1", "--doh-port", "0", "--doq-listen", "127.0.0.1", "--doq-port", "0",
	}, decider("serve"))
	plain := listenAddr(t, gw.waitLine("listening udp+tcp "))
	r := &reloadRig{t: t, file: file, ctl: ctl, plain: plain, root: root, m: tlsMaterial{pool: root.pool()}, gw: gw}
	r.dot = listeningAddr(t, gw.waitLine("listening dot "), "dot")
	r.doh = listeningAddr(t, gw.waitLine("listening doh "), "doh")
	r.doq = listeningAddr(t, gw.waitLine("listening doq "), "doq")
	gw.waitLine("ready upstream ")
	return r
}

// push sends one message to the control socket and returns the reply line.
func (r *reloadRig) push(pem []byte) string {
	r.t.Helper()
	c := dialCtl(r.t, r.ctl)
	_, _ = c.Write(ctlFrame(pem))
	return ctlReply(r.t, c)
}

// rotate pushes a usable certificate and requires the gateway to have taken it: the reply is the barrier, so the next
// handshake on any transport gets it, with nothing to wait for.
func (r *reloadRig) rotate(c *pki) {
	r.t.Helper()
	if got := r.push(chainPEM(r.t, c)); got != "ok" {
		r.t.Fatalf("the push of serial %v got the reply %q, want ok; log:\n%s", c.cert.SerialNumber, got, r.gw.logText())
	}
}

// An exchange is one new connection, its handshake and one query; it returns the certificate the server presented. It
// reports errors instead of failing the test, so that a load test can run it on goroutines.
type tlsExchange func(r *reloadRig, wire []byte) (*x509.Certificate, error)

func answered(reply []byte, err error) error {
	if err != nil {
		return err
	}
	if len(reply) < 12 || reply[2]&0x80 == 0 {
		return fmt.Errorf("not a DNS response: %x", reply)
	}
	return nil
}

func roundTripFramed(rw io.ReadWriter, wire []byte) ([]byte, error) {
	if _, err := rw.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire)))); err != nil {
		return nil, err
	}
	if _, err := rw.Write(wire); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(rw, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	_, err := io.ReadFull(rw, reply)
	return reply, err
}

func dotExchange(r *reloadRig, wire []byte) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: watchdog}, "tcp4", r.dot.String(), r.m.clientConfig())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(watchdog))
	reply, err := roundTripFramed(conn, wire)
	if err := answered(reply, err); err != nil {
		return nil, err
	}
	return conn.ConnectionState().PeerCertificates[0], nil
}

func dohClientOf(r *reloadRig, keepAlive bool) *http.Client {
	return &http.Client{Timeout: watchdog, Transport: &http.Transport{
		TLSClientConfig: r.m.clientConfig(), ForceAttemptHTTP2: true, DisableKeepAlives: !keepAlive,
	}}
}

func dohRoundTrip(c *http.Client, r *reloadRig, wire []byte) (*x509.Certificate, error) {
	resp, err := c.Post(fmt.Sprintf("https://localhost:%d%s", r.doh.Port(), dohPath), dohMediaType, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := answered(body, err); err != nil {
		return nil, err
	}
	return resp.TLS.PeerCertificates[0], nil
}

func dohExchange(r *reloadRig, wire []byte) (*x509.Certificate, error) {
	return dohRoundTrip(dohClientOf(r, false), r, wire)
}

func dialDoQConn(r *reloadRig) (*quic.Conn, *net.UDPConn, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(r.doq), r.m.clientConfig("doq"), &quic.Config{MaxIdleTimeout: time.Minute})
	if err != nil {
		_ = udp.Close()
		return nil, nil, err
	}
	return conn, udp, nil
}

func doqQueryOn(conn *quic.Conn, wire []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	_ = s.SetDeadline(time.Now().Add(watchdog))
	if _, err := s.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire)))); err != nil {
		return err
	}
	if _, err := s.Write(wire); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	data, err := io.ReadAll(s)
	if err == nil && len(data) < 2 {
		err = fmt.Errorf("DoQ reply of %d bytes", len(data))
	}
	if err != nil {
		return err
	}
	return answered(data[2:], nil)
}

func doqExchange(r *reloadRig, wire []byte) (*x509.Certificate, error) {
	conn, udp, err := dialDoQConn(r)
	if err != nil {
		return nil, err
	}
	defer udp.Close()
	defer conn.CloseWithError(0, "")
	if err := doqQueryOn(conn, wire); err != nil {
		return nil, err
	}
	return conn.ConnectionState().TLS.PeerCertificates[0], nil
}

var reloadTransports = []struct {
	name string
	do   tlsExchange
}{{"DoT", dotExchange}, {"DoH", dohExchange}, {"DoQ", doqExchange}}

func (r *reloadRig) requireServing(want *pki) {
	r.t.Helper()
	wire := buildQuery(r.t, 0, "example.", true)
	for _, tr := range reloadTransports {
		leaf, err := tr.do(r, wire)
		if err != nil {
			r.t.Fatalf("%s: %v", tr.name, err)
		}
		if !leaf.Equal(want.cert) {
			r.t.Fatalf("%s serves serial %v, want serial %v", tr.name, leaf.SerialNumber, want.cert.SerialNumber)
		}
	}
}

func TestPushedCertificateIsServedToTheNextHandshakeOnDoTDoHAndDoQ(t *testing.T) {
	r, first := newReloadRig(t)
	r.requireServing(first) // before the rotation, so that what follows is the rotation's doing
	second := newPKI(t, r.root, "localhost", false)
	r.rotate(second)
	r.requireServing(second)
}

func TestOpenConnectionsKeepAnsweringAcrossARotation(t *testing.T) {
	r, first := newReloadRig(t)
	wire := buildQuery(t, 0, "example.", true)

	dot, err := tls.Dial("tcp4", r.dot.String(), r.m.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer dot.Close()
	doh := dohClientOf(r, true)
	if leaf, err := dohRoundTrip(doh, r, wire); err != nil || !leaf.Equal(first.cert) {
		t.Fatalf("DoH before the rotation: cert %v err %v", leaf, err)
	}
	doqConn, udp, err := dialDoQConn(r)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer doqConn.CloseWithError(0, "")
	queryAll := func(when string) {
		t.Helper()
		_ = dot.SetDeadline(time.Now().Add(watchdog))
		if err := answered(roundTripFramed(dot, wire)); err != nil {
			t.Fatalf("the open DoT connection %s: %v", when, err)
		}
		if leaf, err := dohRoundTrip(doh, r, wire); err != nil || !leaf.Equal(first.cert) {
			t.Fatalf("the open DoH connection %s: cert %v err %v", when, leaf, err)
		}
		if err := doqQueryOn(doqConn, wire); err != nil {
			t.Fatalf("the open DoQ connection %s: %v", when, err)
		}
	}
	queryAll("before the rotation")

	second := newPKI(t, r.root, "localhost", false)
	r.rotate(second)
	r.requireServing(second)
	queryAll("after the rotation")
}

func TestAPushThatIsNotUsableKeepsTheServingCertificateOnEveryTransportAndIsReported(t *testing.T) {
	r, first := newReloadRig(t)
	good := chainPEM(t, first)
	other := newPKI(t, r.root, "localhost", false)
	for name, content := range map[string][]byte{
		"half a message":               good[:len(good)/2],
		"a key that is not the cert's": append(first.certPEM(), other.keyPEM(t)...),
		"no PEM at all":                []byte("not a certificate\n"),
	} {
		if reply := r.push(content); !strings.HasPrefix(reply, "error: ") {
			t.Fatalf("%s: reply %q, want `error: <reason>`", name, reply)
		}
		r.gw.waitLine("TLS certificate not replaced")
		r.requireServing(first)
	}

	second := newPKI(t, r.root, "localhost", false)
	r.rotate(second)
	r.gw.waitLine("TLS certificate replaced by a push")
	r.requireServing(second)
}

// The load test: clients of every transport open new connections without a pause, and some keep one connection for
// the whole run, while the gateway is pushed two certificates and a message cut in half. Not one handshake fails, not
// one query goes unanswered, and every certificate presented is one of the two that were ever valid.
func TestRotatingTheCertificateUnderLoadFailsNoHandshakeAndDropsNoQuery(t *testing.T) {
	for _, tr := range reloadTransports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			r, first := newReloadRig(t)
			second := newPKI(t, r.root, "localhost", false)
			third := newPKI(t, r.root, "localhost", false)
			wire := buildQuery(t, 0, "example.", true)

			var mu sync.Mutex
			var failures []string
			served := map[string]int{} // serial -> exchanges that presented it
			fail := func(format string, args ...any) {
				mu.Lock()
				failures = append(failures, fmt.Sprintf(format, args...))
				mu.Unlock()
			}
			sawSerial := func(serial string) int {
				mu.Lock()
				defer mu.Unlock()
				return served[serial]
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					for {
						select {
						case <-stop:
							return
						default:
						}
						leaf, err := tr.do(r, wire)
						if err != nil {
							fail("handshake/query: %v", err)
						} else {
							mu.Lock()
							served[leaf.SerialNumber.String()]++
							mu.Unlock()
						}
						time.Sleep(2 * time.Millisecond)
					}
				})
			}
			holder := holdOpen(t, r, tr.name, wire)
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					if err := holder(); err != nil {
						fail("the connection held open through the rotation: %v", err)
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
			})

			waitFor := func(c *pki) {
				t.Helper()
				eventually(t, fmt.Sprintf("serial %v to be presented", c.cert.SerialNumber), func() bool {
					return sawSerial(c.cert.SerialNumber.String()) > 0
				})
			}
			waitFor(first)
			r.rotate(second)
			waitFor(second)
			if reply := r.push(chainPEM(t, third)[:100]); !strings.HasPrefix(reply, "error: ") { // a writer that dies half way
				t.Fatalf("a cut message got the reply %q, want an error", reply)
			}
			r.rotate(third)
			waitFor(third)
			close(stop)
			wg.Wait()

			mu.Lock()
			defer mu.Unlock()
			if len(failures) > 0 {
				t.Fatalf("%d failures during the rotation, first: %s", len(failures), failures[0])
			}
			for serial := range served {
				known := map[string]bool{first.cert.SerialNumber.String(): true, second.cert.SerialNumber.String(): true, third.cert.SerialNumber.String(): true}
				if !known[serial] {
					t.Fatalf("a certificate nobody installed was presented: serial %s", serial)
				}
			}
		})
	}
}

// holdOpen keeps one connection of the transport and returns a function that asks one query on it.
func holdOpen(t *testing.T, r *reloadRig, name string, wire []byte) func() error {
	t.Helper()
	switch name {
	case "DoT":
		conn, err := tls.Dial("tcp4", r.dot.String(), r.m.clientConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return func() error {
			_ = conn.SetDeadline(time.Now().Add(watchdog))
			return answered(roundTripFramed(conn, wire))
		}
	case "DoH":
		c := dohClientOf(r, true)
		return func() error { _, err := dohRoundTrip(c, r, wire); return err }
	default:
		conn, udp, err := dialDoQConn(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.CloseWithError(0, ""); _ = udp.Close() })
		return func() error { return doqQueryOn(conn, wire) }
	}
}
