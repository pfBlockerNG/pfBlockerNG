package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func listeningAddr(t *testing.T, line, kind string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(strings.TrimPrefix(line, "listening "+kind+" "))
	if err != nil {
		t.Fatalf("readiness line %q: %v", line, err)
	}
	return ap
}

// every TLS transport on: the flags reach the listeners, each bound one is reported before `ready`, and each
// serves with the certificate of the PEM file through the shared decision path.
func TestGatewayServesEveryTLSTransportAndReportsEachListener(t *testing.T) {
	ports := distinctPorts(t, 2)
	tlsport := ports[0]
	path, m := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", strconv.Itoa(ports[1]), "--unbound-conf", "/nonexistent/unbound.conf",
		"--dot-listen", "127.0.0.1", "--dot-port", strconv.Itoa(tlsport), "--tls-pem", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0",
		"--doq-listen", "127.0.0.1", "--doq-port", "0",
	}, decider("serve"))
	gw.waitLine("listening udp+tcp ")
	dot := listeningAddr(t, gw.waitLine("listening dot "), "dot")
	doh := listeningAddr(t, gw.waitLine("listening doh "), "doh")
	doq := listeningAddr(t, gw.waitLine("listening doq "), "doq") // plain, dot, doh, doq, then ready: the order is the contract
	gw.waitLine("ready upstream ")
	if dot.Addr() != netip.MustParseAddr("127.0.0.1") || int(dot.Port()) != tlsport {
		t.Fatalf("DoT listens on %s, want 127.0.0.1:%d (--dot-port)", dot, tlsport)
	}
	if doh.Port() == 0 || doq.Port() == 0 {
		t.Fatalf("--doh-port 0 and --doq-port 0 must report the port picked: doh=%s doq=%s", doh, doq)
	}

	query := buildQuery(t, 0, "example.", true)
	echo := func(wire []byte) []byte { return echoWithQR(seenQuery{wire: wire})[0] }

	conn, err := tls.Dial("tcp4", dot.String(), m.clientConfig())
	if err != nil {
		t.Fatalf("DoT: %v", err)
	}
	defer conn.Close()
	tcpSend(t, conn, query)
	if got := tcpReply(t, conn); !bytes.Equal(got, echo(query)) {
		t.Fatalf("DoT reply %x, want %x", got, echo(query))
	}

	h := newDoHClient(t, doh, m, dohOptions{})
	if resp, body := h.do(h.get(dnsParam(query))); resp.StatusCode != 200 || !bytes.Equal(body, echo(query)) {
		t.Fatalf("DoH: status %d body %x, want 200 and %x", resp.StatusCode, body, echo(query))
	}

	q := dialDoQ(t, doq, m, "")
	if got := q.query(query); !bytes.Equal(got, withID0(echo(query))) {
		t.Fatalf("DoQ reply %x, want %x", got, withID0(echo(query)))
	}

	log := gw.logText()
	if ready, last := strings.Index(log, "ready upstream"), strings.Index(log, "listening doq"); last < 0 || ready < last {
		t.Fatalf("every listening line must come before `ready upstream`:\n%s", log)
	}
}

// An unusable certificate file at start: the reason is logged once, plain UDP/TCP keeps serving (a broken certificate must
// not take :53 down), the TLS listeners are bound but have no certificate, so a handshake fails, and a certificate pushed
// on the control socket is served by the next handshake of every transport with no restart.
func TestAnUnusableCertificateFileLeavesTLSWithoutACertificateUntilOneIsPushed(t *testing.T) {
	leaf, other := newPKI(t, nil, "localhost", false), newPKI(t, nil, "localhost", false)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: bytes.Repeat([]byte{7}, 64)})
	file := func(content []byte) func(t *testing.T) string {
		return func(t *testing.T) string {
			path := filepath.Join(shortTempDir(t), "tls.pem")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
	}
	cases := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"file absent", func(t *testing.T) string { return filepath.Join(shortTempDir(t), "absent.pem") }, "cannot read"},
		{"no PEM text", file([]byte("hello\n")), "cannot load the certificate and key"},
		{"key of another certificate", file(append(leaf.certPEM(), other.keyPEM(t)...)), "does not match"},
		{"encrypted private key", file(append(leaf.certPEM(), encrypted...)), "cannot load the certificate and key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := newPKI(t, nil, "empty start root", true)
			r := startReloadRig(t, c.path(t), root) // waits for every listening line and ready: the listeners are bound
			if reply := udpQuery(t, r.plain, buildQuery(t, 7, "example.", true)); len(reply) == 0 {
				t.Fatal("plain DNS must keep serving")
			}
			log := r.gw.logText()
			if n := strings.Count(log, c.want); n != 1 {
				t.Fatalf("the reason %q must be logged exactly once, found %d times in:\n%s", c.want, n, log)
			}
			if n := strings.Count(log, "TLS certificate not loaded"); n != 1 {
				t.Fatalf("the empty start must be logged once, found %d lines in:\n%s", n, log)
			}
			wire := buildQuery(t, 8, "example.", true)
			for _, tr := range reloadTransports {
				if leaf, err := tr.do(r, wire); err == nil {
					t.Fatalf("%s: a handshake with no certificate loaded presented serial %v, want it to fail", tr.name, leaf.SerialNumber)
				}
			}

			pushed := newPKI(t, root, "localhost", false)
			r.rotate(pushed)
			r.requireServing(pushed) // no restart: the same process, the same listeners
		})
	}
}

// No TLS transport requested: the certificate file is never looked at, so a missing one costs nothing and logs nothing.
func TestCertificateFileIsNotReadWhenNoTLSTransportIsRequested(t *testing.T) {
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf",
		"--tls-pem", "/nonexistent/pfb_dns_cert.pem",
	}, decider("serve"))
	gw.waitLine("ready upstream ")
	if log := gw.logText(); strings.Contains(log, "pfb_dns_cert") || strings.Contains(log, "TLS") {
		t.Fatalf("nothing about TLS or the certificate file may be logged when no TLS transport is requested:\n%s", log)
	}
}

// The file is owned by the run-as user and unreadable to anyone else: the certificate is read before the privilege
// drop, so the first read is not the run-as user's.
func TestCertificateIsReadBeforeThePrivilegeDrop(t *testing.T) {
	ports := distinctPorts(t, 2)
	path, _ := goodPEM(t)
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.port, cfg.dotListen, cfg.dotPort, cfg.tlsPEM = ports[1], cfg.listen, ports[0], path
	cfg.drop = func() error { return os.Remove(path) } // once the drop has happened the file is out of reach
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if text := logs.text(); !strings.Contains(text, "listening dot ") {
		t.Fatalf("the certificate was not read before the drop:\n%s", text)
	}
}

// A --doh-trusted value that is not an address or prefix is logged and ignored; the gateway does not exit.
func TestUnparseableTrustedPrefixIsLoggedAndTheGatewayStillServesDoH(t *testing.T) {
	path, m := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf", "--tls-pem", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0", "--doh-trusted", "junk", "--doh-trusted", "192.0.2.0/24",
	}, decider("serve"))
	doh := listeningAddr(t, gw.waitLine("listening doh "), "doh")
	gw.waitLine("ready upstream ")
	if strings.Contains(gw.logText(), "listening dot") {
		t.Fatalf("DoT is on without --dot-listen:\n%s", gw.logText())
	}
	h := newDoHClient(t, doh, m, dohOptions{})
	if resp, _ := h.do(h.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("DoH status %d", resp.StatusCode)
	}
	if n := strings.Count(gw.logText(), `"junk"`); n != 1 {
		t.Fatalf("the ignored value must be named in exactly one log line, found %d:\n%s", n, gw.logText())
	}
}

// A TLS address that cannot be bound is logged and skipped; the others keep serving.
func TestTLSAddressThatCannotBeBoundIsSkipped(t *testing.T) {
	held, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	tlsport := held.Addr().(*net.TCPAddr).Port
	path, m := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf", "--dot-listen", "127.0.0.1", "--dot-port", strconv.Itoa(tlsport), "--tls-pem", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0",
	}, decider("serve"))
	skipped := gw.waitLine("cannot listen on 127.0.0.1:" + strconv.Itoa(tlsport))
	doh := listeningAddr(t, gw.waitLine("listening doh "), "doh")
	gw.waitLine("ready upstream ")
	if strings.Contains(gw.logText(), "listening dot") {
		t.Fatalf("DoT reported listening although its port is taken:\n%s", gw.logText())
	}
	h := newDoHClient(t, doh, m, dohOptions{})
	if resp, _ := h.do(h.get(dnsParam(buildQuery(t, 0, "example.", true)))); resp.StatusCode != 200 {
		t.Fatalf("DoH status %d after %q", resp.StatusCode, skipped)
	}
}
