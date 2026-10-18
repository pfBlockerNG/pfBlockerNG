package main

import (
	"bytes"
	"crypto/tls"
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
// serves with the certificate of config.xml through the shared decision path.
func TestGatewayServesEveryTLSTransportAndReportsEachListener(t *testing.T) {
	ports := distinctPorts(t, 2)
	tlsport := ports[0]
	path, m := goodConfig(t, strconv.Itoa(tlsport))
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", strconv.Itoa(ports[1]), "--acl-file", "/nonexistent/acl",
		"--dot", "--pfsense-config", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0",
		"--doq-listen", "127.0.0.1", "--doq-port", "0",
	}, decider("serve"))
	gw.waitLine("listening udp+tcp ")
	dot := listeningAddr(t, gw.waitLine("listening dot "), "dot")
	doh := listeningAddr(t, gw.waitLine("listening doh "), "doh")
	doq := listeningAddr(t, gw.waitLine("listening doq "), "doq") // plain, dot, doh, doq, then ready: the order is the contract
	gw.waitLine("ready upstream ")
	if dot.Addr() != netip.MustParseAddr("127.0.0.1") || int(dot.Port()) != tlsport {
		t.Fatalf("DoT listens on %s, want 127.0.0.1:%d (unbound/tlsport)", dot, tlsport)
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

// An unusable certificate with a TLS transport requested: the reason is logged once, no TLS listener is bound, and
// plain UDP/TCP keeps serving (the Python --dot exits 1 instead; a broken certificate must not take :53 down).
func TestUnusableCertificateDisablesTheTLSTransportsButPlainDNSKeepsServing(t *testing.T) {
	leaf := newPKI(t, nil, "localhost", false)
	encrypted := b64([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	cases := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"config.xml absent", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.xml") }, "cannot read"},
		{"sslcertref empty", func(t *testing.T) string {
			return writeConfig(t, configXML(unboundEl(el("sslcertref", "")), certEl(testRefid, el("crt", b64(leaf.certPEM())), el("prv", b64(leaf.keyPEM(t))))))
		}, "unbound/sslcertref is empty"},
		{"encrypted private key", func(t *testing.T) string {
			return writeConfig(t, configXML(unboundEl(el("sslcertref", testRefid)), certEl(testRefid, el("crt", b64(leaf.certPEM())), el("prv", encrypted))))
		}, "encrypted with a passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw := startGatewayProcess(t, []string{
				"--listen", "127.0.0.1", "--port", "0", "--acl-file", "/nonexistent/acl",
				"--dot", "--pfsense-config", c.path(t),
				"--doh-listen", "127.0.0.1", "--doh-port", "0", "--doq-listen", "127.0.0.1", "--doq-port", "0",
			}, decider("serve"))
			serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
			gw.waitLine("ready upstream ")
			reply := udpQuery(t, serving, buildQuery(t, 7, "example.", true))
			if len(reply) == 0 {
				t.Fatal("plain DNS must keep serving")
			}
			log := gw.logText()
			if n := strings.Count(log, c.want); n != 1 {
				t.Fatalf("the reason %q must be logged exactly once, found %d times in:\n%s", c.want, n, log)
			}
			for _, kind := range []string{"dot", "doh", "doq"} {
				if strings.Contains(log, "listening "+kind) {
					t.Fatalf("a %s listener was bound without a usable certificate:\n%s", kind, log)
				}
			}
		})
	}
}

// No TLS transport requested: config.xml is never looked at, so a missing one costs nothing and logs nothing.
func TestConfigXMLIsNotReadWhenNoTLSTransportIsRequested(t *testing.T) {
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--acl-file", "/nonexistent/acl",
		"--pfsense-config", "/nonexistent/config.xml",
	}, decider("serve"))
	gw.waitLine("ready upstream ")
	if log := gw.logText(); strings.Contains(log, "config.xml") || strings.Contains(log, "TLS") {
		t.Fatalf("nothing about TLS or config.xml may be logged when no TLS transport is requested:\n%s", log)
	}
}

// config.xml is root-only: the certificate is read before the privilege drop, not after.
func TestCertificateIsReadBeforeThePrivilegeDrop(t *testing.T) {
	ports := distinctPorts(t, 2)
	path, _ := goodConfig(t, strconv.Itoa(ports[0]))
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.port, cfg.dot, cfg.pfsenseConfig = ports[1], true, path
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
	path, m := goodConfig(t, strconv.Itoa(freePort(t)))
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--acl-file", "/nonexistent/acl", "--pfsense-config", path,
		"--doh-listen", "127.0.0.1", "--doh-port", "0", "--doh-trusted", "junk", "--doh-trusted", "192.0.2.0/24",
	}, decider("serve"))
	doh := listeningAddr(t, gw.waitLine("listening doh "), "doh")
	gw.waitLine("ready upstream ")
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
	path, m := goodConfig(t, strconv.Itoa(tlsport))
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--acl-file", "/nonexistent/acl", "--dot", "--pfsense-config", path,
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
