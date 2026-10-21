package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// requireIPv6Loopback skips the test on a host without IPv6 loopback, as the readiness test does.
func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	held, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	_ = held.Close()
}

// Each --dot-listen address gets one DoT listener, in the order given.
func TestDoTListenFlagsBindTheirAddressesInOrder(t *testing.T) {
	requireIPv6Loopback(t)
	path, _ := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf",
		"--dot-listen", "127.0.0.1", "--dot-listen", "::1", "--dot-port", "0", "--tls-pem", path,
	}, decider("serve"))
	gw.waitLine("ready upstream ") // the listening lines come before it: all of them are logged by now
	var got []netip.AddrPort
	for _, line := range strings.Split(gw.logText(), "\n") {
		if strings.HasPrefix(line, "listening dot ") {
			got = append(got, listeningAddr(t, line, "dot"))
		}
	}
	if len(got) != 2 || got[0].Addr() != netip.MustParseAddr("127.0.0.1") || got[1].Addr() != netip.MustParseAddr("::1") {
		t.Fatalf("DoT listens on %v, want 127.0.0.1 then [::1], one listener each: the order of --dot-listen", got)
	}
}

// DoT is bound on the --dot-listen addresses only: the --listen address gets no DoT listener.
func TestDoTBindsOnlyTheDoTListenAddresses(t *testing.T) {
	requireIPv6Loopback(t)
	path, m := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf",
		"--dot-listen", "::1", "--dot-port", "0", "--tls-pem", path,
	}, decider("serve"))
	gw.waitLine("listening udp+tcp ")
	dot := listeningAddr(t, gw.waitLine("listening dot "), "dot")
	gw.waitLine("ready upstream ")
	if dot.Addr() != netip.MustParseAddr("::1") {
		t.Fatalf("DoT listens on %s, want [::1] from --dot-listen", dot)
	}
	if n := strings.Count(gw.logText(), "listening dot "); n != 1 {
		t.Fatalf("want exactly one DoT listener, got %d:\n%s", n, gw.logText())
	}
	conn, err := tls.Dial("tcp6", dot.String(), m.clientConfig())
	if err != nil {
		t.Fatalf("DoT handshake on %s: %v", dot, err)
	}
	_ = conn.Close()
}

// An --dot-listen value that is not an IP address is logged and skipped; the gateway still becomes ready.
func TestDoTListenThatIsNotAnAddressIsSkipped(t *testing.T) {
	path, _ := goodPEM(t)
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf",
		"--dot-listen", "nonsense", "--dot-port", "0", "--tls-pem", path,
	}, decider("serve"))
	gw.waitLine("ready upstream ")
	if !strings.Contains(gw.logText(), "cannot listen on nonsense:0") {
		t.Fatalf("the bad --dot-listen value is not logged:\n%s", gw.logText())
	}
	if strings.Contains(gw.logText(), "listening dot") {
		t.Fatalf("DoT reported listening on a bad address:\n%s", gw.logText())
	}
}

// An empty --dot-listen is a usage error, as an empty --doh-listen is.
func TestDoTListenEmptyIsAUsageError(t *testing.T) {
	_, err := parse(t, "--dot-listen", "", "--", "decider")
	if err == nil || !strings.Contains(err.Error(), "--dot-listen must not be empty") {
		t.Fatalf("got err=%v, want a usage error saying --dot-listen must not be empty", err)
	}
}

// An empty --dot-listen exits 2 with the reason on stderr, before anything is bound.
func TestRealMainExitsTwoOnEmptyDoTListen(t *testing.T) {
	var stderr bytes.Buffer
	code := realMain([]string{"--listen", "127.0.0.1", "--dot-listen", "", "--", "decider"}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "pfb_dns_gateway: --dot-listen must not be empty") {
		t.Fatalf("exit %d, stderr %q; want exit 2 and `pfb_dns_gateway: --dot-listen must not be empty`", code, stderr.String())
	}
}

// --dot is removed, not kept as an alias: it is an unknown flag. No --listen here: the gateway stops at the usage
// check before it binds anything.
func TestDotBoolFlagIsUnknown(t *testing.T) {
	var stderr bytes.Buffer
	code := realMain([]string{"--dot", "--", "decider"}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "not defined: -dot") {
		t.Fatalf("exit %d, stderr %q; want exit 2 and `flag provided but not defined: -dot`", code, stderr.String())
	}
}
