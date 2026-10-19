package main

import (
	"net"
	"regexp"
	"strings"
	"testing"
)

// The readiness lines carry an IPv6 address in brackets (`[::1]:853`), as the plain line does: whoever parses them
// (smoke, the e2e harness) splits on the last colon.
func TestReadinessLinesBracketIPv6Addresses(t *testing.T) {
	held, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	_ = held.Close()
	ports := distinctPorts(t, 2)
	path, _ := goodPEM(t)
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.port, cfg.dotPort = ports[1], ports[0]
	cfg.listen, cfg.dot, cfg.tlsPEM = []string{"::1"}, true, path
	cfg.dohListen, cfg.doqListen = []string{"::1"}, []string{"::1"}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	lines := strings.Split(logs.text(), "\n")
	for _, kind := range []string{`udp\+tcp`, "dot", "doh", "doq"} {
		re := regexp.MustCompile(`^listening ` + kind + ` \[::1\]:[0-9]+$`)
		n := 0
		for _, l := range lines {
			if re.MatchString(l) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("want exactly one line matching %s, got %d in:\n%s", re, n, logs.text())
		}
	}
}
