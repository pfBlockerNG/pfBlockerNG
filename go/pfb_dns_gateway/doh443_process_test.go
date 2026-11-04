package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694, end to end: the process the rc script starts, with the flags and the control socket verb PHP uses. DDR advertises
// DoH on port 443 (no `port`) on the addresses --ddr-doh-443 and the address table name, and on the configured DoH port
// everywhere else. The sockets are on 127.0.0.1: the tests that bind port 443 itself are in-process (a test seam holds the
// port), these cannot.

// doh443Gateway is a gateway process with DoT and DoH on 127.0.0.1 and DDR's name set.
type doh443Gateway struct {
	gw       *gatewayProcess
	plain    netip.AddrPort
	ctl      string
	dot, doh uint16
}

func startDoH443Gateway(t *testing.T, extra ...string) *doh443Gateway {
	t.Helper()
	ports := distinctPorts(t, 3)
	path, _ := goodPEM(t)
	ctl := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	flags := []string{
		"--listen", "127.0.0.1", "--port", fmt.Sprint(ports[0]), "--unbound-conf", filepath.Join(t.TempDir(), "absent"),
		"--dot-listen", "127.0.0.1", "--dot-port", fmt.Sprint(ports[1]),
		"--doh-listen", "127.0.0.1", "--doh-port", fmt.Sprint(ports[2]),
		"--tls-pem", path, "--ctl-socket", ctl, "--dns-name", ddrTarget,
	}
	gw := startGatewayProcess(t, append(flags, extra...), decider("serve"))
	g := &doh443Gateway{gw: gw, ctl: ctl, dot: uint16(ports[1]), doh: uint16(ports[2])}
	g.plain = listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("listening dot ")
	gw.waitLine("listening doh ")
	gw.waitLine("ready upstream ")
	return g
}

// push sends one address table and returns the reply line.
func (g *doh443Gateway) push(t *testing.T, lines ...string) string {
	t.Helper()
	c := dialCtl(t, g.ctl)
	_, _ = c.Write(addressTableFrame(strings.Join(lines, "\n")))
	return ctlReply(t, c)
}

// records is what DDR designates on 127.0.0.1: DoH with the port given (0: none, as 443 is advertised), then DoT.
func (g *doh443Gateway) records(dohPort uint16) ddrWant {
	return ddrWant{
		svcb:       []ddrSVCB{ddrDoHRec(ddrFQDN, dohPort, "127.0.0.1", ddrDoHPath), ddrDoTRec(ddrFQDN, g.dot, "127.0.0.1")},
		additional: []string{ddrAddrRR(ddrFQDN, "127.0.0.1")},
	}
}

func (g *doh443Gateway) requireDoH(t *testing.T, when string, dohPort uint16) {
	t.Helper()
	query := ddrQuery(t, 0x3694, ddrAsk, dnsmessage.TypeSVCB, 0)
	t.Log(when)
	requireDDR(t, query, udpQuery(t, g.plain, query), g.records(dohPort))
}

// requireName says the name's A query is answered with want, or with the decider's echo when want is "".
func (g *doh443Gateway) requireName(t *testing.T, when, want string) {
	t.Helper()
	query := nameQuery(t, nameFQDN, dnsmessage.TypeA)
	got := udpQuery(t, g.plain, query)
	if want == "" {
		if echo := echoWithQR(seenQuery{wire: query})[0]; string(got) != string(echo) {
			t.Fatalf("%s: the name was answered with %x, want the decider's echo", when, got)
		}
		return
	}
	t.Log(when)
	requireNameAnswer(t, query, got, nameFQDN, want)
}

// requireTableLogs waits for the gateway to have logged n `address table:` lines, and requires that it logged no more. A line
// is written before its push is answered, but the test reads the process's stderr, so it may arrive after the reply.
func (g *doh443Gateway) requireTableLogs(t *testing.T, n int, why string) {
	t.Helper()
	count := func() (lines int) {
		for _, line := range strings.Split(g.gw.logText(), "\n") {
			if strings.HasPrefix(line, "address table: ") {
				lines++
			}
		}
		return lines
	}
	eventually(t, fmt.Sprintf("%d `address table:` lines", n), func() bool { return count() >= n })
	if got := count(); got != n {
		t.Fatalf("%s: %d `address table:` lines, want %d\n%s", why, got, n, g.gw.logText())
	}
}

// D1, D2: an address named by --ddr-doh-443 is advertised without the port DoH listens on; the others carry it.
func TestDDRDoH443FlagIsPerAddress(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		none  bool // DoH is advertised without a port on 127.0.0.1
	}{
		{"D1 no flag: the configured port", nil, false},
		{"D2 the queried address", []string{"--ddr-doh-443", "127.0.0.1"}, true},
		{"D1 another address: the configured port", []string{"--ddr-doh-443", "127.0.0.2"}, false},
		{"D2 several addresses, the queried one among them", []string{"--ddr-doh-443", "127.0.0.2", "--ddr-doh-443", "127.0.0.1"}, true},
		{"D2 the same address twice is one", []string{"--ddr-doh-443", "127.0.0.1", "--ddr-doh-443", "127.0.0.1"}, true},
		{"D2 the IPv4-mapped spelling is the IPv4 address", []string{"--ddr-doh-443", "::ffff:127.0.0.1"}, true},
		{"D1 an IPv6 address is not the IPv4 one", []string{"--ddr-doh-443", "::1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := startDoH443Gateway(t, append([]string{"--ddr"}, c.flags...)...)
			port := g.doh
			if c.none {
				port = 0
			}
			g.requireDoH(t, c.name, port)
		})
	}
}

// N15 for the 443 set: the address table verb replaces it live, with the name answers, and a push that changes one table and
// not the other is logged; one that changes nothing is not.
func TestTheAddressTableVerbMovesTheDoH443AdvertisementLive(t *testing.T) {
	g := startDoH443Gateway(t, "--ddr", "--dns-name-answer", "127.0.0.1="+nameV4)
	answer, other := tableLine("127.0.0.1="+nameV4), tableLine("127.0.0.1=198.51.100.9")
	here, there := "ddr-doh-443 127.0.0.1", "ddr-doh-443 127.0.0.2"
	g.requireDoH(t, "start: no 443 address", g.doh)
	g.requireName(t, "start", nameV4)

	if got := g.push(t, answer, here); got != "ok" {
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireDoH(t, "after a push that names the queried address", 0)
	g.requireName(t, "that push changed only the 443 set, and left the name answers", nameV4)
	g.requireTableLogs(t, 1, "a push that changes only the 443 set must be logged once")

	if got := g.push(t, here, answer); got != "ok" { // the same tables, the lines in another order
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireDoH(t, "the same tables pushed again", 0)

	if got := g.push(t, answer, there); got != "ok" {
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireDoH(t, "after a push that names another address: the replaced set is not merged", g.doh)
	g.requireTableLogs(t, 2, "the unchanged push logged nothing and this one is the second")

	if got := g.push(t, other, there); got != "ok" {
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireName(t, "after a push that changes only the name answers", "198.51.100.9")
	g.requireTableLogs(t, 3, "a push that changes only the name answers must be logged once")

	if got := g.push(t, answer, here, here); got != "ok" { // a repeated line is one member
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireDoH(t, "after a push that changes both tables", 0)
	g.requireName(t, "after a push that changes both tables", nameV4)
	g.requireTableLogs(t, 4, "a push that changes both tables is logged once")

	for label, body := range map[string][]string{
		"a trailing space":                      {answer, here + " "},
		"two addresses":                         {answer, here + " 127.0.0.2"},
		"a zone":                                {answer, "ddr-doh-443 fe80::1%em0"},
		"a port":                                {answer, here + ":443"},
		"no address":                            {answer, "ddr-doh-443"},
		"the retired IPv6 flag's name":          {answer, "ddr-doh-4436 127.0.0.1"},
		"a bad 443 line after a good name line": {other, "ddr-doh-443 127.0.0.1:443"},
	} {
		if got := g.push(t, body...); !strings.HasPrefix(got, "error: ") {
			t.Fatalf("%s: reply %q, want an error", label, got)
		}
		g.requireDoH(t, label+": the 443 set is as it was", 0)
		g.requireName(t, label+": the name answers are as they were", nameV4)
	}

	if got := g.push(t); got != "ok" { // an empty body empties both tables
		t.Fatalf("push: reply %q, want ok", got)
	}
	g.requireDoH(t, "after an empty table", g.doh)
	g.requireName(t, "after an empty table", "")
	g.requireTableLogs(t, 5, "five pushes changed something and none of the refused ones logged")
}

// A line for the 443 set on a gateway that has no DDR is an error, and nothing of that body is taken.
func TestADoH443LineNeedsDDR(t *testing.T) {
	g := startDoH443Gateway(t, "--dns-name-answer", "127.0.0.1="+nameV4) // no --ddr
	g.requireName(t, "start", nameV4)
	if got := g.push(t, tableLine("127.0.0.1=198.51.100.9"), "ddr-doh-443 127.0.0.1"); got != "error: started without --ddr" {
		t.Fatalf("reply %q, want `error: started without --ddr`", got)
	}
	g.requireName(t, "after the refused push", nameV4)
	if got := g.push(t, tableLine("127.0.0.1=198.51.100.9")); got != "ok" {
		t.Fatalf("name answers alone: reply %q, want ok", got)
	}
	g.requireName(t, "after the push of name answers alone", "198.51.100.9")
}
