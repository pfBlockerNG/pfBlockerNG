package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694, end to end: the process the rc script starts. Flags in, answers out over plain UDP and DoT, then a new table
// pushed on the control socket and answered without a restart.
func TestDNSNameGatewayProcessAnswersTheNameDesignatesItAndTakesANewTableLive(t *testing.T) {
	ports := distinctPorts(t, 2)
	path, m := goodPEM(t)
	ctl := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	const name = "Gw.Example.Lan" // mixed case: DDR names it as configured, queries match it in any case
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", fmt.Sprint(ports[1]), "--unbound-conf", filepath.Join(t.TempDir(), "absent"),
		"--dot-listen", "127.0.0.1", "--dot-port", fmt.Sprint(ports[0]), "--tls-pem", path, "--ctl-socket", ctl,
		"--dns-name", name, "--ddr", "--dns-name-answer", "127.0.0.1=" + nameV4 + "," + nameV6,
	}, decider("serve"))
	plain := listenAddr(t, gw.waitLine("listening udp+tcp "))
	dot := listeningAddr(t, gw.waitLine("listening dot "), "dot")
	gw.waitLine("ready upstream ")

	deciders := func(query []byte) []byte { return echoWithQR(seenQuery{wire: query})[0] }
	push := func(body string) string {
		c := dialCtl(t, ctl)
		_, _ = c.Write(addressTableFrame(body))
		return ctlReply(t, c)
	}

	a := nameQuery(t, "gw.example.lan.", dnsmessage.TypeA)
	requireNameAnswer(t, a, udpQuery(t, plain, a), "gw.example.lan.", nameV4)
	shout := nameQuery(t, "GW.EXAMPLE.LAN.", dnsmessage.TypeA)
	requireNameAnswer(t, shout, udpQuery(t, plain, shout), "GW.EXAMPLE.LAN.", nameV4)
	aaaa := nameQuery(t, "gw.example.lan.", dnsmessage.TypeAAAA)
	c := dialDoT(t, dot, m, "")
	tcpSend(t, c, aaaa)
	requireNameAnswer(t, aaaa, tcpReply(t, c), "gw.example.lan.", nameV6)

	mx := nameQuery(t, "gw.example.lan.", dnsmessage.TypeMX)
	if got := udpQuery(t, plain, mx); !bytes.Equal(got, deciders(mx)) {
		t.Fatalf("MX for the name: got %x, want the decider's echo %x", got, deciders(mx))
	}
	other := nameQuery(t, "other.example.lan.", dnsmessage.TypeA)
	if got := udpQuery(t, plain, other); !bytes.Equal(got, deciders(other)) {
		t.Fatalf("another name: got %x, want the decider's echo %x", got, deciders(other))
	}

	// N4: DDR's target and the owner of its address record are the DNS name, as configured
	svcb := ddrQuery(t, 0x3694, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, svcb, udpQuery(t, plain, svcb), ddrWant{
		svcb:       []ddrSVCB{ddrDoTRec(name+".", uint16(ports[0]), "127.0.0.1")},
		additional: []string{ddrAddrRR(name+".", "127.0.0.1")},
	})

	// N15: a new table, answered at once; a refused one changes nothing
	if got := push(tableLine("127.0.0.1=198.51.100.9")); got != "ok" {
		t.Fatalf("push: reply %q, want ok", got)
	}
	gw.waitLine("address table: 1 name answers")
	requireNameAnswer(t, a, udpQuery(t, plain, a), "gw.example.lan.", "198.51.100.9")
	requireNameNODATA(t, aaaa, udpQuery(t, plain, aaaa))
	if got := push(tableLine("127.0.0.1=198.51.100.10") + "\n" + tableLine("127.0.0.2=bad")); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("a table with a bad line: reply %q, want an error", got)
	}
	requireNameAnswer(t, a, udpQuery(t, plain, a), "gw.example.lan.", "198.51.100.9")
	requireDDR(t, svcb, udpQuery(t, plain, svcb), ddrWant{
		svcb:       []ddrSVCB{ddrDoTRec(name+".", uint16(ports[0]), "127.0.0.1")},
		additional: []string{ddrAddrRR(name+".", "127.0.0.1")},
	})
}
