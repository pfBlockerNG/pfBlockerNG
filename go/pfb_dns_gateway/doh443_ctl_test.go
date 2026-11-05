package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: the address table verb carries two kinds of line, keyed by their first word: `dns-name-answer LOCAL=ADDR[,ADDR]`
// and `ddr-doh-443 ADDR`. The body replaces both tables, is validated whole first, and is logged when either table changes.

const (
	tblA = "10.0.0.1" // the address the start's name answer and 443 set name, and where DDR is asked
	tblB = "10.0.0.2" // a second address with a DoH listener, which the start's 443 set does not name
)

func doh443Line(addr string) string { return "ddr-doh-443 " + addr }

// tableRig is the control socket in front of both tables: names (10.0.0.1 answered) and, with DDR on, DoH listeners on 4443
// at both addresses with 10.0.0.1 in the 443 set.
type tableRig struct {
	*namesCtlRig
	ddr *ddr
}

func newTableRig(t *testing.T, ddrOn bool) *tableRig {
	t.Helper()
	names := mustNames(t, ddrTarget, tblA+"="+tblA+",2001:db8:1::1")
	var d *ddr
	if ddrOn {
		d = mustDDR(t, ddrTarget, ddrLoaded(t), nil, addrPorts(tblA, 4443), nil)
		d.change(true, "doh", netip.MustParseAddrPort(tblB+":4443"))
		d.setDoH443(addrSet(tblA))
	}
	k := newCtlRig(t, func(c *ctlServer) { c.names, c.ddr = names, d })
	k.r.g.names, k.r.g.ddr = names, d
	return &tableRig{&namesCtlRig{ctlRig: k, names: names}, d}
}

// dohPort is the port of the one DoH record DDR gives a client of local: 0 is none (443 is advertised).
func (k *tableRig) dohPort(t *testing.T, local string) uint16 {
	t.Helper()
	query := ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0)
	disp, reply := screenAs(k.r.g, local, true, true, query)
	if disp != replyNow {
		t.Fatalf("DDR on %s: screen gave disposition %d, want replyNow", local, disp)
	}
	var ports []uint16
	for _, rr := range parseReply(t, reply).Answers {
		if rec := ddrDecode(t, rr, ddrAsk); rec.alpn == "h2" {
			ports = append(ports, rec.port)
		}
	}
	if len(ports) != 1 {
		t.Fatalf("DDR on %s: %d DoH records, want exactly one", local, len(ports))
	}
	return ports[0]
}

func (k *tableRig) requireDoH(t *testing.T, when string, a, b uint16) {
	t.Helper()
	if got := k.dohPort(t, tblA); got != a {
		t.Fatalf("%s: DoH on %s is advertised on port %d, want %d (0: none)", when, tblA, got, a)
	}
	if got := k.dohPort(t, tblB); got != b {
		t.Fatalf("%s: DoH on %s is advertised on port %d, want %d (0: none)", when, tblB, got, b)
	}
}

// requireStart says neither table has changed since the rig started: and nothing was logged about one.
func (k *tableRig) requireStart(t *testing.T, when string) {
	t.Helper()
	k.requireInitialTable(t, when) // the name answers, and no `address table:` line
	if k.ddr != nil {
		k.requireDoH(t, when, 0, 4443)
	}
}

func TestTheAddressTableVerbReplacesBothTables(t *testing.T) {
	k := newTableRig(t, true)
	k.requireStart(t, "before the push")
	body := strings.Join([]string{tableLine(tblB + "=" + tblB), doh443Line(tblB)}, "\n")
	if got := k.send(t, addressTableFrame(body)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireAnswer(t, tblB, dnsmessage.TypeA, tblB, "after the push")
	k.requireAnswer(t, tblA, dnsmessage.TypeA, "", "after the push: the old name answer is gone, not merged")
	k.requireDoH(t, "after the push: the 443 set is replaced, not merged", 4443, 0)
	if n := k.logsAbout("address table: 1 name answers"); n != 1 {
		t.Fatalf("want one `address table: 1 name answers` line, got %d: %s", n, k.r.logs.joined())
	}
}

func TestAnEmptyAddressTableEmptiesBothTables(t *testing.T) {
	k := newTableRig(t, true)
	if got := k.send(t, addressTableFrame("")); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireAnswer(t, tblA, dnsmessage.TypeA, "", "after an empty table")
	k.requireDoH(t, "after an empty table", 4443, 4443)
}

// The 443 set is a set: a repeated line is one member, and IPv4-mapped is the IPv4 address.
func TestTheDoH443LinesOfATableAreASet(t *testing.T) {
	k := newTableRig(t, true)
	body := strings.Join([]string{doh443Line("::ffff:" + tblB), doh443Line(tblB), doh443Line("::ffff:" + tblB)}, "\n")
	if got := k.send(t, addressTableFrame(body)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireDoH(t, "after the push", 4443, 0)
}

// A push is logged when either table changes, and only then; the order of the lines, and a line repeated, change nothing.
func TestAnAddressTableIsLoggedWhenEitherTableChanges(t *testing.T) {
	k := newTableRig(t, true)
	names := tableLine(tblA + "=" + tblA + ",2001:db8:1::1")
	steps := []struct {
		what   string
		lines  []string
		logged int // the `address table:` lines so far
	}{
		{"the tables the gateway started with", []string{names, doh443Line(tblA)}, 0},
		{"the same tables, the lines in the other order", []string{doh443Line(tblA), names}, 0},
		{"the same tables, a 443 line repeated", []string{doh443Line(tblA), names, doh443Line(tblA)}, 0},
		{"the same tables, the 443 address IPv4-mapped", []string{names, doh443Line("::ffff:" + tblA)}, 0},
		{"only the 443 set differs", []string{names, doh443Line(tblB)}, 1},
		{"that again", []string{names, doh443Line(tblB)}, 1},
		{"a second 443 address", []string{names, doh443Line(tblB), doh443Line(tblA)}, 2},
		{"only the name answers differ", []string{tableLine(tblA + "=" + tblB), doh443Line(tblB), doh443Line(tblA)}, 3},
		{"both differ", []string{tableLine(tblB + "=" + tblB)}, 4},
		{"neither differs: the empty 443 set again", []string{tableLine(tblB + "=" + tblB)}, 4},
		{"an empty table", nil, 5},
		{"an empty table again", nil, 5},
	}
	for _, s := range steps {
		if got := k.send(t, addressTableFrame(strings.Join(s.lines, "\n"))); got != "ok" {
			t.Fatalf("%s: reply %q, want ok", s.what, got)
		}
		if n := k.logsAbout("address table:"); n != s.logged {
			t.Fatalf("%s: %d `address table:` lines, want %d; log:\n%s", s.what, n, s.logged, k.r.logs.joined())
		}
	}
}

// What a line of either kind may not be, in the flag's syntax: the whole body is refused and neither table moves.
func TestABadLineOfEitherKindLeavesBothTablesAsTheyWere(t *testing.T) {
	good := tableLine(tblB + "=" + tblB)
	rows := map[string]string{
		"a 443 line with no address":                      "ddr-doh-443",
		"a 443 line with an empty address":                "ddr-doh-443 ",
		"a 443 line with two spaces":                      "ddr-doh-443  " + tblB,
		"a 443 line with a trailing space":                doh443Line(tblB) + " ",
		"a 443 line with two addresses":                   doh443Line(tblB + " " + tblA),
		"a 443 line with a comma list":                    doh443Line(tblB + "," + tblA),
		"a 443 line with a zone":                          doh443Line("fe80::1%em0"),
		"a 443 line with a port":                          doh443Line(tblB + ":443"),
		"a 443 line with a name":                          doh443Line("fw.example.lan"),
		"a 443 line with a carriage return":               doh443Line(tblB) + "\r",
		"a 443 line with a tab":                           "ddr-doh-443\t" + tblB,
		"a 443 line in upper case":                        "DDR-DOH-443 " + tblB,
		"the retired IPv6 flag's name":                    "ddr-doh-4436 " + tblB,
		"a prefix of the word":                            "ddr-doh-44 " + tblB,
		"a bad 443 line after good lines of both kinds":   good + "\n" + doh443Line(tblB) + "\n" + doh443Line("1.2.3"),
		"a bad name line after a good 443 line":           doh443Line(tblB) + "\n" + tableLine("="+tblB),
		"a good 443 line then an unknown word":            doh443Line(tblB) + "\nsomething " + tblB,
		"a good 443 line, then an empty line":             doh443Line(tblB) + "\n\n" + good,
		"a good name line, a good 443 line and a newline": good + "\n" + doh443Line(tblB) + "\n",
	}
	for label, body := range rows {
		t.Run(label, func(t *testing.T) {
			k := newTableRig(t, true)
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error: ") {
				t.Fatalf("reply %q, want an error", got)
			}
			k.requireStart(t, "after a refused body")
		})
	}
	t.Run("the control: the good lines of those bodies alone are taken", func(t *testing.T) {
		k := newTableRig(t, true)
		if got := k.send(t, addressTableFrame(good+"\n"+doh443Line(tblB))); got != "ok" {
			t.Fatalf("reply %q, want ok", got)
		}
		k.requireAnswer(t, tblB, dnsmessage.TypeA, tblB, "after the push")
		k.requireDoH(t, "after the push", 4443, 0)
	})
}

// A gateway without --ddr has no 443 set: a 443 line is refused with the whole body, an empty set is not.
func TestADoH443LineNeedsDDRInTheTable(t *testing.T) {
	good := tableLine(tblB + "=" + tblB)
	t.Run("a 443 line is refused and the name answers do not move", func(t *testing.T) {
		k := newTableRig(t, false)
		for _, body := range []string{doh443Line(tblB), good + "\n" + doh443Line(tblB), doh443Line(tblB) + "\n" + good} {
			if got := k.send(t, addressTableFrame(body)); got != "error: started without --ddr" {
				t.Fatalf("body %q: reply %q, want `error: started without --ddr`", body, got)
			}
			k.requireStart(t, "after the refused body")
		}
	})
	t.Run("name answers alone and an empty body are taken", func(t *testing.T) {
		k := newTableRig(t, false)
		if got := k.send(t, addressTableFrame(good)); got != "ok" {
			t.Fatalf("reply %q, want ok", got)
		}
		k.requireAnswer(t, tblB, dnsmessage.TypeA, tblB, "after the push")
		if got := k.send(t, addressTableFrame("")); got != "ok" {
			t.Fatalf("reply %q, want ok", got)
		}
		k.requireAnswer(t, tblB, dnsmessage.TypeA, "", "after the empty push")
	})
}

// A query reads one 443 set or the other, never a mix, while the verb replaces it.
func TestQueriesDuringDoH443PushesSeeOneSetOrTheOther(t *testing.T) {
	k := newTableRig(t, true)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	query := ddrQuery(t, 1, ddrAsk, dnsmessage.TypeSVCB, 0)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			disp, reply := screenAs(k.r.g, tblA, true, true, query)
			var m dnsmessage.Message
			if disp != replyNow || m.Unpack(reply) != nil || len(m.Answers) != 1 {
				bad <- fmt.Sprintf("disposition %d reply %x: want one DoH record", disp, reply)
				return
			}
			svcb, ok := m.Answers[0].Body.(*dnsmessage.SVCBResource)
			if !ok {
				bad <- fmt.Sprintf("the answer is a %T, want SVCB", m.Answers[0].Body)
				return
			}
			for _, p := range svcb.Params {
				if p.Key == dnsmessage.SVCParamPort && (len(p.Value) != 2 || p.Value[0] != 0x11 || p.Value[1] != 0x5b) { // 4443
					bad <- fmt.Sprintf("DoH advertised on port %x, want 4443 or none", p.Value)
					return
				}
			}
		}
	}()
	for i := range 60 {
		body := doh443Line(tblA)
		if i%2 == 0 {
			body = doh443Line(tblB)
		}
		if got := k.send(t, addressTableFrame(body)); got != "ok" {
			close(stop)
			wg.Wait()
			t.Fatalf("push %d: reply %q", i, got)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case why := <-bad:
		t.Fatal(why)
	default:
	}
}
