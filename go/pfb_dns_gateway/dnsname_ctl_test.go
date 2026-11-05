package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: root replaces the table of name answers on the running gateway with the control socket's address-table verb:
// FF FF FF FB, a 4-byte big-endian length (0 to 64 KiB) and that many bytes of `dns-name-answer LOCAL=ADDR[,ADDR]` lines
// separated by \n. The whole body is validated first; the reply is `ok` or `error: <reason>`, and an error leaves the table as
// it was.

// namesCtlRig is a control socket in front of the table of names, and the gateway that answers from it. The rig's own plain
// listener is never asked: every query goes straight into screen, so g.names set after it serves has no reader.
type namesCtlRig struct {
	*ctlRig
	names *nameAnswers
}

func newNamesCtlRig(t *testing.T, name string, answers ...string) *namesCtlRig {
	t.Helper()
	names := mustNames(t, name, answers...)
	k := newCtlRig(t, func(c *ctlServer) { c.names = names })
	k.r.g.names = names
	return &namesCtlRig{ctlRig: k, names: names}
}

// ask runs the name's A query that reached local through screen and returns the address answered ("" is the decider's).
func (k *namesCtlRig) ask(t *testing.T, local string, typ dnsmessage.Type) string {
	t.Helper()
	query := nameQuery(t, nameFQDN, typ)
	disp, reply := screenAs(k.r.g, local, true, true, query)
	if disp != replyNow {
		requireDeciders(t, disp, reply, local)
		return ""
	}
	for _, rr := range parseReply(t, reply).Answers {
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			return netip.AddrFrom4(b.A).String()
		case *dnsmessage.AAAAResource:
			return netip.AddrFrom16(b.AAAA).String()
		}
	}
	t.Fatalf("the reply to %v on %s has no address: %x", typ, local, reply)
	return ""
}

func (k *namesCtlRig) requireAnswer(t *testing.T, local string, typ dnsmessage.Type, want, when string) {
	t.Helper()
	if got := k.ask(t, local, typ); got != want {
		t.Fatalf("%s: %v on %s is answered %q, want %q", when, typ, local, got, want)
	}
}

// requireInitialTable says the table is the one newNamesCtlRig was started with, and nothing of what a push offered.
func (k *namesCtlRig) requireInitialTable(t *testing.T, when string) {
	t.Helper()
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "10.0.0.1", when)
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeAAAA, "2001:db8:1::1", when)
	k.requireAnswer(t, "10.0.0.2", dnsmessage.TypeA, "", when)
	k.requireAnswer(t, "10.0.0.9", dnsmessage.TypeA, "", when)
	if n := k.logsAbout("address table:"); n != 0 {
		t.Fatalf("%s: %d `address table:` log lines, want none from a push that was refused", when, n)
	}
}

func newInitialNamesCtlRig(t *testing.T) *namesCtlRig {
	t.Helper()
	return newNamesCtlRig(t, "fw.example.lan", "10.0.0.1=10.0.0.1,2001:db8:1::1")
}

// N15: the table is replaced as a whole, not merged, and the new pair is answered at once.
func TestTheAddressTableVerbReplacesTheWholeTable(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	k.requireInitialTable(t, "before the push")
	body := strings.Join([]string{
		tableLine("10.0.0.2=10.0.0.2,2001:db8:1::2"),
		tableLine("10.0.0.53=10.0.0.53"),
	}, "\n")
	if got := k.send(t, addressTableFrame(body)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireAnswer(t, "10.0.0.2", dnsmessage.TypeA, "10.0.0.2", "after the push")
	k.requireAnswer(t, "10.0.0.2", dnsmessage.TypeAAAA, "2001:db8:1::2", "after the push")
	k.requireAnswer(t, "10.0.0.53", dnsmessage.TypeA, "10.0.0.53", "after the push")
	query := nameQuery(t, nameFQDN, dnsmessage.TypeAAAA)
	_, reply := screenAs(k.r.g, "10.0.0.53", true, true, query)
	requireNameNODATA(t, query, reply)
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "", "after the push: the old entry is gone, not merged")
	if n := k.logsAbout("address table: 2 name answers"); n != 1 {
		t.Fatalf("want one `address table: 2 name answers` line, got %d: %s", n, k.r.logs.joined())
	}
}

// An empty body is a valid, empty table.
func TestAnEmptyAddressTableEmptiesTheTable(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	if got := k.send(t, addressTableFrame("")); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "", "after an empty table")
	if n := k.logsAbout("address table: 0 name answers"); n != 1 {
		t.Fatalf("want one `address table: 0 name answers` line, got %d: %s", n, k.r.logs.joined())
	}
}

// Every value the flag takes, a line takes; every one it refuses, a line refuses and leaves the table as it was.
func TestAnAddressTableLineIsTheFlagsSyntax(t *testing.T) {
	for label, v := range goodNameValues {
		t.Run("good: "+label, func(t *testing.T) {
			k := newInitialNamesCtlRig(t)
			if got := k.send(t, addressTableFrame(tableLine(v.value))); got != "ok" {
				t.Fatalf("reply %q, want ok", got)
			}
			requireValueAnswers(t, func(local string, wire []byte) []byte {
				disp, reply := screenAs(k.r.g, local, true, true, wire)
				if disp != replyNow {
					return nil
				}
				return reply
			}, v)
		})
	}
	for label, value := range badNameValues {
		t.Run("bad: "+label, func(t *testing.T) {
			k := newInitialNamesCtlRig(t)
			if got := k.send(t, addressTableFrame(tableLine(value))); !strings.HasPrefix(got, "error: ") {
				t.Fatalf("reply %q, want an error", got)
			}
			k.requireInitialTable(t, "after a refused line")
		})
	}
}

// The body is validated whole: a bad line anywhere, however good the lines before it, applies nothing.
func TestABadLineLeavesTheAddressTableAsItWas(t *testing.T) {
	good := tableLine("10.0.0.2=10.0.0.2")
	rows := map[string]string{
		"an unknown first word":                   "ddr-doh-4436 10.0.0.2",
		"an unknown first word after a good line": good + "\nsomething 10.0.0.9=10.0.0.9",
		"a good line, then a bad value":           good + "\n" + tableLine("10.0.0.3=bad"),
		"a bad value, then a good line":           tableLine("10.0.0.3=bad") + "\n" + good,
		"CRLF line endings":                       good + "\r\n" + tableLine("10.0.0.3=10.0.0.3"),
		"the same LOCAL twice":                    good + "\n" + tableLine("10.0.0.2=10.0.0.9"),
		"the same LOCAL, once IPv4-mapped":        good + "\n" + tableLine("::ffff:10.0.0.2=10.0.0.9"),
		"an empty line between lines":             good + "\n\n" + tableLine("10.0.0.3=10.0.0.3"),
		"a newline at the end":                    good + "\n",
		"the word alone":                          "dns-name-answer",
		"the word and a space":                    "dns-name-answer ",
		"two spaces after the word":               "dns-name-answer  10.0.0.2=10.0.0.2",
		"the word in upper case":                  "DNS-NAME-ANSWER 10.0.0.2=10.0.0.2",
		"a NUL byte":                              good + "\x00",
	}
	for label, body := range rows {
		t.Run(label, func(t *testing.T) {
			k := newInitialNamesCtlRig(t)
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error: ") {
				t.Fatalf("reply %q, want an error", got)
			}
			k.requireInitialTable(t, "after a refused body")
		})
	}
	t.Run("the control: the good line alone is taken", func(t *testing.T) {
		k := newInitialNamesCtlRig(t)
		if got := k.send(t, addressTableFrame(good)); got != "ok" {
			t.Fatalf("reply %q, want ok", got)
		}
		k.requireAnswer(t, "10.0.0.2", dnsmessage.TypeA, "10.0.0.2", "after the push")
	})
}

// The body is 0 to 64 KiB: a body of 64 KiB is read in full, one byte over is refused unread.
func TestTheAddressTableIsBoundedTo64KiB(t *testing.T) {
	t.Run("a large valid table is taken", func(t *testing.T) {
		k := newInitialNamesCtlRig(t)
		var lines []string
		for i := range 1300 { // 49 bytes a line and a newline: 65 KB less a little, so within the bound
			lines = append(lines, tableLine(fmt.Sprintf("2001:db8:%04x::1=2001:db8:%04x::1", i, i)))
		}
		body := strings.Join(lines, "\n")
		if len(body) > 65536 {
			t.Fatalf("fixture: %d bytes, want at most 65536", len(body))
		}
		if got := k.send(t, addressTableFrame(body)); got != "ok" {
			t.Fatalf("reply %q, want ok", got)
		}
		k.requireAnswer(t, "2001:db8:0513::1", dnsmessage.TypeAAAA, "2001:db8:513::1", "after the large push")
		k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "", "after the large push")
	})
	t.Run("a body of exactly 64 KiB is read, and judged by what it holds", func(t *testing.T) {
		k := newInitialNamesCtlRig(t)
		got := k.send(t, addressTableFrame(tableLine(strings.Repeat("x", 65536-len(tableLine(""))))))
		if !strings.HasPrefix(got, "error: ") || strings.Contains(got, "65536 bytes is over") {
			t.Fatalf("reply %.200q, want an error about the line, not about the size", got)
		}
		if len(got) > 1024 {
			t.Fatalf("the error is %d bytes: it must not carry the whole body back", len(got))
		}
		k.requireInitialTable(t, "after the refused body")
	})
	t.Run("one byte over is refused by its length alone", func(t *testing.T) {
		k := newInitialNamesCtlRig(t)
		c := dialCtl(t, k.path)
		if _, err := c.Write(binary.BigEndian.AppendUint32(slices.Clone(addressTableVerb), 65537)); err != nil {
			t.Fatal(err)
		}
		if got := ctlReply(t, c); got != "error: an address table of 65537 bytes is over 65536" {
			t.Fatalf("reply %q, want the size error", got)
		}
		k.requireInitialTable(t, "after the refused length")
	})
}

// A body that ends before its length says is refused, and the table is as it was.
func TestAnAddressTableCutShortIsRefused(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	c := dialCtl(t, k.path)
	_, _ = c.Write(append(binary.BigEndian.AppendUint32(slices.Clone(addressTableVerb), 100), tableLine("10.0.0.2=10.0.0.2")...))
	_ = c.CloseWrite()
	if got := ctlReply(t, c); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("reply %q, want an error", got)
	}
	k.requireInitialTable(t, "after a cut-short body")
}

// A gateway started without --dns-name has no table to replace.
func TestTheAddressTableVerbNeedsADNSName(t *testing.T) {
	k := newCtlRig(t) // no names
	for label, body := range map[string]string{"a table": tableLine("10.0.0.2=10.0.0.2"), "an empty table": ""} {
		if got := k.send(t, addressTableFrame(body)); got != "error: started without --dns-name" {
			t.Fatalf("%s: reply %q, want `error: started without --dns-name`", label, got)
		}
	}
	if n := k.logsAbout("address table:"); n != 0 {
		t.Fatalf("%d `address table:` log lines, want none", n)
	}
}

// Like every verb, only root's push is read.
func TestTheAddressTableVerbIsRootsOnly(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	k.peer.Store(ctlUID + 1001)
	if got := k.send(t, addressTableFrame(tableLine("10.0.0.2=10.0.0.2"))); got != "" {
		t.Fatalf("a peer that is not root got the reply %q, want none", got)
	}
	k.requireInitialTable(t, "after a push from another user")
}

// Queries run while the table is replaced: each is answered by the table before the push or the one after, never by a mix.
func TestQueriesDuringTablePushesSeeOneTableOrTheOther(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	query := nameQuery(t, nameFQDN, dnsmessage.TypeA)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			disp, reply := screenAs(k.r.g, "10.0.0.1", true, true, query)
			if disp != replyNow {
				bad <- "a query on an address both tables answer reached the decider"
				return
			}
			var m dnsmessage.Message
			if err := m.Unpack(reply); err != nil || len(m.Answers) != 1 {
				bad <- fmt.Sprintf("reply %x: %v", reply, err)
				return
			}
			if got := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A).String(); got != "10.0.0.1" && got != "198.51.100.1" {
				bad <- "answered " + got
				return
			}
		}
	}()
	for i := range 60 {
		to := "10.0.0.1"
		if i%2 == 0 {
			to = "198.51.100.1"
		}
		if got := k.send(t, addressTableFrame(tableLine("10.0.0.1="+to))); got != "ok" {
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
