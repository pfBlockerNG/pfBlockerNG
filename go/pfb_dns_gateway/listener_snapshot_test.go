package main

import (
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func listenerRow(ip, label string) string {
	return "listener-interface " + ip + "=" + base64.StdEncoding.EncodeToString([]byte(label))
}

func TestListenerInterfaceSnapshotOnOpenConnection(t *testing.T) {
	k := newCtlRig(t)
	c := k.r.tcpClient(clientAllowed)
	push := func(body string) {
		t.Helper()
		if got := k.send(t, addressTableFrame(body)); got != "ok" {
			t.Fatalf("owner-only update: got %q, want ok", got)
		}
	}
	ask := func(want string) transportQuery {
		t.Helper()
		tcpSend(t, c, buildQuery(t, 0, "allowed.example.", true))
		q := k.r.recvTransportQuery()
		if q.listenerIP != "127.0.0.1" || q.listenerInterface != want {
			t.Fatalf("listener=%q interface=%q, want 127.0.0.1 %q", q.listenerIP, q.listenerInterface, want)
		}
		return q
	}
	answer := func(q transportQuery) {
		t.Helper()
		k.r.p.answer(q.id, echoAnswer(decidedQuery{wire: q.wire}))
		if got := tcpReply(t, c); len(got) == 0 {
			t.Fatal("empty socket answer")
		}
	}
	label := "LAN, \"quoted\" \\ café"
	push(listenerRow("127.0.0.1", label))
	held := ask(label)
	push(listenerRow("127.0.0.1", "renamed"))
	if held.listenerInterface != label {
		t.Fatalf("in-flight owner=%q, want immutable %q", held.listenerInterface, label)
	}
	answer(held)
	answer(ask("renamed"))
	push(listenerRow("127.0.0.2", "moved"))
	answer(ask(""))
	push("")
	answer(ask(""))
}

// listenerValue is one `IP=BASE64` listener-interface value: what a flag takes and a pushed row carries after its word.
func listenerValue(ip, label string) string {
	return ip + "=" + base64.StdEncoding.EncodeToString([]byte(label))
}

// badListenerInterfaces are the entries that are skipped, as a flag and as a pushed row, whatever else is given.
var badListenerInterfaces = map[string]string{
	"base64 that is not base64":               "127.0.0.1=%%%",
	"base64 with its trailing bits set":       "127.0.0.1=TF==",
	"base64 with a carriage return in it":     "127.0.0.1=TE\rFO",
	"base64 of a label with a line feed":      "127.0.0.1=YmFkCg==",
	"no equals sign":                          "127.0.0.1",
	"no value at all":                         "",
	"an unspecified IPv4 address":             listenerValue("0.0.0.0", "bad"),
	"an unspecified IPv6 address":             listenerValue("::", "bad"),
	"an IPv6 address with a zone":             listenerValue("fe80::1%lo", "bad"),
	"an address in brackets":                  listenerValue("[::1]", "bad"),
	"an address with a port":                  listenerValue("127.0.0.1:53", "bad"),
	"an address with a prefix length":         listenerValue("127.0.0.1/8", "bad"),
	"an IPv4-mapped unspecified address":      listenerValue("::ffff:0.0.0.0", "bad"),
	"an IPv4-mapped IPv6 address with a zone": listenerValue("::ffff:127.0.0.1%lo", "bad"),
	"a label with a line feed":                listenerValue("127.0.0.1", "bad\nlabel"),
	"a label with a NUL":                      listenerValue("127.0.0.1", "bad\x00label"),
	"a label with a DEL":                      listenerValue("127.0.0.1", "bad\x7flabel"),
	"a label with a C1 control":               listenerValue("127.0.0.1", "bad\u0085label"),
	"a label that is not UTF-8":               listenerValue("127.0.0.1", string([]byte{0xff})),
	"a label with a zero-width joiner":        listenerValue("127.0.0.1", "bad\u200dlabel"),
	"a label with a left-to-right mark":       listenerValue("127.0.0.1", "bad\u200elabel"),
	"a label with a line separator":           listenerValue("127.0.0.1", "bad\u2028label"),
	"a label with a paragraph separator":      listenerValue("127.0.0.1", "bad\u2029label"),
}

// goodListenerLabels are text: the rule skips controls, format characters and line breaks, not what is not ASCII.
var goodListenerLabels = map[string]string{
	"ASCII":                  "LAN",
	"Latin letters":          "Län",
	"CJK":                    "日本",
	"a no-break space":       "a\u00a0b",
	"an empty label":         "",
	"quotes and a backslash": "LAN, \"quoted\" \\ café",
}

func listenerSnapshot(k *ctlRig) map[string]string {
	got := map[string]string{}
	if table := k.r.g.listenerInterfaces.Load(); table != nil {
		for ip, label := range *table {
			got[ip.String()] = label
		}
	}
	return got
}

func requireListenerSnapshot(t *testing.T, k *ctlRig, want map[string]string, when string) {
	t.Helper()
	if got := listenerSnapshot(k); !maps.Equal(got, want) {
		t.Fatalf("%s: listener interfaces %q, want %q", when, got, want)
	}
}

func pushTable(t *testing.T, k *ctlRig, body string) {
	t.Helper()
	if got := k.send(t, addressTableFrame(body)); got != "ok" {
		t.Fatalf("push %q: reply %q, want ok", body, got)
	}
}

// requireLogLine says the log has the line, whole.
func requireLogLine(t *testing.T, log, want string) {
	t.Helper()
	if !slices.Contains(strings.Split(log, "\n"), want) {
		t.Fatalf("the log has no line %q; log:\n%s", want, log)
	}
}

// requireSkipped says the log skips exactly these entries, each on a line of its own.
func requireSkipped(t *testing.T, log string, values ...string) {
	t.Helper()
	if n := strings.Count(log, "listener-interface "); n != len(values) {
		t.Fatalf("%d `listener-interface` lines in the log, want %d; log:\n%s", n, len(values), log)
	}
	for _, v := range values {
		if want := fmt.Sprintf("listener-interface %.64q skipped: ", v); !strings.Contains("\n"+log, "\n"+want) {
			t.Fatalf("the log has no line starting %q; log:\n%s", want, log)
		}
	}
}

// A listener-interface row that is not valid costs only itself: the push is answered ok and the good rows are applied.
func TestABadListenerInterfaceRowIsSkippedAndTheGoodRowsAreApplied(t *testing.T) {
	for name, value := range badListenerInterfaces {
		t.Run(name, func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow("127.0.0.1", "LAN"))
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.1": "LAN"}, "before the push")
			pushTable(t, k, listenerRow("127.0.0.2", "kept")+"\nlistener-interface "+value)
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.2": "kept"}, "after the push")
			requireSkipped(t, k.r.logs.joined(), value)
		})
	}
}

// A push refused whole applies nothing, so it logs no skipped listener-interface entry either.
func TestARefusedPushLogsNoSkippedListenerInterface(t *testing.T) {
	bad := "\nlistener-interface 0.0.0.0=YmFk"
	t.Run("started without --ddr", func(t *testing.T) {
		k := newTableRig(t, false)
		if got := k.send(t, addressTableFrame(doh443Line(tblB)+bad)); got != "error: started without --ddr" {
			t.Fatalf("reply %q, want `error: started without --ddr`", got)
		}
		requireSkipped(t, k.r.logs.joined())
	})
	t.Run("started without --dns-name", func(t *testing.T) {
		k := newCtlRig(t)
		if got := k.send(t, addressTableFrame(tableLine(tblB+"="+tblB)+bad)); got != "error: started without --dns-name" {
			t.Fatalf("reply %q, want `error: started without --dns-name`", got)
		}
		requireSkipped(t, k.r.logs.joined())
	})
}

// Bad rows are skipped wherever they stand among the good ones, and the log counts what was applied.
func TestBadListenerInterfaceRowsBetweenGoodRowsAreAllSkipped(t *testing.T) {
	k := newCtlRig(t)
	rows := []string{listenerRow("127.0.0.2", "first")}
	var values []string
	for _, value := range badListenerInterfaces {
		values = append(values, value)
		rows = append(rows, "listener-interface "+value)
	}
	rows = append(rows, listenerRow("127.0.0.3", "last"))
	pushTable(t, k, strings.Join(rows, "\n"))
	requireListenerSnapshot(t, k, map[string]string{"127.0.0.2": "first", "127.0.0.3": "last"}, "after the push")
	requireSkipped(t, k.r.logs.joined(), values...)
	requireLogLine(t, k.r.logs.joined(), "address table: 0 name answers, 0 DoH 443 addresses, 2 listener interfaces")
}

// Labels that are text are applied, so that the skipped set above is not everything.
func TestListenerInterfaceLabelsThatAreTextAreApplied(t *testing.T) {
	for name, label := range goodListenerLabels {
		t.Run(name, func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow("127.0.0.1", label))
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.1": label}, "after the push")
			requireSkipped(t, k.r.logs.joined())
		})
	}
}

// Two rows for one address: the first is applied, the second is skipped and logged, whatever its label.
func TestTheFirstOfTwoListenerInterfaceRowsForOneAddressWins(t *testing.T) {
	initial := listenerRow("127.0.0.1", "LAN")
	for name, second := range map[string]string{"the same row twice": initial, "a different label": listenerRow("127.0.0.1", "other")} {
		t.Run(name, func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow("127.0.0.2", "kept")+"\n"+initial+"\n"+second)
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.2": "kept", "127.0.0.1": "LAN"}, "after the push")
			requireSkipped(t, k.r.logs.joined(), strings.TrimPrefix(second, "listener-interface "))
		})
	}
}

// An IP in any numeric spelling is keyed by its value, as a flag and as a pushed row: an IPv4-mapped address is the IPv4
// address and netip's text names the rest. Issue #3849.
func TestListenerInterfaceIPsAreKeyedByValue(t *testing.T) {
	for name, row := range map[string]struct{ spelling, key string }{
		"an IPv4-mapped IPv6 address":           {"::ffff:127.0.0.1", "127.0.0.1"},
		"an IPv6 address Go spells differently": {"::1.2.3.4", "::102:304"},
		"an IPv6 address in upper case":         {"2001:DB8::1", "2001:db8::1"},
	} {
		want := map[string]string{row.key: "LAN"}
		t.Run(name+" pushed", func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow(row.spelling, "LAN"))
			requireListenerSnapshot(t, k, want, "after the push")
			requireSkipped(t, k.r.logs.joined())
		})
		t.Run(name+" as a flag", func(t *testing.T) {
			cfg, logs := lifecycleConfig(t)
			cfg.listenerInterfaces = []string{listenerValue(row.spelling, "LAN")}
			srv, err := start(cfg, logs.logf)
			if err != nil {
				t.Fatalf("start with listener-interface %q: %v", row.spelling, err)
			}
			defer srv.shutdown()
			got := map[string]string{}
			if table := srv.g.listenerInterfaces.Load(); table != nil {
				for ip, label := range *table {
					got[ip.String()] = label
				}
			}
			if !maps.Equal(got, want) {
				t.Fatalf("listener interfaces %q, want %q", got, want)
			}
			requireSkipped(t, logs.text())
		})
	}
}

// Two spellings of one address are two rows for one address: the first is applied and the second is skipped as a duplicate.
func TestTheFirstOfTwoSpellingsOfOneListenerInterfaceAddressWins(t *testing.T) {
	for name, row := range map[string]struct{ first, second, key string }{
		"IPv4-mapped, then IPv4":      {"::ffff:127.0.0.1", "127.0.0.1", "127.0.0.1"},
		"IPv4, then IPv4-mapped":      {"127.0.0.1", "::ffff:127.0.0.1", "127.0.0.1"},
		"lower case, then upper case": {"2001:db8::1", "2001:DB8::1", "2001:db8::1"},
		"dotted, then netip":          {"::1.2.3.4", "::102:304", "::102:304"},
	} {
		t.Run(name, func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow("127.0.0.2", "kept")+"\n"+listenerRow(row.first, "first")+"\n"+listenerRow(row.second, "second"))
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.2": "kept", row.key: "first"}, "after the push")
			second := listenerValue(row.second, "second")
			requireSkipped(t, k.r.logs.joined(), second)
			requireLogLine(t, k.r.logs.joined(), fmt.Sprintf("listener-interface %.64q skipped: duplicate listener IP %s", second, row.key))
		})
	}
}

// What still refuses the whole push: the framing of the body.
func TestABodyThatIsNotFramedRightIsRefusedWholeAndKeepsTheListenerInterfaceSnapshot(t *testing.T) {
	good := listenerRow("127.0.0.2", "must not leak")
	for name, body := range map[string]string{
		"a newline at the end":    good + "\n",
		"an empty line":           good + "\n\n" + listenerRow("127.0.0.3", "must not leak"),
		"an unknown word":         good + "\nsomething 127.0.0.3=TEFO",
		"a bad row and a newline": good + "\nlistener-interface " + badListenerInterfaces["no equals sign"] + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			k := newCtlRig(t)
			pushTable(t, k, listenerRow("127.0.0.1", "LAN"))
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error:") {
				t.Fatalf("reply %q, want an error", got)
			}
			requireListenerSnapshot(t, k, map[string]string{"127.0.0.1": "LAN"}, "after the refused push")
		})
	}
}

// A good listener row does not rescue a body whose name row is bad: names and DDR are still validated whole.
func TestABadNameRowStillRefusesTheWholePushWithGoodListenerInterfaceRows(t *testing.T) {
	k := newInitialNamesCtlRig(t)
	pushTable(t, k.ctlRig, tableLine("10.0.0.1=10.0.0.9")+"\n"+listenerRow("127.0.0.1", "LAN"))
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "10.0.0.9", "before the refused push")
	body := listenerRow("127.0.0.2", "must not leak") + "\n" + tableLine("10.0.0.3=bad")
	if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("reply %q, want an error", got)
	}
	requireListenerSnapshot(t, k.ctlRig, map[string]string{"127.0.0.1": "LAN"}, "after the refused push")
	k.requireAnswer(t, "10.0.0.1", dnsmessage.TypeA, "10.0.0.9", "after the refused push")
}

// The log line says how many interfaces the push set, and an ownership-only change is logged too.
func TestAnAddressTableLogLineCountsTheListenerInterfaces(t *testing.T) {
	k := newCtlRig(t)
	pushTable(t, k, listenerRow("127.0.0.1", "LAN"))
	requireLogLine(t, k.r.logs.joined(), "address table: 0 name answers, 0 DoH 443 addresses, 1 listener interfaces")
	n := newInitialNamesCtlRig(t)
	pushTable(t, n.ctlRig, tableLine("10.0.0.2=10.0.0.2")+"\n"+listenerRow("127.0.0.1", "LAN")+"\n"+listenerRow("127.0.0.2", "WAN"))
	requireLogLine(t, n.r.logs.joined(), "address table: 1 name answers, 0 DoH 443 addresses, 2 listener interfaces")
}

// An entry that is not valid is no reason to refuse the flags: the gateway starts and skips it, as a push does. A good one needs no
// --dns-name either.
func TestBadListenerInterfaceFlagsAreNotRefusedByParse(t *testing.T) {
	values := maps.Clone(badListenerInterfaces)
	values["a good entry"] = listenerValue("127.0.0.1", "LAN")
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			cfg, err := parse(t, "--listener-interface", value)
			if err != nil || !slices.Equal(cfg.listenerInterfaces, []string{value}) {
				t.Fatalf("flag %q: listenerInterfaces %q, error %v, want the flag kept and no error", value, cfg.listenerInterfaces, err)
			}
		})
	}
}

// At start the good flags are applied, the first flag for an address wins, and each skipped flag is logged.
func TestStartSkipsBadListenerInterfaceFlagsAndAppliesTheGoodOnes(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	oversized := listenerValue("127.0.0.9", strings.Repeat("a", 65536))
	second := listenerValue("127.0.0.1", "second")
	cfg.listenerInterfaces = []string{listenerValue("127.0.0.1", "kept"), listenerValue("127.0.0.2", "Län"), listenerValue("127.0.0.3", "日本"), oversized}
	skipped := []string{oversized, second}
	for _, value := range badListenerInterfaces {
		cfg.listenerInterfaces = append(cfg.listenerInterfaces, value)
		skipped = append(skipped, value)
	}
	cfg.listenerInterfaces = append(cfg.listenerInterfaces, second)
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("a bad listener-interface flag must not stop the gateway: %v", err)
	}
	defer srv.shutdown()
	got := map[string]string{}
	for ip, label := range *srv.g.listenerInterfaces.Load() {
		got[ip.String()] = label
	}
	if want := map[string]string{"127.0.0.1": "kept", "127.0.0.2": "Län", "127.0.0.3": "日本"}; !maps.Equal(got, want) {
		t.Fatalf("listener interfaces %q, want %q", got, want)
	}
	requireSkipped(t, logs.text(), skipped...)
}
