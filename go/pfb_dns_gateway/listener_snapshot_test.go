package main

import (
	"encoding/base64"
	"strings"
	"testing"
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
		k.r.p.send(tAnswer, q.id, echoAnswer(decidedQuery{wire: q.wire}))
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

func TestListenerInterfaceInvalidUpdateKeepsSnapshot(t *testing.T) {
	k := newCtlRig(t)
	initial := listenerRow("127.0.0.1", "LAN")
	if got := k.send(t, addressTableFrame(initial)); got != "ok" {
		t.Fatalf("initial snapshot: %q, want ok", got)
	}
	for _, bad := range []string{
		"listener-interface 127.0.0.1=%%%", "listener-interface 127.0.0.1=TEFO\n", listenerRow("0.0.0.0", "bad"), listenerRow("::", "bad"), listenerRow("fe80::1%lo", "bad"), listenerRow("[::1]", "bad"), listenerRow("127.0.0.1:53", "bad"), listenerRow("127.0.0.1/8", "bad"), listenerRow("::ffff:127.0.0.1", "bad"), listenerRow("127.0.0.1", "bad\nlabel"), listenerRow("127.0.0.1", "bad\x00label"), listenerRow("127.0.0.1", string([]byte{0xff})), initial + "\n" + initial,
	} {
		t.Run(bad, func(t *testing.T) {
			body := listenerRow("127.0.0.2", "must not leak") + "\n" + bad
			if got := k.send(t, addressTableFrame(body)); !strings.HasPrefix(got, "error:") {
				t.Fatalf("bad update returned %q, want error", got)
			}
			table := k.r.g.listenerInterfaces.Load()
			if table == nil || len(*table) != 1 {
				t.Fatalf("snapshot=%v, want unchanged one-row table", table)
			}
			for ip, label := range *table {
				if ip.String() != "127.0.0.1" || label != "LAN" {
					t.Fatalf("snapshot contains %s=%q, want only 127.0.0.1=LAN", ip, label)
				}
			}
		})
	}
}

func TestListenerInterfaceFlagWithoutDNSName(t *testing.T) {
	if _, err := parse(t, "--listener-interface", "127.0.0.1=TEFO", "--", "decider"); err != nil {
		t.Fatalf("owner flag without DNS name: %v", err)
	}
	for _, row := range []string{"127.0.0.1=%%%", "0.0.0.0=TEFO", "127.0.0.1=YmFkCg=="} {
		if _, err := parse(t, "--listener-interface", row, "--", "decider"); err == nil {
			t.Fatalf("invalid owner flag %q accepted", row)
		}
	}
}
