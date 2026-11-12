package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// issue #3848: PHP sends the whole address table on every apply and tick and restarts the gateway on any error reply. A gateway
// that started without the DNS name or DDR because it could not use them (they are lost parts of its status) takes the table
// all the same and ignores the rows that are for what it does not have; one that never had them still refuses those rows.

// pushAddressTable sends an address table to the gateway's control socket and returns the reply line.
func pushAddressTable(t *testing.T, sock string, lines ...string) string {
	t.Helper()
	c := dialCtl(t, sock)
	_, _ = c.Write(addressTableFrame(strings.Join(lines, "\n")))
	return ctlReply(t, c)
}

func TestTheAddressTableOfAGatewayThatLostTheNameOrDDRIsTakenAndTheRowsForWhatIsLostAreIgnored(t *testing.T) {
	name, doh443 := tableLine("127.0.0.1=192.0.2.1"), doh443Line("127.0.0.1")
	const label = "listener-interface 127.0.0.1=bGFu" // the rows that are not lost still apply
	cases := []struct {
		name       string
		flags      []string
		lines      []string
		nameAnswer int // name answers the gateway holds after the push: one only when it still has the DNS name
		wantLosses []string
	}{
		{"an invalid name", []string{"--dns-name", "fw..lan"}, []string{name, label}, 0, []string{"dns_name"}},
		{"an invalid name with DDR", []string{"--dns-name", "fw..lan", "--ddr"}, []string{name, doh443, label}, 0, []string{"dns_name", "ddr"}},
		{"DDR with a --ddr-doh-443 that is no address", []string{"--dns-name", "fw.example.lan", "--ddr", "--ddr-doh-443", "192.0.2.1:443"}, []string{name, doh443, label}, 1, []string{"ddr"}},
		{"--ddr-doh-443 without --ddr", []string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"}, []string{name, doh443, label}, 1, []string{"ddr"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _, sock := startFromFlags(t, echoOpen, c.flags...)
			if rows, _ := statusLost(t, sock); !slices.Equal(lostParts(rows), c.wantLosses) {
				t.Fatalf("before the push: degraded %+v, want %q", rows, c.wantLosses)
			}
			if got := pushAddressTable(t, sock, c.lines...); got != "ok" {
				t.Fatalf("push %q: reply %q, want ok", c.lines, got)
			}
			if got := (*srv.g.listenerInterfaces.Load())[netip.MustParseAddr("127.0.0.1")]; got != "lan" {
				t.Errorf("listener interface of 127.0.0.1 is %q after the push, want lan: the rows that are not lost apply", got)
			}
			status := statusObject(t, sock)
			if answers := status["name_answers"].(map[string]any); len(answers) != c.nameAnswer {
				t.Errorf("name answers %v after the push, want %d", answers, c.nameAnswer)
			}
			if status["ddr"] != false {
				t.Errorf("ddr %v after the push, want it still off", status["ddr"])
			}
			if rows, _ := statusLost(t, sock); !slices.Equal(lostParts(rows), c.wantLosses) {
				t.Errorf("after the push: degraded %+v, want %q", rows, c.wantLosses)
			}
		})
	}
}

// A gateway that was never asked for the DNS name or DDR has nothing it lost: it refuses the rows, as it always did.
func TestTheAddressTableOfAGatewayStartedWithoutTheNameOrDDRStillRefusesTheirRows(t *testing.T) {
	_, _, sock := startFromFlags(t, echoOpen)
	if got := pushAddressTable(t, sock, tableLine("127.0.0.1=192.0.2.1")); got != "error: started without --dns-name" {
		t.Errorf("a name row: reply %q, want `error: started without --dns-name`", got)
	}
	if got := pushAddressTable(t, sock, doh443Line("127.0.0.1")); got != "error: started without --ddr" {
		t.Errorf("a DoH 443 row: reply %q, want `error: started without --ddr`", got)
	}
	if got := pushAddressTable(t, sock); got != "ok" {
		t.Errorf("an empty table: reply %q, want ok", got)
	}
}
