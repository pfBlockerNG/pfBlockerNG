package main

import (
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// issue #3848: a gateway that lost the DNS name or DDR drops the rows for the lost part from a well-formed address table (see
// degrade_table_test.go). A row that is malformed is still an error that leaves both tables as they were, whatever else the body
// holds: dropping what is lost is no licence to take what is wrong.

const (
	labelLAN  = "bGFu" // "lan"
	labelWAN  = "d2Fu" // "wan"
	labelEdge = "ZWRnZQ=="
)

// tablesOf is what a gateway's address tables hold now: the name answers its status reports and its listener interfaces.
func tablesOf(t *testing.T, srv *server, sock string) (names any, interfaces map[netip.Addr]string) {
	t.Helper()
	return statusObject(t, sock)["name_answers"], maps.Clone(*srv.g.listenerInterfaces.Load())
}

func requireTables(t *testing.T, srv *server, sock string, wantNames any, wantInterfaces map[netip.Addr]string, when string) {
	t.Helper()
	names, interfaces := tablesOf(t, srv, sock)
	if !reflect.DeepEqual(names, wantNames) || !maps.Equal(interfaces, wantInterfaces) {
		t.Fatalf("%s: name answers %v and listener interfaces %v, want %v and %v", when, names, interfaces, wantNames, wantInterfaces)
	}
}

// H1: the gateway lost dns_name (an invalid --dns-name) and holds no name table. A malformed name row is an error, and the
// listener table of the startup flag stays.
func TestAMalformedNameRowOnAGatewayThatLostTheNameIsAnErrorAndLeavesTheTablesAsTheyWere(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	for label, bad := range map[string]string{
		"a value that is no address": "dns-name-answer 127.0.0.1=bad",
		"no equals sign":             "dns-name-answer 127.0.0.1",
		"no LOCAL":                   "dns-name-answer =192.0.2.1",
		"two addresses of a family":  "dns-name-answer 127.0.0.1=192.0.2.1,192.0.2.2",
		"the same LOCAL twice":       "dns-name-answer 127.0.0.1=192.0.2.1\ndns-name-answer 127.0.0.1=192.0.2.2",
		"no value at all":            "dns-name-answer",
	} {
		t.Run(label, func(t *testing.T) {
			srv, _, sock := startFromFlags(t, echoOpen, "--dns-name", "fw..lan", "--listener-interface", "127.0.0.1="+labelLAN)
			if rows, _ := statusLost(t, sock); len(rows) != 1 || rows[0].Part != "dns_name" {
				t.Fatalf("degraded %+v, want dns_name lost", rows)
			}
			before := map[netip.Addr]string{loopback: "lan"}
			requireTables(t, srv, sock, map[string]any{}, before, "at start")
			got := pushAddressTable(t, sock, "listener-interface 127.0.0.1="+labelWAN, bad)
			if !strings.HasPrefix(got, "error: ") {
				t.Fatalf("reply %q, want an error", got)
			}
			requireTables(t, srv, sock, map[string]any{}, before, "after the malformed push")
		})
	}
}

// H2: the gateway lost ddr (--ddr-doh-443 with no --ddr) and holds the name table of its flag. A malformed DoH 443 row is an
// error, and neither the name table nor the listener table moves, though the same body carries good rows for both.
func TestAMalformedDoH443RowOnAGatewayThatLostDDRIsAnErrorAndLeavesTheTablesAsTheyWere(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	for label, bad := range map[string]string{
		"a port":               "ddr-doh-443 192.0.2.1:443",
		"a zone":               "ddr-doh-443 fe80::1%em0",
		"a name":               "ddr-doh-443 fw.example.lan",
		"no value":             "ddr-doh-443",
		"two addresses in one": "ddr-doh-443 192.0.2.1,192.0.2.2",
		"a trailing space":     "ddr-doh-443 192.0.2.1 ",
	} {
		t.Run(label, func(t *testing.T) {
			srv, _, sock := startFromFlags(t, echoOpen, "--dns-name", "fw.example.lan", "--dns-name-answer", "127.0.0.1=192.0.2.1",
				"--ddr-doh-443", "192.0.2.1", "--listener-interface", "127.0.0.1="+labelLAN)
			if rows, _ := statusLost(t, sock); len(rows) != 1 || rows[0].Part != "ddr" {
				t.Fatalf("degraded %+v, want ddr lost", rows)
			}
			names, before := tablesOf(t, srv, sock)
			if !reflect.DeepEqual(before, map[netip.Addr]string{loopback: "lan"}) || len(names.(map[string]any)) != 1 {
				t.Fatalf("at start: name answers %v and listener interfaces %v, want the flags'", names, before)
			}
			got := pushAddressTable(t, sock, "dns-name-answer 127.0.0.1=192.0.2.9", "listener-interface 127.0.0.1="+labelWAN, bad)
			if !strings.HasPrefix(got, "error: ") {
				t.Fatalf("reply %q, want an error", got)
			}
			requireTables(t, srv, sock, names, before, "after the malformed push")
		})
	}
}

// H3: the push that was taken stays when the next one is bad: on a gateway that lost the name, and on one that lost DDR.
func TestABadPushAfterAGoodOneOnAGatewayThatLostAPartKeepsTheGoodOnesTables(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	cases := map[string]struct {
		flags     []string
		good, bad []string
		goodNames int // name answers the good push leaves: the gateway that lost the name has none to take
	}{
		"lost the name": {
			[]string{"--dns-name", "fw..lan"},
			[]string{"dns-name-answer 127.0.0.1=192.0.2.1", "listener-interface 127.0.0.1=" + labelEdge},
			[]string{"dns-name-answer 127.0.0.1=bad", "listener-interface 127.0.0.1=" + labelWAN},
			0,
		},
		"lost DDR": {
			[]string{"--dns-name", "fw.example.lan", "--ddr-doh-443", "192.0.2.1"},
			[]string{"dns-name-answer 127.0.0.1=192.0.2.1", "ddr-doh-443 127.0.0.1", "listener-interface 127.0.0.1=" + labelEdge},
			[]string{"dns-name-answer 127.0.0.1=192.0.2.9", "ddr-doh-443 192.0.2.1:443", "listener-interface 127.0.0.1=" + labelWAN},
			1,
		},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			srv, _, sock := startFromFlags(t, echoOpen, c.flags...)
			before, _ := tablesOf(t, srv, sock)
			if len(before.(map[string]any)) != 0 {
				t.Fatalf("at start: name answers %v, want none", before)
			}
			if got := pushAddressTable(t, sock, c.good...); got != "ok" {
				t.Fatalf("the good push: reply %q, want ok", got)
			}
			names, interfaces := tablesOf(t, srv, sock)
			if len(names.(map[string]any)) != c.goodNames || interfaces[loopback] != "edge" {
				t.Fatalf("after the good push: name answers %v and listener interfaces %v, want %d name answer(s) and 127.0.0.1=edge", names, interfaces, c.goodNames)
			}
			if got := pushAddressTable(t, sock, c.bad...); !strings.HasPrefix(got, "error: ") {
				t.Fatalf("the bad push: reply %q, want an error", got)
			}
			requireTables(t, srv, sock, names, interfaces, "after the bad push")
		})
	}
}
