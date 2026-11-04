package main

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: PHP pushes the address table on every sync, so a push that changes nothing must not be logged, or the log gains
// a line a minute. The table is compared by what it holds, not by the order of its lines.
func TestAnAddressTableIsLoggedOnlyWhenItChanges(t *testing.T) {
	k := newInitialNamesCtlRig(t) // starts with 10.0.0.1=10.0.0.1,2001:db8:1::1
	lines := func(values ...string) string {
		var l []string
		for _, v := range values {
			l = append(l, tableLine(v))
		}
		return strings.Join(l, "\n")
	}
	start := "10.0.0.1=10.0.0.1,2001:db8:1::1"
	first := lines("10.0.0.2=10.0.0.2", "10.0.0.53=10.0.0.53,2001:db8:53::53")
	reordered := lines("10.0.0.53=2001:db8:53::53,10.0.0.53", "10.0.0.2=10.0.0.2")
	other := lines("10.0.0.2=10.0.0.3", "10.0.0.53=10.0.0.53,2001:db8:53::53")

	steps := []struct {
		what    string
		body    string
		logged  int // the `address table:` lines so far
		answers string
	}{
		{"the table the gateway started with", lines(start), 0, "10.0.0.1"},
		{"a new table", first, 1, "10.0.0.2"},
		{"the same table again", first, 1, "10.0.0.2"},
		{"the same table with its lines and addresses in another order", reordered, 1, "10.0.0.2"},
		{"a table that differs in one address", other, 2, "10.0.0.3"},
		{"that table again", other, 2, "10.0.0.3"},
		{"the first table back", first, 3, "10.0.0.2"},
		{"an empty table", "", 4, ""},
		{"an empty table again", "", 4, ""},
	}
	for _, s := range steps {
		if got := k.send(t, addressTableFrame(s.body)); got != "ok" {
			t.Fatalf("%s: reply %q, want ok", s.what, got)
		}
		if n := k.logsAbout("address table:"); n != s.logged {
			t.Fatalf("%s: %d `address table:` lines, want %d; log:\n%s", s.what, n, s.logged, k.r.logs.joined())
		}
		local := "10.0.0.2"
		if s.what == "the table the gateway started with" {
			local = "10.0.0.1"
		}
		k.requireAnswer(t, local, dnsmessage.TypeA, s.answers, s.what) // a push that is not logged is still taken
	}
}
