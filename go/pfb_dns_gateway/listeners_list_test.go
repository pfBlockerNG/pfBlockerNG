package main

import (
	"errors"
	"testing"
)

// A refusal is recorded with the bind's own error, and an error that does not wrap one is recorded whole: a bind error
// of another shape must never take the start down.
func TestARefusalKeepsTheBindsOwnErrorAndAnUnwrappedErrorWhole(t *testing.T) {
	refused := map[string]string{}
	refuse(refused, "dot", "127.0.0.1", 853, listenError("127.0.0.1:853", errors.New("bind: address already in use")))
	refuse(refused, "doq", "::1", 853, errors.New("quic: no listener"))
	refuse(refused, "doh", "nonsense", 443, errors.New("not an address")) // no canonical key: not recorded
	want := map[string]string{"dot 127.0.0.1:853": "bind: address already in use", "doq [::1]:853": "quic: no listener"}
	if len(refused) != len(want) || refused["dot 127.0.0.1:853"] != want["dot 127.0.0.1:853"] || refused["doq [::1]:853"] != want["doq [::1]:853"] {
		t.Fatalf("refusals %q, want %q", refused, want)
	}
}

// The reply lists every served listener, then every refusal, each group in key order whatever order they were recorded
// in, with a reason's newline flattened so that one refusal is one line.
func TestListPutsEachGroupInKeyOrderAndKeepsEachRefusalOnOneLine(t *testing.T) {
	s := &listenerSet{
		served:  map[string]func(){"udp+tcp 127.0.0.1:53": nil, "dot 127.0.0.1:853": nil},
		refused: map[string]string{"udp+tcp 192.0.2.1:53": "bind: a", "doq 192.0.2.1:853": "two\nlines"},
	}
	want := "listening dot 127.0.0.1:853\nlistening udp+tcp 127.0.0.1:53\n" +
		"refused doq 192.0.2.1:853 two lines\nrefused udp+tcp 192.0.2.1:53 bind: a\nok\n"
	if got := s.list(); got != want {
		t.Fatalf("list reply %q, want %q", got, want)
	}
}
