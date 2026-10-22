package main

import (
	"strings"
	"testing"
)

// maxOutstandingIDs is the bound docs/misc/dns-gateway-protocol.md gives on ids the gateway keeps reserved: in
// flight, or abandoned and waiting for the decider's final frame. Live queries top out far below it.
const maxOutstandingIDs = 4096

func newCall() *call { return &call{forward: make(chan []byte, 1), final: make(chan []byte, 1)} }

// Abandoned queries keep their id until the decider's final frame, so a decider that never answers could grow the
// table without bound. At the cap a new query is answered SERVFAIL and nothing outstanding is evicted; the next
// final frame frees a place. One log line per burst.
func TestAtTheCapOfOutstandingIDsNewQueriesGetServfailAndNothingIsEvicted(t *testing.T) {
	r := newRig(t, rigConfig{acl: aclMixed})
	r.autoAnswer(echoAnswer)
	d := r.g.dec.Load()
	for range maxOutstandingIDs {
		if _, err := d.register(newCall()); err != nil {
			t.Fatalf("an id below the cap was refused: %v", err)
		}
	}
	for range 2 {
		query := buildQuery(t, 0x2222, "refused.example.", true)
		reply := r.roundTrip(transport{"tcp", true}, "", query)
		servfailFor(t, reply)
		if queryID(reply) != 0x2222 {
			t.Fatalf("SERVFAIL is for query %#x, want 0x2222", queryID(reply))
		}
	}
	r.requireNoOtherQuery()
	if n := strings.Count(r.logs.joined(), "queries outstanding"); n != 1 {
		t.Fatalf("a burst over the cap must log once, got %d lines: %s", n, r.logs.joined())
	}
	d.mu.Lock()
	outstanding := len(d.calls)
	d.mu.Unlock()
	if outstanding != maxOutstandingIDs {
		t.Fatalf("%d ids are outstanding, want the %d that were reserved: an id was evicted or one was added over the cap", outstanding, maxOutstandingIDs)
	}

	d.finish(1, nil) // the decider's final frame for the oldest one
	query := buildQuery(t, 0x3333, "allowed.example.", true)
	if got, want := r.roundTrip(transport{"tcp", true}, "", query), echoAnswer(decidedQuery{wire: query}); string(got) != string(want) {
		t.Fatalf("after an id was freed the query got %x, want the decider's answer %x", got, want)
	}
}
