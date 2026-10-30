package main

import (
	"testing"
	"time"
)

// closeOnStop's contract, which the live add and remove rely on: what is registered is closed exactly once however many
// of stop(), a remove's closeNow and a stray run reach it, a removed closer leaves the list, and a closer registered on a
// gateway that has begun to stop is closed at once, since stop() took its list before it.

func newBareGateway() *gateway {
	return newGateway(nil, nil, nil, time.Second, func(string, ...any) {})
}

func TestACloserRegisteredOnAStoppingGatewayIsClosedAtOnceAndIsNotListed(t *testing.T) {
	g := newBareGateway()
	g.cancel() // what stop() does first
	closed := 0
	closeNow := g.closeOnStop(func() { closed++ })
	if closed != 1 {
		t.Fatalf("a closer registered after the stop began ran %d times at registration, want 1: stop() has taken its list already", closed)
	}
	if n := len(g.closers); n != 0 {
		t.Fatalf("the gateway lists %d closers, want 0: nothing would close it again", n)
	}
	closeNow()
	g.stop()
	if closed != 1 {
		t.Fatalf("the closer ran %d times after its closeNow and the stop, want still 1", closed)
	}
}

func TestACloserRunsExactlyOnceHoweverOftenItIsReached(t *testing.T) {
	g := newBareGateway()
	closed := 0
	closeNow := g.closeOnStop(func() { closed++ })
	if closed != 0 || len(g.closers) != 1 {
		t.Fatalf("after registration the closer ran %d times and %d are listed, want 0 and 1", closed, len(g.closers))
	}
	g.closers[0].run()
	g.closers[0].run()
	closeNow()
	if closed != 1 {
		t.Fatalf("the closer ran %d times for two runs of the listed closer and one closeNow, want 1", closed)
	}
	if n := len(g.closers); n != 0 {
		t.Fatalf("the gateway lists %d closers after closeNow, want 0: a removed listener must not stay registered", n)
	}
}

// A closer a closeNow removed is not closed again by the shutdown, and one the shutdown closed is not closed again by a
// closeNow that comes after it.
func TestAClosedCloserIsNotClosedAgainByTheOtherPath(t *testing.T) {
	g := newBareGateway()
	removed, stopped := 0, 0
	closeRemoved := g.closeOnStop(func() { removed++ })
	closeStopped := g.closeOnStop(func() { stopped++ })
	closeRemoved()
	g.stop()
	closeStopped()
	if removed != 1 || stopped != 1 {
		t.Fatalf("the closer removed first ran %d times, the one the stop closed first ran %d, want 1 and 1", removed, stopped)
	}
}
