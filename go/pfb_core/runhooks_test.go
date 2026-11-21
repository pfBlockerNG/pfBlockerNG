package main

import (
	"context"
	"testing"
)

// WHEN the hook context has been read in full by the time a signal ends the wait for it THEN the one-shot goes on with
// what it read, on every call, whichever ready case select would pick.
func TestHookInputTakesAFinishedReadOverASimultaneousSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 200 {
		got := make(chan hookInput, 1)
		got <- hookInput{data: []byte("{}")}
		in, ok := awaitHookInput(ctx, got)
		if !ok || string(in.data) != "{}" {
			t.Fatalf("call %d: got %q and read %v, want the finished read {} taken", i, in.data, ok)
		}
	}
}
