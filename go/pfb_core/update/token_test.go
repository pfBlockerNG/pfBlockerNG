package update

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
)

func TestStartAddsFreshPerRunToken(t *testing.T) {
	requests := make(chan Request, 2)
	release := make(chan struct{}, 2)
	g := newGate(t, func(_ context.Context, req Request, _ *os.File) (Result, error) {
		requests <- req
		<-release
		return Result{}, nil
	}, nil)

	seen := map[string]bool{}
	for range 2 {
		if err := g.Start(Request{Trigger: "manual"}); err != nil {
			t.Fatal(err)
		}
		req := recv(t, requests, "the Update did not start")
		raw, err := hex.DecodeString(req.Token)
		if err != nil || len(raw) != 32 {
			t.Fatalf("token = %q (%v), want 32 random bytes in hex", req.Token, err)
		}
		if seen[req.Token] {
			t.Fatalf("two Updates received the same token %q", req.Token)
		}
		seen[req.Token] = true
		release <- struct{}{}
		settle(t, g)
	}
}
