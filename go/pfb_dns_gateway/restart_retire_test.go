package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// issue #3566: what a real restart does to the decider it replaces: a query that read it just before the swap is asked of
// the new one, and a replaced decider that holds a query forever and ignores EOF is closed and killed all the same.

// holdQuery sends a query that the active (forward-tagged) decider holds in its FORWARD until release.
func holdQuery(t *testing.T, srv *server, name string, id uint16) (release func()) {
	t.Helper()
	entered, held := make(chan struct{}), make(chan struct{})
	release = sync.OnceFunc(func() { close(held) })
	t.Cleanup(release)
	wire := buildQuery(t, id, name, true)
	go resolveVia(srv, wire, func(ctx context.Context, _ []byte) []byte {
		close(entered)
		select {
		case <-held:
		case <-ctx.Done():
		}
		return nil
	})
	waitClosed(t, entered, "the held query to reach the decider's FORWARD")
	return release
}

func TestAQueryThatReadTheOldDeciderJustBeforeARestartIsAnsweredByTheNewOne(t *testing.T) {
	srv, sock := startRestartRig(t, "forward-tagged", nil)
	_, old := srv.active()
	defer holdQuery(t, srv, "held.example.", 0x0202)() // the old decider stays open, so it could still answer
	srv.g.deciderRead = sync.OnceFunc(func() {
		if got := requestRestart(t, sock); got != "ok" {
			t.Errorf("restart between reading the decider and asking it: reply %q, want ok", got)
		}
	})
	pid := askPid(t, srv, "stale.example.")
	_, cur := srv.active()
	if cur == old || pid != cur.cmd.Process.Pid {
		t.Fatalf("a query that read the old decider (pid %d) before the restart was decided by pid %d, want the new one %d",
			old.cmd.Process.Pid, pid, cur.cmd.Process.Pid)
	}
}

// The old decider never answers the query it holds and ignores EOF: it is closed once a query could no longer be waiting
// for it, and killed when it does not leave.
func TestAReplacedDeciderThatHoldsAQueryAndIgnoresEOFIsClosedAndKilled(t *testing.T) {
	modes := modeFile(t, "ignore-eof")
	srv, sock := startRestartRig(t, "from-file", func(c *config) { c.timeout = 100 * time.Millisecond; c.killAfter = 300 * time.Millisecond })
	_, old := srv.active()
	resolveVia(srv, buildQuery(t, 0x0b01, "never.example.", true), emptyReply) // SERVFAIL; its id stays reserved: no answer comes
	writeMode(t, modes, "forward-tagged")
	if got := requestRestart(t, sock); got != "ok" {
		t.Fatalf("restart: reply %q, want ok", got)
	}
	requireExited(t, old, "the replaced decider")
	if old.err == nil {
		t.Fatal("the replaced decider ignores EOF, so it must have been killed, but it exited by itself")
	}
	requireNoFatal(t, srv, "after the replaced decider was killed")
}
