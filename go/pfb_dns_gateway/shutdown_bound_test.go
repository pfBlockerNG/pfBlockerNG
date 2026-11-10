package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

// What the rc stop gives the gateway after TERM before it sends KILL: the `5)` tick of the stop script that
// pfb_dns_proxy_service() writes (pfblockerng.inc), pinned there by DnsProxyServiceTest
// (testAProcessIgnoringTermIsKilledAfterFiveTicksAndItsStalePidfilesAreRemoved). A KILL leaves the ready file behind.
const rcStopKillAfter = 5 * time.Second

// The default budget has to end the shutdown before the rc stop's KILL: the transports' stop and the decider's close share it.
func TestTheDefaultShutdownBudgetEndsBeforeTheRcStopSendsKill(t *testing.T) {
	if defaultShutdownBudget >= rcStopKillAfter {
		t.Fatalf("the shutdown budget is %v, the rc stop sends KILL %v after TERM: a slow shutdown would be killed with its ready file in place", defaultShutdownBudget, rcStopKillAfter)
	}
}

// stuckFrontend is a decider whose Close does not return until the test lets it.
type stuckFrontend struct {
	echoFrontend
	release chan struct{}
}

func (f stuckFrontend) Close() { <-f.release }

// A decider that cannot be closed does not hold the shutdown past its budget: the gateway says so and returns, and the process
// exit takes the decider with it. The ready file goes first, so that even this shutdown leaves none behind.
func TestShutdownEndsInsideItsBudgetWhenTheDeciderCannotBeClosed(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	stuck := stuckFrontend{release: make(chan struct{})}
	t.Cleanup(sync.OnceFunc(func() { close(stuck.release) }))
	useDecider(t, func(decider.Options) (frontend, error) { return stuck, nil })
	cfg.shutdownBudget = 50 * time.Millisecond
	cfg.readyFile = t.TempDir() + "/ready"
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "shutdown to end inside its budget")
	if text := logs.text(); !strings.Contains(text, "the decider did not close within") {
		t.Fatalf("the log must say that the decider was left:\n%s", text)
	}
	if _, err := os.Stat(cfg.readyFile); err == nil {
		t.Fatal("the ready file is still there after the shutdown")
	}
}
