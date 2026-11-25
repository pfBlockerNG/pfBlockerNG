package decider

// A Sync is never cut for taking long (owner, 2026-11-25): a Core that dies drops the connection, and a slow transfer runs
// to its end however long it takes. So no request the poller makes carries a deadline.

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// roundTrip answers a request with the handler, in memory.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnCoreNoRequestOfThePollerHasADeadline(t *testing.T) {
	core := coretest.New(coreData("1", "a.example"))
	var requests, deadlines atomic.Int32
	client := coreinput.NewTransport(roundTrip(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		if _, ok := r.Context().Deadline(); ok {
			deadlines.Add(1)
		}
		rec := httptest.NewRecorder()
		core.ServeHTTP(rec, r)
		return rec.Result(), nil
	}))
	ticks := make(coreTicks)
	m, err := bootCore(coreModuleDir(t), testLogDir, client, false, ticks.source)
	if err != nil {
		t.Fatalf("bootCore: %v", err)
	}
	stopModule(t, m)
	ticks.settle()
	if !serves(m, "a.example") {
		t.Fatal("the generation is not served")
	}
	if requests.Load() == 0 {
		t.Fatal("the poller made no request")
	}
	if n := deadlines.Load(); n != 0 {
		t.Errorf("%d of the poller's requests to Core carry a deadline: a slow Sync would be cut", n)
	}
}
