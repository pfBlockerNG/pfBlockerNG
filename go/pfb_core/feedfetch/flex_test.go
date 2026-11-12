package feedfetch_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// Flex (pfb_download_fetch: cURL 35/51/60 with $pflex) drops verification only for a feed that enabled it AND only
// after its first attempt failed verification: the first connection is always verified, and a trusted server is
// never fetched without verification.
func TestFlexDowngradesOnlyAfterAFirstVerifiedAttemptFails(t *testing.T) {
	var conns, served atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		io.WriteString(w, "tls\n")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	target := "https://feed.example:" + port(t, srv.URL) + "/list"

	f, feed := fetcherFor(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: target, Timeout: 10 * time.Second, Flex: true})
	if !res.OK || conns.Load() != 2 || served.Load() != 1 {
		t.Fatalf("flex must first try a verified connection, then downgrade once: %+v, connections %d, served %d",
			res, conns.Load(), served.Load())
	}

	conns.Store(0)
	served.Store(0)
	res = f.Ingest(context.Background(), feed, feedfetch.Request{URL: target, Timeout: 10 * time.Second})
	if res.OK || conns.Load() != 3 || served.Load() != 0 {
		t.Fatalf("without flex every attempt must verify and fail: %+v, connections %d, served %d",
			res, conns.Load(), served.Load())
	}
}
