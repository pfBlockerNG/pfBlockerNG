package feedfetch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// An ingest that fails says why: a status pfb_download() does not accept is named in its words, a 304 included when
// there is no published copy to keep.
func TestAFailedIngestAlwaysNamesItsReason(t *testing.T) {
	for status, want := range map[int]string{404: "404 Not Found", 304: "304 Not Modified", 299: "Unknown Failure Code [299]"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		f, feed := fetcherFor(t)
		res := f.Ingest(context.Background(), feed, feedfetch.Request{
			URL: "http://feed.example:" + port(t, srv.URL) + "/list", Timeout: 10 * time.Second, MaxBytes: 1 << 20})
		srv.Close()
		if res.OK || res.Reason != want {
			t.Errorf("status %d: want a failure named %q, got %+v", status, want, res)
		}
	}
}
