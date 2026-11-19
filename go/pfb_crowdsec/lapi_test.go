package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPullSendsTheBouncerRequest(t *testing.T) {
	lapi := newStubLAPI(t, ok(`{"new":[{"id":1,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.10",
		"duration":"4h","scenario":"manual"}],"deleted":[]}`))
	c, err := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.pull(context.Background(), true)
	if err != nil {
		t.Fatalf("pull(startup) = %v", err)
	}
	if len(r.New) != 1 || r.New[0].Value != "198.51.100.10" {
		t.Fatalf("pull returned %+v", r)
	}
	if _, err := c.pull(context.Background(), false); err != nil {
		t.Fatalf("pull(delta) = %v", err)
	}
	reqs, _ := lapi.requests()
	if len(reqs) != 2 {
		t.Fatalf("LAPI saw %d requests; want 2", len(reqs))
	}
	for i, r := range reqs {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/decisions/stream" {
			t.Errorf("request %d = %s %s", i, r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Api-Key"); got != testKey {
			t.Errorf("request %d X-Api-Key = %q", i, got)
		}
		if got := r.Header.Get("User-Agent"); got != "pfb_crowdsec/"+version {
			t.Errorf("request %d User-Agent = %q", i, got)
		}
		if got := r.URL.Query().Get("scopes"); got != "ip,range" {
			t.Errorf("request %d scopes = %q; want ip,range", i, got)
		}
	}
	if got := reqs[0].URL.Query().Get("startup"); got != "true" {
		t.Errorf("first request startup = %q; want true", got)
	}
	if _, has := reqs[1].URL.Query()["startup"]; has {
		t.Errorf("delta request carries startup: %s", reqs[1].URL.RawQuery)
	}
}

func TestPullKeepsTheLAPIURLsPathPrefix(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		_, _ = io.WriteString(w, `{"new":[],"deleted":[]}`)
	}))
	defer srv.Close()
	c, err := newLAPIClient(testConfig(t, srv.URL+"/crowdsec"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.pull(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := path.Load(); got != "/crowdsec/v1/decisions/stream" {
		t.Fatalf("path = %v; want /crowdsec/v1/decisions/stream", got)
	}
}

func TestPullFailsOnAnErrorStatus(t *testing.T) {
	lapi := newStubLAPI(t, lapiReply{http.StatusForbidden, `{"message":"access forbidden"}`})
	c, _ := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	_, err := c.pull(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("pull = %v; want an error naming status 403", err)
	}
}

func TestPullRefusesAnOversizedBody(t *testing.T) {
	big := `{"new":[` + strings.Repeat(`{"id":1,"type":"ban","scope":"ip","value":"198.51.100.1"},`, 100) +
		`{"id":2}],"deleted":[]}`
	lapi := newStubLAPI(t, ok(big))
	c, _ := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	c.maxBody = 1024
	if _, err := c.pull(context.Background(), true); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("pull(oversized) = %v; want a size error", err)
	}
	c.maxBody = int64(len(big))
	if _, err := c.pull(context.Background(), true); err != nil {
		t.Fatalf("pull(body exactly at the cap) = %v; want accepted", err)
	}
}

func TestPullRefusesMalformedJSON(t *testing.T) {
	lapi := newStubLAPI(t, ok(`{"new":[{"id":1,`))
	c, _ := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	if _, err := c.pull(context.Background(), true); err == nil {
		t.Fatal("pull(truncated JSON) = nil error")
	}
}

func TestTheDefaultBodyCapIs256MiB(t *testing.T) {
	c, err := newLAPIClient(testConfig(t, "https://lapi.example.test/"))
	if err != nil {
		t.Fatal(err)
	}
	if c.maxBody != 256<<20 {
		t.Fatalf("maxBody = %d; want 256 MiB", c.maxBody)
	}
	if c.http.Timeout.Seconds() != 30 {
		t.Fatalf("request timeout = %v; want 30s", c.http.Timeout)
	}
}

// A redirect would carry X-Api-Key to wherever it points, so none is followed.
func TestPullDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" {
			leaked.Store(true)
		}
		_, _ = io.WriteString(w, `{"new":[],"deleted":[]}`)
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer redirector.Close()
	c, _ := newLAPIClient(testConfig(t, redirector.URL+"/"))
	if _, err := c.pull(context.Background(), true); err == nil {
		t.Fatal("pull through a redirect = nil error")
	}
	if leaked.Load() {
		t.Fatal("the key was sent to the redirect target")
	}
}

func TestPostUsageSendsJSONWithTheKey(t *testing.T) {
	lapi := newStubLAPI(t)
	c, _ := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	if err := c.postUsage(context.Background(), []byte(`{"remediation_components":[]}`)); err != nil {
		t.Fatalf("postUsage = %v", err)
	}
	reqs, bodies := lapi.requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].URL.Path != "/v1/usage-metrics" {
		t.Fatalf("requests = %v", reqs)
	}
	if reqs[0].Header.Get("X-Api-Key") != testKey || reqs[0].Header.Get("Content-Type") != "application/json" ||
		reqs[0].Header.Get("User-Agent") != "pfb_crowdsec/"+version {
		t.Fatalf("headers = %v", reqs[0].Header)
	}
	if bodies[0] != `{"remediation_components":[]}` {
		t.Fatalf("body = %q", bodies[0])
	}
	lapi.mu.Lock()
	lapi.usage = http.StatusNotFound
	lapi.mu.Unlock()
	if err := c.postUsage(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("postUsage against a 404 = nil error")
	}
}

// Even when the LAPI echoes the key back in an error body, the error text does not carry it.
func TestPullErrorNeverCarriesTheKey(t *testing.T) {
	lapi := newStubLAPI(t, lapiReply{http.StatusForbidden, `{"message":"unknown key ` + testKey + `"}`})
	c, _ := newLAPIClient(testConfig(t, lapi.srv.URL+"/"))
	_, err := c.pull(context.Background(), true)
	if err == nil {
		t.Fatal("pull = nil error")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("error %q carries the key", err)
	}
}
