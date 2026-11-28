package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_crowdsec/spoa"
)

func TestConfigSPOAAndAppSecValidation(t *testing.T) {
	base := `{"api_url":"http://127.0.0.1:8080","api_key":"secret123"`
	validCases := []string{
		base + `,"spoa_listen":"127.0.0.1:10091"}`,
		base + `,"spoa_listen":"[::1]:10091"}`,
		base + `,"spoa_listen":"unix:/var/run/pfb_crowdsec/spoa.sock","spoa_socket_group":80}`,
		base + `,"spoa_listen":"127.0.0.1:10091","appsec_url":"http://10.0.0.5:7422","appsec_timeout":"750ms","appsec_failure_action":"passthrough"}`,
		base + `,"spoa_listen":"127.0.0.1:10091","appsec_url":"https://appsec.local:7422","appsec_failure_action":"deny"}`,
	}
	for _, raw := range validCases {
		if _, err := parseConfig([]byte(raw)); err != nil {
			t.Errorf("parseConfig(%s) failed: %v", raw, err)
		}
	}
	invalidCases := []string{
		base + `,"spoa_listen":"0.0.0.0:10091"}`,
		base + `,"spoa_listen":"unix:relative.sock"}`,
		base + `,"spoa_socket_group":-1}`,
		base + `,"appsec_url":"ftp://10.0.0.5:7422"}`,
		base + `,"appsec_url":"http://10.0.0.5:7422?foo=1"}`,
		base + `,"appsec_timeout":"10ms"}`,
		base + `,"appsec_timeout":"5m"}`,
		base + `,"appsec_failure_action":"explode"}`,
	}
	for _, raw := range invalidCases {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("parseConfig(%s) succeeded, want error", raw)
		}
	}
}

func actionMap(actions []spoa.Action) map[string]spoa.Value {
	out := make(map[string]spoa.Value, len(actions))
	for _, a := range actions {
		out[a.Name] = a.Value
	}
	return out
}

func TestSPOAHandlerLocalDecisionsAndLAPIOutageSurvival(t *testing.T) {
	cfg := &config{
		APIURL:              "http://127.0.0.1:8080",
		APIKey:              "my-secret-key",
		TableV4:             "crowdsec_v4",
		TableV6:             "crowdsec_v6",
		StatusFile:          t.TempDir() + "/status.json",
		SPOAListen:          "127.0.0.1:10091",
		interval:            10 * time.Second,
		appSecTimeout:       500 * time.Millisecond,
		AppSecFailureAction: "passthrough",
	}
	d := newDaemon(cfg, newLogger(io.Discard, levelError), &pfctl{r: newFakePF()}, nil, time.Now)

	// Initial full pull populates ban, range ban, captcha, and secret-containing origin.
	resp := &streamResponse{
		New: []decision{
			{ID: 1, Origin: "crowdsec", Scenario: "crowdsecurity/http-probing", Type: "ban", Scope: "ip", Value: "198.51.100.10"},
			{ID: 2, Origin: "CAPI", Scenario: "crowdsecurity/ssh-bf", Type: "ban", Scope: "range", Value: "203.0.113.0/24"},
			{ID: 3, Origin: "lists:firehol", Scenario: "crowdsecurity/http-crawl", Type: "captcha", Scope: "ip", Value: "192.0.2.50"},
			{ID: 4, Origin: "bad-my-secret-key-origin", Scenario: "test/redact", Type: "ban", Scope: "ip", Value: "2001:db8::1"},
		},
	}
	_ = d.finishPull(context.Background(), true, resp, nil)

	// Simulate LAPI outage: finishPull with error must NOT clear cached SPOA decisions.
	_ = d.finishPull(context.Background(), false, nil, errors.New("connection refused"))

	cases := []struct {
		ip          string
		wantRem     string
		wantOrigin  string
		wantScen    string
		wantBlocked bool
	}{
		{"198.51.100.10", "ban", "crowdsec", "crowdsecurity/http-probing", true},
		{"203.0.113.77", "ban", "CAPI", "crowdsecurity/ssh-bf", true},
		{"192.0.2.50", "captcha", "lists:firehol", "crowdsecurity/http-crawl", true},
		{"2001:db8::1", "ban", "(hidden)", "test/redact", true},
		{"198.51.100.99", "bypass", "", "", false},
	}
	for _, tc := range cases {
		acts, blocked, err := d.spoa.Handle(context.Background(), []spoa.Message{{
			Name: "cs-check",
			Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr(tc.ip))}},
		}})
		if err != nil {
			t.Fatalf("Handle(%s): %v", tc.ip, err)
		}
		m := actionMap(acts)
		if blocked != tc.wantBlocked || m["remediation"].String != tc.wantRem || m["origin"].String != tc.wantOrigin || m["scenario"].String != tc.wantScen {
			t.Errorf("Handle(%s) = (blocked=%v, rem=%q, origin=%q, scen=%q), want (%v, %q, %q, %q)",
				tc.ip, blocked, m["remediation"].String, m["origin"].String, m["scenario"].String,
				tc.wantBlocked, tc.wantRem, tc.wantOrigin, tc.wantScen)
		}
	}
}

func TestSPOAHandlerAppSecPassthroughAndFailOpen(t *testing.T) {
	var hits atomic.Int32
	var mode atomic.Int32 // 0=allow, 1=deny, 2=500 error

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Crowdsec-Appsec-Api-Key") != "appsec-key" {
			t.Errorf("missing/wrong api key header: %q", r.Header.Get("X-Crowdsec-Appsec-Api-Key"))
		}
		switch mode.Load() {
		case 0:
			w.WriteHeader(http.StatusOK)
		case 1:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(appSecResponse{Action: "ban", HTTPStatus: 403, Scenario: "crowdsecurity/vpatch-sqli"})
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	cfg := &config{
		APIKey:              "appsec-key",
		SPOAListen:          "127.0.0.1:10091",
		AppSecURL:           ts.URL,
		appSecTimeout:       500 * time.Millisecond,
		AppSecFailureAction: "passthrough",
	}
	st := newSPOAState(cfg, nil)
	b := spoa.NewRadixBuilder[spoaDecision]()
	b.Insert(netip.MustParsePrefix("198.51.100.1/32"), spoaDecision{Remediation: "ban", Origin: "crowdsec", Scenario: "local"}, false)
	st.swap(b.Build())

	makeMsg := func(ip string) []spoa.Message {
		return []spoa.Message{{
			Name: "cs-check",
			Args: []spoa.KV{
				{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr(ip))},
				{Key: "method", Value: spoa.StringValue("GET")},
				{Key: "host", Value: spoa.StringValue("example.com")},
				{Key: "uri", Value: spoa.StringValue("/login?id=1")},
				{Key: "user-agent", Value: spoa.StringValue("curl/8.0")},
			},
		}}
	}

	// 1. Local ban short-circuits BEFORE AppSec (0 AppSec hits).
	acts, blocked, _ := st.Handle(context.Background(), makeMsg("198.51.100.1"))
	if !blocked || actionMap(acts)["origin"].String != "crowdsec" || hits.Load() != 0 {
		t.Fatalf("local ban did not short-circuit AppSec: blocked=%v hits=%d", blocked, hits.Load())
	}

	// 2. Clean IP -> AppSec 200 -> bypass.
	mode.Store(0)
	acts, blocked, _ = st.Handle(context.Background(), makeMsg("203.0.113.5"))
	if blocked || actionMap(acts)["remediation"].String != "bypass" || hits.Load() != 1 {
		t.Fatalf("AppSec allow failed: blocked=%v acts=%+v hits=%d", blocked, acts, hits.Load())
	}

	// 3. Clean IP -> AppSec 403 -> ban with origin=appsec & scenario.
	mode.Store(1)
	acts, blocked, _ = st.Handle(context.Background(), makeMsg("203.0.113.5"))
	m := actionMap(acts)
	if !blocked || m["remediation"].String != "ban" || m["origin"].String != "appsec" || m["scenario"].String != "crowdsecurity/vpatch-sqli" {
		t.Fatalf("AppSec deny failed: blocked=%v m=%+v", blocked, m)
	}

	// 4. AppSec 500 with passthrough -> fail-open bypass (no outage).
	mode.Store(2)
	acts, blocked, _ = st.Handle(context.Background(), makeMsg("203.0.113.5"))
	if blocked || actionMap(acts)["remediation"].String != "bypass" || st.appsecErrors.Load() != 1 {
		t.Fatalf("AppSec fail-open failed: blocked=%v acts=%+v errs=%d", blocked, acts, st.appsecErrors.Load())
	}

	// 5. AppSec 500 with deny -> fail-closed ban.
	st.appSec.failureAction = "deny"
	acts, blocked, _ = st.Handle(context.Background(), makeMsg("203.0.113.5"))
	if !blocked || actionMap(acts)["remediation"].String != "ban" {
		t.Fatalf("AppSec fail-closed failed: blocked=%v acts=%+v", blocked, acts)
	}
}
