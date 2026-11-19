package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Key names are matched exactly: encoding/json alone would take "API_KEY" for api_key, and let a repeated key win.
func TestParseConfigRejectsMisspelledAndRepeatedKeys(t *testing.T) {
	cases := map[string]string{
		"upper-case key": `{"API_URL":"https://l.test/","api_key":"k"}`,
		"mixed-case key": `{"api_url":"https://l.test/","Api_Key":"k"}`,
		"repeated key":   `{"api_url":"https://l.test/","api_key":"first","api_key":"second"}`,
	}
	for name, raw := range cases {
		if cfg, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: parseConfig(%s) = %+v, nil; want an error", name, raw, cfg)
		}
	}
}

// A short key is not blanked out letter by letter (that garbles every line and spells the key out); instead an error
// reply that repeats the key is dropped from the error text.
func TestAShortKeyNeitherGarblesLogsNorLeaksThroughAnEchoedReply(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(&buf, levelDebug)
	l.setSecret("e")
	l.infof("pfb_crowdsec started")
	if got := buf.String(); got != "level=info msg=pfb_crowdsec started\n" {
		t.Fatalf("log line = %q; want it unchanged", got)
	}

	lapi := newStubLAPI(t, lapiReply{http.StatusForbidden, `{"message":"unknown bouncer key e"}`})
	cfg, err := parseConfig([]byte(fmt.Sprintf(`{"api_url":%q,"api_key":"e"}`, lapi.srv.URL+"/")))
	if err != nil {
		t.Fatal(err)
	}
	c, err := newLAPIClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.pull(context.Background(), true)
	if err == nil {
		t.Fatal("pull against a 403 = nil")
	}
	if !strings.Contains(err.Error(), "/v1/decisions/stream") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %q; want the path and status readable", err)
	}
	if strings.Contains(err.Error(), "unknown bouncer key") {
		t.Fatalf("error = %q; the reply that repeats the key reached the error text", err)
	}
}
