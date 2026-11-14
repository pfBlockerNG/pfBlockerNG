package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestFeedPhaseRejectsInvalidAndOversizedRequests(t *testing.T) {
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"feed-phase-validation","trigger":"manual"}`), 200, `{}`)
	var active struct {
		Token string `json:"token"`
	}
	waitFor(t, func() bool {
		if _, err := os.Stat(f.dir + "/req"); err != nil {
			return false
		}
		return json.Unmarshal([]byte(f.request()), &active) == nil && len(active.Token) == 64
	})
	if err := json.Unmarshal([]byte(f.request()), &active); err != nil || len(active.Token) != 64 {
		t.Fatalf("Update token = %q (%v)", active.Token, err)
	}

	cases := []struct {
		name   string
		params map[string]any
	}{
		{"unknown field", map[string]any{"phase": "dnsbl", "feeds": []string{}, "force": "none", "extra": true}},
		{"invalid phase", map[string]any{"phase": "geoip", "feeds": []string{}, "force": "none"}},
		{"invalid force", map[string]any{"phase": "dnsbl", "feeds": []string{}, "force": "full"}},
		{"force differs from Update", map[string]any{"phase": "dnsbl", "feeds": []string{}, "force": "download"}},
		{"duplicate feed id", map[string]any{"phase": "dnsbl", "feeds": []string{"dnsbl:feed", "dnsbl:feed"}, "force": "none"}},
		{"unsafe feed id", map[string]any{"phase": "dnsbl", "feeds": []string{"dnsbl:../feed"}, "force": "none"}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"requestId": fmt.Sprintf("invalid-%d", i), "token": active.Token}
			for key, value := range tc.params {
				params[key] = value
			}
			body, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.post("FeedPhase", string(body)); got.status != 400 {
				t.Fatalf("FeedPhase status = %d %s, want 400", got.status, got.body)
			}
		})
	}

	feeds := make([]string, 1025)
	for i := range feeds {
		feeds[i] = fmt.Sprintf("ipv4:feed_%d_v4", i)
	}
	oversized, err := json.Marshal(map[string]any{
		"requestId": "too-many-feeds", "token": active.Token, "phase": "ip", "feeds": feeds, "force": "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.post("FeedPhase", string(oversized)); got.status != 400 {
		t.Fatalf("FeedPhase with %d feeds = %d %s, want 400", len(feeds), got.status, got.body)
	}
	if strings.Contains(c.getUpdate("").Log, active.Token) {
		t.Fatal("the API logged the per-Update token")
	}
}
