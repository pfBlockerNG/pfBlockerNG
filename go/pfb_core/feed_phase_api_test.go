package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestFeedPhaseRequiresTheCurrentUpdateToken(t *testing.T) {
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"feed-phase-token","trigger":"manual"}`), 200, `{}`)
	var request struct {
		Token string `json:"token"`
	}
	waitFor(t, func() bool {
		if _, err := os.Stat(f.dir + "/req"); err != nil {
			return false
		}
		return json.Unmarshal([]byte(f.request()), &request) == nil && len(request.Token) == 64
	})
	if err := json.Unmarshal([]byte(f.request()), &request); err != nil || len(request.Token) != 64 {
		t.Fatalf("Update stdin token = %q (%v), want 64 hex characters", request.Token, err)
	}

	for _, body := range []string{
		`{"requestId":"missing-token","phase":"dnsbl","feeds":[],"force":"none"}`,
		`{"requestId":"wrong-token","token":"` + strings.Repeat("0", 64) + `","phase":"dnsbl","feeds":[],"force":"none"}`,
	} {
		got := c.post("FeedPhase", body)
		if got.status == 200 {
			t.Fatalf("FeedPhase(%s) succeeded without the live token: %s", body, got.body)
		}
	}

	body := `{"requestId":"active-token","token":"` + request.Token + `","phase":"dnsbl","feeds":[],"force":"none"}`
	got := c.post("FeedPhase", body)
	if got.status != 200 {
		t.Fatalf("FeedPhase with the active token = %d %s, want 200", got.status, got.body)
	}
	sameJSON(t, string(got.body), `{"results":[]}`)
	if strings.Contains(string(got.body), request.Token) || strings.Contains(c.getUpdate("").Log, request.Token) {
		t.Fatalf("the Update token leaked into the reply or log: %s", request.Token)
	}

	f.release()
	c.waitFinished("manual")
	got = c.post("FeedPhase", `{"requestId":"ended-token","token":"`+request.Token+`","phase":"dnsbl","feeds":[],"force":"none"}`)
	if got.status == 200 {
		t.Fatalf("FeedPhase with an ended Update's token succeeded: %s", got.body)
	}
}

func TestFeedPhaseAcceptsCurrentApplyUpdateToken(t *testing.T) {
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"feed-phase-apply","trigger":"apply"}`), 200, `{}`)
	var request struct {
		Token string `json:"token"`
	}
	waitFor(t, func() bool {
		if _, err := os.Stat(f.dir + "/req"); err != nil {
			return false
		}
		return json.Unmarshal([]byte(f.request()), &request) == nil && len(request.Token) == 64
	})

	body := `{"requestId":"apply-token","token":"` + request.Token + `","phase":"ip","feeds":[],"force":"none"}`
	got := c.post("FeedPhase", body)
	if got.status != 200 {
		t.Fatalf("FeedPhase with the active apply token = %d %s, want 200", got.status, got.body)
	}
	sameJSON(t, string(got.body), `{"results":[]}`)
	f.release()
	c.waitFinished("apply")
}

func TestFeedPhaseAcceptsConfiguredBlacklistCategoryIDs(t *testing.T) {
	c, f := startUpdateCore(t)
	t.Cleanup(f.release)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"feed-phase-blacklist","trigger":"manual"}`), 200, `{}`)
	var request struct {
		Token string `json:"token"`
	}
	waitFor(t, func() bool {
		if _, err := os.Stat(f.dir + "/req"); err != nil {
			return false
		}
		return json.Unmarshal([]byte(f.request()), &request) == nil && len(request.Token) == 64
	})

	valid := `{"requestId":"valid-blacklist","token":"` + request.Token +
		`","phase":"dnsbl","feeds":["blacklist:work:adult"],"force":"none"}`
	got := c.post("FeedPhase", valid)
	if got.status != 200 || !strings.Contains(string(got.body), `"blacklist:work:adult"`) {
		t.Fatalf("FeedPhase rejected a configured blacklist category: %d %s", got.status, got.body)
	}
	for i, id := range []string{
		"blacklist:../work:adult",
		"blacklist:/tmp:adult",
		"blacklist:work:../adult",
		"blacklist:work:/etc",
	} {
		body := `{"requestId":"bad-blacklist-` + string(rune('a'+i)) + `","token":"` + request.Token +
			`","phase":"dnsbl","feeds":[` + `"` + id + `"` + `],"force":"none"}`
		if got := c.post("FeedPhase", body); got.status == 200 {
			t.Fatalf("FeedPhase accepted unsafe blacklist ID %q: %s", id, got.body)
		}
	}
	f.release()
	c.waitFinished("manual")
}
