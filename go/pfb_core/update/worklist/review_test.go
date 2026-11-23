package worklist

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// Scenario: review of #4038 9i. An Update with nothing due keeps a pending feed that was only stopped this Update.
//
// GIVEN the feed A left pending by an earlier Update, its folder a symbolic link (recovery refuses it: the feed is stopped)
// WHEN a scheduled Update that names nothing runs
// THEN nothing is due, and A is still pending: its folder can be repaired without a settings change.
func TestANothingDueUpdateKeepsAPendingFeedThatWasOnlyStopped(t *testing.T) {
	f := newFixture(t, "https://example.invalid/a")
	real := f.dir + ".real"
	if err := os.Rename(f.dir, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, f.dir); err != nil {
		t.Fatal(err)
	}
	plan := build(t, f.input(Input{Trigger: "scheduled", PendingFeeds: []string{"ipv4:A_v4"}}))
	if plan.Decision != Nothing {
		t.Fatalf("decision = %q, items %+v; want nothing due", plan.Decision, plan.Items)
	}
	if !slices.Equal(plan.PendingFeeds, []string{"ipv4:A_v4"}) {
		t.Errorf("pending = %q, want ipv4:A_v4 kept", plan.PendingFeeds)
	}
}

// Scenario: review of #4038 9i. A category that is stopped keeps its provider's marker, so the caller does not consume it.
//
// GIVEN a selected provider whose title is no word (its categories are stopped) and the provider's update marker
// WHEN an Update runs the pass
// THEN the stopped category item carries the marker.
func TestAStoppedCategoryCarriesItsProvidersMarker(t *testing.T) {
	c := newCategoryFixture(t)
	c.in.Settings["schedule"]["categoryProviders"].([]any)[0].(map[string]any)["title"] = "U T"
	writeFile(t, c.marker(), "")
	in := c.in
	in.Trigger, in.Scope, in.Force = "manual", "dnsbl", "none"
	var stopped []Item
	for _, item := range build(t, in).Items {
		if item.Stopped != "" {
			stopped = append(stopped, item)
		}
	}
	if len(stopped) != 2 {
		t.Fatalf("stopped items = %+v, want both categories", stopped)
	}
	for _, item := range stopped {
		if item.Marker != c.marker() {
			t.Errorf("%s: marker %q, want %q", item.Feed.ID, item.Marker, c.marker())
		}
	}
}

// Scenario: review of #4038 9i. A category whose feed name a configured DNSBL feed holds is refused, never run against
// that feed's files.
//
// GIVEN a DNSBL feed with the header UT1_ads, and the category ads of the provider titled UT1
// WHEN an Update runs the pass
// THEN the category is stopped with feed_name_taken under its own id, and the DNSBL feed runs as before.
func TestACategoryWhoseNameAFeedHoldsIsRefused(t *testing.T) {
	c := newCategoryFixture(t)
	c.in.Settings["feeds/dnsbl"] = map[string]any{"groups": []any{map[string]any{"name": "Ads", "action": "unbound",
		"updateFrequency": "01hour", "customList": "", "feeds": []any{map[string]any{"header": "UT1_ads", "state": "enabled",
			"format": "auto", "url": "file://" + filepath.Join(c.db, "UT1", "UT1_ads"), "credentials": ""}}}}}
	in := c.in
	in.Trigger, in.Scope, in.Force = "manual", "dnsbl", "none"
	got := map[string]Item{}
	for _, item := range build(t, in).Items {
		got[item.Feed.ID] = item
	}
	if item := got["blacklist:UT1:ads"]; item.Stopped != "feed_name_taken" {
		t.Errorf("category = %+v, want stopped with feed_name_taken", item)
	}
	if item := got["dnsbl:UT1_ads"]; item.Stopped != "" || item.Change.Verdict != feedstage.VerdictChanged {
		t.Errorf("DNSBL feed = %+v, want it run as changed", item)
	}
}

// CodeRabbit r4671035990: a scheduled walk keeps a stopped category in the plan, carrying its provider's marker, so the
// caller does not consume the marker.
func TestAScheduledWalkKeepsAStoppedCategoryWithItsMarker(t *testing.T) {
	c := newCategoryFixture(t)
	c.in.Settings["schedule"]["categoryProviders"].([]any)[0].(map[string]any)["title"] = "U T"
	writeFile(t, c.marker(), "")
	f := newFixture(t, "https://example.invalid/a")
	in := c.in
	in.Trigger, in.Feeds = "scheduled", []string{"ipv4:A_v4"}
	in.Settings["feeds/ipv4"] = map[string]any{"groups": []any{f.group}}
	in.Stages = map[string]*feedstage.Stage{"ipv4": f.stage, "ipv6": f.stage, "dnsbl": c.in.Stages["dnsbl"]}
	var stopped []Item
	for _, item := range build(t, in).Items {
		if item.Feed.Kind == "dnsbl" {
			stopped = append(stopped, item)
		}
	}
	if len(stopped) != 2 {
		t.Fatalf("category items = %+v, want both, stopped", stopped)
	}
	for _, item := range stopped {
		if item.Stopped == "" || item.Marker != c.marker() {
			t.Errorf("%s: %+v, want stopped carrying %s", item.Feed.ID, item, c.marker())
		}
	}
}
