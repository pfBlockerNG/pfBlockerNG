package worklist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// categoryFixture is a Blacklist provider "UT1" titled "UT1" with the categories ads and porn-x selected, its archive
// published by the Extras stage under the database folder, and a DNSBL feed folder.
type categoryFixture struct {
	db, feeds string
	in        Input
}

func newCategoryFixture(t *testing.T) *categoryFixture {
	t.Helper()
	db, feeds := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(db, "UT1"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"ads", "porn_x"} {
		writeFile(t, filepath.Join(db, "UT1", "UT1_"+c), "ads.example\n")
	}
	empty := map[string]any{"groups": []any{}}
	fetcher := &feedfetch.Fetcher{Policy: feedfetch.Policy{LocalDirs: []string{filepath.Join(db, "UT1")}}, RetryDelay: 1}
	stage := &feedstage.Stage{Paths: feedstage.Paths{FeedDir: feeds}, Fetcher: fetcher}
	return &categoryFixture{db: db, feeds: feeds, in: Input{InWindow: true, BlacklistDir: db,
		Stages: map[string]*feedstage.Stage{"ipv4": stage, "ipv6": stage, "dnsbl": stage},
		Settings: map[string]map[string]any{"feeds/ipv4": empty, "feeds/ipv6": empty, "feeds/dnsbl": empty, "feeds/geoip": empty,
			"schedule": {"categoryUpdates": true, "categoryProviders": []any{
				map[string]any{"id": "UT1", "title": "UT1", "selected": true, "categories": "ads,porn-x"},
				map[string]any{"id": "Other", "title": "Other", "selected": false, "categories": "ads"}}}}}}
}

func (c *categoryFixture) marker() string { return filepath.Join(c.db, "UT1", "UT1.update") }

// publish leaves each category's lists as a run of the per-feed stage would.
func (c *categoryFixture) publish(t *testing.T) {
	t.Helper()
	for _, name := range []string{"UT1_ads", "UT1_porn_x"} {
		writeFile(t, filepath.Join(c.feeds, name+".orig"), "ads.example\n")
		writeFile(t, filepath.Join(c.feeds, name+".parsed.ndjson"), "")
		writeFile(t, filepath.Join(c.feeds, name+".parsed.v4.ip"), "")
		writeFile(t, filepath.Join(c.feeds, name+".parsed.v6.ip"), "")
	}
}

// categories are the plan's items of the selected provider's categories, by feed name.
func categories(plan Plan) map[string]Item {
	out := map[string]Item{}
	for _, item := range plan.Items {
		if item.Feed.Name == "UT1_ads" || item.Feed.Name == "UT1_porn_x" || item.Feed.Name == "Other_ads" {
			out[item.Feed.Name] = item
		}
	}
	return out
}

// Scenario: the Blacklist categories reach the per-feed stage (issue #4038, gap for 9i): no stage parsed them, so the
// DNSBL build found no <title>_<category>.parsed.ndjson.
//
// GIVEN a selected provider with two categories (a dash in a category name becomes an underscore, as today) and an
// unselected one
// WHEN an Update runs the pass
// THEN each selected category is a DNSBL feed of the per-feed stage, read from the provider's folder as a local file, and
// built when its lists are missing or the Extras stage left the provider's update marker; otherwise its lists are reused.
func TestTheBlacklistCategoriesAreFeedsOfThePerFeedStage(t *testing.T) {
	c := newCategoryFixture(t)
	manual := Input{Trigger: "manual", Scope: "dnsbl", Force: "none"}
	manual.InWindow, manual.Stages, manual.Settings, manual.BlacklistDir = true, c.in.Stages, c.in.Settings, c.in.BlacklistDir

	got := categories(build(t, manual))
	if len(got) != 2 || got["Other_ads"].Feed.Name != "" {
		t.Fatalf("category items = %+v, want UT1_ads and UT1_porn_x only", got)
	}
	ads := got["UT1_ads"]
	want := feedstage.Feed{ID: "blacklist:UT1:ads", Kind: "dnsbl", Name: "UT1_ads", State: "enabled", Format: "auto",
		Source: "file://" + filepath.Join(c.db, "UT1", "UT1_ads")}
	if ads.Feed != want {
		t.Errorf("feed = %+v\n want %+v", ads.Feed, want)
	}
	if ads.Change.Verdict != feedstage.VerdictChanged || ads.Stopped != "" {
		t.Errorf("first run: change %+v stopped %q, want changed (its lists are missing)", ads.Change, ads.Stopped)
	}
	if _, reason := c.in.Stages["dnsbl"].Request(ads.Feed); reason != "" {
		t.Errorf("the stage refuses the category's source: %s", reason)
	}

	c.publish(t)
	if v := categories(build(t, manual))["UT1_ads"].Change.Verdict; v != feedstage.VerdictUnchanged {
		t.Errorf("lists published, no marker: verdict %q, want unchanged (reused)", v)
	}
	writeFile(t, c.marker(), "")
	item := categories(build(t, manual))["UT1_porn_x"]
	if item.Change.Verdict != feedstage.VerdictChanged || item.Marker != c.marker() {
		t.Errorf("after a download: change %+v marker %q, want changed with the marker %q to remove", item.Change, item.Marker, c.marker())
	}
	if _, err := os.Stat(c.marker()); err != nil {
		t.Errorf("Build removed the provider's marker: %v; the caller removes it once the categories ran", err)
	}
}

// Scenario: a Blacklist download makes a scheduled Update build its categories.
//
// GIVEN published category lists
// WHEN a scheduled Update names no feed, without and then with the provider's update marker
// THEN nothing is due without it; with it the walk builds both categories, reporting no outcome (Core named none).
func TestAScheduledUpdateBuildsTheCategoriesOfANewDownload(t *testing.T) {
	c := newCategoryFixture(t)
	c.publish(t)
	in := c.in
	in.Trigger = "scheduled"
	if plan := build(t, in); plan.Decision != Nothing {
		t.Fatalf("without a marker: decision %q, items %+v, want nothing due", plan.Decision, plan.Items)
	}
	writeFile(t, c.marker(), "")
	plan := build(t, in)
	got := categories(plan)
	if plan.Decision != Now || len(got) != 2 {
		t.Fatalf("with a marker: decision %q, categories %+v, want now with both categories", plan.Decision, got)
	}
	for name, item := range got {
		if item.Change.Verdict != feedstage.VerdictChanged || item.Outcome != "" || item.Marker != c.marker() {
			t.Errorf("%s: %+v, want changed, no outcome, the marker", name, item)
		}
	}
	if len(plan.PendingFeeds) != 0 {
		t.Errorf("pending = %q, want none: a category is never a pending feed", plan.PendingFeeds)
	}
}
