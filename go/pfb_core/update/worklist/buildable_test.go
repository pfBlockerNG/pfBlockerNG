package worklist

import (
	"os"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// A capped pending feed leaves pending once its cap verdict stands: the next Update, given what this one left pending, does
// not build it past the cap.
// Inside the window or outside it, where the build waits for the apply.
func TestRetryCappedPendingFeedIsNotBuiltLater(t *testing.T) {
	for _, inWindow := range []bool{true, false} {
		f := newFixture(t, "http://192.0.2.1/list")
		writeFile(t, f.path(".fail"), "") // checked without a probe
		in := f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}, PendingFeeds: []string{"ipv4:A_v4"}})
		in.SkipFeed, in.Failures, in.InWindow = 1, map[string]int{"A_v4": 1}, inWindow
		first := build(t, in)
		if item := onlyItem(t, first); item.Outcome != OutcomeRetryCapReach || present(f.path(".fail")) {
			t.Fatalf("in window %v, first Update: item %+v, fail marker stands %v; want the cap reached and its marker "+
				"consumed", inWindow, item, present(f.path(".fail")))
		}
		next := build(t, f.input(Input{Trigger: "apply", PendingFeeds: first.PendingFeeds}))
		if len(next.Items) != 0 || len(next.PendingFeeds) != 0 {
			t.Fatalf("in window %v, next Update: plan %+v, want the capped feed neither built nor pending", inWindow, next)
		}
	}
}

// A pending feed whose source the stage refuses (feed_source_invalid: today's "Invalid URL" and the like) can never be
// built without a settings change: it is dropped from pending, checked or not, and an apply does not run it. A refusal of
// the stage's own configuration (no rsync program, no GeoIP folder) can clear without one: the feed stays pending.
func TestRequestRefusedPendingFeedIsDropped(t *testing.T) {
	for _, in := range []Input{{Trigger: "apply"}, {Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}} {
		f := newFixture(t, "../US")
		f.row()["format"] = "geoip" // a country code that is no word: the stage refuses the source
		in.PendingFeeds = []string{"ipv4:A_v4"}
		if plan := build(t, f.input(in)); len(plan.PendingFeeds) != 0 || in.Trigger == "apply" && len(plan.Items) != 0 {
			t.Errorf("%s: plan %+v, want the refused feed dropped and not run", in.Trigger, plan)
		}
	}
	for _, in := range []Input{{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}, {Trigger: "apply"}} {
		f := newFixture(t, "rsync://feed.example/module/list")
		f.row()["format"] = "rsync" // the stage has no rsync program
		in.PendingFeeds = []string{"ipv4:A_v4"}
		if plan := build(t, f.input(in)); len(plan.PendingFeeds) != 1 {
			t.Errorf("%s: plan %+v, want the feed kept pending while the stage cannot transfer it", in.Trigger, plan)
		}
	}
}

// A pass stops a whois or asn feed whose source today's check refuses while its list stands, as the check does: the
// stage would resolve the refused source again.
// A Reload with the baseline saved parses it again without resolving the source, so it runs the feed.
func TestPassStopsARefusedListSource(t *testing.T) {
	for _, c := range []struct {
		force    string
		baseline bool
		runs     bool
	}{{"none", true, false}, {"parse", true, true}, {"parse", false, false}} {
		f := newFixture(t, "AS64-500")
		f.row()["format"] = "asn"
		if !c.baseline {
			if err := os.Remove(f.path(".orig")); err != nil {
				t.Fatal(err)
			}
		}
		item := onlyItem(t, build(t, f.input(Input{Trigger: "manual", Scope: "ip", Force: c.force})))
		stopped := item.Stopped == "feed_source_invalid" && item.Change == (feedstage.Change{})
		run := item.Stopped == "" && item.Change == (feedstage.Change{Force: c.force})
		if c.runs && !run || !c.runs && !stopped {
			t.Errorf("force %s, baseline %v: item %+v, want run %v", c.force, c.baseline, item, c.runs)
		}
	}
}
