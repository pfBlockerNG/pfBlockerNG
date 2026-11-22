package worklist

import (
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// A capped pending feed leaves pending once its cap verdict stands: the next Update, given what this one left pending, does
// not build it past the cap.
func TestRetryCappedPendingFeedIsNotBuiltLater(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	writeFile(t, f.path(".fail"), "") // checked without a probe
	in := f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}, PendingFeeds: []string{"ipv4:A_v4"}})
	in.SkipFeed, in.Failures = 1, map[string]int{"A_v4": 1}
	first := build(t, in)
	if item := onlyItem(t, first); item.Outcome != OutcomeRetryCapReach || present(f.path(".fail")) {
		t.Fatalf("first Update: item %+v, fail marker stands %v; want the cap reached and its marker consumed", item,
			present(f.path(".fail")))
	}
	next := build(t, f.input(Input{Trigger: "apply", PendingFeeds: first.PendingFeeds}))
	if len(next.Items) != 0 || len(next.PendingFeeds) != 0 {
		t.Fatalf("next Update: plan %+v, want the capped feed neither built nor pending", next)
	}
}

// A pending feed whose transfer request the stage refuses (today's "Invalid URL" and the like) can never be built
// without a settings change: it is dropped from pending, checked or not.
func TestRequestRefusedPendingFeedIsDropped(t *testing.T) {
	for _, in := range []Input{{Trigger: "apply"}, {Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}} {
		f := newFixture(t, "rsync://feed.example/module/list")
		f.row()["format"] = "rsync" // the stage has no rsync program: refused
		in.PendingFeeds = []string{"ipv4:A_v4"}
		if plan := build(t, f.input(in)); len(plan.PendingFeeds) != 0 {
			t.Errorf("%s: pending %v, want the refused feed dropped", in.Trigger, plan.PendingFeeds)
		}
	}
}

// A pass stops a whois or asn feed whose source today's check refuses while its list stands, as the check does: the
// stage would resolve the refused source again.
func TestPassStopsARefusedListSource(t *testing.T) {
	f := newFixture(t, "AS64-500")
	f.row()["format"] = "asn"
	item := onlyItem(t, build(t, f.input(Input{Trigger: "manual", Scope: "ip", Force: "none"})))
	if item.Stopped != "feed_source_invalid" || item.Change != (feedstage.Change{}) {
		t.Fatalf("item %+v, want stopped as feed_source_invalid", item)
	}
}
