package worklist

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// A pending feed the walk checks keeps the check's verdict: past the retry cap it is not downloaded and leaves pending, so
// no later Update builds it past the cap; a failed check is failed with its reason (the stage's failure path owns the fail
// marker) and stays pending; a change found is built, and a source found unchanged has no change left to build.
func TestCheckVerdictOfAPendingFeedStands(t *testing.T) {
	srv := servedBodies(t, map[string]string{"/changed": "9.9.9.9\n", "/same": "1.2.3.4\n"})
	for _, c := range []struct {
		name, path string
		capped     bool
		verdict    feedstage.Verdict
		outcome    string
		pending    []string
	}{
		{"retry cap", "/same", true, feedstage.VerdictUnchanged, OutcomeRetryCapReach, nil},
		{"failed check", "/missing", false, feedstage.VerdictFailed, "", []string{"ipv4:A_v4"}},
		{"changed", "/changed", false, feedstage.VerdictChanged, OutcomeSuccess, nil},
		{"unchanged", "/same", false, feedstage.VerdictUnchanged, OutcomeSuccess, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, remoteURL(srv)+c.path)
			in := f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}, PendingFeeds: []string{"ipv4:A_v4"}})
			if c.capped {
				in.SkipFeed, in.Failures = 1, map[string]int{"A_v4": 1}
			}
			plan := build(t, in)
			item := onlyItem(t, plan)
			if item.Change.Verdict != c.verdict || item.Outcome != c.outcome || !slices.Equal(plan.PendingFeeds, c.pending) ||
				c.verdict == feedstage.VerdictFailed && item.Change.Reason == "" {
				t.Fatalf("item %+v, pending %v; want verdict %s, outcome %q, pending %v", item, plan.PendingFeeds, c.verdict,
					c.outcome, c.pending)
			}
		})
	}
}

// A pending feed that can never be built without a settings change is dropped: a name that is no word, a whois or asn
// source today's check refuses while the feed's list stands.
func TestPendingFeedThatCanNeverBeBuiltIsDropped(t *testing.T) {
	for _, c := range []struct {
		name string
		in   Input
		set  func(f *fixture)
	}{
		{"name, apply", Input{Trigger: "apply"}, func(f *fixture) { f.row()["header"] = "../x" }},
		{"name, outside the window", Input{Trigger: "scheduled"}, func(f *fixture) { f.row()["header"] = "../x" }},
		{"invalid whois, apply", Input{Trigger: "apply"}, func(f *fixture) {
			f.row()["format"], f.row()["url"] = "whois", "exa\x01mple.com"
		}},
		{"invalid asn, walk", Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}, func(f *fixture) {
			f.row()["format"], f.row()["url"] = "asn", "AS64-500"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "http://192.0.2.1/list")
			c.set(f)
			id := "ipv4:" + f.row()["header"].(string) + "_v4"
			c.in.PendingFeeds = []string{id}
			in := f.input(c.in)
			in.InWindow = c.name != "name, outside the window"
			plan := build(t, in)
			if len(plan.PendingFeeds) != 0 {
				t.Fatalf("plan %+v, want %s dropped from pending", plan, id)
			}
		})
	}
}

// A pending feed stopped for a reason that can clear stays pending, but makes no scheduled Update due by itself: the
// Update that cannot build it does nothing.
func TestStoppedPendingFeedStaysPendingWithoutMakingAnUpdateDue(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	writeFile(t, filepath.Join(f.dir, ".pfbrun-A_v4"), "") // a run folder that is no directory: Recover refuses it
	plan := build(t, f.input(Input{Trigger: "scheduled", PendingFeeds: []string{"ipv4:A_v4"}}))
	if plan.Decision != Nothing || len(plan.Items) != 0 || !slices.Equal(plan.PendingFeeds, []string{"ipv4:A_v4"}) {
		t.Fatalf("plan %+v, want nothing to run and the feed still pending", plan)
	}
}

// A pending feed a pass holds follows the walk's Hold rule: held, its stale fail marker consumed.
func TestPassHoldsAPendingHeldFeed(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["state"] = "hold"
	writeFile(t, f.path(".fail"), "")
	plan := build(t, f.input(Input{Trigger: "manual", Scope: "ip", Force: "none", PendingFeeds: []string{"ipv4:A_v4"}}))
	item := onlyItem(t, plan)
	if _, err := os.Lstat(f.path(".fail")); err == nil || item.Change.Verdict != feedstage.VerdictUnchanged ||
		len(plan.PendingFeeds) != 0 {
		t.Fatalf("item %+v, fail marker stands %v, pending %v; want held, its marker gone, nothing pending", item, err == nil,
			plan.PendingFeeds)
	}
}

// A Reload is never held (feedstage): it parses a held feed again from its baseline and leaves its fail marker, which only
// a pass that holds the feed consumes.
func TestReloadParsesAHeldFeedAndLeavesItsFailMarker(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["state"] = "hold"
	writeFile(t, f.path(".fail"), "")
	item := onlyItem(t, build(t, f.input(Input{Trigger: "manual", Scope: "ip", Force: "parse"})))
	if item.Stopped != "" || item.Change != (feedstage.Change{Force: "parse"}) || !present(f.path(".fail")) {
		t.Fatalf("item %+v, fail marker stands %v; want the feed parsed again and its marker left", item,
			present(f.path(".fail")))
	}
}
