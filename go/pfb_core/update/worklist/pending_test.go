package worklist

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// Feeds earlier Updates left pending are never lost: every plan builds those it can, as changed, and Plan.PendingFeeds
// holds exactly the ones still pending after it. A feed that left the settings is dropped.
func TestPendingFeedsAreNeverLost(t *testing.T) {
	for _, c := range []struct {
		name    string
		in      Input
		broken  bool // the feed folder cannot be recovered
		change  feedstage.Change
		pending []string
	}{
		{"manual pass", Input{Trigger: "manual", Scope: "ip", Force: "none"}, false,
			feedstage.Change{Verdict: feedstage.VerdictChanged, Force: "none"}, nil},
		{"reload keeps it pending", Input{Trigger: "manual", Scope: "ip", Force: "parse"}, false,
			feedstage.Change{Force: "parse"}, []string{"ipv4:A_v4"}},
		{"force check", Input{Trigger: "manual", Scope: "ip", Force: "download"}, false,
			feedstage.Change{Force: "download"}, nil},
		{"outside the scope", Input{Trigger: "manual", Scope: "dnsbl", Force: "none"}, false,
			feedstage.Change{}, []string{"ipv4:A_v4"}},
		{"in-window walk", Input{Trigger: "scheduled"}, false,
			feedstage.Change{Verdict: feedstage.VerdictChanged, Force: "none"}, nil},
		{"apply", Input{Trigger: "apply"}, false, feedstage.Change{Verdict: feedstage.VerdictChanged, Force: "none"}, nil},
		{"apply with the folder broken", Input{Trigger: "apply"}, true, feedstage.Change{}, []string{"ipv4:A_v4"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "http://192.0.2.1/list")
			if c.broken {
				writeFile(t, filepath.Join(f.dir, ".pfbrun-A_v4"), "") // a run folder that is no directory
			}
			c.in.PendingFeeds = []string{"ipv4:Gone_v4", "ipv4:A_v4"}
			plan := build(t, f.input(c.in))
			var got feedstage.Change
			for _, item := range plan.Items {
				if item.Feed.ID == "ipv4:A_v4" {
					got = item.Change
				}
			}
			if got.Verdict != c.change.Verdict || got.Force != c.change.Force || !slices.Equal(plan.PendingFeeds, c.pending) {
				t.Fatalf("change %+v, pending %v; want change %+v, pending %v", got, plan.PendingFeeds, c.change, c.pending)
			}
		})
	}
}

// Outside the window the pending feeds stay pending, with the ones this Update found changed.
func TestPendingFeedsWaitOutsideTheWindow(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	in := f.input(Input{Trigger: "scheduled", PendingFeeds: []string{"ipv4:A_v4"}})
	in.InWindow = false
	if plan := build(t, in); plan.Decision != Pending || !slices.Equal(plan.PendingFeeds, []string{"ipv4:A_v4"}) {
		t.Fatalf("plan %+v, want pending with the feed left to the apply", plan)
	}
}

// An apply holds a pending feed now on Hold with its list, as the walk does: not built, its fail marker consumed.
func TestApplyHoldsAPendingFeedOnHold(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["state"] = "hold"
	writeFile(t, f.path(".fail"), "")
	plan := build(t, f.input(Input{Trigger: "apply", PendingFeeds: []string{"ipv4:A_v4"}}))
	item := onlyItem(t, plan)
	if item.Change.Verdict != feedstage.VerdictUnchanged || present(f.path(".fail")) || len(plan.PendingFeeds) != 0 {
		t.Fatalf("item %+v, fail marker stands %v, pending %v; want held, its marker gone, nothing pending", item,
			present(f.path(".fail")), plan.PendingFeeds)
	}
}

// A GeoIP change leaves every geoip feed to be built: now in the window, pending outside it (today's geoip.update).
func TestGeoIPChangeBuildsEveryGeoIPFeed(t *testing.T) {
	for _, inWindow := range []bool{true, false} {
		f := newFixture(t, "http://192.0.2.1/list")
		f.group["feeds"] = append(f.group["feeds"].([]any), map[string]any{"header": "C", "state": "enabled",
			"format": "geoip", "url": "US", "credentials": ""})
		writeFile(t, filepath.Join(f.dir, "C_v4.parsed.ip"), "1.2.3.4\n")
		writeFile(t, f.path(".fail"), "") // A is checked without a probe
		in := f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}, GeoIPChanged: true})
		in.InWindow = inWindow
		plan := build(t, in)
		var geoip *Item
		for i := range plan.Items {
			if plan.Items[i].Feed.ID == "ipv4:C_v4" {
				geoip = &plan.Items[i]
			}
		}
		switch {
		case inWindow && (geoip == nil || geoip.Change.Verdict != feedstage.VerdictChanged || len(plan.PendingFeeds) != 0):
			t.Errorf("in the window: plan %+v, want the geoip feed built as changed", plan)
		case !inWindow && (plan.Decision != Pending || !slices.Contains(plan.PendingFeeds, "ipv4:C_v4")):
			t.Errorf("outside the window: plan %+v, want the geoip feed left pending", plan)
		}
	}
}

// A held feed whose stale fail marker cannot be removed is reported stopped, named or not.
func TestHeldFeedWhoseFailMarkerStandsIsReported(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["state"] = "hold"
	if err := os.Mkdir(f.path(".fail"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.path(".fail"), "x"), "") // a directory with a file: no removal takes it
	plan := build(t, f.input(Input{Trigger: "retry"}))
	if len(plan.Items) != 1 || plan.Items[0].Stopped != "fail_marker_remove_failed" {
		t.Fatalf("items %+v, want the held feed reported stopped", plan.Items)
	}
}

// An apply needs the stages of the pending feeds' kinds only.
func TestApplyNeedsOnlyThePendingFeedsStages(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	in := f.input(Input{Trigger: "apply", PendingFeeds: []string{"ipv4:A_v4"}})
	in.Settings["feeds/dnsbl"] = map[string]any{"groups": []any{map[string]any{"name": "GD", "action": "unbound",
		"updateFrequency": "01hour", "feeds": []any{map[string]any{"header": "D", "state": "enabled", "format": "auto",
			"url": "http://192.0.2.1/d", "credentials": ""}}}}}
	if item := onlyItem(t, build(t, in)); item.Change.Verdict != feedstage.VerdictChanged {
		t.Fatalf("item %+v, want the pending IPv4 feed built", item)
	}
}
