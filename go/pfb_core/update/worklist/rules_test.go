package worklist

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

func (f *fixture) row() map[string]any { return f.group["feeds"].([]any)[0].(map[string]any) }

func named() Input { return Input{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}} }

// A feed folder Recover refuses is read by no rule: its fail marker makes no walk due, so nothing is.
func TestUnrecoverableFolderIsNotReadForWork(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	writeFile(t, filepath.Join(f.dir, ".pfbrun-A_v4"), "") // a run folder that is no directory
	writeFile(t, f.path(".fail"), "")
	if plan := build(t, f.input(Input{Trigger: "retry"})); plan.Decision != Nothing || len(plan.Items) != 0 {
		t.Fatalf("plan = %+v, want nothing: the folder's fail marker is not read before the folder is recovered", plan)
	}
}

// A feed whose name is no word is stopped before Build reads or removes anything under its name.
func TestFeedNameThatIsNoWordIsStopped(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["header"], f.row()["state"] = "../x", "hold"
	outside := filepath.Join(filepath.Dir(f.dir), "x_v4")
	writeFile(t, outside+".parsed.ip", "1.2.3.4\n")
	writeFile(t, outside+".fail", "")
	item := onlyItem(t, build(t, f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:../x_v4"}})))
	if item.Stopped != "feed_name_invalid" || item.Outcome != "" {
		t.Fatalf("item = %+v, want stopped as feed_name_invalid without an outcome", item)
	}
	if !present(outside + ".fail") {
		t.Fatal("Build removed a file outside the feed folder")
	}
}

// An rsync feed with a baseline is a changed success without a probe, as today's check never contacts its host.
func TestRsyncFeedIsChangedWithoutAProbe(t *testing.T) {
	f := newFixture(t, "rsync://feed.example/module/list")
	f.row()["format"] = "rsync"
	f.stage.Fetcher.RsyncBin = "/nonexistent/rsync" // never run: Build transfers nothing
	var resolved atomic.Bool
	f.stage.Fetcher.Policy.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		resolved.Store(true)
		return nil, errors.New("no resolver in this test")
	}
	item := onlyItem(t, build(t, f.input(named())))
	if item.Change.Verdict != feedstage.VerdictChanged || item.Outcome != OutcomeSuccess || resolved.Load() {
		t.Fatalf("item = %+v, host resolved %v; want a changed success with no probe", item, resolved.Load())
	}
}

// The record of a kept probe body names its source: the URL, the user and the rsync transfer. A body kept for any other
// source is dropped; one kept for the same source stays, whatever the password: a password is no part of a source's
// identity (CodeQL: no secret in the probe source identity; a password change does not change the source).
func TestProbeSourceCoversTheWholeRequest(t *testing.T) {
	for _, c := range []struct {
		name string
		move func(row map[string]any)
		kept bool
	}{
		{"same", func(map[string]any) {}, true},
		{"url", func(row map[string]any) { row["url"] = "http://feed.example/other" }, false},
		{"user", func(row map[string]any) { row["credentials"] = "other:secret" }, false},
		{"password", func(row map[string]any) { row["credentials"] = "user:other" }, true},
		{"rsync", func(row map[string]any) { row["format"] = "rsync" }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "http://feed.example/list")
			f.row()["credentials"] = "user:secret"
			f.stage.Fetcher.RsyncBin = "/nonexistent/rsync" // never run: Build transfers nothing
			source, ok := probeIdentity(candidate{feed: feedFor("ipv4", f.group, f.row()), stage: f.stage, dir: f.dir})
			if !ok {
				t.Fatal("no source for a remote feed")
			}
			writeFile(t, f.path(".probe"), "9.9.9.9\n")
			writeFile(t, f.path(".probe.src"), source)
			c.move(f.row())
			writeFile(t, f.path(".fail"), "") // checked without a probe
			build(t, f.input(named()))
			if present(f.path(".probe")) != c.kept {
				t.Fatalf("the kept probe body stands: %v, want %v", present(f.path(".probe")), c.kept)
			}
		})
	}
}

// The record depends on no secret: the same request with two passwords gives the same record.
func TestProbeSourceRecordIgnoresThePassword(t *testing.T) {
	record := func(credentials string) string {
		f := newFixture(t, "http://feed.example/list")
		f.row()["credentials"] = credentials
		source, ok := probeIdentity(candidate{feed: feedFor("ipv4", f.group, f.row()), stage: f.stage, dir: f.dir})
		if !ok {
			t.Fatal("no source for a remote feed")
		}
		return source
	}
	if a, b := record("user:secret"), record("user:other"); a != b {
		t.Fatalf("record with password secret = %q, with password other = %q; want the same", a, b)
	}
}

// A source record that is a symbolic link is not followed: the body it stands beside is of an unknown source.
func TestProbeSourceRecordBehindALinkIsNotRead(t *testing.T) {
	f := newFixture(t, "http://feed.example/list")
	source, _ := probeIdentity(candidate{feed: feedFor("ipv4", f.group, f.row()), stage: f.stage, dir: f.dir})
	elsewhere := filepath.Join(t.TempDir(), "record")
	writeFile(t, elsewhere, source)
	writeFile(t, f.path(".probe"), "9.9.9.9\n")
	if err := os.Symlink(elsewhere, f.path(".probe.src")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.path(".fail"), "")
	build(t, f.input(named()))
	if present(f.path(".probe")) {
		t.Fatal("a probe body whose source record is a link was kept")
	}
	if got, err := os.ReadFile(elsewhere); err != nil || string(got) != source {
		t.Fatalf("the link's target = %q, %v; want it untouched", got, err)
	}
}

// A Force Check runs a held feed with its list (the stage holds it) and consumes its fail marker, unchecked.
func TestForceCheckRunsAHeldFeed(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.row()["state"] = "hold"
	writeFile(t, f.path(".fail"), "")
	item := onlyItem(t, build(t, f.input(Input{Trigger: "manual", Scope: "ip", Force: "download"})))
	if item.Change.Force != "download" || item.Checked || present(f.path(".fail")) {
		t.Fatalf("item = %+v, fail marker stands %v; want it run with the force, unchecked, its marker gone", item,
			present(f.path(".fail")))
	}
}

// A whois or asn source is checked as today's: an asn feed's AS number is letters and digits, a whois feed's domain passes
// today's domain filter (PFB_FILTER_DOMAIN), each cut at its first space. Another source stops the feed.
func TestWhoisAndASNSources(t *testing.T) {
	for _, c := range []struct {
		format, source string
		valid          bool
	}{
		{"asn", "AS64500 Example", true}, {"asn", "AS64-500", false}, {"whois", "example.com", true},
		{"whois", "exa\x01mple.com", false},
		{"whois", "notadomain", false}, {"whois", "a..example.com", false},
	} {
		f := newFixture(t, c.source)
		f.row()["format"] = c.format
		item := onlyItem(t, build(t, f.input(named())))
		ok := item.Stopped == "" && item.Change.Verdict == feedstage.VerdictChanged && item.Outcome == OutcomeSuccess
		stopped := item.Stopped == "feed_source_invalid" && item.Outcome == ""
		if c.valid && !ok || !c.valid && !stopped {
			t.Errorf("%s %q: item %+v, want valid %v", c.format, c.source, item, c.valid)
		}
	}
}

// A fail marker the walk must consume and cannot remove stops the feed: no outcome settles it.
func TestFailMarkerThatCannotBeRemovedStopsTheFeed(t *testing.T) {
	for _, rule := range []string{"hold", "retry-cap"} {
		f := newFixture(t, "http://192.0.2.1/list")
		if err := os.Mkdir(f.path(".fail"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.path(".fail"), "x"), "") // a directory with a file: no removal takes it
		in := f.input(named())
		if rule == "hold" {
			f.row()["state"] = "hold"
		} else {
			in.SkipFeed, in.Failures = 1, map[string]int{"A_v4": 1}
		}
		if item := onlyItem(t, build(t, in)); item.Stopped != "fail_marker_remove_failed" || item.Outcome != "" {
			t.Errorf("%s: item %+v, want stopped as fail_marker_remove_failed without an outcome", rule, item)
		}
	}
}

// Groups of a kind are walked in config order, whatever order Core named their feeds in.
func TestGroupsAreWalkedInConfigOrder(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	second := map[string]any{"name": "G5", "action": "Deny_Inbound", "updateFrequency": "01hour", "feeds": []any{
		map[string]any{"header": "B", "state": "enabled", "format": "auto", "url": "http://192.0.2.1/b", "credentials": ""}}}
	for _, name := range []string{"A_v4", "B_v4"} {
		base := filepath.Join(f.dir, name)
		writeFile(t, base+".orig", "1.2.3.4\n")
		writeFile(t, base+".orig.xxhash128", digest.Bytes([]byte("1.2.3.4\n")))
		writeFile(t, base+".parsed.ip", "1.2.3.4\n")
		writeFile(t, base+".fail", "") // checked without a probe
	}
	in := f.input(Input{Trigger: "scheduled", Feeds: []string{"ipv4:B_v4", "ipv4:A_v4"}})
	in.Settings["feeds/ipv4"]["groups"] = []any{f.group, second}
	var order []string
	for _, item := range build(t, in).Items {
		order = append(order, item.Feed.ID)
	}
	if !slices.Equal(order, []string{"ipv4:A_v4", "ipv4:B_v4"}) {
		t.Fatalf("walk order %v, want the groups' config order", order)
	}
}

// A missing DNSBL manifest makes a scheduled Update due though no feed is named, and its pass runs whatever the window
// (pfb_core_update_retry_due(): deferring the repair of an outage would extend it).
func TestMissingManifestMakesAScheduledUpdateDue(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	for _, inWindow := range []bool{true, false} {
		in := f.input(Input{Trigger: "scheduled", ManifestMissing: true})
		in.InWindow = inWindow
		if plan := build(t, in); plan.Decision != Now || len(plan.Items) != 0 {
			t.Errorf("in window %v: plan %+v, want the pass now with no feed", inWindow, plan)
		}
	}
	if plan := build(t, f.input(Input{Trigger: "scheduled"})); plan.Decision != Nothing {
		t.Fatalf("before: with the manifest present the plan is %+v, want nothing", plan)
	}
}
