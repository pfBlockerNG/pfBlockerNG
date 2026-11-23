package update

// The review round of sub-slice 9i (issue #4038) and the owner's decisions of 2026-11-23.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// Owner decision: a narrow scope skips the other side's stages entirely, as today.
//
// GIVEN a published Update, then a DNSBL whitelist edit and an IP group action edit
// WHEN an ip Update runs, then a dnsbl Update
// THEN the ip Update leaves the DNSBL manifest's generation where it was, and the dnsbl Update leaves the IP set where it
// was and lists no ip-set in its request.
func TestANarrowScopeBuildsNothingOfTheOtherSide(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	manifest := generation(t, fx.storeOf(), dnsbl.ManifestID)
	set := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4")
	fx.settings["policy/dnsbl"]["whitelist"] = []any{map[string]any{"domain": "allowed.example"}}
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["action"] = "Deny_Both"
	fx.reply(t)
	if _, err := fx.run(t, Request{Trigger: "manual", Scope: "ip", Force: "none"}); err != nil {
		t.Fatal(err)
	}
	if after := generation(t, fx.storeOf(), dnsbl.ManifestID); after.Generation != manifest.Generation {
		t.Errorf("an ip Update moved dnsbl/manifest from %d to %d", manifest.Generation, after.Generation)
	}
	set = generation(t, fx.storeOf(), "ip-set/Abuse/ipv4") // the ip Update applied the action edit
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["action"] = "Deny_Inbound"
	fx.reply(t)
	if _, err := fx.run(t, Request{Trigger: "manual", Scope: "dnsbl", Force: "none"}); err != nil {
		t.Fatal(err)
	}
	if after := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4"); after.Generation != set.Generation {
		t.Errorf("a dnsbl Update moved ip-set/Abuse/ipv4 from %d to %d", set.Generation, after.Generation)
	}
	if ids := requestIDs(fx.request(t)); len(ids) != 0 {
		t.Errorf("the dnsbl Update's request lists %q, want no ip-set", ids)
	}
}

// Required fix 1: an apply that defers or fails leaves this Update's feeds pending.
func TestAnApplyThatDefersOrFailsLeavesItsFeedsPending(t *testing.T) {
	for _, code := range []string{"75", "1"} {
		t.Run("exit "+code, func(t *testing.T) {
			fx := newLoopFixture(t)
			if _, err := fx.run(t, manual()); err != nil {
				t.Fatal(err)
			}
			touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.8\n")
			touch(t, filepath.Join(fx.applyDir, "exit"), code)
			if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}); err == nil {
				t.Fatal("run = nil, want the apply's deferral or failure")
			}
			if got := readUpdaterState(fx.state).PendingFeeds; !slices.Contains(got, "ipv4:A_v4") {
				t.Errorf("pending = %q, want ipv4:A_v4 left for the next Update", got)
			}
		})
	}
}

// Required fix 1: the apply runs while the store holds generations no apply took, whatever the work list found.
//
// GIVEN an action edit an apply Update published and whose apply deferred
// WHEN a scheduled Update with nothing due runs
// THEN the apply runs and is given the published generation.
func TestTheApplyRunsWhileTheStoreHoldsGenerationsNotApplied(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["action"] = "Deny_Both"
	fx.reply(t)
	touch(t, filepath.Join(fx.applyDir, "exit"), "75")
	if _, err := fx.run(t, Request{Trigger: "apply"}); !errors.Is(err, ErrDeferred) {
		t.Fatalf("run = %v, want ErrDeferred", err)
	}
	os.Remove(filepath.Join(fx.applyDir, "exit"))
	published := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4")
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatal(err)
	}
	if fx.applyRuns(t) != runs+1 {
		t.Fatalf("apply runs %d, want one more: the store holds a generation no apply took", fx.applyRuns(t))
	}
	for _, r := range fx.request(t)["resources"].([]any) {
		if r := r.(map[string]any); r["id"] == "ip-set/Abuse/ipv4" && r["generation"] != "2" {
			t.Errorf("request gives %v, want the published generation %d", r, published.Generation)
		}
	}
	if !slices.Contains(requestIDs(fx.request(t)), "ip-set/Abuse/ipv4") {
		t.Errorf("request = %v, want ip-set/Abuse/ipv4", fx.request(t))
	}
}

// Required fix 3: the Blacklist and MaxMind markers are consumed only once the settle succeeded, and the MaxMind marker
// only when the geoip-format feeds were in scope.
func TestTheMarkersStayUntilTheSettleSucceeds(t *testing.T) {
	setup := func(t *testing.T) *loopFixture {
		fx := newLoopFixture(t)
		fx.settings["schedule"] = map[string]any{"categoryUpdates": true, "categoryProviders": []any{
			map[string]any{"id": "UT1", "title": "UT1", "selected": true, "categories": "ads"}}}
		fx.reply(t)
		mkdirs(t, filepath.Join(fx.db, "UT1"))
		touch(t, filepath.Join(fx.db, "UT1", "UT1_ads"), "category.example\n")
		touch(t, filepath.Join(fx.db, "UT1", "UT1.update"), "")
		touch(t, filepath.Join(fx.db, "geoip.update"), "")
		return fx
	}
	t.Run("a failed apply", func(t *testing.T) {
		fx := setup(t)
		touch(t, filepath.Join(fx.applyDir, "exit"), "1")
		if _, err := fx.run(t, manual()); err == nil {
			t.Fatal("run = nil, want the apply's failure")
		}
		for _, m := range []string{filepath.Join(fx.db, "geoip.update"), filepath.Join(fx.db, "UT1", "UT1.update")} {
			if _, err := os.Stat(m); err != nil {
				t.Errorf("%s was consumed although the apply failed: %v", m, err)
			}
		}
	})
	t.Run("a dnsbl scope", func(t *testing.T) {
		fx := setup(t)
		if _, err := fx.run(t, Request{Trigger: "manual", Scope: "dnsbl", Force: "none"}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(fx.db, "geoip.update")); err != nil {
			t.Errorf("geoip.update was consumed by an Update that ran no geoip-format feed: %v", err)
		}
	})
}

// Required fix 4: a stopped category keeps its provider's marker.
func TestAStoppedCategoryKeepsItsProvidersMarker(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["schedule"] = map[string]any{"categoryUpdates": true, "categoryProviders": []any{
		map[string]any{"id": "UT1", "title": "U T", "selected": true, "categories": "ads"}}}
	fx.reply(t)
	mkdirs(t, filepath.Join(fx.db, "UT1"))
	touch(t, filepath.Join(fx.db, "UT1", "UT1_ads"), "category.example\n")
	touch(t, filepath.Join(fx.db, "UT1", "UT1.update"), "")
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(fx.db, "UT1", "UT1.update")); err != nil {
		t.Errorf("the marker of a provider whose category was stopped was consumed: %v", err)
	}
}

// Required fix 6: a country database that exists but cannot be opened is an issue, not a silent lookup-less build.
func TestACountryDatabaseThatCannotBeOpenedRaisesAnIssue(t *testing.T) {
	fx := newLoopFixture(t)
	touch(t, filepath.Join(fx.geoip, "GeoLite2-Country.mmdb"), "not a MaxMind database")
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if issues := jsonText(t, fx.request(t)["issues"]); !strings.Contains(issues, "country_lookup_failed") {
		t.Errorf("issues = %s, want country_lookup_failed", issues)
	}
}

// Required fix 7: the pre hook fires only when a pass runs, and an apply Update's hooks see the trigger update.
func TestThePreHookFiresOnlyWhenAPassRuns(t *testing.T) {
	t.Run("nothing due", func(t *testing.T) {
		fx := newLoopFixture(t)
		if _, err := fx.run(t, manual()); err != nil {
			t.Fatal(err)
		}
		os.Remove(filepath.Join(fx.hookDir, "pre.json"))
		if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
			t.Fatal(err)
		}
		if _, ran := readHook(t, fx, "pre"); ran {
			t.Error("the pre hook fired on an Update with nothing due")
		}
	})
	t.Run("outside the window", func(t *testing.T) {
		fx := newLoopFixture(t)
		fx.settings["ingest"]["applyWindow"] = outsideWindow(t)
		fx.reply(t)
		if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}); err != nil {
			t.Fatal(err)
		}
		if _, ran := readHook(t, fx, "pre"); ran {
			t.Error("the pre hook fired on an Update deferred outside the apply window")
		}
	})
	t.Run("apply trigger", func(t *testing.T) {
		fx := newLoopFixture(t)
		if _, err := fx.run(t, Request{Trigger: "apply"}); err != nil {
			t.Fatal(err)
		}
		for _, when := range []string{"pre", "post"} {
			if rec, ran := readHook(t, fx, when); !ran || rec.Env["PFB_TRIGGER"] != "update" {
				t.Errorf("%s hook ran %t with PFB_TRIGGER %q, want update", when, ran, rec.Env["PFB_TRIGGER"])
			}
		}
	})
}

// Required fix 8: the worker reads applied.json with the Core API's reader: a record with data after it is not taken.
func TestAnAppliedRecordWithTrailingDataIsNotFolded(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	id := dnsbl.FeedPrefix + "D"
	applied := generation(t, fx.storeOf(), id)
	writeApplied(t, fx, id)
	b, _ := os.ReadFile(filepath.Join(fx.state, "applied.json"))
	touch(t, filepath.Join(fx.state, "applied.json"), string(b)+`{"format":1}`)
	touch(t, filepath.Join(fx.src, "D.txt"), "other.example\n")
	if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"dnsbl:D"}}); err != nil {
		t.Fatal(err)
	}
	if now := generation(t, fx.storeOf(), id); now.Generation == applied.Generation {
		t.Fatalf("%s did not move from generation %d: the test needs a new publication", id, now.Generation)
	}
	if _, _, err := fx.storeOf().Body(id, applied.Generation, resources.PartMembers, 0); !errors.Is(err, resources.ErrNotFound) {
		t.Errorf("generation %d was kept as applied from a record the Core API refuses (%v)", applied.Generation, err)
	}
}

// Missing test: the post hook does not run after an apply that failed, and the failure is the Update's.
func TestThePostHookDoesNotRunAfterAFailedApply(t *testing.T) {
	fx := newLoopFixture(t)
	touch(t, filepath.Join(fx.applyDir, "exit"), "1")
	_, err := fx.run(t, manual())
	if err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("run = %v, want the apply's exit status 1", err)
	}
	if _, ran := readHook(t, fx, "post"); ran {
		t.Error("the post hook ran after a failed apply")
	}
}

// Missing test: an apply ended by a signal fails the Update.
func TestAnApplyEndedByASignalFailsTheUpdate(t *testing.T) {
	fx := newLoopFixture(t)
	script(t, filepath.Join(fx.applyDir, "apply.sh"), "kill -KILL $$")
	_, err := fx.run(t, manual())
	if err == nil || !strings.Contains(err.Error(), "signal") {
		t.Fatalf("run = %v, want the apply's signal", err)
	}
	if _, ran := readHook(t, fx, "post"); ran {
		t.Error("the post hook ran after an apply ended by a signal")
	}
}

// Missing test: a removal the apply applied is deleted at the settle.
func TestARemovalTheApplyAppliedIsDeletedAtTheSettle(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	fx.settings["feeds/ipv4"]["groups"] = []any{}
	fx.reply(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if removed, _ := fx.request(t)["removed"].([]any); !slices.Contains(removed, any("ip-set/Abuse/ipv4")) {
		t.Errorf("request removed = %v, want ip-set/Abuse/ipv4", removed)
	}
	if removed, err := fx.storeOf().RemovedIDs("ip-set/"); err != nil || len(removed) != 0 {
		t.Errorf("removed ip-set ids = %q, %v; want the applied removal deleted", removed, err)
	}
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
