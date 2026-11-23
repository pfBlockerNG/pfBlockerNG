package update

// The light review of 7cc5e5137..42b7ad279 (issue #4038, sub-slice 9i).

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Required fix 1: the apply of what the store holds unapplied waits for the apply window, as every apply does.
//
// GIVEN an action edit an apply Update published and whose apply deferred
// WHEN a scheduled Update with nothing due runs outside the apply window
// THEN no apply runs.
func TestTheApplyOfUnappliedGenerationsWaitsForTheWindow(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["action"] = "Deny_Both"
	fx.reply(t)
	touch(t, filepath.Join(fx.applyDir, "exit"), "75")
	if _, err := fx.run(t, Request{Trigger: "apply"}); err == nil {
		t.Fatal("run = nil, want the deferral")
	}
	os.Remove(filepath.Join(fx.applyDir, "exit"))
	fx.settings["ingest"]["applyWindow"] = outsideWindow(t)
	fx.reply(t)
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatal(err)
	}
	if fx.applyRuns(t) != runs {
		t.Errorf("apply runs %d, want %d: outside the window nothing is applied", fx.applyRuns(t), runs)
	}
}

// Required fix 2: an id the apply refuses does not make every later Update run the apply.
//
// GIVEN an apply that runs and refuses ip-set/Abuse/ipv4 (it reports it failed)
// WHEN two scheduled Updates with nothing due run
// THEN neither runs the apply: the generation was requested already, and the refusal is the apply's issue.
func TestAnIDTheApplyRefusedDoesNotRunTheApplyAgain(t *testing.T) {
	fx := newLoopFixture(t)
	script(t, filepath.Join(fx.applyDir, "apply.sh"), `cat > /dev/null; echo run >> '`+fx.applyDir+`/runs'
printf '%s\n' '{"version":2,"failed":[{"id":"ip-set/Abuse/ipv4","stage":"apply","message":"pfctl: table limit"}]}' >&3`)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	runs := fx.applyRuns(t)
	for tick := 1; tick <= 2; tick++ {
		if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
			t.Fatalf("tick %d: %v", tick, err)
		}
	}
	if fx.applyRuns(t) != runs {
		t.Errorf("apply runs %d after two ticks, want %d", fx.applyRuns(t), runs)
	}
}

// Required fix 5: an ip Update publishes no DNSBLIP set whose list the DNSBL build never wrote.
func TestAnIPUpdateBeforeAnyDNSBLBuildPublishesNoDNSBLIP(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, Request{Trigger: "manual", Scope: "ip", Force: "none"}); err != nil {
		t.Fatal(err)
	}
	ids, err := fx.storeOf().IDs("ip-set/")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if strings.HasPrefix(id, "ip-set/DNSBLIP/") {
			t.Errorf("the store holds %s, published from no list", id)
		}
	}
}

// A damaged body of a set the last apply was requested to load does not fail a nothing-due tick: the tick reads
// generations from the store's index alone, and the next publication repairs the body.
func TestADamagedBodyDoesNotFailANothingDueTick(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	g := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4").Generation
	touch(t, filepath.Join(fx.store, "ip-set~Abuse~ipv4."+strconv.FormatUint(g, 10)+".body"), "damaged\n")
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatalf("tick = %v, want success: a damaged body is the next publication's to repair", err)
	}
	if fx.applyRuns(t) != runs {
		t.Errorf("apply runs %d, want %d: the generation was requested already", fx.applyRuns(t), runs)
	}
}
