package update

// CodeRabbit's review of #4224 (issue #4038, sub-slice 9i).

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Major r4671035959: a geoip-format feed reads its country list from the country folder, which the transfer takes as a
// local folder of its own, whatever --feed-local-dir lists.
func TestAGeoIPFormatFeedBuildsFromTheCountryFolder(t *testing.T) {
	fx := newLoopFixture(t)
	mkdirs(t, filepath.Join(fx.geoip, "cc"))
	touch(t, filepath.Join(fx.geoip, "cc", "US_v4.txt"), "93.184.220.0/24\n")
	fx.settings["feeds/ipv4"]["groups"] = append(fx.settings["feeds/ipv4"]["groups"].([]any), map[string]any{"name": "Geo",
		"action": "Deny_Inbound", "listClass": "deny", "updateFrequency": "01hour",
		"feeds": []any{map[string]any{"header": "GeoUS", "state": "enabled", "format": "geoip", "url": "US"}}})
	fx.reply(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if got := storeMembers(t, fx.storeOf(), "ip-set/Geo/ipv4"); !slices.Equal(got, []string{"93.184.220.0/24"}) {
		t.Errorf("ip-set/Geo/ipv4 = %q, want the country list", got)
	}
}

// deferredActionEdit publishes an action edit of ip-set/Abuse/ipv4 through an apply Update whose apply defers, and
// returns the generation it published.
func deferredActionEdit(t *testing.T, fx *loopFixture) uint64 {
	t.Helper()
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	before := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4").Generation
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["action"] = "Deny_Both"
	fx.reply(t)
	touch(t, filepath.Join(fx.applyDir, "exit"), "75")
	if _, err := fx.run(t, Request{Trigger: "apply"}); !errors.Is(err, ErrDeferred) {
		t.Fatalf("run = %v, want ErrDeferred", err)
	}
	os.Remove(filepath.Join(fx.applyDir, "exit"))
	g := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4").Generation
	if g <= before {
		t.Fatalf("the action edit published generation %d, want one after %d", g, before)
	}
	return g
}

// Major r4671035976: the apply request is built from the store's index alone; the apply reads the bodies itself, so a
// damaged body does not keep it from running.
func TestADamagedBodyDoesNotKeepTheApplyFromRunning(t *testing.T) {
	fx := newLoopFixture(t)
	g := deferredActionEdit(t, fx)
	touch(t, filepath.Join(fx.store, "ip-set~Abuse~ipv4."+strconv.FormatUint(g, 10)+".body"), "damaged\n")
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatalf("tick = %v, want success", err)
	}
	if fx.applyRuns(t) != runs+1 {
		t.Fatalf("apply runs %d, want %d", fx.applyRuns(t), runs+1)
	}
	for _, r := range fx.request(t)["resources"].([]any) {
		if r := r.(map[string]any); r["id"] == "ip-set/Abuse/ipv4" && r["generation"] != strconv.FormatUint(g, 10) {
			t.Errorf("request gives %v, want generation %d", r, g)
		}
	}
}

// Major r4671035985: what the apply was requested to load is recorded only once the settle reconciled its result, so a
// settle that fails leaves the generation to the next tick inside the window.
func TestASettleThatFailsLeavesTheGenerationToTheNextTick(t *testing.T) {
	fx := newLoopFixture(t)
	g := deferredActionEdit(t, fx)
	blocker := filepath.Join(fx.store, "index.json.tmp")
	prev := boundary
	t.Cleanup(func() { boundary = prev })
	boundary = func(name string) {
		if name == "settle" { // the store cannot save its index: Applied fails
			mkdirs(t, filepath.Join(blocker, "x"))
		}
	}
	if _, err := fx.run(t, Request{Trigger: "apply"}); err == nil {
		t.Fatal("run = nil, want the settle's failure")
	}
	boundary = prev
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	runs := fx.applyRuns(t)
	if _, err := fx.run(t, Request{Trigger: "scheduled"}); err != nil {
		t.Fatal(err)
	}
	if fx.applyRuns(t) != runs+1 {
		t.Errorf("apply runs %d, want %d: generation %d was never settled", fx.applyRuns(t), runs+1, g)
	}
}

// Minor r4671035914: a DNSBLIP list that cannot be checked for a reason other than its absence is kept, not left out.
func TestStandingDNSBLIPLeavesOutOnlyAnAbsentList(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("DNSBLIP_v4.txt", filepath.Join(dir, "DNSBLIP_v4.txt")); err != nil { // a loop: ELOOP
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "DNSBLIP_v4.txt")); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("before: stat = %v, want ELOOP", err)
	}
	settings := map[string]map[string]any{"policy/dnsbl": {"enabled": true, "dnsblIpAction": "Deny_Inbound"},
		"dns": {"pfbDnsEnabled": true}}
	var families []string
	for _, s := range standingDNSBLIP(settings, dir) {
		families = append(families, s.Family)
	}
	if strings.Join(families, ",") != "ipv4" {
		t.Errorf("families = %q, want ipv4 only (ipv6 has no list)", families)
	}
}
