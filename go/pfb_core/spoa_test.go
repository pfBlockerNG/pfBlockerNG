package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/spoa"
)

func actionVars(actions []spoa.Action) map[string]spoa.Value {
	out := make(map[string]spoa.Value, len(actions))
	for _, a := range actions {
		out[a.Name] = a.Value
	}
	return out
}

func TestSPOAEngineLoadLookupHotSwapAndAliasOverride(t *testing.T) {
	dbDir := t.TempDir()
	denyDir := filepath.Join(dbDir, "deny")
	if err := os.MkdirAll(denyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denyDir, "FireHOL_L1_v4.txt"), []byte("# comment\n198.51.100.0/24\n203.0.113.42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denyDir, "Spamhaus_v6.txt"), []byte("2001:db8:bad::/48\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := newSPOAEngine("127.0.0.1:10090", dbDir, nil, "", nil)
	snap := eng.Reload()
	if snap.generation != 1 || snap.entriesV4 != 2 || snap.entriesV6 != 1 {
		t.Fatalf("initial Reload = gen %d v4=%d v6=%d, want gen 1 v4=2 v6=1", snap.generation, snap.entriesV4, snap.entriesV6)
	}

	// 1. Global lookup hits IPv4 CIDR with alias/feed/action attribution.
	acts, blocked, err := eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("198.51.100.77"))}},
	}})
	if err != nil || !blocked {
		t.Fatalf("Handle v4 = (blocked=%v, err=%v), want blocked=true", blocked, err)
	}
	v := actionVars(acts)
	if !v["blocked"].Bool || v["alias"].String != "pfB_FireHOL_L1_v4" || v["feed"].String != "FireHOL_L1_v4" || v["action"].String != "deny" {
		t.Fatalf("unexpected v4 vars: %+v", v)
	}

	// 2. Global lookup hits IPv6 prefix.
	acts, blocked, _ = eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("2001:db8:bad::99"))}},
	}})
	if !blocked || actionVars(acts)["alias"].String != "pfB_Spamhaus_v6" {
		t.Fatalf("Handle v6 = (blocked=%v, acts=%+v)", blocked, acts)
	}

	// 3. Per-message alias override narrows lookup to only that alias.
	acts, blocked, _ = eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{
			{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("198.51.100.77"))},
			{Key: "alias", Value: spoa.StringValue("pfB_Spamhaus_v6")},
		},
	}})
	if blocked || actionVars(acts)["blocked"].Bool {
		t.Fatalf("alias override should not match FireHOL IP: blocked=%v acts=%+v", blocked, acts)
	}

	// 4. Clean IP returns blocked=false.
	acts, blocked, _ = eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("192.0.2.1"))}},
	}})
	if blocked || actionVars(acts)["blocked"].Bool {
		t.Fatalf("clean IP matched: blocked=%v acts=%+v", blocked, acts)
	}

	// 5. Hot-swap: update file on disk and call ReloadSPOA API method; new IP immediately blocked, old IP cleared.
	if err := os.WriteFile(filepath.Join(denyDir, "FireHOL_L1_v4.txt"), []byte("192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	methods := spoaMethods(eng)
	res, err := methods["ReloadSPOA"].call(context.Background(), []byte(`{"requestId":"req-1"}`))
	if err != nil {
		t.Fatalf("ReloadSPOA: %v", err)
	}
	st := res.(spoaStatusResp)
	if !st.Enabled || st.Generation != 2 || st.EntriesV4 != 1 {
		t.Fatalf("ReloadSPOA status = %+v", st)
	}
	_, blockedOld, _ := eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("198.51.100.77"))}},
	}})
	_, blockedNew, _ := eng.Handle(context.Background(), []spoa.Message{{
		Name: "pfb-check",
		Args: []spoa.KV{{Key: "src-ip", Value: spoa.IPValue(netip.MustParseAddr("192.0.2.55"))}},
	}})
	if blockedOld || !blockedNew {
		t.Fatalf("after hot-swap: blockedOld=%v (want false), blockedNew=%v (want true)", blockedOld, blockedNew)
	}

	// 6. GetSPOAStatus reports per-alias and per-feed hit counters.
	stRes, err := methods["GetSPOAStatus"].call(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("GetSPOAStatus: %v", err)
	}
	finalSt := stRes.(spoaStatusResp)
	if finalSt.ByAlias["pfB_FireHOL_L1_v4"] != 2 || finalSt.ByFeed["FireHOL_L1_v4"] != 2 {
		t.Fatalf("hit counters = %+v, want 2 for FireHOL_L1_v4", finalSt)
	}
}
