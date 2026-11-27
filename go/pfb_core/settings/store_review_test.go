package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Core's defaults are what today's PHP gives with nothing stored: the parity fixture's defaults case, field for field,
// and the fixture names every dns field the schema has.
func TestCoreDefaultsAreTheParityFixturesDefaults(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_dns_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			ID     string                     `json:"id"`
			Native map[string]json.RawMessage `json:"native"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(doc.Cases, func(c struct {
		ID     string                     `json:"id"`
		Native map[string]json.RawMessage `json:"native"`
	}) bool {
		return c.ID == "defaults"
	})
	if i < 0 {
		t.Fatal("the fixture has no defaults case")
	}
	want := doc.Cases[i].Native
	st := open(t, t.TempDir())
	if _, err := st.Initialize(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	value := projection(t, get(t, st, "dns"), "dns").Value
	if len(value) != len(want) {
		t.Errorf("the schema has %d dns fields, the fixture's defaults case %d: every field needs its PHP default", len(value), len(want))
	}
	for field, w := range want {
		if have := jsonOf(t, value[field]); have != string(w) {
			t.Errorf("default %s = %s, PHP gives %s", field, have, w)
		}
	}
}

func TestConcurrentSavesAtOneRevisionAcceptExactlyOne(t *testing.T) {
	st, _ := initialized(t)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			_, err := st.Save(t.Context(), 1, changes(t, `{"dns": {"decisionCacheMax": `+jsonOf(t, i+1)+`}}`))
			results <- err
		})
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case !isConflict(err):
			t.Errorf("a concurrent save failed with %v, want success or a conflict", err)
		}
	}
	if snap := get(t, st); accepted != 1 || snap.Revision != 2 {
		t.Errorf("%d of %d saves at revision 1 accepted, store at revision %d; want exactly one, revision 2", accepted, n, snap.Revision)
	}
}

func writeStore(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenRefusesAStoreWithDataAfterItsDocument(t *testing.T) {
	_, dir := initialized(t)
	raw, err := os.ReadFile(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(writeStore(t, string(raw)+"garbage"), testSchema()); err == nil {
		t.Error("Open took a store with data after its JSON document")
	}
}

func TestOpenRefusesAStoreHoldingAProjectionThisCoreDoesNotKnow(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":4,"projections":{"dns":{"generation":2,"values":{}},
		"feedauth":{"generation":1,"values":{}},"retired":{"generation":1,"values":{}}}}`)
	if _, err := Open(dir, testSchema()); err == nil || !strings.Contains(err.Error(), "projection") {
		t.Errorf("Open = %v, want a refusal naming the unknown projection", err)
	}
}

// A Core whose schema grew reads the store an older Core wrote: a field or projection it does not hold is its default and
// the revision is unchanged. The generation that older store carries is ignored: a generation comes from the values.
func TestOpenFillsWhatAnOlderStoreDoesNotHoldWithDefaults(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":4,"projections":{"dns":{"generation":3,"values":{"control":true}}}}`)
	st, err := Open(dir, testSchema())
	if err != nil {
		t.Fatalf("Open of an older store: %v", err)
	}
	snap := get(t, st)
	dns, auth := projection(t, snap, "dns"), projection(t, snap, "feedauth")
	fresh := open(t, t.TempDir())
	if _, err := fresh.Initialize(t.Context(), changes(t, `{"dns": {"control": true}}`)); err != nil {
		t.Fatal(err)
	}
	want := get(t, fresh)
	if snap.Revision != 4 || dns.Value["control"] != true || dns.Value["replyLogging"] != true || auth.Value["user"] != "" ||
		dns.Generation != projection(t, want, "dns").Generation || auth.Generation != projection(t, want, "feedauth").Generation {
		t.Errorf("older store read as %s, want revision 4, control on and defaults, and the generations of equal values %s",
			jsonOf(t, snap), jsonOf(t, want))
	}
	if _, err := st.Save(t.Context(), 4, changes(t, `{"feedauth": {"user": "u"}}`)); err != nil {
		t.Errorf("the grown store takes a save: %v", err)
	}
}

func TestAOneSidedBoundIsCheckedWithoutPanicking(t *testing.T) {
	floor := Field{Name: "n", Type: TypeInt, Default: int64(0), Min: new(int64(0))}
	ceiling := Field{Name: "n", Type: TypeInt, Default: int64(0), Max: new(int64(9))}
	if _, err := decode(floor, json.RawMessage(`-1`)); err == nil || !strings.Contains(err.Error(), "0") {
		t.Errorf("below a lone minimum = %v, want an error naming 0", err)
	}
	if _, err := decode(ceiling, json.RawMessage(`10`)); err == nil || !strings.Contains(err.Error(), "9") {
		t.Errorf("above a lone maximum = %v, want an error naming 9", err)
	}
}

// Once the new store is renamed into place it is the store: a failed directory sync after it still fails the call, but
// the next read serves what is on disk, never the revision before it.
func TestAFailedDirectorySyncAfterTheRenameServesWhatIsOnDisk(t *testing.T) {
	st, dir := initialized(t)
	syncDir = func(*os.File) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDir = (*os.File).Sync })
	if _, err := st.Save(t.Context(), 1, changes(t, `{"dns": {"control": true}}`)); err == nil {
		t.Error("Save hid the failed directory sync")
	}
	mem := get(t, st)
	disk := get(t, open(t, dir))
	if jsonOf(t, mem) != jsonOf(t, disk) || mem.Revision != 2 {
		t.Errorf("memory %s, disk %s: want both at revision 2", jsonOf(t, mem), jsonOf(t, disk))
	}
}

// A standalone Core whose settings.json still holds a field the schema has dropped (logViaWebserver with #4054,
// hstsNullBlocking with #4056) starts without it and keeps the rest; its next save no longer stores it. The API still
// refuses the name (#4055).
func TestOpenDropsARetiredFieldAndKeepsTheRest(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":3,"projections":{"dns":{"values":`+
		`{"hstsNullBlocking":true,"logViaWebserver":false,"replyLogging":false}}}}`)
	st, err := Open(dir, Production())
	if err != nil {
		t.Fatalf("Open of a store holding retired fields: %v", err)
	}
	dns := projection(t, get(t, st), "dns")
	_, hsts := dns.Value["hstsNullBlocking"]
	_, webserver := dns.Value["logViaWebserver"]
	if hsts || webserver || dns.Value["replyLogging"] != false {
		t.Errorf("dns read as %s, want no retired field and replyLogging still off", jsonOf(t, dns))
	}
	if _, err := st.Save(t.Context(), 3, changes(t, `{"dns": {"tldWildcard": true}}`)); err != nil {
		t.Fatalf("save after the load: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hstsNullBlocking") || strings.Contains(string(raw), "logViaWebserver") {
		t.Errorf("the saved store still holds a retired field: %s", raw)
	}
	var invalid *ValidationError
	if _, err := st.Save(t.Context(), 4, changes(t, `{"dns": {"hstsNullBlocking": false}}`)); !errors.As(err, &invalid) {
		t.Errorf("a save naming a retired field = %v, want a validation error", err)
	}
}

// A store initialized before #4054 also holds the read-only ingest projection's sinkholeV4 and sinkholeV6, which #4054
// dropped with the VIP response: it loads too (#4055).
func TestOpenDropsTheRetiredSinkholeAddresses(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":2,"projections":{"ingest":{"values":{"sinkholeV4":"","sinkholeV6":""}}}}`)
	st, err := Open(dir, Production())
	if err != nil {
		t.Fatalf("Open of a store holding the retired sinkhole addresses: %v", err)
	}
	ingest := projection(t, get(t, st), "ingest")
	_, v4 := ingest.Value["sinkholeV4"]
	_, v6 := ingest.Value["sinkholeV6"]
	if v4 || v6 {
		t.Errorf("ingest read as %s, want no sinkhole address", jsonOf(t, ingest))
	}
}

// A standalone store that saved the DNSBL mechanism "enabled" (the VIP response #4054 removed) loads it as Null Blocking
// (logging), "disabled_log", in a group too, as config.xml's migration and PfbConfig's read adapters take it; the API
// still refuses "enabled" (#4060).
func TestOpenReadsTheRemovedVipMechanismAsNullBlockingWithLogging(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":5,"projections":{"policy/dnsbl":{"values":{"logging":"enabled",`+
		`"blacklistLogging":"nxdomain","groups":[{"name":"Ads","logging":"enabled"},{"name":"Mal","logging":"nodata"}]}}}}`)
	st, err := Open(dir, Production())
	if err != nil {
		t.Fatalf("Open of a store holding the VIP mechanism: %v", err)
	}
	policy := projection(t, get(t, st), "policy/dnsbl")
	want := `{"blacklistLogging":"nxdomain","groups":[{"logging":"disabled_log","name":"Ads","primary":false,"top1mFilter":false},` +
		`{"logging":"nodata","name":"Mal","primary":false,"top1mFilter":false}],"logging":"disabled_log"}`
	got := map[string]any{"logging": policy.Value["logging"], "blacklistLogging": policy.Value["blacklistLogging"],
		"groups": policy.Value["groups"]}
	if jsonOf(t, got) != want {
		t.Errorf("policy/dnsbl read as %s, want %s", jsonOf(t, got), want)
	}
	var invalid *ValidationError
	if _, err := st.Save(t.Context(), 5, changes(t, `{"policy/dnsbl": {"logging": "enabled"}}`)); !errors.As(err, &invalid) {
		t.Errorf("a save of the VIP mechanism = %v, want a validation error", err)
	}
}

// The Blacklist mechanism is upgraded as config.xml's migration upgrades blacklist_logging, and Validate refuses the
// legacy token as Save does: only a load reads it (#4060 review).
func TestTheBlacklistVipMechanismLoadsAndValidateRefusesIt(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":2,"projections":{"policy/dnsbl":{"values":{"blacklistLogging":"enabled"}}}}`)
	st, err := Open(dir, Production())
	if err != nil {
		t.Fatalf("Open of a store holding the Blacklist VIP mechanism: %v", err)
	}
	if got := projection(t, get(t, st), "policy/dnsbl").Value["blacklistLogging"]; got != "disabled_log" {
		t.Errorf("blacklistLogging = %v, want disabled_log", got)
	}
	var invalid *ValidationError
	if err := st.Validate(changes(t, `{"policy/dnsbl": {"blacklistLogging": "enabled"}}`)); !errors.As(err, &invalid) {
		t.Errorf("Validate of the VIP mechanism = %v, want a validation error", err)
	}
}

// A store saved before #4273 holds ingest.dnsblLenient, which dnsblParseMode replaced: Open drops it instead of refusing the
// whole store (Core would not start, and every Update would fail). Ingest is read-only, so the dropped value was a default.
func TestOpenDropsTheRetiredDnsblLenient(t *testing.T) {
	dir := writeStore(t, `{"format":1,"revision":2,"projections":{"ingest":{"values":{"dnsblLenient":true}}}}`)
	st, err := Open(dir, Production())
	if err != nil {
		t.Fatalf("Open of a store holding the retired dnsblLenient: %v", err)
	}
	ingest := projection(t, get(t, st), "ingest")
	if _, ok := ingest.Value["dnsblLenient"]; ok || ingest.Value["dnsblParseMode"] != "ports" {
		t.Errorf("ingest read as %s, want no dnsblLenient and the default dnsblParseMode ports", jsonOf(t, ingest))
	}
}
