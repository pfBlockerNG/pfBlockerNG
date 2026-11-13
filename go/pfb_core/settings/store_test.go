package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testSchema is the production schema plus a projection holding a secret, which the production schema does not have yet.
func testSchema() Schema {
	s := Production()
	s.Projections = append(s.Projections, Projection{ID: "feedauth", Fields: []Field{
		{Name: "user", Type: TypeString, Default: ""},
		{Name: "password", Type: TypeString, Default: "", Secret: true},
	}})
	return s
}

func open(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := Open(dir, testSchema())
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	return st
}

// changes builds a change set from JSON text, as a client sends it.
func changes(t *testing.T, text string) map[string]map[string]json.RawMessage {
	t.Helper()
	var c map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		t.Fatalf("bad change set %s: %v", text, err)
	}
	return c
}

func initialized(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	st := open(t, dir)
	if _, err := st.Initialize(changes(t, `{"dns": {"decisionCacheMax": 500}}`)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return st, dir
}

func projection(t *testing.T, snap Snapshot, id string) ProjectionValue {
	t.Helper()
	for _, p := range snap.Projections {
		if p.ResourceID == "settings/"+id {
			return p
		}
	}
	t.Fatalf("no settings/%s in %+v", id, snap.Projections)
	return ProjectionValue{}
}

func get(t *testing.T, st *Store, ids ...string) Snapshot {
	t.Helper()
	snap, err := st.Get(ids)
	if err != nil {
		t.Fatalf("Get(%v): %v", ids, err)
	}
	return snap
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheSchemaNamesEveryDnsFieldWithItsTypeAndDefault(t *testing.T) {
	s := Production()
	got := jsonOf(t, s)
	var back Schema
	if err := json.Unmarshal([]byte(got), &back); err != nil {
		t.Fatalf("the schema does not read back: %v", err)
	}
	if again := jsonOf(t, back); again != got {
		t.Errorf("schema round-trip changed it:\n have %s\n want %s", again, got)
	}
	want := map[string]string{
		"replyLogging": "bool true", "hstsNullBlocking": "bool true", "tldWildcard": "bool false",
		"pslIncludePrivate": "bool true", "pslAllowPrivate": "bool false",
		"pslFeedPrivatePolicy": `enum "honor" [ignore apex honor]`, "pslFeedIcannPolicy": `enum "honor" [ignore apex honor]`,
		"idnMode": `enum "off" [off confusable on]`, "idnBlockMalicious": "bool true", "idnEscalateSuspicious": "bool false",
		"decisionCacheMax": "int 10000 0..5000000", "logViaWebserver": "bool false", "cnameValidation": "bool false",
		"control": "bool false", "controlLegacy": "bool false requires control", "regexCap": "bool false",
		"metricsClientIp": "bool false",
	}
	if s.Projections[0].ID != "dns" {
		t.Fatalf("projections = %s, want dns first", got)
	}
	have := map[string]string{}
	for _, f := range s.Projections[0].Fields {
		d := string(f.Type) + " " + jsonOf(t, f.Default)
		if f.Enum != nil {
			d += " " + fmt.Sprint(f.Enum)
		}
		if f.Min != nil || f.Max != nil {
			d += " " + jsonOf(t, f.Min) + ".." + jsonOf(t, f.Max)
		}
		if f.Requires != "" {
			d += " requires " + f.Requires
		}
		if f.Secret {
			d += " secret"
		}
		have[f.Name] = d
	}
	if jsonOf(t, have) != jsonOf(t, want) {
		t.Errorf("dns fields:\n have %s\n want %s", jsonOf(t, have), jsonOf(t, want))
	}
}

func TestAnUninitializedStoreSaysSoAndHoldsNothing(t *testing.T) {
	st := open(t, t.TempDir())
	snap := get(t, st)
	if snap.Initialized || snap.Revision != 0 || len(snap.Projections) != 0 {
		t.Errorf("uninitialized Get = %s, want initialized false, revision 0, no projection", jsonOf(t, snap))
	}
	if _, err := st.Save(0, changes(t, `{"dns": {"control": true}}`)); !isConflict(err) {
		t.Errorf("Save before Initialize = %v, want a conflict", err)
	}
}

func isConflict(err error) bool {
	var c *ConflictError
	return errors.As(err, &c)
}

func validationFields(err error) []string {
	var v *ValidationError
	if !errors.As(err, &v) {
		return nil
	}
	var fields []string
	for _, f := range v.Fields {
		fields = append(fields, f.Field)
	}
	return fields
}

func TestInitializeTakesSettingsOnceAndRefusesASecondTime(t *testing.T) {
	st := open(t, t.TempDir())
	res, err := st.Initialize(changes(t, `{"dns": {"decisionCacheMax": 500, "idnMode": "confusable"}}`))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if res.Revision != 1 {
		t.Errorf("revision after Initialize = %d, want 1", res.Revision)
	}
	dns := projection(t, get(t, st, "dns"), "dns")
	if dns.Value["decisionCacheMax"] != int64(500) || dns.Value["idnMode"] != "confusable" ||
		dns.Value["replyLogging"] != true {
		t.Errorf("dns after Initialize = %s, want the given values and the defaults", jsonOf(t, dns))
	}
	if _, err := st.Initialize(changes(t, `{"dns": {"decisionCacheMax": 7}}`)); !isConflict(err) {
		t.Errorf("second Initialize = %v, want a conflict", err)
	}
	if snap := get(t, st, "dns"); snap.Revision != 1 || projection(t, snap, "dns").Value["decisionCacheMax"] != int64(500) {
		t.Errorf("the refused Initialize changed the store: %s", jsonOf(t, snap))
	}
}

func TestInitializeRefusesInvalidSettingsWhole(t *testing.T) {
	st := open(t, t.TempDir())
	_, err := st.Initialize(changes(t, `{"dns": {"decisionCacheMax": 5000001, "idnMode": "all", "control": true}}`))
	if got := strings.Join(validationFields(err), ","); got != "dns.decisionCacheMax,dns.idnMode" {
		t.Errorf("Initialize field errors = %q (%v), want dns.decisionCacheMax,dns.idnMode", got, err)
	}
	if get(t, st).Initialized {
		t.Error("a refused Initialize initialized the store")
	}
}

func TestSaveWithAStaleRevisionConflictsAndChangesNothing(t *testing.T) {
	st, _ := initialized(t)
	if _, err := st.Save(1, changes(t, `{"dns": {"control": true}}`)); err != nil {
		t.Fatalf("Save at revision 1: %v", err)
	}
	before := jsonOf(t, get(t, st))
	if _, err := st.Save(1, changes(t, `{"dns": {"cnameValidation": true}}`)); !isConflict(err) {
		t.Errorf("Save with stale revision 1 = %v, want a conflict", err)
	}
	if after := jsonOf(t, get(t, st)); after != before {
		t.Errorf("the conflicting Save changed the store:\n before %s\n after  %s", before, after)
	}
}

func TestAnInvalidChangeSetIsRejectedWhole(t *testing.T) {
	st, _ := initialized(t)
	before := jsonOf(t, get(t, st))
	_, err := st.Save(1, changes(t, `{"dns": {"control": true, "decisionCacheMax": -1, "idnMode": 3, "nosuch": 1},
		"nosuchprojection": {"x": 1}}`))
	want := "dns.decisionCacheMax,dns.idnMode,dns.nosuch,nosuchprojection"
	if got := strings.Join(validationFields(err), ","); got != want {
		t.Errorf("field errors = %q (%v), want %q", got, err, want)
	}
	if after := jsonOf(t, get(t, st)); after != before {
		t.Errorf("a rejected change set changed the store (control is part of it):\n before %s\n after  %s", before, after)
	}
}

func TestSaveAdvancesTheRevisionAndOnlyTheChangedProjectionsGeneration(t *testing.T) {
	st, _ := initialized(t)
	before := get(t, st)
	res, err := st.Save(1, changes(t, `{"dns": {"decisionCacheMax": 500}, "feedauth": {"user": "u"}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if res.Revision != 2 {
		t.Errorf("revision = %d, want 2: every accepted save advances it", res.Revision)
	}
	if len(res.Projections) != 1 || res.Projections[0].ResourceID != "settings/feedauth" ||
		res.Projections[0].Generation == projection(t, before, "feedauth").Generation {
		t.Errorf("changed projections = %s, want only settings/feedauth, at another generation than %d", jsonOf(t, res.Projections),
			projection(t, before, "feedauth").Generation)
	}
	if dns := projection(t, get(t, st, "dns"), "dns"); dns.Generation != projection(t, before, "dns").Generation {
		t.Errorf("dns generation = %d after an unchanged value was saved, want the unchanged %d", dns.Generation,
			projection(t, before, "dns").Generation)
	}
}

func TestCoreHoldsLegacyControlOffWhileControlIsOff(t *testing.T) {
	st, _ := initialized(t)
	res, err := st.Save(1, changes(t, `{"dns": {"controlLegacy": true}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(res.Projections) != 0 {
		t.Errorf("changed projections = %s, want none: controlLegacy stays false while control is off", jsonOf(t, res.Projections))
	}
	if res, err = st.Save(2, changes(t, `{"dns": {"control": true, "controlLegacy": true}}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if v := res.Projections[0].Value; v["control"] != true || v["controlLegacy"] != true {
		t.Errorf("dns = %s, want control and controlLegacy on", jsonOf(t, v))
	}
}

func TestNullResetsAFieldToItsDefault(t *testing.T) {
	st, _ := initialized(t)
	res, err := st.Save(1, changes(t, `{"dns": {"decisionCacheMax": null}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if v := res.Projections[0].Value["decisionCacheMax"]; v != int64(10000) {
		t.Errorf("decisionCacheMax after null = %v, want the default 10000", v)
	}
}

func TestASecretNeverAppearsInARead(t *testing.T) {
	st, _ := initialized(t)
	snap := get(t, st, "feedauth")
	if got := jsonOf(t, projection(t, snap, "feedauth").Value["password"]); got != `{"present":false}` {
		t.Errorf("unset password reads %s, want {\"present\":false}", got)
	}
	res, err := st.Save(1, changes(t, `{"feedauth": {"password": "hunter2-secret"}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if strings.Contains(jsonOf(t, res), "hunter2") {
		t.Errorf("the Save result shows the secret: %s", jsonOf(t, res))
	}
	whole := jsonOf(t, get(t, st))
	if strings.Contains(whole, "hunter2") {
		t.Errorf("GetSettings shows the secret: %s", whole)
	}
	if got := jsonOf(t, projection(t, get(t, st, "feedauth"), "feedauth").Value["password"]); got != `{"present":true}` {
		t.Errorf("set password reads %s, want {\"present\":true}", got)
	}
	if strings.Contains(jsonOf(t, Production()), "hunter2") || !secretInSchema(testSchema()) {
		t.Error("the schema marks the secret field (secret: true) and never carries a value")
	}
}

func secretInSchema(s Schema) bool {
	for _, p := range s.Projections {
		for _, f := range p.Fields {
			if f.Secret {
				return true
			}
		}
	}
	return false
}

func TestGetRefusesAnUnknownProjection(t *testing.T) {
	st, _ := initialized(t)
	if _, err := st.Get([]string{"dns", "nosuch"}); strings.Join(validationFields(err), ",") != "projectionIds[1]" {
		t.Errorf("Get unknown = %v, want a field error on projectionIds[1]", err)
	}
}

func TestTheStoreSurvivesARestartWithItsRevisionAndGenerationsIntact(t *testing.T) {
	st, dir := initialized(t)
	if _, err := st.Save(1, changes(t, `{"dns": {"idnMode": "on"}, "feedauth": {"password": "p"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(2, changes(t, `{"dns": {"cnameValidation": true}}`)); err != nil {
		t.Fatal(err)
	}
	before := jsonOf(t, get(t, st))
	again := open(t, dir) // the restart
	if after := jsonOf(t, get(t, again)); after != before {
		t.Errorf("after a restart:\n have %s\n want %s", after, before)
	}
	if snap := get(t, again); snap.Revision != 3 {
		t.Errorf("restarted store = %s, want revision 3", before)
	}
	if _, err := again.Save(3, changes(t, `{"dns": {"regexCap": true}}`)); err != nil {
		t.Errorf("the restarted store takes a save at its revision: %v", err)
	}
}

func TestTheStoreFileIsTheOwnersAlone(t *testing.T) {
	_, dir := initialized(t)
	info, err := os.Stat(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %v, want 0600: it holds secrets", storeFile, info.Mode().Perm())
	}
}

func TestOpenRefusesAStoreItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(`{"format": 1, "revision": `), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testSchema()); err == nil {
		t.Error("Open took a truncated store: Core would start uninitialized over real settings")
	}
}

// crashEnv runs the helper below in a child process: it saves and is killed between writing the new store and renaming it.
const crashEnv = "PFB_CORE_SETTINGS_CRASH_DIR"

func TestCrashHelperProcess(t *testing.T) {
	dir := os.Getenv(crashEnv)
	if dir == "" {
		t.Skip("the child process of TestACrashDuringASaveLeavesThePreviousRevisionReadable")
	}
	st, err := Open(dir, testSchema())
	if err != nil {
		os.Exit(2)
	}
	beforeRename = func() { os.Exit(42) }
	_, _ = st.Save(1, changes(t, `{"dns": {"decisionCacheMax": 777}}`))
	os.Exit(3) // the save returned: the hook never ran
}

func TestACrashDuringASaveLeavesThePreviousRevisionReadable(t *testing.T) {
	_, dir := initialized(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelperProcess$")
	cmd.Env = append(os.Environ(), crashEnv+"="+dir)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("the child = %v, want it killed (exit 42) inside the save", err)
	}
	partial, err := os.ReadFile(filepath.Join(dir, storeFile+".tmp"))
	if err != nil || !strings.Contains(string(partial), "777") {
		t.Fatalf("the interrupted save left no new store beside the old one (%v): the crash was not inside the write", err)
	}
	st := open(t, dir)
	snap := get(t, st)
	if snap.Revision != 1 || projection(t, snap, "dns").Value["decisionCacheMax"] != int64(500) {
		t.Errorf("after the crash = %s, want revision 1 with decisionCacheMax 500", jsonOf(t, snap))
	}
	if _, err := st.Save(1, changes(t, `{"dns": {"decisionCacheMax": 9}}`)); err != nil {
		t.Errorf("the store takes the next save after a crash: %v", err)
	}
}
