package update

// The Core Updater loop assembled (issue #4038, sub-slice 9i): the stages of spec section 3 run in order behind --update-loop,
// with the Outpost apply played by a stand-in that holds its stdin to the contract fixture of slice 8a.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/schedule"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// applyEnv names the folder of the stand-in apply; this test binary is the stand-in when its only argument is
// "apply-stand-in", and the hook recorder when it is "hook-recorder" (hookEnv names the recorder's folder). Neither name
// starts with PFB_, which the hook runner strips from a hook's environment.
const (
	applyEnv = "LOOPTEST_APPLY"
	hookEnv  = "LOOPTEST_HOOK"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "apply-stand-in" {
		os.Exit(standInApply(os.Getenv(applyEnv)))
	}
	if len(os.Args) == 2 && os.Args[1] == "hook-recorder" {
		os.Exit(recordHook(os.Getenv(hookEnv)))
	}
}

// standInApply is the Outpost apply as the contract describes it: it records its stdin, refuses (exit status 2, no result)
// a request the contract fixture would not accept, exits with the status in the file "exit" without a result when it
// exists, and otherwise writes one result line that applies every resource and removal of the request, or, outside the
// window, one line that applies nothing.
func standInApply(dir string) int {
	in, err := readAllStdin()
	if err != nil {
		return 1
	}
	appendFile(filepath.Join(dir, "runs"), "run\n")
	_ = os.WriteFile(filepath.Join(dir, "request.json"), in, 0o600)
	if reason := contractRefusal(dir, in); reason != "" {
		_ = os.WriteFile(filepath.Join(dir, "refused"), []byte(reason), 0o600)
		return 2
	}
	var req struct {
		Resources []struct {
			ID         string `json:"id"`
			Generation string `json:"generation"`
		} `json:"resources"`
		Removed              []string        `json:"removed"`
		DNSBL                json.RawMessage `json:"dnsbl"`
		PendingOutsideWindow bool            `json:"pendingOutsideWindow"`
	}
	if json.Unmarshal(in, &req) != nil {
		return 1
	}
	line := map[string]any{"version": 2}
	if !req.PendingOutsideWindow {
		applied, aliases := map[string]string{}, []string{}
		for _, r := range req.Resources {
			applied[r.ID] = r.Generation
			if alias, ok := apply.Alias(r.ID); ok {
				aliases = append(aliases, alias)
			}
		}
		line["applied"], line["removed"], line["changedAliases"] = applied, append([]string{}, req.Removed...), aliases
		line["ipChanged"], line["dnsblChanged"] = len(req.Resources) > 0, len(req.DNSBL) > 0 && string(req.DNSBL) != "null"
	}
	b, _ := json.Marshal(line)
	result := os.NewFile(3, "result")
	if _, err := result.Write(append(b, '\n')); err != nil {
		return 1
	}
	// An exit status in the file "exit" ends the apply after its line: the loop must not settle what a deferring or a
	// failing apply reported.
	if b, err := os.ReadFile(filepath.Join(dir, "exit")); err == nil {
		code, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return code
	}
	return 0
}

func readAllStdin() ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(os.Stdin)
	return b.Bytes(), err
}

// contractRefusal holds a request to tests/core/fixtures/apply_contract_v2.json (its path is in the stand-in's folder, file
// "fixture"): within the request bound, version 2, every member at a path and of a JSON type some accepted request of the
// fixture holds, a generation of 1 to 20 digits, and each ip-set and ip-aggregate mapping to an alias. "" accepts it.
func contractRefusal(dir string, in []byte) string {
	path, err := os.ReadFile(filepath.Join(dir, "fixture"))
	if err != nil {
		return "no fixture: " + err.Error()
	}
	raw, err := os.ReadFile(string(path))
	if err != nil {
		return "no fixture: " + err.Error()
	}
	var doc struct {
		Limits   struct{ RequestBytes int }
		Requests []struct {
			Request  json.RawMessage `json:"request"`
			Accepted json.RawMessage `json:"accepted"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "the fixture cannot be read: " + err.Error()
	}
	allowed := map[string]bool{}
	for _, row := range doc.Requests {
		var v any
		if row.Accepted != nil && row.Request != nil && json.Unmarshal(row.Request, &v) == nil {
			shapes("", v, allowed)
		}
	}
	if len(in) > doc.Limits.RequestBytes {
		return "the request is over the bound"
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "not one JSON object: " + err.Error()
	}
	got := map[string]bool{}
	shapes("", v, got)
	for s := range got {
		if !allowed[s] {
			return "a member no accepted request holds: " + s
		}
	}
	var req struct {
		Version   json.Number `json:"version"`
		Resources []struct {
			ID, Generation string
		} `json:"resources"`
		DNSBL *struct{ Generation string } `json:"dnsbl"`
	}
	if err := json.Unmarshal(in, &req); err != nil || req.Version != "2" {
		return "not version 2"
	}
	digits := func(g string) bool { return len(g) >= 1 && len(g) <= 20 && strings.Trim(g, "0123456789") == "" }
	for _, r := range req.Resources {
		if _, ok := apply.Alias(r.ID); !ok && r.ID != "geo-catalog" || !digits(r.Generation) {
			return "a resource the apply cannot load: " + r.ID + " at " + r.Generation
		}
	}
	if req.DNSBL != nil && !digits(req.DNSBL.Generation) {
		return "a dnsbl generation of the wrong shape"
	}
	return ""
}

// shapes adds each member path of v with its JSON type: "resources[].generation:string".
func shapes(path string, v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		into[path+":object"] = true
		for k, item := range x {
			shapes(path+"."+k, item, into)
		}
	case []any:
		into[path+":array"] = true
		for _, item := range x {
			shapes(path+"[]", item, into)
		}
	case string:
		into[path+":string"] = true
	case bool:
		into[path+":bool"] = true
	case nil:
		into[path+":null"] = true
	default: // float64 or json.Number
		into[path+":number"] = true
	}
}

// hookRecord is what the hook recorder saw while a hook ran.
type hookRecord struct {
	Env        map[string]string
	LockHeld   bool // the Update lock could not be taken
	Finished   bool // the worker's status already reports the Update finished
	ApplyRuns  int  // runs of the stand-in apply so far
	PublishedA bool // the IPv4 set was in the store
}

// recordHook writes, to <dir>/<PFB_WHEN>.json, the PFB_* environment the hook got, whether the Update lock (path in the
// file "lock") is held, whether the status (path in "status") reports a finished Update, how often the apply has run
// (the stand-in's runs in the folder named in "apply") and whether the store (in "store") holds ip-set/Abuse/ipv4.
func recordHook(dir string) int {
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(dir, name)); return string(b) }
	rec := hookRecord{Env: map[string]string{}}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "PFB_") {
			rec.Env[k] = v
		}
	}
	if f, err := os.Open(read("lock")); err == nil {
		rec.LockHeld = errors.Is(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB), syscall.EWOULDBLOCK)
		f.Close()
	}
	if b, err := os.ReadFile(read("status")); err == nil {
		var st struct{ FinishedAt *int64 }
		rec.Finished = json.Unmarshal(b, &st) == nil && st.FinishedAt != nil
	}
	runs, _ := os.ReadFile(filepath.Join(read("apply"), "runs"))
	rec.ApplyRuns = strings.Count(string(runs), "run\n")
	_, err := resources.Open(read("store")).Get("ip-set/Abuse/ipv4", nil)
	rec.PublishedA = err == nil
	b, _ := json.Marshal(rec)
	return map[bool]int{true: 0, false: 1}[os.WriteFile(filepath.Join(dir, rec.Env["PFB_WHEN"]+".json"), b, 0o600) == nil]
}

// loopFixture is one box for the loop: Core's private state folder with update.log, the package's folders, local feed
// sources, the resource store, the hooks, the settings adapter and the stand-in apply, every one a temporary folder.
type loopFixture struct {
	root, state, db, geoip, logs, pkg, src, hooks, store, applyDir, hookDir string
	log                                                                     *os.File
	adapter, adapterDir                                                     string
	settings                                                                map[string]map[string]any
	token                                                                   string
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func script(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newLoopFixture(t *testing.T) *loopFixture {
	t.Helper()
	root := t.TempDir()
	fx := &loopFixture{root: root, state: filepath.Join(root, "state"), db: filepath.Join(root, "db"), geoip: filepath.Join(root, "GeoIP"),
		logs: filepath.Join(root, "log"), pkg: filepath.Join(root, "pkg"), src: filepath.Join(root, "src"), hooks: filepath.Join(root, "hooks"),
		store: filepath.Join(root, "store"), applyDir: filepath.Join(root, "apply"), hookDir: filepath.Join(root, "hookrec"), token: "tok-A"}
	mkdirs(t, fx.db, fx.geoip, fx.logs, fx.pkg, fx.src, fx.hooks, fx.applyDir, fx.hookDir)
	if err := os.Mkdir(fx.state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"deny", "permit", "match", "native", "original", "dnsbl"} {
		mkdirs(t, filepath.Join(fx.db, d))
	}
	log, err := os.OpenFile(filepath.Join(fx.state, "update.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	fx.log = log
	touch(t, filepath.Join(fx.pkg, "dnsbl_psl"), testPSL)
	touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.1\n")
	touch(t, filepath.Join(fx.src, "B.txt"), "93.184.217.1\n")
	touch(t, filepath.Join(fx.src, "D.txt"), "ads.example\n151.101.1.7\n")
	fixture, err := filepath.Abs("../../../tests/core/fixtures/apply_contract_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.applyDir, "fixture"), fixture)
	script(t, filepath.Join(fx.applyDir, "apply.sh"), "exec '"+os.Args[0]+"' apply-stand-in")
	for _, when := range []string{"pre", "post"} {
		script(t, filepath.Join(fx.hooks, "hook_"+when+"_rec.sh"), "exec '"+os.Args[0]+"' hook-recorder")
	}
	for name, text := range map[string]string{"lock": fx.log.Name() + ".lock", "status": fx.log.Name() + ".status", "apply": fx.applyDir,
		"store": fx.store} {
		touch(t, filepath.Join(fx.hookDir, name), text)
	}
	t.Setenv(applyEnv, fx.applyDir)
	t.Setenv(hookEnv, fx.hookDir)
	feed := func(header string) map[string]any {
		return map[string]any{"header": header, "state": "enabled", "format": "auto", "url": "file://" + filepath.Join(fx.src, header+".txt")}
	}
	fx.settings = map[string]map[string]any{
		"ingest":       {"dnsblIp": true},
		"dns":          {"pfbDnsEnabled": true},
		"policy/ip":    {"dedup": true},
		"policy/dnsbl": {"enabled": true, "dnsblIpAction": "Deny_Inbound"},
		"feeds/ipv4": {"groups": []any{map[string]any{"name": "Abuse", "action": "Deny_Inbound", "listClass": "deny",
			"updateFrequency": "01hour", "feeds": []any{feed("A"), feed("B")}}}},
		"feeds/dnsbl": {"groups": []any{map[string]any{"name": "Ads", "action": "unbound", "updateFrequency": "01hour",
			"feeds": []any{map[string]any{"header": "D", "state": "enabled", "url": "file://" + filepath.Join(fx.src, "D.txt"), "action": "deny"}}}}},
		"hooks": {"rows": []any{map[string]any{"id": "0", "when": "pre", "script": "hook_pre_rec.sh", "enabled": true},
			map[string]any{"id": "1", "when": "post", "script": "hook_post_rec.sh", "enabled": true}}},
	}
	fx.adapter, fx.adapterDir = settingsAdapter(t, "{}")
	fx.reply(t)
	return fx
}

// reply writes the adapter's answer from fx.settings and fx.token.
func (fx *loopFixture) reply(t *testing.T) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 1, "revision": 3, "settings": fx.settings, "platform": map[string]any{"pendingToken": fx.token}})
	if err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.adapterDir, "reply"), string(b))
}

func (fx *loopFixture) loop() *Loop {
	return &Loop{SettingsCmd: fx.adapter, ResourceDir: fx.store, FeedLocalDirs: []string{fx.src}, HookDir: fx.hooks, DBDir: fx.db,
		GeoIPDir: fx.geoip, LogDir: fx.logs, PkgDir: fx.pkg, ASNTable: filepath.Join(fx.root, "pfblockerng_asn.txt")}
}

func (fx *loopFixture) storeOf() *resources.Store { return resources.Open(fx.store) }

// run runs the loop in this process for req, as the worker does: under the Update lock, its outcomes in a fresh
// update.log.result, which it returns read back.
func (fx *loopFixture) run(t *testing.T, req Request) (Result, error) {
	t.Helper()
	return fx.runLoop(t, fx.loop(), req)
}

func (fx *loopFixture) runLoop(t *testing.T, loop *Loop, req Request) (Result, error) {
	t.Helper()
	lock, err := operationLock(fx.log.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	result, err := replaceRegular(fx.log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	u := &updater{loop: *loop, req: req, stateDir: fx.state, sinks: output.Sinks{Transcript: fx.log}, program: filepath.Join(fx.applyDir, "apply.sh"),
		logPath: fx.log.Name(), lock: lock, result: result, log: fx.log}
	runErr := u.run()
	res, err := readResult(result)
	if err != nil {
		t.Fatalf("the outcome lines cannot be read as version 1: %v", err)
	}
	os.Remove(fx.log.Name() + ".result") // as a settled worker leaves it for the next admission: no result without a status
	return res, runErr
}

func (fx *loopFixture) applyRuns(t *testing.T) int {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(fx.applyDir, "runs"))
	return strings.Count(string(b), "run\n")
}

// request is the last request the stand-in apply read.
func (fx *loopFixture) request(t *testing.T) map[string]any {
	t.Helper()
	if b, err := os.ReadFile(filepath.Join(fx.applyDir, "refused")); err == nil {
		t.Fatalf("the stand-in apply refused the request: %s", b)
	}
	var req map[string]any
	b, err := os.ReadFile(filepath.Join(fx.applyDir, "request.json"))
	if err != nil || json.Unmarshal(b, &req) != nil {
		t.Fatalf("the apply's request = %q, %v", b, err)
	}
	return req
}

func requestIDs(req map[string]any) []string {
	var ids []string
	list, _ := req["resources"].([]any)
	for _, r := range list {
		ids = append(ids, r.(map[string]any)["id"].(string))
	}
	return ids
}

// members is what the store serves of id now.
func storeMembers(t *testing.T, s *resources.Store, id string) []string {
	t.Helper()
	reply, err := s.Get(id, nil)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return generationMembers(t, s, id, reply.Generation)
}

func generationMembers(t *testing.T, s *resources.Store, id string, g uint64) []string {
	t.Helper()
	f, _, err := s.Body(id, g, resources.PartMembers, 0)
	if err != nil {
		t.Fatalf("%s generation %d: %v", id, g, err)
	}
	defer f.Close()
	var b bytes.Buffer
	if _, err := b.ReadFrom(f); err != nil {
		t.Fatal(err)
	}
	return strings.Fields(b.String())
}

func generation(t *testing.T, s *resources.Store, id string) resources.Reply {
	t.Helper()
	reply, err := s.Get(id, nil)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return reply
}

func readHook(t *testing.T, fx *loopFixture, when string) (hookRecord, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fx.hookDir, when+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return hookRecord{}, false
	}
	var rec hookRecord
	if err != nil || json.Unmarshal(b, &rec) != nil {
		t.Fatalf("%s hook record = %q, %v", when, b, err)
	}
	return rec, true
}

func manual() Request { return Request{Trigger: "manual", Scope: "both", Force: "none"} }

// Scenario: one manual Update of the loop, end to end.
//
// GIVEN an IPv4 group with two local feeds, a DNSBL group with one feed holding a domain and an address (DNSBLIP on), a
// selected Blacklist category, a GeoIP catalog, a feed whose source is missing, the MaxMind marker of a download not yet
// consumed, and a pre and a post hook
// WHEN a manual Update runs
// THEN the IPv4 set, DNSBLIP, the DNSBL data with the category and the geo-catalog are published; the apply runs once,
// with a request the contract accepts that lists every IP resource, the geo-catalog, the DNSBL generation and the issue of
// the failed feed, and the Updater's pending token; what it applied becomes the store's baseline; its lines go to their
// own file; the outcome file says GeoIP is ready; the closing report and the marker's consumption follow.
func TestAManualUpdateBuildsPublishesAppliesAndSettles(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["feeds"] = append(
		fx.settings["feeds/ipv4"]["groups"].([]any)[0].(map[string]any)["feeds"].([]any),
		map[string]any{"header": "C", "state": "enabled", "format": "auto", "url": "file://" + filepath.Join(fx.src, "C.txt")})
	fx.settings["schedule"] = map[string]any{"categoryUpdates": true, "categoryProviders": []any{
		map[string]any{"id": "UT1", "title": "UT1", "selected": true, "categories": "ads"}}}
	fx.reply(t)
	mkdirs(t, filepath.Join(fx.db, "UT1"), filepath.Join(fx.geoip, "cc"))
	touch(t, filepath.Join(fx.db, "UT1", "UT1_ads"), "category.example\n")
	touch(t, filepath.Join(fx.db, "UT1", "UT1.update"), "")
	touch(t, filepath.Join(fx.geoip, "cc", ".geo_catalog"), `{"kind":"page","name":"Top"}`+"\n")
	touch(t, filepath.Join(fx.db, "geoip.update"), "")

	res, err := fx.run(t, manual())
	if err != nil {
		t.Fatalf("run = %v, want success", err)
	}
	s := fx.storeOf()
	if got := storeMembers(t, s, "ip-set/Abuse/ipv4"); !slices.Equal(got, []string{"93.184.216.1", "93.184.217.1"}) {
		t.Errorf("ip-set/Abuse/ipv4 = %q, want both feeds' addresses", got)
	}
	if got := storeMembers(t, s, "ip-set/DNSBLIP/ipv4"); !slices.Equal(got, []string{"151.101.1.7"}) {
		t.Errorf("ip-set/DNSBLIP/ipv4 = %q, want the DNSBL feed's address", got)
	}
	for _, id := range []string{dnsbl.FeedPrefix + "D", dnsbl.FeedPrefix + "UT1_ads", dnsbl.ManifestID, "geo-catalog"} {
		generation(t, s, id)
	}
	if fx.applyRuns(t) != 1 {
		t.Fatalf("the apply ran %d times, want once", fx.applyRuns(t))
	}
	req := fx.request(t)
	if req["trigger"] != "manual" || req["scope"] != "both" || req["pendingToken"] != "tok-A" || req["pendingOutsideWindow"] == true {
		t.Errorf("request head = %v %v %v %v, want manual both tok-A in the window", req["trigger"], req["scope"], req["pendingToken"], req["pendingOutsideWindow"])
	}
	ids := requestIDs(req)
	for _, id := range []string{"geo-catalog", "ip-set/Abuse/ipv4", "ip-set/DNSBLIP/ipv4"} {
		if !slices.Contains(ids, id) {
			t.Errorf("the request's resources %q lack %s", ids, id)
		}
	}
	manifest := generation(t, s, dnsbl.ManifestID)
	if d, _ := req["dnsbl"].(map[string]any); d == nil || d["generation"] != strconv.FormatUint(manifest.Generation, 10) {
		t.Errorf("request dnsbl = %v, want the manifest's generation %d", req["dnsbl"], manifest.Generation)
	}
	issues, _ := json.Marshal(req["issues"])
	if !strings.Contains(string(issues), `"resource":"ip-set/Abuse/ipv4","stage":"download"`) {
		t.Errorf("request issues = %s, want one for the feed whose source is missing, naming its group's set", issues)
	}
	for _, id := range ids {
		reply := generation(t, s, id)
		if again, err := s.Get(id, &resources.Cursor{Generation: reply.Generation, Digest: reply.Digest}); err != nil || again.Kind != resources.KindUnchanged {
			t.Errorf("%s at its applied generation: %+v, %v", id, again, err)
		}
	}
	if b, err := os.ReadFile(fx.log.Name() + apply.ResultSuffix); err != nil || !strings.Contains(string(b), `"version":2`) {
		t.Errorf("the apply's own result file = %q, %v; want its version 2 line", b, err)
	}
	// The settled generation is the baseline: once a newer one is published, a cursor at it gets a delta.
	settled := generation(t, s, "ip-set/Abuse/ipv4")
	touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.3\n")
	touch(t, filepath.Join(fx.applyDir, "exit"), "75") // the newer generation is published, not settled
	if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}); !errors.Is(err, ErrDeferred) {
		t.Fatalf("run = %v, want ErrDeferred", err)
	}
	// only a settled baseline gives a delta: without one the store answers the cursor with the full body
	if got, err := s.Get("ip-set/Abuse/ipv4", &resources.Cursor{Generation: settled.Generation, Digest: settled.Digest}); err != nil ||
		got.Generation <= settled.Generation || got.Kind != resources.KindDelta || got.From != settled.Generation {
		t.Errorf("a cursor at the settled generation %d gets %+v, %v; want a delta from it", settled.Generation, got, err)
	}
	if res.GeoIPReady == nil || !*res.GeoIPReady {
		t.Errorf("geoipReady = %v, want true: the loop's conversion ran or was not needed", res.GeoIPReady)
	}
	for _, gone := range []string{filepath.Join(fx.db, "geoip.update"), filepath.Join(fx.db, "UT1", "UT1.update")} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there (%v): consumed once its consumers succeeded", gone, err)
		}
	}
	if text := logText(t, fx.log); !strings.Contains(text, "Database Sanity check") {
		t.Errorf("transcript lacks the closing report:\n%s", text)
	}
	if b, err := os.ReadDir(fx.state); err == nil {
		for _, e := range b {
			if strings.HasPrefix(e.Name(), ".stdin-") {
				t.Errorf("the apply's stdin %s is left in the state folder: it holds the pending token", e.Name())
			}
		}
	}
}

// Scenario: the post contract (spec section 5; issue #4038 verification), with a recording hook, through the worker.
//
// WHEN a manual Update with a pre and a post hook runs in the worker
// THEN pre runs before the apply with the trigger; post runs after the apply returned, while the Update lock is held and
// before the Update is reported finished, with the apply's report, STATUS ok and the changed DNSBL groups.
func TestThePostHookRunsAfterTheApplyUnderTheLockBeforeTheUpdateEnds(t *testing.T) {
	fx := newLoopFixture(t)
	c := &Command{Path: filepath.Join(fx.applyDir, "apply.sh"), Loop: fx.loop()}
	if _, err := c.Run(context.Background(), manual(), fx.log); err != nil {
		t.Fatalf("Run = %v, want success", err)
	}
	pre, ok := readHook(t, fx, "pre")
	if !ok || pre.ApplyRuns != 0 || pre.PublishedA || pre.Env["PFB_TRIGGER"] != "update" {
		t.Errorf("pre = %+v (ran %t), want it before any publication and the apply, trigger update", pre, ok)
	}
	post, ok := readHook(t, fx, "post")
	if !ok {
		t.Fatal("the post hook did not run")
	}
	if post.ApplyRuns != 1 || !post.PublishedA || !post.LockHeld || post.Finished {
		t.Errorf("post saw apply runs %d, published %t, lock held %t, finished %t; want 1, true, true, false",
			post.ApplyRuns, post.PublishedA, post.LockHeld, post.Finished)
	}
	want := map[string]string{"PFB_WHEN": "post", "PFB_TRIGGER": "update", "PFB_IP_CHANGED": "1", "PFB_DNSBL_CHANGED": "1",
		"PFB_STATUS": "ok", "PFB_POST_INSTALL": "0", "PFB_PRE_UNINSTALL": "0", "PFB_PKG_OP": ""}
	for k, v := range want {
		if post.Env[k] != v {
			t.Errorf("post %s = %q, want %q", k, post.Env[k], v)
		}
	}
	if aliases := strings.Fields(post.Env["PFB_CHANGED_IP_ALIASES"]); !slices.Contains(aliases, "pfB_Abuse_v4") {
		t.Errorf("PFB_CHANGED_IP_ALIASES = %q, want the apply's changed aliases", aliases)
	}
	if groups := post.Env["PFB_CHANGED_DNSBL_GROUPS"]; !strings.Contains(groups, "Ads") {
		t.Errorf("PFB_CHANGED_DNSBL_GROUPS = %q, want the group whose feed was parsed", groups)
	}
	state, err := readWorkerState(fx.log.Name() + ".status")
	if err != nil || state.ExitCode == nil || *state.ExitCode != 0 {
		t.Errorf("status = %+v, %v; want exit 0", state, err)
	}
}

// Ordering case: Extras before feeds (spec section 3, stage 5 before 6).
//
// GIVEN a published feed A, and an Extra whose run changes A's source
// WHEN a scheduled Update names the Extra and A
// THEN A's change detection sees the Extra's change and the set holds A's new address; the Extra is a success.
func TestTheExtrasRunBeforeTheFeedsAreChecked(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	prev := extrasRun
	t.Cleanup(func() { extrasRun = prev })
	extrasRun = func(_ *feedfetch.Fetcher, _ context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
		if v.Name == "dcc" {
			touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.9\n")
		}
		return 0, feedfetch.ExtrasResult{OK: true}
	}
	res, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}, Extras: []string{"extra:dcc"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := storeMembers(t, fx.storeOf(), "ip-set/Abuse/ipv4"); !slices.Contains(got, "93.184.216.9") {
		t.Errorf("ip-set/Abuse/ipv4 = %q, want A's address from after the Extra ran", got)
	}
	if res.Outcomes["extra:dcc"] != "success" || res.Outcomes["ipv4:A_v4"] != "success" {
		t.Errorf("outcomes = %v, want extra:dcc and ipv4:A_v4 success", res.Outcomes)
	}
}

// Ordering case: DNSBLIP is built after the DNSBL stage and consumed by the IP stage, in one Update.
func TestDNSBLIPIsBuiltFromTheDNSBLStageAndPublishedByTheIPStageInOneUpdate(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.src, "D.txt"), "ads.example\n151.101.2.4\n")
	if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"dnsbl:D"}}); err != nil {
		t.Fatal(err)
	}
	if got := storeMembers(t, fx.storeOf(), "ip-set/DNSBLIP/ipv4"); !slices.Equal(got, []string{"151.101.2.4"}) {
		t.Errorf("ip-set/DNSBLIP/ipv4 = %q, want the address the DNSBL feed holds now", got)
	}
}

// Ordering case: the work list is decided from the snapshot under the lock, not from the request's plan: a feed the
// request names that left the settings is skipped with no outcome (hostile-input row).
func TestAFeedThatLeftTheSettingsIsSkippedWithNoOutcome(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	res, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:Gone_v4", "ipv4:A_v4"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Outcomes["ipv4:Gone_v4"]; ok || res.Outcomes["ipv4:A_v4"] != "success" {
		t.Errorf("outcomes = %v, want A only", res.Outcomes)
	}
}

// Ordering case: a feed with a fail marker is added though the request does not name it.
func TestAFailedFeedIsAddedThoughNotNamed(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.src, "B.txt"), "93.184.217.9\n")
	touch(t, filepath.Join(fx.db, "original", "B_v4.fail"), "")
	if _, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}); err != nil {
		t.Fatal(err)
	}
	if got := storeMembers(t, fx.storeOf(), "ip-set/Abuse/ipv4"); !slices.Contains(got, "93.184.217.9") {
		t.Errorf("ip-set/Abuse/ipv4 = %q, want B rebuilt for its fail marker", got)
	}
}

// Ordering case: a change marked pending while the loop runs is not the Update's: the apply gets the token of the
// Updater's own snapshot, never a later one (and never the Core API's, which reaches the Updater not at all).
func TestTheApplyGetsTheTokenOfTheUpdatersSnapshot(t *testing.T) {
	fx := newLoopFixture(t)
	prev := boundary
	t.Cleanup(func() { boundary = prev })
	boundary = func(name string) {
		if name == "work-list" {
			fx.token = "tok-B" // the Outpost marks a change after the snapshot
			fx.reply(t)
		}
	}
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if got := fx.request(t)["pendingToken"]; got != "tok-A" {
		t.Errorf("pendingToken = %v, want tok-A of the snapshot", got)
	}
}

// Ordering case: a narrower scope leaves other work pending.
//
// GIVEN the Updater's state with the DNSBL feed D left pending by an earlier Update
// WHEN a manual Update of scope ip runs
// THEN D stays pending, and the request has scope ip and no DNSBL data.
func TestANarrowerScopeLeavesOtherWorkPending(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.state, updaterStateName), `{"pendingFeeds":["dnsbl:D"]}`)
	if _, err := fx.run(t, Request{Trigger: "manual", Scope: "ip", Force: "none"}); err != nil {
		t.Fatal(err)
	}
	if got := readUpdaterState(fx.state).PendingFeeds; !slices.Equal(got, []string{"dnsbl:D"}) {
		t.Errorf("pending = %q, want dnsbl:D still pending", got)
	}
	req := fx.request(t)
	if req["scope"] != "ip" || req["dnsbl"] != nil {
		t.Errorf("request scope %v dnsbl %v, want ip without DNSBL data", req["scope"], req["dnsbl"])
	}
}

// Ordering case: a changed TOP1M rebuilds DNSBL in the same Update.
func TestAChangedTop1MRebuildsTheDNSBLDataInTheSameUpdate(t *testing.T) {
	fx := newLoopFixture(t)
	fx.settings["policy/dnsbl"]["top1m"] = true
	fx.reply(t)
	whitelist := filepath.Join(fx.db, "pfbalexawhitelist.txt")
	touch(t, whitelist, "old.example\n")
	prev := extrasRun
	t.Cleanup(func() { extrasRun = prev })
	code := 0
	extrasRun = func(_ *feedfetch.Fetcher, _ context.Context, v feedfetch.ExtrasVerb) (int, feedfetch.ExtrasResult) {
		if v.Name == "dcc" && code == 2 {
			touch(t, whitelist, "new.example\n")
			return 2, feedfetch.ExtrasResult{OK: true, Top1MChanged: true}
		}
		return 0, feedfetch.ExtrasResult{OK: true}
	}
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	code = 2
	res, err := fx.run(t, Request{Trigger: "scheduled", Extras: []string{"extra:dcc"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(storeMembers(t, fx.storeOf(), dnsbl.Top1mID), " "); !strings.Contains(got, "new.example") {
		t.Errorf("dnsbl/top1m = %q, want the TOP1M list the Extra changed", got)
	}
	if res.Outcomes["extra:dcc"] != "success" {
		t.Errorf("outcomes = %v, want extra:dcc success", res.Outcomes)
	}
}

// outsideWindow is an apply window that does not hold now, three hours wide around it.
func outsideWindow(t *testing.T) string {
	now := time.Now()
	for _, w := range []string{
		fmt.Sprintf("%02d:00-%02d:00", (now.Hour()+2)%24, (now.Hour()+23)%24),
		fmt.Sprintf("%02d:00-%02d:00", (now.Hour()+23)%24, (now.Hour()+2)%24),
	} {
		if !schedule.InApplyWindow(now.Unix(), w, time.Local) {
			return w
		}
	}
	t.Fatal("no window excludes now")
	return ""
}

// Ordering case: outside the apply window.
//
// GIVEN a published feed A whose source then changed, and an apply window that does not hold now
// WHEN a scheduled Update names A
// THEN nothing is built: the apply runs once with pendingOutsideWindow and no resource, the post hook does not run, and A
// is left pending; a later apply Update inside the window builds it.
func TestOutsideTheApplyWindowTheApplyOnlyRecordsThePendingWork(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	before := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4")
	os.Remove(filepath.Join(fx.hookDir, "post.json"))
	touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.5\n")
	fx.settings["ingest"]["applyWindow"] = outsideWindow(t)
	fx.reply(t)
	res, err := fx.run(t, Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})
	if err != nil {
		t.Fatal(err)
	}
	req := fx.request(t)
	if fx.applyRuns(t) != 2 || req["pendingOutsideWindow"] != true || len(requestIDs(req)) != 0 || req["dnsbl"] != nil {
		t.Errorf("apply runs %d, request %v; want a second run with pendingOutsideWindow and nothing to load", fx.applyRuns(t), req)
	}
	if after := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4"); after.Generation != before.Generation {
		t.Errorf("ip-set/Abuse/ipv4 moved from %d to %d outside the window", before.Generation, after.Generation)
	}
	if _, ran := readHook(t, fx, "post"); ran {
		t.Error("the post hook ran outside the window: no pass ran")
	}
	if res.Outcomes["ipv4:A_v4"] != "success" || !slices.Contains(readUpdaterState(fx.state).PendingFeeds, "ipv4:A_v4") {
		t.Errorf("outcomes %v, pending %q; want A checked and left pending", res.Outcomes, readUpdaterState(fx.state).PendingFeeds)
	}

	delete(fx.settings["ingest"], "applyWindow")
	fx.reply(t)
	if _, err := fx.run(t, Request{Trigger: "apply"}); err != nil {
		t.Fatal(err)
	}
	if got := storeMembers(t, fx.storeOf(), "ip-set/Abuse/ipv4"); !slices.Contains(got, "93.184.216.5") {
		t.Errorf("after the apply Update: %q, want A's pending change built", got)
	}
}

// Scenario: B.9 row 14. An apply that exits 75 makes the Update skipped: nothing it reported is settled, and the feed
// outcomes of the Update are not recorded.
func TestAnApplyThatDefersMakesTheUpdateSkipped(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(fx.applyDir, "exit"), "75")
	touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.6\n")
	c := &Command{Path: filepath.Join(fx.applyDir, "apply.sh"), Loop: fx.loop()}
	res, err := c.Run(context.Background(), Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}, fx.log)
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("Run = %v, want ErrDeferred (skipped)", err)
	}
	if len(res.Outcomes) != 0 {
		t.Errorf("outcomes = %v, want none recorded", res.Outcomes)
	}
	s := fx.storeOf()
	g := generation(t, s, "ip-set/Abuse/ipv4")
	if _, _, err := s.Body("ip-set/Abuse/ipv4", g.Generation-1, resources.PartMembers, 0); err != nil {
		t.Fatalf("the generation applied before is gone: %v", err)
	}
	// Nothing the deferred apply saw is a baseline: the next publication drops it.
	touch(t, filepath.Join(fx.src, "A.txt"), "93.184.216.7\n")
	if _, err := c.Run(context.Background(), Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}, fx.log); !errors.Is(err, ErrDeferred) {
		t.Fatal(err)
	}
	if _, _, err := s.Body("ip-set/Abuse/ipv4", g.Generation, resources.PartMembers, 0); !errors.Is(err, resources.ErrNotFound) {
		t.Errorf("generation %d of a deferred apply was settled as applied (%v)", g.Generation, err)
	}
}

// Scenario: an apply that refuses its request (exit status 2) fails the Update and settles nothing.
func TestAnApplyThatRefusesFailsTheUpdate(t *testing.T) {
	fx := newLoopFixture(t)
	touch(t, filepath.Join(fx.applyDir, "exit"), "2")
	seen := recordBoundaries(t)
	_, err := fx.run(t, manual())
	if err == nil || !strings.Contains(err.Error(), "the apply refused the request (exit status 2)") {
		t.Fatalf("run = %v, want the apply's refusal", err)
	}
	if _, ran := readHook(t, fx, "post"); ran {
		t.Error("the post hook ran after a refused apply")
	}
	if slices.Contains(*seen, "settle") {
		t.Errorf("boundaries %q: the settle ran after a refused apply", *seen)
	}
}

// Scenario: an unset resource folder fails the Update before any stage publishes or touches a feed folder.
func TestALoopWithoutAResourceFolderFailsBeforeAnyStageRuns(t *testing.T) {
	fx := newLoopFixture(t)
	loop := fx.loop()
	loop.ResourceDir = ""
	seen := recordBoundaries(t)
	_, err := fx.runLoop(t, loop, manual())
	if err == nil || !strings.Contains(err.Error(), "resource") {
		t.Fatalf("run = %v, want a failure naming the resource folder", err)
	}
	if !slices.Equal(*seen, []string{"snapshot", "work-list"}) {
		t.Errorf("boundaries = %q, want the Update to stop in the work list", *seen)
	}
	if entries, _ := os.ReadDir(filepath.Join(fx.db, "original")); len(entries) != 0 || fx.applyRuns(t) != 0 {
		t.Errorf("feed folder %v, apply runs %d: want nothing touched", entries, fx.applyRuns(t))
	}
}

// writeApplied records the report pfB-DNS made of ids at what the store holds now, as ReportApplied writes it.
func writeApplied(t *testing.T, fx *loopFixture, ids ...string) {
	t.Helper()
	rows := map[string]any{}
	for _, id := range ids {
		r := generation(t, fx.storeOf(), id)
		rows[id] = map[string]string{"generation": strconv.FormatUint(r.Generation, 10), "digest": r.Digest}
	}
	b, _ := json.Marshal(map[string]any{"format": 1, "resources": rows})
	touch(t, filepath.Join(fx.state, "applied.json"), string(b))
}

// Scenario: issue #4038, from CodeRabbit's review of #4221: the applied report is folded before each dnsbl/* publication,
// so a publication that fails after one feed body is written leaves the bodies pfB-DNS applied readable.
func TestTheAppliedDNSBLBodiesStayReadableWhenAPublicationFailsMidway(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	id := dnsbl.FeedPrefix + "D"
	applied := generation(t, fx.storeOf(), id)
	writeApplied(t, fx, id)
	prev := publishDNSBL
	t.Cleanup(func() { publishDNSBL = prev })
	publishDNSBL = func(s *resources.Store, set dnsbl.Set) (dnsbl.Result, error) {
		if _, err := s.Publish(id, []string{"a body written before the failure"}, nil); err != nil {
			return dnsbl.Result{}, err
		}
		return dnsbl.Result{}, errors.New("the publication stopped after one body")
	}
	if _, err := fx.run(t, manual()); err == nil || !strings.Contains(err.Error(), "the publication stopped after one body") {
		t.Fatalf("run = %v, want the injected publication failure", err)
	}
	if now := generation(t, fx.storeOf(), id); now.Generation <= applied.Generation {
		t.Fatalf("%s at %d, want a body published after the applied %d", id, now.Generation, applied.Generation)
	}
	if got := generationMembers(t, fx.storeOf(), id, applied.Generation); len(got) == 0 {
		t.Errorf("the applied generation %d serves nothing", applied.Generation)
	}
}

// Scenario: plan section C row 10, the stale report. While DNSBL is off, the settle folds an empty report: the removed
// dnsbl/* bodies a report that no longer comes would pin are deleted.
func TestWhileDNSBLIsOffTheRemovedDNSBLBodiesAreDeleted(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	held, err := fx.storeOf().IDs("dnsbl/")
	if err != nil || len(held) == 0 {
		t.Fatalf("dnsbl ids = %q, %v", held, err)
	}
	writeApplied(t, fx, held...)
	fx.settings["policy/dnsbl"]["enabled"] = false
	fx.reply(t)
	var marked []string
	prev := boundary
	t.Cleanup(func() { boundary = prev })
	boundary = func(name string) {
		if name == "settle" {
			marked, _ = fx.storeOf().RemovedIDs("dnsbl/")
		}
	}
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(marked, held) {
		t.Errorf("removed before the settle = %q, want every dnsbl id %q marked removed", marked, held)
	}
	removed, err := fx.storeOf().RemovedIDs("dnsbl/")
	if err != nil || len(removed) != 0 {
		t.Errorf("removed dnsbl ids = %q, %v; want every one deleted", removed, err)
	}
	entries, _ := os.ReadDir(fx.store)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dnsbl~") {
			t.Errorf("the store still holds %s", e.Name())
		}
	}
}

// Scenario: an unreadable ipsets.state (plan, item 9h) is a lost state: the next Update rebuilds every set from its lists
// and publishes the same bodies, so nothing moves.
func TestAnUnreadableIPSetsStateRebuildsTheSameSets(t *testing.T) {
	fx := newLoopFixture(t)
	if _, err := fx.run(t, manual()); err != nil {
		t.Fatal(err)
	}
	before := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4")
	touch(t, filepath.Join(fx.state, ipStateName), "{not json")
	if _, err := fx.run(t, Request{Trigger: "apply"}); err != nil {
		t.Fatalf("run = %v, want success", err)
	}
	if after := generation(t, fx.storeOf(), "ip-set/Abuse/ipv4"); after.Generation != before.Generation || after.Digest != before.Digest {
		t.Errorf("ip-set/Abuse/ipv4 moved from %+v to %+v", before, after)
	}
	var st ipState
	b, err := os.ReadFile(filepath.Join(fx.state, ipStateName))
	if err != nil || json.Unmarshal(b, &st) != nil {
		t.Fatalf("%s = %q, %v; want it replaced with a valid state", ipStateName, b, err)
	}
	if st.Deny["A_v4"] != "93.184.216.1\n" || st.Deny["B_v4"] != "93.184.217.1\n" {
		t.Errorf("%s holds deny %q, want the Abuse feeds' results A_v4 and B_v4", ipStateName, st.Deny)
	}
}
