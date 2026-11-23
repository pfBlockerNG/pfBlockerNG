package update

// The end-to-end replay of issue #4038 (sub-slice 9j): every case of testdata/e2e/corpus.json, frozen from today's PHP
// Update on a pfSense box by tests/smoke/test_smoke_update_loop_corpus.py, run step by step through the Core Updater's
// loop as Core starts it (Command.Run with a Loop: the independent worker), against a feed server that answers as the
// smoke harness's mock does, with the settings adapter answering the settings read the box gave before that step. After
// each step the loop's outputs are compared with what today's Update left, through the departures decided on #4038
// (each named where it is applied):
//
//   - the desired sets: every ip-set and ip-aggregate the store holds, by its alias, against the pfB_* mirrors;
//   - the DNSBL data: dnsbl/manifest and its feed bodies against the manifest pfb_py_sources.json and its raw files;
//   - the feed outcomes and the attempted ids: the worker's Result against the result lines today's program wrote;
//   - the issues: the issues of the version 2 request, by table and stage, against the ADR-61 ledgers' open entries;
//   - the stage order: the stages today's transcript shows keep their order among the loop's stage boundaries.
//
// The Loop is given as JSON (e2eLoop): its paths besides today's fields name the folders of a pfSense box under a
// sandbox root, by the keys the README of testdata/e2e lists; the loop takes those it knows.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

const e2eCorpusPath = "testdata/e2e/corpus.json"

// e2eEnv makes this test binary, run with no argument, stand in for the settings adapter and the apply program: a settings
// read ({"op":"read"} on stdin) is answered with the file reply of the folder the variable names; anything else is the
// version 2 apply request, which is appended to the file requests there and answered on fd 3 with one result line that
// applies every resource and removal it names. The worker, the same binary started with arguments, instead records each
// stage boundary it reaches in the file stages there (e2eWorkerStages).
const e2eEnv = "PFB_TEST_E2E_REPLAY"

// e2eWorkerStages installs the worker's boundary recorder. It is a package variable's initializer, not an init function:
// the worker runs from worker.go's init, which comes before any test file's, while every package variable is initialized
// before any init function runs.
var e2eWorkerStages = func() bool {
	dir := os.Getenv(e2eEnv)
	if dir == "" || len(os.Args) == 1 {
		return false
	}
	boundary = func(name string) { appendFile(filepath.Join(dir, "stages"), name+"\n") }
	return true
}()

func init() {
	dir := os.Getenv(e2eEnv)
	if dir == "" || len(os.Args) != 1 {
		return
	}
	in, _ := io.ReadAll(io.LimitReader(os.Stdin, apply.MaxRequest+1))
	var op struct{ Op string }
	if json.Unmarshal(in, &op) == nil && op.Op == "read" {
		reply, _ := os.ReadFile(filepath.Join(dir, "reply"))
		os.Stdout.Write(reply)
		os.Exit(0)
	}
	appendFile(filepath.Join(dir, "requests"), strings.TrimSpace(string(in))+"\n")
	var req struct {
		Resources []struct{ ID, Generation string }
		Removed   []string
	}
	if err := json.Unmarshal(in, &req); err != nil {
		os.Exit(2) // refused: nothing ran
	}
	applied := map[string]string{}
	for _, r := range req.Resources {
		applied[r.ID] = r.Generation
	}
	line, _ := json.Marshal(map[string]any{"version": apply.Version, "applied": applied, "removed": req.Removed,
		"changedAliases": []string{}, "ipChanged": false, "dnsblChanged": false, "reloadLaunched": false, "failed": []any{}})
	if fd3 := os.NewFile(3, "result"); fd3 != nil {
		_, _ = fd3.Write(append(line, '\n'))
	}
	os.Exit(0)
}

type e2eBody struct{ Text, Etag string }

type e2eStep struct {
	Request Request
	Serve   map[string]e2eBody
}

// e2eExpect is what today's Update left after a step.
type e2eExpect struct {
	Exit      int
	Outcomes  map[string]string
	Attempted []string
	Sets      map[string][]string
	DNSBL     *struct {
		Config struct {
			TLDWildcardBlacklist []string `json:"tld_wildcard_blacklist"`
			TLDWildcardExclusion []string `json:"tld_wildcard_exclusion"`
			UserWhitelist        []string `json:"user_whitelist"`
			Top1mEnabled         bool     `json:"top1m_enabled"`
			BuiltinLogFlag       string   `json:"builtin_log_flag"`
		}
		Feeds []map[string]any
	}
	Issues []struct{ Facility, Item, Stage, Message string }
	Stages []string
	// Snapshot is the settings read the box gave before the step, the feed server's address written as {{FEEDS}}.
	Snapshot json.RawMessage
}

type e2eCase struct {
	ID       string
	Ordering string
	Serve    map[string]e2eBody
	Steps    []e2eStep
	Expect   []e2eExpect
}

// e2eFeeds answers as the smoke harness's mock feed server (tests/smoke/conftest.py, _MockFeedServer with an ETag per
// served body): a served name gets 200 with its ETag and a fixed Last-Modified, or 304 to a matching If-None-Match; any
// other name is 404.
type e2eFeeds struct {
	mu     sync.Mutex
	bodies map[string]e2eBody
}

func (f *e2eFeeds) set(bodies map[string]e2eBody) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, b := range bodies {
		f.bodies[name] = b
	}
}

func (f *e2eFeeds) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	b, ok := f.bodies[strings.TrimPrefix(r.URL.Path, "/")]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("ETag", b.Etag)
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == b.Etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Last-Modified", "Tue, 14 Nov 2023 22:13:20 GMT")
	_, _ = io.WriteString(w, b.Text)
}

// e2eLoop is the Loop of a sandbox at root: today's fields, and the folders of a pfSense box under root by the keys the
// corpus README lists. A key the Loop does not know is left out.
func e2eLoop(t *testing.T, root, self string) *Loop {
	t.Helper()
	pkg, err := filepath.Abs("../../../src/usr/local/pkg/pfblockerng")
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(root, "var/db/pfblockerng")
	for _, d := range []string{"deny", "permit", "match/generated", "native", "original", "snapshot", "dnsbl", "dnsblorig", "ET"} {
		if err := os.MkdirAll(filepath.Join(db, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"usr/local/share/GeoIP", "var/log/pfblockerng", "core/resources"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths, _ := json.Marshal(map[string]string{
		"settingsCmd":   self,
		"resourceDir":   filepath.Join(root, "core/resources"),
		"mainLog":       filepath.Join(root, "var/log/pfblockerng/pfblockerng.log"),
		"dbDir":         db,
		"geoipShareDir": filepath.Join(root, "usr/local/share/GeoIP"),
		"ccDir":         filepath.Join(root, "usr/local/share/GeoIP/cc"),
		"pkgDir":        pkg,
	})
	var loop Loop
	if err := json.Unmarshal(paths, &loop); err != nil {
		t.Fatal(err)
	}
	return &loop
}

func TestTheLoopReplaysTodaysUpdate(t *testing.T) {
	raw, err := os.ReadFile(e2eCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema int
		Cases  []e2eCase
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Schema != 1 || len(doc.Cases) == 0 {
		t.Fatalf("corpus: err %v, schema %d, %d cases", err, doc.Schema, len(doc.Cases))
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if len(c.Expect) != len(c.Steps) {
				t.Fatalf("the case has %d steps and %d frozen records: freeze it from the smoke run", len(c.Steps), len(c.Expect))
			}
			feeds := &e2eFeeds{bodies: map[string]e2eBody{}}
			feeds.set(c.Serve)
			server := httptest.NewServer(feeds)
			defer server.Close()
			dir, root := t.TempDir(), t.TempDir()
			t.Setenv(e2eEnv, dir)
			loop := e2eLoop(t, root, self)
			store := resources.Open(filepath.Join(root, "core/resources"))
			// One state directory for the case, as on a box: the Core Updater's own state (updater.json) carries over
			log := independentLog(t)
			for i, step := range c.Steps {
				want := c.Expect[i]
				feeds.set(step.Serve)
				// The box's mock network is the SLIRP host alias; here the feed server is on the loopback address.
				reply := strings.ReplaceAll(string(want.Snapshot), "{{FEEDS}}", server.URL)
				reply = strings.ReplaceAll(reply, "192.168.89.0/24", "127.0.0.0/8")
				if err := os.WriteFile(filepath.Join(dir, "reply"), []byte(reply), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, f := range []string{"stages", "requests"} {
					if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				}
				res, err := runCmd(t, &Command{Path: self, Loop: loop}, step.Request, log)
				if exit := e2eExit(t, log, err); exit != want.Exit {
					t.Errorf("step %d: exit status %d (Run = %v), want %d of today's Update\ntranscript:\n%s", i, exit, err, want.Exit, logText(t, log))
				}
				for _, d := range e2eCompare(t, store, dir, res, want) {
					t.Errorf("step %d %s", i, d)
				}
			}
		})
	}
}

// e2eExit is the worker's exit status for the step as today's program would give it: the status it recorded, 1 for a
// failure it recorded without one (the loop's own), and 1 when Run failed before the worker recorded anything.
func e2eExit(t *testing.T, log *os.File, runErr error) int {
	t.Helper()
	state, err := readWorkerState(log.Name() + ".status")
	switch {
	case err != nil:
		return 1
	case state.ExitCode != nil:
		return *state.ExitCode
	case state.Failure != "" || runErr != nil:
		return 1
	}
	return 0
}

// e2eCompare is every difference between what the loop gave after a step and what today's Update left.
func e2eCompare(t *testing.T, store *resources.Store, dir string, res Result, want e2eExpect) []string {
	t.Helper()
	var out []string
	diff := func(what string, got, exp any) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(exp)
		if !bytes.Equal(g, w) {
			out = append(out, fmt.Sprintf("%s:\n have %s\n want %s", what, g, w))
		}
	}
	diff("outcomes", nonNil(res.Outcomes), nonNil(want.Outcomes))
	diff("attempted", sortedSet(res.Attempted), sortedSet(want.Attempted))
	diff("sets", e2eSets(t, store), e2eWantSets(want.Sets))
	gotDNSBL, wantDNSBL := e2eDNSBL(t, store), e2eWantDNSBL(want)
	diff("DNSBL data", gotDNSBL, wantDNSBL)
	diff("issues", e2eIssues(t, dir), e2eWantIssues(want))
	if stages := e2eLines(t, filepath.Join(dir, "stages")); !subsequence(want.Stages, stages) {
		out = append(out, fmt.Sprintf("stage order: today's %q are not in that order among the loop's boundaries %q", want.Stages, stages))
	}
	return out
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func sortedSet(rows []string) []string {
	out := slices.Clone(rows)
	sort.Strings(out)
	out = slices.Compact(out)
	if out == nil {
		return []string{}
	}
	return out
}

func subsequence(want, have []string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && want[i] == h {
			i++
		}
	}
	return i == len(want)
}

func e2eLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// e2eSets is every ip-set and ip-aggregate the store holds and has not marked removed, by its alias, as a sorted set.
func e2eSets(t *testing.T, store *resources.Store) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, prefix := range []string{"ip-set/", "ip-aggregate/"} {
		ids, err := store.IDs(prefix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		for _, id := range ids {
			alias, ok := apply.Alias(id)
			if !ok {
				t.Errorf("the store holds %s, which maps to no alias", id)
				continue
			}
			out[alias] = sortedSet(body(t, store, id))
		}
	}
	return out
}

// e2eWantSets is today's mirrors as Core publishes them. Departures: no placeholder (#4038 owner question 1: an empty set
// has no member), so today's placeholder rows (pfb_ip_placeholder(), 127.1.7.7 and its IPv6 form ::127.1.7.7) are left
// out; one spelling per network and the address guard (apply.Member, #4038 2026-11-21), a row it refuses being left out;
// a set is a sorted set.
func e2eWantSets(mirrors map[string][]string) map[string][]string {
	out := map[string][]string{}
	for alias, rows := range mirrors {
		family := "ipv4"
		if strings.HasSuffix(alias, "_v6") {
			family = "ipv6"
		}
		var members []string
		for _, row := range rows {
			if row == "127.1.7.7" || row == "::127.1.7.7" {
				continue
			}
			if m, err := apply.Member(row, family); err == nil {
				members = append(members, m)
			}
		}
		out[alias] = sortedSet(members)
	}
	return out
}

type e2eFeed struct {
	Feed, Group, LogFlag, Provenance, Mode string
	Rows                                   []string
}

type e2eDNSBLData struct {
	BuiltinLogFlag string
	Top1mEnabled   bool
	Whitelist      []string
	TLDBlacklist   []string
	TLDExclusion   []string
	Feeds          []e2eFeed
}

// e2eDNSBL is dnsbl/manifest and its feed bodies, nil while the store holds no manifest.
func e2eDNSBL(t *testing.T, store *resources.Store) *e2eDNSBLData {
	t.Helper()
	ids, err := store.IDs(dnsbl.ManifestID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if !slices.Contains(ids, dnsbl.ManifestID) {
		return nil
	}
	out := &e2eDNSBLData{Whitelist: []string{}, TLDBlacklist: []string{}, TLDExclusion: []string{}, Feeds: []e2eFeed{}}
	type row struct {
		Kind, Domain, TLD, BuiltinLogFlag, Feed, Group, LogFlag, Provenance, Mode, Resource string
		Top1mEnabled                                                                        bool
		Position                                                                            int
	}
	var feeds []row
	for _, line := range body(t, store, dnsbl.ManifestID) {
		var r row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		switch r.Kind {
		case "config":
			out.BuiltinLogFlag, out.Top1mEnabled = r.BuiltinLogFlag, r.Top1mEnabled
		case "whitelist":
			out.Whitelist = append(out.Whitelist, r.Domain)
		case "tld_blacklist":
			out.TLDBlacklist = append(out.TLDBlacklist, r.TLD)
		case "tld_exclusion":
			out.TLDExclusion = append(out.TLDExclusion, r.Domain)
		case "feed":
			feeds = append(feeds, r)
		}
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].Position < feeds[j].Position })
	for _, r := range feeds {
		out.Feeds = append(out.Feeds, e2eFeed{r.Feed, r.Group, r.LogFlag, r.Provenance, r.Mode, sortedSet(body(t, store, r.Resource))})
	}
	out.Whitelist, out.TLDBlacklist, out.TLDExclusion = sortedSet(out.Whitelist), sortedSet(out.TLDBlacklist), sortedSet(out.TLDExclusion)
	return out
}

// e2eWantDNSBL is today's manifest as Core publishes it. Departure: a feed's rows are a sorted, de-duplicated set (#4036
// owner question 2, 2026-11-23); a feed without today's permit mode is a deny feed.
func e2eWantDNSBL(want e2eExpect) *e2eDNSBLData {
	if want.DNSBL == nil {
		return nil
	}
	c := want.DNSBL.Config
	out := &e2eDNSBLData{BuiltinLogFlag: c.BuiltinLogFlag, Top1mEnabled: c.Top1mEnabled, Whitelist: sortedSet(c.UserWhitelist),
		TLDBlacklist: sortedSet(c.TLDWildcardBlacklist), TLDExclusion: sortedSet(c.TLDWildcardExclusion), Feeds: []e2eFeed{}}
	text := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	for _, f := range want.DNSBL.Feeds {
		mode := text(f, "mode")
		if mode != "permit" {
			mode = "deny"
		}
		var rows []string
		for _, r := range f["rows"].([]any) {
			rows = append(rows, r.(string))
		}
		out.Feeds = append(out.Feeds, e2eFeed{text(f, "feed"), text(f, "group"), text(f, "log_flag"), text(f, "provenance"), mode, sortedSet(rows)})
	}
	return out
}

// e2eIssues is the issues of every version 2 request the loop wrote this step, as "<table>: <stage>": an ip-set's issue
// names its alias, as the ADR-61 ledger names the table.
func e2eIssues(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(readOr(t, filepath.Join(dir, "requests"))), "\n") {
		if line == "" {
			continue
		}
		var req struct{ Issues []apply.Issue }
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			t.Fatalf("the apply request %q: %v", line, err)
		}
		for _, is := range req.Issues {
			item, ok := apply.Alias(is.Resource)
			if !ok {
				item = is.Resource
			}
			out = append(out, item+": "+is.Stage)
		}
	}
	return sortedSet(out)
}

// e2eWantIssues is the ADR-61 ledgers' open entries after today's Update, as "<table>: <stage>"; messages differ by design
// and are not compared.
func e2eWantIssues(want e2eExpect) []string {
	var out []string
	for _, is := range want.Issues {
		out = append(out, is.Item+": "+is.Stage)
	}
	return sortedSet(out)
}

func readOr(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}
