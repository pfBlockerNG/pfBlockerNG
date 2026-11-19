package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const startupBody = `{"new":[
 {"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"4h","scenario":"s"},
 {"id":2,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.11","duration":"4h","scenario":"manual"},
 {"id":3,"origin":"crowdsec","type":"ban","scope":"Range","value":"203.0.113.0/24","duration":"4h","scenario":"s"},
 {"id":4,"origin":"CAPI","type":"ban","scope":"Ip","value":"2001:db8:dead::1","duration":"4h","scenario":"s"},
 {"id":5,"origin":"crowdsec","type":"ban","scope":"Range","value":"2001:db8:beef::/48","duration":"4h","scenario":"s"}
],"deleted":[]}`

var (
	startupV4 = []string{"198.51.100.10", "198.51.100.11", "203.0.113.0/24"}
	startupV6 = []string{"2001:db8:beef::/48", "2001:db8:dead::1"}
)

const emptyDelta = `{"new":[],"deleted":[]}`

// synced returns a harness whose daemon has set up its tables and applied startupBody.
func synced(t *testing.T, more ...lapiReply) *harness {
	t.Helper()
	h := newHarness(t, append([]lapiReply{ok(startupBody)}, more...)...)
	if err := h.d.setup(context.Background()); err != nil {
		t.Fatalf("setup = %v", err)
	}
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatalf("startup pull = %v", err)
	}
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	h.pf.takeCalls()
	return h
}

func readStatus(t *testing.T, h *harness) map[string]any {
	t.Helper()
	data, err := os.ReadFile(h.cfg.StatusFile)
	if err != nil {
		t.Fatalf("status file: %v", err)
	}
	var st map[string]any
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("status file is not JSON: %v (%s)", err, data)
	}
	return st
}

// nextEvent returns the run loop's next event, failing at once if run returns first instead of waiting forever.
func nextEvent(t *testing.T, events <-chan string, result <-chan error) string {
	t.Helper()
	select {
	case e := <-events:
		return e
	case err := <-result:
		t.Fatalf("run returned %v before the expected event", err)
		return ""
	}
}

// Start-up creates both tables when missing and empties them when present.
func TestSetupCreatesAndFlushesBothTables(t *testing.T) {
	h := newHarness(t)
	h.pf.setTable("crowdsec_v4", "192.0.2.99")
	if err := h.d.setup(context.Background()); err != nil {
		t.Fatalf("setup = %v", err)
	}
	assertTable(t, h.pf, "crowdsec_v4")
	assertTable(t, h.pf, "crowdsec_v6")
	want := []string{
		"-t crowdsec_v4 -T add -f /dev/null", "-t crowdsec_v4 -T flush",
		"-t crowdsec_v6 -T add -f /dev/null", "-t crowdsec_v6 -T flush",
	}
	if got := callStrings(h.pf.takeCalls()); !slices.Equal(got, want) {
		t.Fatalf("calls = %q; want %q", got, want)
	}
}

func TestSetupFailsWhenATableCannotBeCreated(t *testing.T) {
	h := newHarness(t)
	h.pf.failOn = func(args []string) error {
		if slices.Contains(args, "crowdsec_v6") {
			return errors.New("pfctl: Operation not permitted")
		}
		return nil
	}
	if err := h.d.setup(context.Background()); err == nil {
		t.Fatal("setup = nil; want the pfctl error")
	}
}

// Scenario: the LAPI is down at start-up. The daemon keeps asking for the full set (startup=true) on every tick,
// leaves the tables empty and logs each failure; once a pull succeeds it switches to deltas.
func TestStartupPullIsRetriedUntilItSucceeds(t *testing.T) {
	h := newHarness(t,
		lapiReply{http.StatusBadGateway, `bad gateway`},
		lapiReply{http.StatusServiceUnavailable, `{"message":"busy"}`},
		ok(startupBody),
		ok(emptyDelta),
	)
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := h.d.pull(ctx); err == nil {
			t.Fatalf("pull %d against a failing LAPI = nil", i+1)
		}
		assertTable(t, h.pf, "crowdsec_v4")
		assertTable(t, h.pf, "crowdsec_v6")
	}
	if got := strings.Count(h.logs.String(), "level=error msg=LAPI pull failed"); got != 2 {
		t.Fatalf("logged %d pull failures; want 2:\n%s", got, h.logs.String())
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatalf("third pull = %v", err)
	}
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	if err := h.d.pull(ctx); err != nil {
		t.Fatalf("fourth pull = %v", err)
	}
	reqs, _ := h.lapi.requests()
	var startups []string
	for _, r := range reqs {
		startups = append(startups, r.URL.Query().Get("startup"))
	}
	if want := []string{"true", "true", "true", ""}; !slices.Equal(startups, want) {
		t.Fatalf("startup parameter per request = %q; want %q", startups, want)
	}
}

// A failed pull changes nothing in pf: no add or delete is run and both tables keep the last known set.
func TestAFailedPullLeavesTheTablesAlone(t *testing.T) {
	h := synced(t, lapiReply{http.StatusInternalServerError, `oops`}, ok(`{"new":[`))
	ctx := context.Background()
	for i := range 2 {
		if err := h.d.pull(ctx); err == nil {
			t.Fatalf("failing pull %d = nil", i+1)
		}
		for _, c := range h.pf.takeCalls() {
			if slices.Contains(c.args, "add") || slices.Contains(c.args, "delete") || slices.Contains(c.args, "flush") ||
				slices.Contains(c.args, "replace") {
				t.Fatalf("failed pull %d ran %s", i+1, c)
			}
		}
		assertTable(t, h.pf, "crowdsec_v4", startupV4...)
		assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	}
}

// One pfctl add and one pfctl delete per table per pull, each from a 0600 file holding the validated values.
func TestAPullBatchesOneCallPerTableAndOperation(t *testing.T) {
	h := synced(t, ok(`{"new":[
	 {"id":10,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.20","duration":"4h","scenario":"s"},
	 {"id":11,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.21","duration":"4h","scenario":"s"},
	 {"id":12,"origin":"crowdsec","type":"ban","scope":"Ip","value":"2001:db8::20","duration":"4h","scenario":"s"},
	 {"id":13,"origin":"crowdsec","type":"ban","scope":"Ip","value":"bogus","duration":"4h","scenario":"s"}
	],"deleted":[
	 {"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"-1s","scenario":"s"},
	 {"id":3,"origin":"crowdsec","type":"ban","scope":"Range","value":"203.0.113.0/24","duration":"-1s","scenario":"s"},
	 {"id":4,"origin":"CAPI","type":"ban","scope":"Ip","value":"2001:db8:dead::1","duration":"-1s","scenario":"s"}
	]}`))
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	type op struct{ args, content string }
	var ops []op
	for _, c := range h.pf.takeCalls() {
		if c.file == "" {
			continue
		}
		if c.mode != 0o600 {
			t.Errorf("%s: file mode %o; want 600", c, c.mode)
		}
		if _, err := os.Stat(c.file); !os.IsNotExist(err) {
			t.Errorf("%s: file left behind", c)
		}
		ops = append(ops, op{strings.Join(c.args[:4], " "), c.content})
	}
	want := []op{
		{"-t crowdsec_v4 -T delete", "198.51.100.10\n203.0.113.0/24\n"},
		{"-t crowdsec_v6 -T delete", "2001:db8:dead::1\n"},
		{"-t crowdsec_v4 -T add", "198.51.100.20\n198.51.100.21\n"},
		{"-t crowdsec_v6 -T add", "2001:db8::20\n"},
	}
	if !slices.Equal(ops, want) {
		t.Fatalf("file-fed pfctl calls = %q; want %q", ops, want)
	}
	assertTable(t, h.pf, "crowdsec_v4", "198.51.100.11", "198.51.100.20", "198.51.100.21")
	assertTable(t, h.pf, "crowdsec_v6", "2001:db8:beef::/48", "2001:db8::20")
}

func TestAnEmptyDeltaRunsNoTableChange(t *testing.T) {
	h := synced(t, ok(emptyDelta))
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.pf.takeCalls() {
		if c.file != "" || slices.Contains(c.args, "-k") || slices.Equal(c.args, []string{"-s", "states"}) {
			t.Fatalf("an empty delta ran %s", c)
		}
	}
}

// Criterion 1 at the daemon level: a value banned by two decisions stays in its table until both are deleted.
func TestAValueBannedTwiceStaysUntilBothDecisionsGo(t *testing.T) {
	h := synced(t,
		ok(`{"new":[{"id":20,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"4h","scenario":"m"}],"deleted":[]}`),
		ok(`{"new":[],"deleted":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"-1s","scenario":"s"}]}`),
		ok(`{"new":[],"deleted":[{"id":20,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"-1s","scenario":"m"}]}`),
	)
	ctx := context.Background()
	for range 2 {
		if err := h.d.pull(ctx); err != nil {
			t.Fatal(err)
		}
		assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	assertTable(t, h.pf, "crowdsec_v4", "198.51.100.11", "203.0.113.0/24")
}

// States are killed only for newly added single addresses that the state list shows: not for a new range, not for
// a new address without states, and with `pfctl -s states` read once per pull.
func TestStateKillsAreLimitedToNewSingleAddressesWithStates(t *testing.T) {
	h := newHarness(t, ok(startupBody))
	h.pf.states = "vtnet0 tcp 192.168.1.1:22 <- 198.51.100.10:50122       ESTABLISHED:ESTABLISHED\n" +
		"vtnet0 tcp 192.168.1.1:443 <- 203.0.113.5:40000       ESTABLISHED:ESTABLISHED\n" +
		"vtnet0 tcp 192.168.1.1:443 <- 198.51.100.99:40000       ESTABLISHED:ESTABLISHED\n" +
		"vtnet0 tcp 2001:db8::10[443] <- 2001:db8:dead::1[51515]       ESTABLISHED:ESTABLISHED\n"
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	h.pf.takeCalls()
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	var kills []string
	statesReads := 0
	for _, c := range h.pf.takeCalls() {
		switch {
		case slices.Equal(c.args, []string{"-s", "states"}):
			statesReads++
		case c.args[0] == "-k":
			kills = append(kills, c.String())
		}
	}
	want := []string{
		"-k 198.51.100.10", "-k 0.0.0.0/0 -k 198.51.100.10",
		"-k 2001:db8:dead::1", "-k ::/0 -k 2001:db8:dead::1",
	}
	if !slices.Equal(kills, want) {
		t.Fatalf("kills = %q; want %q", kills, want)
	}
	if statesReads != 1 {
		t.Fatalf("pfctl -s states ran %d times; want once per pull", statesReads)
	}
}

func TestNoStatesAreReadWhenAPullAddsOnlyRanges(t *testing.T) {
	h := synced(t, ok(`{"new":[{"id":30,"origin":"crowdsec","type":"ban","scope":"Range","value":"192.0.2.0/24","duration":"4h","scenario":"s"}],"deleted":[]}`))
	h.pf.states = "vtnet0 tcp 192.168.1.1:22 <- 192.0.2.7:50122       ESTABLISHED:ESTABLISHED\n"
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.pf.takeCalls() {
		if slices.Equal(c.args, []string{"-s", "states"}) || c.args[0] == "-k" {
			t.Fatalf("a range-only pull ran %s", c)
		}
	}
}

// Reconcile: a table killed by a filter reload is re-created and refilled; the other table is left alone.
func TestReconcileRecreatesAMissingTable(t *testing.T) {
	h := synced(t)
	h.pf.killTable("crowdsec_v4")
	h.d.reconcile(context.Background())
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	got := callStrings(h.pf.takeCalls())
	if len(got) != 3 || got[0] != "-vvs Tables" || got[1] != "-t crowdsec_v4 -T add -f /dev/null" ||
		!strings.HasPrefix(got[2], "-t crowdsec_v4 -T replace -f ") {
		t.Fatalf("calls = %q; want the tables read, then crowdsec_v4 created and replaced", got)
	}
}

func TestReconcileRefillsAShortTable(t *testing.T) {
	h := synced(t)
	h.pf.setTable("crowdsec_v6", "2001:db8:beef::/48")
	h.d.reconcile(context.Background())
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	got := callStrings(h.pf.takeCalls())
	if len(got) != 2 || !strings.HasPrefix(got[1], "-t crowdsec_v6 -T replace -f ") {
		t.Fatalf("calls = %q; want the tables read and crowdsec_v6 replaced", got)
	}
}

func TestReconcileDoesNothingWhenTheTablesMatch(t *testing.T) {
	h := synced(t)
	h.d.reconcile(context.Background())
	if got := callStrings(h.pf.takeCalls()); !slices.Equal(got, []string{"-vvs Tables"}) {
		t.Fatalf("calls = %q; want only the tables read", got)
	}
}

// After every pull, failed or not, the tables are checked: with the LAPI down, a reload's kill is still repaired.
func TestEveryPullReconcilesEvenWhenItFails(t *testing.T) {
	h := synced(t, lapiReply{http.StatusBadGateway, `down`})
	h.pf.killTable("crowdsec_v4")
	h.pf.killTable("crowdsec_v6")
	if err := h.d.pull(context.Background()); err == nil {
		t.Fatal("pull against a down LAPI = nil")
	}
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
}

// A failed pfctl add leaves pf short of the set; the same pull's reconcile replaces the table.
func TestAFailedAddIsRepairedByReplace(t *testing.T) {
	h := synced(t, ok(`{"new":[{"id":40,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.40","duration":"4h","scenario":"s"}],"deleted":[]}`))
	h.pf.failOn = func(args []string) error {
		if len(args) > 3 && args[3] == "add" && args[5] != "/dev/null" {
			return errors.New("pfctl: Cannot allocate memory")
		}
		return nil
	}
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatalf("pull = %v; a pfctl failure is not a LAPI failure", err)
	}
	assertTable(t, h.pf, "crowdsec_v4", append(slices.Clone(startupV4), "198.51.100.40")...)
	if !strings.Contains(h.logs.String(), "level=error msg=pfctl") {
		t.Fatalf("logs = %q; want the pfctl failure logged", h.logs.String())
	}
}

// Scenario: SIGUSR1 after a filter reload. Given a running daemon that has synced, when both tables are killed and
// SIGUSR1 arrives, then both are back with the full set without any LAPI request; when the context ends the
// daemon flushes both tables and returns.
func TestRunReconcilesOnSIGUSR1AndFlushesOnShutdown(t *testing.T) {
	h := newHarness(t, ok(startupBody))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	usr1 := make(chan os.Signal, 1)
	events := make(chan string, 16)
	result := make(chan error, 1)
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { h.d.run(ctx, ticks, nil, usr1, func(e string) { events <- e }); result <- nil }()
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("first event = %q; want the immediate start-up pull", e)
	}
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	reqsBefore, _ := h.lapi.requests()

	h.pf.killTable("crowdsec_v4")
	h.pf.killTable("crowdsec_v6")
	select {
	case usr1 <- syscall.SIGUSR1:
	case err := <-result:
		t.Fatalf("run returned %v before SIGUSR1", err)
	}
	if e := nextEvent(t, events, result); e != "reconcile" {
		t.Fatalf("event after SIGUSR1 = %q; want reconcile", e)
	}
	assertTable(t, h.pf, "crowdsec_v4", startupV4...)
	assertTable(t, h.pf, "crowdsec_v6", startupV6...)
	if reqsAfter, _ := h.lapi.requests(); len(reqsAfter) != len(reqsBefore) {
		t.Fatalf("SIGUSR1 made %d LAPI requests; want none", len(reqsAfter)-len(reqsBefore))
	}

	select {
	case ticks <- time.Now():
	case err := <-result:
		t.Fatalf("run returned %v before the tick", err)
	}
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("event after a tick = %q; want pull", e)
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("run ended with %v", err)
	}
	assertTable(t, h.pf, "crowdsec_v4")
	assertTable(t, h.pf, "crowdsec_v6")
}

func TestRunPostsUsageOnItsTicker(t *testing.T) {
	h := newHarness(t, ok(startupBody))
	ctx, cancel := context.WithCancel(context.Background())
	usage := make(chan time.Time)
	events := make(chan string, 16)
	result := make(chan error, 1)
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { h.d.run(ctx, nil, usage, nil, func(e string) { events <- e }); result <- nil }()
	if e := nextEvent(t, events, result); e != "pull" {
		t.Fatalf("first event = %q; want the start-up pull", e)
	}
	select {
	case usage <- time.Now():
	case err := <-result:
		t.Fatalf("run returned %v before the usage tick", err)
	}
	if e := nextEvent(t, events, result); e != "usage" {
		t.Fatalf("event = %q; want usage", e)
	}
	cancel()
	<-result
	reqs, _ := h.lapi.requests()
	if last := reqs[len(reqs)-1]; last.URL.Path != "/v1/usage-metrics" || last.Method != http.MethodPost {
		t.Fatalf("last request = %s %s; want the usage post", last.Method, last.URL.Path)
	}
}

func TestShutdownFlushesBothTables(t *testing.T) {
	h := synced(t)
	h.d.shutdown(context.Background())
	assertTable(t, h.pf, "crowdsec_v4")
	assertTable(t, h.pf, "crowdsec_v6")
	want := []string{"-t crowdsec_v4 -T flush", "-t crowdsec_v6 -T flush"}
	if got := callStrings(h.pf.takeCalls()); !slices.Equal(got, want) {
		t.Fatalf("calls = %q; want %q", got, want)
	}
}

// The status file after each pull: the D1 fields, atomically replaced, mode 0644.
func TestStatusFileReportsThePull(t *testing.T) {
	h := newHarness(t, ok(startupBody), lapiReply{http.StatusBadGateway, `upstream down`})
	h.pf.rules = "block drop in quick inet from <crowdsec_v4> to any label \"CrowdSec IPv4\"\n" +
		"  [ Evaluations: 9 Packets: 7 Bytes: 420 States: 0 ]\n" +
		"block drop in quick inet6 from <crowdsec_v6> to any label \"CrowdSec IPv6\"\n" +
		"  [ Evaluations: 9 Packets: 2 Bytes: 160 States: 0 ]\n"
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	h.now = testEpoch.Add(5 * time.Second)
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	st := readStatus(t, h)
	want := map[string]any{
		"version":                  version,
		"start_time":               float64(testEpoch.Unix()),
		"update_frequency_seconds": float64(10),
		"updated_at":               float64(testEpoch.Unix() + 5),
		"last_pull":                float64(testEpoch.Unix() + 5),
		"last_error_time":          float64(0),
		"last_error":               "",
		"lapi_requests":            float64(1),
		"lapi_errors":              float64(0),
		"banned": map[string]any{
			"ipv4": map[string]any{"total": float64(3), "origins": map[string]any{"crowdsec": float64(2), "cscli": float64(1)}},
			"ipv6": map[string]any{"total": float64(2), "origins": map[string]any{"CAPI": float64(1), "crowdsec": float64(1)}},
		},
		"dropped": map[string]any{
			"ipv4": map[string]any{"packets": float64(7), "bytes": float64(420)},
			"ipv6": map[string]any{"packets": float64(2), "bytes": float64(160)},
		},
	}
	gotJSON, _ := json.Marshal(st)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("status =\n%s\nwant\n%s", gotJSON, wantJSON)
	}
	info, err := os.Stat(h.cfg.StatusFile)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("status file mode = %v, %v; want 0644", info.Mode().Perm(), err)
	}

	h.now = testEpoch.Add(15 * time.Second)
	if err := h.d.pull(ctx); err == nil {
		t.Fatal("second pull against a 502 = nil")
	}
	st = readStatus(t, h)
	if st["last_pull"] != float64(testEpoch.Unix()+5) || st["last_error_time"] != float64(testEpoch.Unix()+15) ||
		!strings.Contains(st["last_error"].(string), "502") || st["lapi_requests"] != float64(2) ||
		st["lapi_errors"] != float64(1) || st["updated_at"] != float64(testEpoch.Unix()+15) {
		t.Fatalf("status after a failed pull = %v; want last_pull kept, the error recorded and counted", st)
	}
	if b := st["banned"].(map[string]any)["ipv4"].(map[string]any)["total"]; b != float64(3) {
		t.Fatalf("banned ipv4 after a failed pull = %v; want the last known 3", b)
	}
}

// The status file is replaced by rename, never rewritten in place, and no temp file is left beside it.
func TestWriteStatusReplacesTheFileAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pfb_crowdsec.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	held, err := os.Open(path) // a reader holding the old file keeps seeing the old content
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := writeStatus(path, &status{Version: version, LastError: "x"}); err != nil {
		t.Fatalf("writeStatus = %v", err)
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) {
		t.Fatal("the status file was rewritten in place, not replaced by rename")
	}
	if after.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o; want 644", after.Mode().Perm())
	}
	old := make([]byte, 64)
	n, _ := held.Read(old)
	if string(old[:n]) != `{"old":true}` {
		t.Fatalf("a reader of the old file saw %q", old[:n])
	}
	var st status
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &st); err != nil || st.Version != version {
		t.Fatalf("new content = %s, %v", data, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v; want only the status file", names)
	}
}

// The key appears in no log line and not in the status file, even when the LAPI echoes it back.
func TestTheKeyNeverReachesLogsOrTheStatusFile(t *testing.T) {
	h := newHarness(t,
		lapiReply{http.StatusForbidden, `{"message":"bouncer key ` + testKey + ` is unknown"}`},
		ok(startupBody),
	)
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err == nil {
		t.Fatal("pull against a 403 = nil")
	}
	status1, _ := os.ReadFile(h.cfg.StatusFile)
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	h.d.sendUsage(ctx)
	h.d.shutdown(ctx)
	status2, _ := os.ReadFile(h.cfg.StatusFile)
	if !strings.Contains(string(status1), "403") {
		t.Fatalf("status after the 403 = %s; want the error recorded", status1)
	}
	for what, text := range map[string]string{
		"logs": h.logs.String(), "status after the 403": string(status1), "final status": string(status2),
	} {
		if strings.Contains(text, testKey) {
			t.Errorf("%s carry the key:\n%s", what, text)
		}
	}
	if !strings.Contains(h.logs.String(), "level=debug") {
		t.Fatal("debug logging was not exercised")
	}
}

func TestInvalidValuesAreLoggedOncePerPull(t *testing.T) {
	h := synced(t, ok(`{"new":[
	 {"id":50,"origin":"crowdsec","type":"ban","scope":"Ip","value":"bad-1","duration":"4h","scenario":"s"},
	 {"id":51,"origin":"crowdsec","type":"ban","scope":"Ip","value":"bad-2\nlevel=error","duration":"4h","scenario":"s"},
	 {"id":52,"origin":"crowdsec","type":"ban","scope":"Range","value":"10.0.0.0/99","duration":"4h","scenario":"s"}
	],"deleted":[]}`))
	before := strings.Count(h.logs.String(), "\n")
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	logs := h.logs.String()
	newLines := strings.Split(strings.TrimSuffix(logs, "\n"), "\n")[before:]
	var invalid []string
	for _, line := range newLines {
		if strings.Contains(line, "invalid") {
			invalid = append(invalid, line)
		}
	}
	if len(invalid) != 1 || !strings.HasPrefix(invalid[0], "level=warning") ||
		!strings.Contains(invalid[0], "3 ") || !strings.Contains(invalid[0], "bad-1") {
		t.Fatalf("invalid-value lines = %q; want one warning naming the count and a sample", invalid)
	}
	for _, line := range newLines {
		if strings.HasPrefix(line, "level=error") {
			t.Fatalf("a LAPI value forged a log line: %q", line)
		}
	}
}

// Scenario: an add and a delete of the same size both fail, so pf's count still matches memory.
// The failure alone must make the reconcile replace the table, and once replaced the table is left alone again.
func TestAFailedAddAndDeleteOfTheSameSizeAreRepairedOnce(t *testing.T) {
	h := synced(t, ok(`{"new":[{"id":60,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.60","duration":"4h","scenario":"s"}],
	"deleted":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.10","duration":"-1s","scenario":"s"}]}`))
	h.pf.failOn = func(args []string) error {
		if len(args) == 6 && (args[3] == "add" || args[3] == "delete") && args[5] != "/dev/null" {
			return errors.New("pfctl: Cannot allocate memory")
		}
		return nil
	}
	if err := h.d.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTable(t, h.pf, "crowdsec_v4", "198.51.100.11", "198.51.100.60", "203.0.113.0/24")
	h.pf.takeCalls()
	h.d.reconcile(context.Background())
	if got := callStrings(h.pf.takeCalls()); !slices.Equal(got, []string{"-vvs Tables"}) {
		t.Fatalf("calls after the repair = %q; want only the tables read", got)
	}
}
