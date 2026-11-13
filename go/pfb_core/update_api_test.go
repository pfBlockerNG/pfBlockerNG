package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeUpdate is a #!/bin/sh program standing in for the Outpost's update program (--update-cmd). It keeps its last stdin
// request, its pid and one line per run in its directory, writes a line to the log, waits until the file "release" exists,
// reports the file "result" (when there is one) on fd 3 and exits 0.
type fakeUpdate struct {
	t    *testing.T
	dir  string
	path string
}

func newFakeUpdate(t *testing.T) *fakeUpdate {
	t.Helper()
	f := &fakeUpdate{t: t, dir: t.TempDir()}
	f.path = filepath.Join(f.dir, "update.sh")
	script := "#!/bin/sh\nD='" + f.dir + "'\n" + `cat > "$D/req"
echo $$ > "$D/pid"
echo run >> "$D/runs"
echo "update program started"
while [ ! -e "$D/release" ]; do sleep 0.05; done
if [ -f "$D/result" ]; then cat "$D/result" >&3; fi
echo "update program done"
exit 0
`
	if err := os.WriteFile(f.path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeUpdate) release() {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "release"), nil, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeUpdate) result(s string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "result"), []byte(s), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// request is the JSON the program's last run read on its stdin.
func (f *fakeUpdate) request() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "req"))
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func (f *fakeUpdate) runs() int {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func (f *fakeUpdate) pid() int {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "pid"))
	if err != nil {
		f.t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		f.t.Fatal(err)
	}
	return pid
}

// heldQuarters is the scheduler loop's timer in a test: the loop waits on fire, which a test sends to when it wants the
// quarter hour to come, and armed counts the waits the loop began.
type heldQuarters struct {
	armed atomic.Int32
	fire  chan time.Time
}

// holdQuarters keeps the scheduler loop of the Core the test starts next from ever seeing a quarter-hour boundary of the real
// clock: a scheduled Update starting under a test would turn a manual or retry request into a conflict.
func holdQuarters(t *testing.T) *heldQuarters {
	t.Helper()
	q := &heldQuarters{fire: make(chan time.Time)}
	prev := quarterTimer
	quarterTimer = func(time.Duration) <-chan time.Time { q.armed.Add(1); return q.fire }
	t.Cleanup(func() { quarterTimer = prev }) // runs after the Core's own cleanup (it was registered first)
	return q
}

func startUpdateCoreHeld(t *testing.T) (*runningCore, *fakeUpdate, *heldQuarters) {
	t.Helper()
	q := holdQuarters(t)
	f := newFakeUpdate(t)
	return startCore(t, scratchDir(t), "--update-cmd", f.path), f, q
}

func startUpdateCore(t *testing.T) (*runningCore, *fakeUpdate) {
	t.Helper()
	c, f, _ := startUpdateCoreHeld(t)
	return c, f
}

type updateView struct {
	Running bool `json:"running"`
	Update  *struct {
		Trigger    string `json:"trigger"`
		Scope      string `json:"scope"`
		Force      string `json:"force"`
		StartedAt  int64  `json:"startedAt"`
		FinishedAt *int64 `json:"finishedAt"`
		Result     string `json:"result"`
	} `json:"update"`
	Log  string `json:"log"`
	Next string `json:"next"` // an opaque cursor: a JSON string
}

// getUpdate reads the Update from the cursor after ("": no after parameter, from the start).
func (c *runningCore) getUpdate(after string) updateView {
	c.t.Helper()
	body := `{}`
	if after != "" {
		body = fmt.Sprintf(`{"after":%q}`, after)
	}
	got := c.post("GetUpdate", body)
	var v updateView
	if got.status != http.StatusOK || json.Unmarshal(got.body, &v) != nil {
		c.t.Fatalf("GetUpdate = %d %s", got.status, got.body)
	}
	return v
}

// waitLog waits until the log, read from the cursor after, holds text.
func (c *runningCore) waitLog(after string, text string) updateView {
	c.t.Helper()
	var v updateView
	waitFor(c.t, func() bool { v = c.getUpdate(after); return strings.Contains(v.Log, text) })
	return v
}

// waitFinished waits until the last Update is one of trigger that has ended.
func (c *runningCore) waitFinished(trigger string) updateView {
	c.t.Helper()
	var v updateView
	waitFor(c.t, func() bool { v = c.getUpdate(""); return !v.Running && v.Update != nil && v.Update.Trigger == trigger })
	return v
}

func sameJSON(t *testing.T, got, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad expectation %s: %v", want, err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	if !bytes.Equal(gb, wb) {
		t.Errorf("JSON:\n have %s\n want %s", gb, wb)
	}
}

// scheduleFixture initializes the settings with one hourly feed and a Blacklist provider with a category: the schedule model
// has the feed, extra:dcc and extra:bl.
const scheduleFixture = `{"requestId":"init","settings":{
"feeds/ipv4":{"groups":[{"name":"Alpha","action":"Deny_Inbound","updateFrequency":"01hour","feeds":[
  {"header":"Feed1","state":"enabled","url":"https://example.org/f.txt"}]}]},
"schedule":{"categoryUpdates":true,"categoryFrequency":"Weekly","categoryProviders":[{"id":"prov","selected":true,"categories":"cat1"}]}}}`

func (c *runningCore) initialize() {
	c.t.Helper()
	if got := c.post("InitializeSettings", scheduleFixture); got.status != http.StatusOK {
		c.t.Fatalf("InitializeSettings = %d %s", got.status, got.body)
	}
}

func TestTheUpdateMethodsAnswerUnavailableWithoutUpdateCmd(t *testing.T) {
	c := startCore(t, scratchDir(t))
	for name, body := range map[string]string{"StartUpdate": `{"requestId":"r1","trigger":"apply"}`, "GetUpdate": `{}`, "GetSchedule": `{}`} {
		got := c.post(name, body)
		wantError(t, got, http.StatusServiceUnavailable, codeUnavailable)
		if !bytes.Contains(got.body, []byte("start it with --update-cmd")) {
			t.Errorf("%s = %s, want the message to name --update-cmd", name, got.body)
		}
	}
}

func TestAManualUpdateRunsTheProgramAndGetUpdateShowsIt(t *testing.T) {
	c, f := startUpdateCore(t)
	wantJSON(t, c.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)

	wantJSON(t, c.post("StartUpdate", `{"requestId":"m1","trigger":"manual","scope":"dnsbl","force":"parse"}`), http.StatusOK, `{}`)
	v := c.waitLog("", "update program started")
	if !v.Running || v.Update == nil || v.Update.Trigger != "manual" || v.Update.Scope != "dnsbl" || v.Update.Force != "parse" ||
		v.Update.StartedAt <= 0 || v.Update.FinishedAt != nil || v.Update.Result != "" {
		t.Errorf("GetUpdate while it runs = %+v, want it running with its trigger, scope and force and no end", v)
	}
	sameJSON(t, f.request(), `{"version":1,"trigger":"manual","scope":"dnsbl","force":"parse"}`)

	f.release()
	end := c.waitFinished("manual")
	if end.Update.FinishedAt == nil || end.Update.Result != "success" || end.Log != "update program started\nupdate program done\n" {
		t.Errorf("GetUpdate after it ended = %+v, want a success with the program's whole output", end)
	}
	if got := c.getUpdate(""); got.Update == nil || got.Update.Trigger != "manual" {
		t.Errorf("the finished Update is not readable until the next one: %+v", got)
	}
}

func TestAManualUpdateDefaultsToBothScopesAndNoForce(t *testing.T) {
	c, f := startUpdateCore(t)
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"d1","trigger":"manual"}`), http.StatusOK, `{}`)
	if v := c.waitFinished("manual"); v.Update.Scope != "both" || v.Update.Force != "none" {
		t.Errorf("GetUpdate = %+v, want scope both and force none", v)
	}
	sameJSON(t, f.request(), `{"version":1,"trigger":"manual","scope":"both","force":"none"}`)
}

func TestASecondStartWhileAnUpdateRunsIsAConflictAndARepeatedRequestIDReplays(t *testing.T) {
	c, f := startUpdateCore(t)
	first := `{"requestId":"s1","trigger":"manual"}`
	wantJSON(t, c.post("StartUpdate", first), http.StatusOK, `{}`)
	c.waitLog("", "update program started")

	refused := c.post("StartUpdate", `{"requestId":"s2","trigger":"manual"}`)
	wantError(t, refused, http.StatusConflict, codeConflict)
	if !bytes.Contains(refused.body, []byte("an Update is running")) {
		t.Errorf("the refusal = %s, want it to say an Update is running", refused.body)
	}
	// the first request's own answer, not the 409 a second run of the method would give
	wantJSON(t, c.post("StartUpdate", first), http.StatusOK, `{}`)
	if n := f.runs(); n != 1 {
		t.Errorf("the program ran %d times, want 1", n)
	}
	f.release()
	c.waitFinished("manual")
	if n := f.runs(); n != 1 {
		t.Errorf("the program ran %d times after the Update ended, want 1", n)
	}
}

func TestStartUpdateRefusesWhatItCannotRun(t *testing.T) {
	c, f := startUpdateCore(t)
	for i, tc := range []struct {
		params string
		fields []string
	}{
		{`"x":1`, []string{"x"}},
		{``, []string{"trigger"}},
		{`"trigger":"nosuch"`, []string{"trigger"}},
		{`"trigger":"scheduled"`, []string{"trigger"}}, // Core's own trigger, never asked for
		{`"trigger":"manual","scope":"all","force":"always"`, []string{"scope", "force"}},
		{`"trigger":"manual","scope":""`, []string{"scope"}},
		{`"trigger":"manual","scope":5`, []string{"scope"}},
		{`"trigger":"apply","scope":"ip"`, []string{"scope"}},
		{`"trigger":"apply","force":"parse"`, []string{"force"}},
		{`"trigger":"retry","scope":"ip","force":"none"`, []string{"scope", "force"}},
	} {
		params := tc.params
		if params != "" {
			params = "," + params
		}
		body := fmt.Sprintf(`{"requestId":"bad%d"%s}`, i, params)
		wantError(t, c.post("StartUpdate", body), http.StatusBadRequest, codeInvalidArgument, tc.fields...)
	}
	if n := f.runs(); n != 0 {
		t.Errorf("the program ran %d times for requests that were refused, want 0", n)
	}
	wantJSON(t, c.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)
}

func TestGetUpdateAfterNextReturnsOnlyTheNewBytes(t *testing.T) {
	c, f := startUpdateCore(t)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"p1","trigger":"apply"}`), http.StatusOK, `{}`)
	first := c.waitLog("", "update program started")
	if first.Log != "update program started\n" || first.Next == "" || strings.Trim(first.Next, "0123456789") != "" {
		t.Fatalf("GetUpdate = %+v, want the first line and a next that is a decimal string", first)
	}
	f.release()
	c.waitFinished("apply")
	rest := c.getUpdate(first.Next)
	if rest.Log != "update program done\n" || rest.Next == first.Next {
		t.Errorf("GetUpdate after %s = %+v, want only the line written since, and a later next", first.Next, rest)
	}
	if end := c.getUpdate(rest.Next); end.Log != "" || end.Next != rest.Next {
		t.Errorf("GetUpdate at the end = %+v, want no bytes and the same next", end)
	}
	for _, from := range []string{"", "0"} { // absent and zero both read from the start
		if all := c.getUpdate(from); all.Log != "update program started\nupdate program done\n" || all.Next != rest.Next {
			t.Errorf("GetUpdate after %q = %+v, want the whole log and the same end", from, all)
		}
	}
}

func TestGetUpdateRefusesAnAfterThatIsNotADecimalString(t *testing.T) {
	c, _ := startUpdateCore(t)
	for _, after := range []string{`"-1"`, `"abc"`, `""`, `"1.5"`, `"+1"`, `" 1"`, `"0x10"`, `"99999999999999999999"`, `0`, `5`, `null`, `[]`} {
		body := `{"after":` + after + `}`
		if after == "null" { // an explicit null is no cursor: it reads like an absent one, the Go decoding of a JSON null
			wantJSON(t, c.post("GetUpdate", body), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)
			continue
		}
		wantError(t, c.post("GetUpdate", body), http.StatusBadRequest, codeInvalidArgument, "after")
	}
}

// A cursor carries which Update it belongs to: one from an earlier Update reads the next Update's log from its start, where a
// bare offset would skip what the new Update wrote under it.
func TestACursorOfAnEarlierUpdateReadsTheNextUpdateFromItsStart(t *testing.T) {
	c, f := startUpdateCore(t)
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"c1","trigger":"apply"}`), http.StatusOK, `{}`)
	first := c.waitFinished("apply")
	if first.Log != "update program started\nupdate program done\n" {
		t.Fatalf("the first Update's log = %q", first.Log)
	}
	wantJSON(t, c.post("StartUpdate", `{"requestId":"c2","trigger":"manual"}`), http.StatusOK, `{}`)
	second := c.waitFinished("manual")
	if second.Log != first.Log || second.Next == first.Next {
		t.Fatalf("the second Update's view = %+v, want the same text under a cursor of its own (first %+v)", second, first)
	}
	if got := c.getUpdate(first.Next); got.Log != second.Log || got.Next != second.Next {
		t.Errorf("GetUpdate after the first Update's last cursor = %+v, want the second Update from its start (%+v)", got, second)
	}
}

func TestApplyAndRetryRunWithTheRequestTheProgramReads(t *testing.T) {
	c, f := startUpdateCore(t)
	c.initialize()
	f.release()

	wantJSON(t, c.post("StartUpdate", `{"requestId":"a1","trigger":"apply"}`), http.StatusOK, `{}`)
	c.waitFinished("apply")
	sameJSON(t, f.request(), `{"version":1,"trigger":"apply","scope":"both","force":"none"}`)

	wantJSON(t, c.post("StartUpdate", `{"requestId":"r1","trigger":"retry"}`), http.StatusOK, `{}`)
	c.waitFinished("retry")
	var req struct {
		Version int      `json:"version"`
		Trigger string   `json:"trigger"`
		Scope   string   `json:"scope"`
		Force   string   `json:"force"`
		Feeds   []string `json:"feeds"`
	}
	if err := json.Unmarshal([]byte(f.request()), &req); err != nil {
		t.Fatal(err)
	}
	if req.Version != 1 || req.Trigger != "retry" || req.Scope != "both" || req.Force != "none" || !slices.Equal(req.Feeds, []string{"ipv4:Feed1_v4"}) {
		t.Errorf("the retry's request = %s, want trigger retry, scope both, force none and the pending feed ipv4:Feed1_v4", f.request())
	}
}

func TestGetScheduleAnswersTheViewOfTheCurrentSettings(t *testing.T) {
	c, _ := startUpdateCore(t)
	wantError(t, c.post("GetSchedule", `{}`), http.StatusServiceUnavailable, codeUnavailable) // no settings yet
	c.initialize()

	type entry struct {
		LastRun int64 `json:"lastRun"`
		NextDue int64 `json:"nextDue"`
	}
	view := func() (v struct {
		Scheduled bool             `json:"scheduled"`
		Feeds     *entry           `json:"feeds"`
		Extras    map[string]entry `json:"extras"`
	}) {
		t.Helper()
		got := c.post("GetSchedule", `{}`)
		if got.status != http.StatusOK || json.Unmarshal(got.body, &v) != nil {
			t.Fatalf("GetSchedule = %d %s", got.status, got.body)
		}
		return v
	}
	v := view()
	if !v.Scheduled || v.Feeds == nil || v.Feeds.NextDue <= 0 || v.Extras["extra:dcc"].NextDue <= 0 || v.Extras["extra:bl"].NextDue <= 0 || len(v.Extras) != 2 {
		t.Errorf("GetSchedule = %+v, want scheduled, the feeds' entry and both Extras with a next due time", v)
	}
	wantError(t, c.post("GetSchedule", `{"x":1}`), http.StatusBadRequest, codeInvalidArgument, "x")

	// the settings are read as they are now: a save moves the view with no notice to the scheduler
	if got := c.post("SaveSettings", `{"requestId":"off","expectedRevision":1,"changes":{"schedule":{"scheduledUpdates":false}}}`); got.status != http.StatusOK {
		t.Fatalf("SaveSettings = %d %s", got.status, got.body)
	}
	if v := view(); v.Scheduled || v.Feeds != nil {
		t.Errorf("GetSchedule after scheduled updates were turned off = %+v, want not scheduled and no feeds' entry", v)
	}
}

func TestAnUpdatesOutcomesAreRecordedInTheStateDirectory(t *testing.T) {
	c, f := startUpdateCore(t)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"},"attempted":["ipv4:Feed1_v4"],"geoipReady":true}`)
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"o1","trigger":"retry"}`), http.StatusOK, `{}`)
	c.waitFinished("retry")

	state, err := os.ReadFile(filepath.Join(c.state, "schedule_state.json"))
	if err != nil || !bytes.Contains(state, []byte("ipv4:Feed1_v4")) {
		t.Fatalf("schedule_state.json in the state directory = %q (%v), want it to hold the feed", state, err)
	}
	if _, err := os.Stat(filepath.Join(c.state, "update.log")); err != nil {
		t.Errorf("update.log is not in the state directory: %v", err)
	}
	var v struct {
		Feeds *struct {
			LastRun int64 `json:"lastRun"`
		} `json:"feeds"`
	}
	if got := c.post("GetSchedule", `{}`); json.Unmarshal(got.body, &v) != nil || v.Feeds == nil || v.Feeds.LastRun <= 0 {
		t.Errorf("GetSchedule = %s, want the feeds' last run to be the Update that reported success", got.body)
	}
}

func TestStoppingCoreDuringAnUpdateKillsTheProgram(t *testing.T) {
	c, f := startUpdateCore(t)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"k1","trigger":"manual"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")
	pid := f.pid()

	if code := c.stop(); code != 0 {
		t.Errorf("run = %d after the stop during an Update, want 0; stderr:\n%s", code, c.stderr.String())
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("the update program (pid %d) is still there after Core returned: %v", pid, err)
	}
}

func TestARetryWhoseModelCannotBeBuiltIsUnavailableAndStartsNothing(t *testing.T) {
	c, f := startUpdateCore(t) // the settings are not initialized: there is no schedule model
	retry := c.post("StartUpdate", `{"requestId":"u1","trigger":"retry"}`)
	wantError(t, retry, http.StatusServiceUnavailable, codeUnavailable)
	if !bytes.Contains(retry.body, []byte("not initialized")) {
		t.Errorf("the refusal = %s, want it to give the reason", retry.body)
	}
	wantError(t, c.post("GetSchedule", `{}`), http.StatusServiceUnavailable, codeUnavailable)
	if n := f.runs(); n != 0 {
		t.Errorf("the program ran %d times for a retry that could not be planned, want 0", n)
	}
	wantJSON(t, c.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)

	// an apply plans nothing, so it needs no model
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"u2","trigger":"apply"}`), http.StatusOK, `{}`)
	c.waitFinished("apply")
}

func TestTheSchedulerLoopWaitsOnItsTimerAndStartsNothingUntilItFires(t *testing.T) {
	c, f, q := startUpdateCoreHeld(t)
	c.initialize() // the feed is due at any time
	f.release()
	waitFor(t, func() bool { return q.armed.Load() > 0 }) // the loop waits on the timer the test holds
	for range 3 {
		c.post("GetSchedule", `{}`)
	}
	if n := f.runs(); n != 0 {
		t.Errorf("the update program ran %d times while the quarter hour was held, want 0", n)
	}
	wantJSON(t, c.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)
}

func TestTheSchedulerLoopStartsAScheduledUpdateWhenItsTimerFires(t *testing.T) {
	c, f, q := startUpdateCoreHeld(t)
	c.initialize()
	f.release()
	waitFor(t, func() bool { return q.armed.Load() == 1 })
	select {
	case q.fire <- time.Now():
	case <-time.After(watchdog):
		t.Fatalf("STUCK: the scheduler loop did not take the quarter hour within the %v watchdog", watchdog)
	}
	c.waitFinished("scheduled")
	var req struct {
		Trigger string   `json:"trigger"`
		Feeds   []string `json:"feeds"`
	}
	if err := json.Unmarshal([]byte(f.request()), &req); err != nil {
		t.Fatal(err)
	}
	if req.Trigger != "scheduled" || !slices.Equal(req.Feeds, []string{"ipv4:Feed1_v4"}) {
		t.Errorf("the scheduled Update's request = %s, want trigger scheduled and the due feed ipv4:Feed1_v4", f.request())
	}
	waitFor(t, func() bool { return q.armed.Load() == 2 }) // the loop waits for the next one
	if n := f.runs(); n != 1 {
		t.Errorf("the program ran %d times for one quarter hour, want 1", n)
	}
}
