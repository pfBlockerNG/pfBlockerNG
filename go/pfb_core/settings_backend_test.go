package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// fakeAdapter is a #!/bin/sh program standing in for the pfSense adapter: it keeps the last request and one line per call
// in its directory and answers the file "reply", which a test rewrites between calls.
type fakeAdapter struct {
	t    *testing.T
	dir  string
	path string
}

func newFakeAdapter(t *testing.T, reply string) *fakeAdapter {
	t.Helper()
	f := &fakeAdapter{t: t, dir: t.TempDir()}
	f.path = filepath.Join(f.dir, "adapter.sh")
	f.script(`cat > "$D/req"; echo run >> "$D/runs"; cat "$D/reply"`)
	f.reply(reply)
	return f
}

func (f *fakeAdapter) script(body string) {
	f.t.Helper()
	text := "#!/bin/sh\nD='" + f.dir + "'\n" + body + "\n"
	if err := os.WriteFile(f.path, []byte(text), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeAdapter) reply(s string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "reply"), []byte(s+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeAdapter) request() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "req"))
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func (f *fakeAdapter) runs() int {
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

// failing makes the program exit 1 with a message on stderr.
func (f *fakeAdapter) failing() {
	f.t.Helper()
	f.script(`cat > "$D/req"; echo 'config.xml is locked' >&2; exit 1`)
}

// readReply is the adapter's answer to a read: the production defaults with over laid on them.
func readReply(t *testing.T, revision uint64, over map[string]any) string {
	t.Helper()
	values := map[string]any{}
	for _, f := range settings.Production().Projections[0].Fields {
		values[f.Name] = f.Default
	}
	maps.Copy(values, over)
	b, err := json.Marshal(map[string]any{"version": 1, "revision": revision, "settings": map[string]any{"dns": values}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runningCore is run() serving in this process, with a client for its socket.
type runningCore struct {
	t       *testing.T
	client  *http.Client
	stderr  *syncBuffer
	state   string
	cancel  context.CancelFunc
	done    chan int
	stopped bool
	code    int
}

// coreArgs is the command line of a Core in dir, its socket named sock inside it.
func coreArgs(dir, sock string, extra ...string) []string {
	return append([]string{"--socket", filepath.Join(dir, sock, "api.sock"), "--state-dir", filepath.Join(dir, "state"),
		"--allow-uid", strconv.Itoa(os.Getuid())}, extra...)
}

// startCore runs Core in dir (from scratchDir) until it serves; a Core that exits first fails the test with its log.
func startCore(t *testing.T, dir string, extra ...string) *runningCore {
	t.Helper()
	args := coreArgs(dir, "run", extra...)
	socket := args[1]
	c := &runningCore{t: t, state: args[3], stderr: &syncBuffer{}, done: make(chan int, 1)}
	c.client = &http.Client{Timeout: watchdog, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	var ctx context.Context
	ctx, c.cancel = context.WithCancel(context.Background())
	go func() { c.done <- run(ctx, args, c.stderr) }()
	t.Cleanup(func() { c.stop() })
	for deadline := time.Now().Add(watchdog); !strings.Contains(c.stderr.String(), "serving API v1 on "+socket); time.Sleep(time.Millisecond) {
		select {
		case c.code = <-c.done:
			c.stopped = true
			t.Fatalf("Core exited %d before it served; its log:\n%s", c.code, c.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: Core did not serve within the %v watchdog; its log:\n%s", watchdog, c.stderr.String())
		}
	}
	return c
}

// stop ends the Core (once) and returns run's exit status.
func (c *runningCore) stop() int {
	c.cancel()
	if !c.stopped {
		c.code, c.stopped = <-c.done, true
	}
	c.client.CloseIdleConnections()
	return c.code
}

func (c *runningCore) post(method, body string) reply {
	c.t.Helper()
	resp, err := c.client.Post("http://pfb-core/v1/"+method, "application/json", strings.NewReader(body))
	if err != nil {
		c.t.Fatalf("%s: %v", method, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s: reading the reply: %v", method, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: got}
}

type snapshot struct {
	Initialized bool   `json:"initialized"`
	Revision    uint64 `json:"revision"`
	Projections []struct {
		ResourceID string         `json:"resourceId"`
		Value      map[string]any `json:"value"`
	} `json:"projections"`
}

func snapshotOf(t *testing.T, r reply) snapshot {
	t.Helper()
	var s snapshot
	if r.status != http.StatusOK || json.Unmarshal(r.body, &s) != nil {
		t.Fatalf("want a settings snapshot, got %d %s", r.status, r.body)
	}
	return s
}

// runOnce runs Core with args to its end (or to a short watchdog): the exit status and the log.
func runOnce(t *testing.T, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var stderr syncBuffer
	code := run(ctx, args, &stderr)
	return code, stderr.String()
}

func TestCoreServesTheAdaptersSettings(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, map[string]any{"control": true, "decisionCacheMax": 500}))
	c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
	snap := snapshotOf(t, c.post("GetSettings", `{}`))
	if !snap.Initialized || snap.Revision != 5 || len(snap.Projections) != 1 || snap.Projections[0].Value["control"] != true ||
		snap.Projections[0].Value["decisionCacheMax"] != float64(500) || snap.Projections[0].Value["replyLogging"] != true {
		t.Errorf("GetSettings = %+v, want the adapter's revision 5, control on, cap 500 and the defaults", snap)
	}
	if !strings.Contains(c.stderr.String(), "settings: adapter revision 5") {
		t.Errorf("the log does not say which backend Core reads, and at which revision:\n%s", c.stderr.String())
	}
}

func TestTheFileBackendIsTheDefaultAndNeedsNoAdapter(t *testing.T) {
	dir := scratchDir(t)
	c := startCore(t, dir)
	if !strings.Contains(c.stderr.String(), "settings: file revision 0") {
		t.Errorf("the log of a fresh Core does not say it reads its file at revision 0:\n%s", c.stderr.String())
	}
	if r := c.post("InitializeSettings", `{"requestId":"i","settings":{}}`); r.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", r.status, r.body)
	}
	c.stop()
	again := startCore(t, dir)
	if !strings.Contains(again.stderr.String(), "settings: file revision 1") {
		t.Errorf("the log after a restart does not say file revision 1:\n%s", again.stderr.String())
	}
}

func TestSettingsChangedMakesCoreReadTheAdapterAgain(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, nil))
	c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
	f.reply(readReply(t, 6, map[string]any{"idnMode": "on"}))
	snap := snapshotOf(t, c.post("SettingsChanged", `{}`))
	if !snap.Initialized || snap.Revision != 6 || len(snap.Projections) != 1 || snap.Projections[0].Value["idnMode"] != "on" {
		t.Errorf("SettingsChanged = %+v, want what the adapter now holds: revision 6, idnMode on", snap)
	}
	if got := snapshotOf(t, c.post("GetSettings", `{}`)); got.Revision != 6 || got.Projections[0].Value["idnMode"] != "on" {
		t.Errorf("GetSettings afterwards = %+v, want the values SettingsChanged read", got)
	}
	wantError(t, c.post("SettingsChanged", `{"nosuch":1}`), http.StatusBadRequest, codeInvalidArgument, "nosuch")
}

func TestSettingsChangedAnswersUnavailableWhileTheAdapterFailsAndRecovers(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, map[string]any{"control": true}))
	c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
	f.failing()
	failed := c.post("SettingsChanged", `{}`)
	wantError(t, failed, http.StatusServiceUnavailable, codeUnavailable)
	if !bytes.Contains(failed.body, []byte("config.xml is locked")) || !bytes.Contains(failed.body, []byte("the settings backend failed")) {
		t.Errorf("the error does not name the adapter's cause: %s", failed.body)
	}
	if snap := snapshotOf(t, c.post("GetSettings", `{}`)); snap.Revision != 5 || snap.Projections[0].Value["control"] != true {
		t.Errorf("GetSettings after the failed read = %+v, want the last values (revision 5, control on)", snap)
	}
	f.script(`cat > "$D/req"; cat "$D/reply"`)
	f.reply(readReply(t, 6, nil))
	if snap := snapshotOf(t, c.post("SettingsChanged", `{}`)); snap.Revision != 6 {
		t.Errorf("SettingsChanged after the adapter recovered = %+v, want revision 6", snap)
	}
}

func TestSaveSettingsGoesThroughTheAdapterAndWritesNothingInTheStateDirectory(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, nil))
	c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
	f.reply(`{"version":1,"revision":9}`)
	saved := c.post("SaveSettings", `{"requestId":"s1","expectedRevision":5,"changes":{"dns":{"control":true}}}`)
	if saved.status != http.StatusOK || !bytes.Contains(saved.body, []byte(`"revision":9`)) {
		t.Fatalf("SaveSettings = %d %s, want the adapter's revision 9", saved.status, saved.body)
	}
	if req := f.request(); !strings.HasPrefix(req, `{"version":1,"op":"write","expectedRevision":5,"settings":{"dns":{`) ||
		!strings.Contains(req, `"control":true`) {
		t.Errorf("the adapter was sent %s, want a version 1 write at revision 5 with control on", req)
	}
	if got := snapshotOf(t, c.post("GetSettings", `{}`)); got.Revision != 9 || got.Projections[0].Value["control"] != true {
		t.Errorf("GetSettings after the save = %+v, want revision 9 with control on", got)
	}
	entries, err := os.ReadDir(c.state)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !strings.Contains(strings.Join(names, " "), "core.lock") {
		t.Fatalf("the state directory holds %v, want core.lock at least: the listing proves nothing otherwise", names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "settings.json") {
			t.Errorf("Core wrote %s in the state directory over an adapter backend", n)
		}
	}
}

func TestAnAdaptersRefusalOfASaveMapsToTheAPICodes(t *testing.T) {
	cases := []struct {
		name, reply string
		status      int
		code        string
		fields      []string
	}{
		{"conflict", `{"version":1,"error":{"code":"conflict","message":"config.xml is at revision 8"}}`, http.StatusConflict, codeConflict,
			[]string{"expectedRevision"}},
		{"invalid_argument", `{"version":1,"error":{"code":"invalid_argument","message":"bad",` +
			`"fieldErrors":[{"field":"dns.decisionCacheMax","message":"too big"}]}}`, http.StatusBadRequest, codeInvalidArgument,
			[]string{"changes.dns.decisionCacheMax"}},
		{"unavailable", `{"version":1,"error":{"code":"unavailable","message":"write_config refused"}}`, http.StatusServiceUnavailable,
			codeUnavailable, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAdapter(t, readReply(t, 5, nil))
			c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
			f.reply(tc.reply)
			wantError(t, c.post("SaveSettings", `{"requestId":"s1","expectedRevision":5,"changes":{"dns":{"control":true}}}`),
				tc.status, tc.code, tc.fields...)
			if snap := snapshotOf(t, c.post("GetSettings", `{}`)); snap.Revision != 5 || snap.Projections[0].Value["control"] != false {
				t.Errorf("GetSettings after the refused save = %+v, want revision 5 and control off", snap)
			}
		})
	}
}

func TestInitializeSettingsIsRefusedOverTheAdapterWithoutAskingItToWrite(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, nil))
	c := startCore(t, scratchDir(t), "--settings-backend-cmd", f.path)
	wantError(t, c.post("InitializeSettings", `{"requestId":"i1","settings":{"dns":{"control":true}}}`), http.StatusConflict, codeConflict)
	if f.runs() != 1 || strings.Contains(f.request(), `"write"`) {
		t.Errorf("the adapter ran %d times, last asked %s: want only the start's read", f.runs(), f.request())
	}
}

func TestRunExitsOneAndLogsTheCauseWhenTheAdapterFailsAtStart(t *testing.T) {
	f := newFakeAdapter(t, "")
	f.failing()
	code, log := runOnce(t, coreArgs(scratchDir(t), "run", "--settings-backend-cmd", f.path)...)
	if code != 1 {
		t.Errorf("run over a failing adapter = %d, want 1 (the supervisor restarts it)", code)
	}
	if !strings.Contains(log, "exit status 1") || !strings.Contains(log, "config.xml is locked") {
		t.Errorf("the log does not name the adapter's failure:\n%s", log)
	}
	if strings.Contains(log, "serving API") {
		t.Errorf("Core served without settings:\n%s", log)
	}
}

// One Core per state directory, whichever backend it reads: a second would be a second writer next to the first.
func TestASecondCoreOnTheSameStateDirectoryIsRefused(t *testing.T) {
	f := newFakeAdapter(t, readReply(t, 5, nil))
	for name, extra := range map[string][]string{"file backend": nil, "adapter backend": {"--settings-backend-cmd", f.path}} {
		t.Run(name, func(t *testing.T) {
			dir := scratchDir(t)
			first := startCore(t, dir, extra...)
			code, log := runOnce(t, coreArgs(dir, "run2", extra...)...)
			if code != 1 || !strings.Contains(log, "in use by another Core") {
				t.Errorf("a second Core on the state directory = %d, want 1 saying it is in use by another Core; its log:\n%s", code, log)
			}
			if r := first.post("GetVersion", `{}`); r.status != http.StatusOK {
				t.Errorf("the first Core stopped serving: %d %s", r.status, r.body)
			}
			if code := first.stop(); code != 0 {
				t.Errorf("the first Core exited %d, want 0", code)
			}
			startCore(t, dir, extra...) // the lock went with the first Core
		})
	}
}

func TestTheUsageNamesTheSettingsBackendFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"--socket", filepath.Join(scratchDir(t), "api.sock")}, &stderr); code != 2 {
		t.Errorf("run without --state-dir = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--settings-backend-cmd") {
		t.Errorf("the usage does not name --settings-backend-cmd: %q", stderr.String())
	}
}

func TestSettingsChangedOverTheFileBackendRereadsItsFile(t *testing.T) {
	h, dir := startSettingsIn(t)
	if r := h.post("/v1/InitializeSettings", `{"requestId":"i1","settings":{"dns":{"control":true}}}`); r.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", r.status, r.body)
	}
	want := h.post("/v1/GetSettings", `{}`)
	wantJSON(t, h.post("/v1/SettingsChanged", `{}`), http.StatusOK, string(want.body))

	file := filepath.Join(dir, "settings.json")
	good, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"format": 1, "revision": `), 0o600); err != nil {
		t.Fatal(err)
	}
	wantError(t, h.post("/v1/SettingsChanged", `{}`), http.StatusServiceUnavailable, codeUnavailable)
	wantJSON(t, h.post("/v1/GetSettings", `{}`), http.StatusOK, string(want.body))
	if err := os.WriteFile(file, good, 0o600); err != nil {
		t.Fatal(err)
	}
	wantJSON(t, h.post("/v1/SettingsChanged", `{}`), http.StatusOK, string(want.body))
}
