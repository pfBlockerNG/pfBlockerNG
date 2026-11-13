package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// startSettings serves the production methods and the settings methods over a store in a fresh state directory.
func startSettings(t *testing.T) *harness {
	t.Helper()
	h, _ := startSettingsIn(t)
	return h
}

// startSettingsIn is startSettings that also names the state directory the store's file lives in.
func startSettingsIn(t *testing.T) (*harness, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := settings.Open(dir, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return start(t, func(o *options) {
		for name, m := range settingsMethods(st) {
			o.methods[name] = m
		}
	}, nil), dir
}

// dnsGeneration is the generation GetSettings shows for settings/dns.
func dnsGeneration(t *testing.T, h *harness) uint64 {
	t.Helper()
	got := h.post("/v1/GetSettings", `{"projectionIds":["dns"]}`)
	var snap struct {
		Projections []struct {
			Generation uint64 `json:"generation"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(got.body, &snap); err != nil || len(snap.Projections) != 1 {
		t.Fatalf("GetSettings = %s (%v), want one projection", got.body, err)
	}
	return snap.Projections[0].Generation
}

func TestGetSettingsSchemaAnswersTheNativeSchema(t *testing.T) {
	h := startSettings(t)
	want, err := json.Marshal(settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	wantJSON(t, h.post("/v1/GetSettingsSchema", `{}`), http.StatusOK, string(want))
}

func TestTheSettingsMethodsOverTheAPI(t *testing.T) {
	h := startSettings(t)
	wantJSON(t, h.post("/v1/GetSettings", `{}`), http.StatusOK, `{"initialized":false,"revision":0,"projections":[]}`)
	wantError(t, h.post("/v1/SaveSettings", `{"requestId":"s0","expectedRevision":0,"changes":{"dns":{"control":true}}}`),
		http.StatusConflict, codeConflict)

	init := h.post("/v1/InitializeSettings", `{"requestId":"i1","settings":{"dns":{"decisionCacheMax":500}}}`)
	if init.status != http.StatusOK || !bytes.Contains(init.body, []byte(`"revision":1`)) ||
		!bytes.Contains(init.body, []byte(`"resourceId":"settings/dns"`)) {
		t.Fatalf("InitializeSettings = %d %s, want revision 1 with settings/dns", init.status, init.body)
	}
	wantError(t, h.post("/v1/InitializeSettings", `{"requestId":"i2","settings":{}}`), http.StatusConflict, codeConflict)
	initialGeneration := dnsGeneration(t, h)

	wantError(t, h.post("/v1/SaveSettings", `{"requestId":"s1","expectedRevision":1,"changes":{"dns":{"decisionCacheMax":5000001,"control":true}}}`),
		http.StatusBadRequest, codeInvalidArgument, "changes.dns.decisionCacheMax")
	wantError(t, h.post("/v1/SaveSettings", `{"requestId":"s2","changes":{}}`), http.StatusBadRequest, codeInvalidArgument, "expectedRevision")

	save := `{"requestId":"s3","expectedRevision":1,"changes":{"dns":{"control":true}}}`
	first := h.post("/v1/SaveSettings", save)
	if first.status != http.StatusOK || !bytes.Contains(first.body, []byte(`"revision":2`)) {
		t.Fatalf("SaveSettings = %d %s, want revision 2", first.status, first.body)
	}
	if again := h.post("/v1/SaveSettings", save); again.status != first.status || !bytes.Equal(again.body, first.body) {
		t.Errorf("a repeated requestId did not replay the first result:\n first %d %s\n again %d %s", first.status, first.body,
			again.status, again.body)
	}
	wantError(t, h.post("/v1/SaveSettings", `{"requestId":"s4","expectedRevision":1,"changes":{"dns":{"regexCap":true}}}`),
		http.StatusConflict, codeConflict, "expectedRevision")

	got := h.post("/v1/GetSettings", `{"projectionIds":["dns"]}`)
	var snap struct {
		Initialized bool   `json:"initialized"`
		Revision    uint64 `json:"revision"`
		Projections []struct {
			ResourceID string         `json:"resourceId"`
			Generation uint64         `json:"generation"`
			Value      map[string]any `json:"value"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(got.body, &snap); err != nil {
		t.Fatalf("GetSettings: %v\n%s", err, got.body)
	}
	if !snap.Initialized || snap.Revision != 2 || len(snap.Projections) != 1 || snap.Projections[0].Generation == initialGeneration ||
		snap.Projections[0].Value["control"] != true || snap.Projections[0].Value["decisionCacheMax"] != float64(500) {
		t.Errorf("GetSettings = %s, want revision 2 (the replay ran once), a dns generation other than %d, control on, cap 500",
			got.body, initialGeneration)
	}
	wantError(t, h.post("/v1/GetSettings", `{"projectionIds":["nosuch"]}`), http.StatusBadRequest, codeInvalidArgument,
		"projectionIds[0]")
}

func TestRunNeedsTheStateDirFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"--socket", filepath.Join(scratchDir(t), "api.sock")}, &stderr); code != 2 {
		t.Errorf("run without --state-dir = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--state-dir") {
		t.Errorf("stderr does not name --state-dir: %q", stderr.String())
	}
}

func TestRunKeepsSettingsAcrossARestart(t *testing.T) {
	dir := scratchDir(t)
	socket, state := filepath.Join(dir, "run", "api.sock"), filepath.Join(dir, "state")
	client := &http.Client{Timeout: watchdog, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	serve := func(method, body string) string {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		var stderr syncBuffer
		code := make(chan int, 1)
		go func() {
			code <- run(ctx, []string{"--socket", socket, "--state-dir", state, "--allow-uid", strconv.Itoa(os.Getuid())}, &stderr)
		}()
		waitFor(t, func() bool { return strings.Contains(stderr.String(), "serving API v1 on "+socket) })
		resp, err := client.Post("http://pfb-core/v1/"+method, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		client.CloseIdleConnections()
		cancel()
		if c := <-code; c != 0 {
			t.Errorf("run = %d, want 0; stderr:\n%s", c, stderr.String())
		}
		return string(got)
	}
	if got := serve("InitializeSettings", `{"requestId":"i","settings":{"dns":{"idnMode":"on"}}}`); !strings.Contains(got, `"revision":1`) {
		t.Fatalf("InitializeSettings = %s", got)
	}
	info, err := os.Lstat(state)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("state directory = %v %v, want mode 0700", info, err)
	}
	if got := serve("GetSettings", `{}`); !strings.Contains(got, `"initialized":true,"revision":1`) || !strings.Contains(got, `"idnMode":"on"`) {
		t.Errorf("GetSettings after a restart = %s, want revision 1 with idnMode on", got)
	}
}

// adapterStore loads the production schema from a #!/bin/sh adapter that runs onRead for a read and onWrite for a write; $D
// is its directory. The adapter's own timeouts are a minute: a backstop the method's context must beat.
func adapterStore(t *testing.T, onRead, onWrite string) (*settings.Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "adapter.sh")
	script := "#!/bin/sh\nD='" + dir + "'\nreq=$(cat)\ncase \"$req\" in\n*'\"op\":\"write\"'*)\n" + onWrite + "\n;;\n*)\n" + onRead + "\n;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := settings.Load(&settings.AdapterBackend{Path: path, ReadTimeout: time.Minute, WriteTimeout: time.Minute}, settings.Production())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return st, dir
}

const (
	adapterReads  = `echo '{"version":1,"revision":1,"settings":{}}'`
	adapterWrites = `echo '{"version":1,"revision":2}'`
	// adapterStalls records its pid and a child's, says it started, and never answers.
	adapterStalls = `sleep 600 & echo $! > "$D/child"; echo $$ > "$D/pid"; true > "$D/started"; exec sleep 600`
	// adapterConflicts refuses a write: the configuration moved under Core.
	adapterConflicts = `echo '{"version":1,"error":{"code":"conflict","message":"the configuration moved"}}'`
	// adapterStallsAfterLoad answers the read that loads the store and stalls on every read after it.
	adapterStallsAfterLoad = `if [ -e "$D/loaded" ]; then ` + adapterStalls + `; fi; true > "$D/loaded"; ` + adapterReads
	saveParams             = `{"requestId":"r1","expectedRevision":1,"changes":{"dns":{"idnMode":"on"}}}`
)

// pidIn is the pid the adapter recorded in dir/name.
func pidIn(dir, name string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// exited reports whether pid is no longer a live process; a zombie counts as exited (a bare container may not reap it).
func exited(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	return err == nil && bytes.HasPrefix(stat[bytes.LastIndexByte(stat, ')')+2:], []byte("Z"))
}

// awaitExit reports through t unless pid stops being a live process within the watchdog: the kill that ends a call lands
// a moment after the call returns.
func awaitExit(t *testing.T, what string, pid int) {
	t.Helper()
	for deadline := time.Now().Add(watchdog); !exited(pid); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Errorf("STUCK: the adapter's %s %d is still alive %v after the call returned", what, pid, watchdog)
			return
		}
	}
}

// awaitAdapterGone waits for the stalled adapter in dir and the child it started to be gone.
func awaitAdapterGone(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"pid", "child"} {
		pid, err := pidIn(dir, name)
		if err != nil {
			t.Fatalf("ENVIRONMENT: the adapter's %s: %v", name, err)
		}
		awaitExit(t, name, pid)
	}
}

// stalledCall runs method on a store whose adapter stalls in the leg onRead/onWrite names, cancels the call's context once
// the adapter says it started, and returns the adapter's directory and the call's result. The adapter's group dies with
// the test whatever happens.
func stalledCall(t *testing.T, method, params, onRead, onWrite string) (string, any, error) {
	t.Helper()
	st, dir := adapterStore(t, onRead, onWrite)
	t.Cleanup(func() {
		if pid, err := pidIn(dir, "pid"); err == nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type outcome struct {
		res any
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := settingsMethods(st)[method].call(ctx, []byte(params))
		done <- outcome{res, err}
	}()
	waitFor(t, func() bool { _, err := os.Stat(filepath.Join(dir, "started")); return err == nil })
	cancel()
	select {
	case o := <-done:
		return dir, o.res, o.err
	case <-time.After(watchdog):
		t.Fatalf("STUCK: %s did not end within the %v watchdog after its context was cancelled", method, watchdog)
		return dir, nil, nil
	}
}

func notAnAPIError(t *testing.T, err error) {
	t.Helper()
	var e *apiError
	if errors.As(err, &e) {
		t.Errorf("err = %v, want one that is no *apiError (the server maps it to internal, logged), got code %s", err, e.Code)
	}
}

func TestASaveSettingsWhoseMethodDeadlineHasPassedWritesNothing(t *testing.T) {
	st, dir := adapterStore(t, adapterReads, `true > "$D/wrote"; `+adapterWrites)
	ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer cancel()
	_, err := settingsMethods(st)["SaveSettings"].call(ctx, []byte(saveParams))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("SaveSettings = %v, want an error that is context.DeadlineExceeded", err)
	}
	notAnAPIError(t, err)
	if _, statErr := os.Stat(filepath.Join(dir, "wrote")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the adapter was asked to write after the method's deadline had passed: stat %s/wrote = %v", dir, statErr)
	}
}

func TestAStalledAdapterWriteEndsWhenTheMethodsContextEnds(t *testing.T) {
	dir, _, err := stalledCall(t, "SaveSettings", saveParams, adapterReads, adapterStalls)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("SaveSettings = %T: %v, want an error that is context.Canceled", err, err)
	}
	notAnAPIError(t, err)
	awaitAdapterGone(t, dir)
}

func TestAStalledAdapterReadEndsWhenTheMethodsContextEnds(t *testing.T) {
	// The Load read answers; every read after it stalls, so SettingsChanged's Reload is the one that hangs.
	_, _, err := stalledCall(t, "SettingsChanged", `{}`, adapterStallsAfterLoad, adapterWrites)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("SettingsChanged = %T: %v, want an error that is context.Canceled", err, err)
	}
	notAnAPIError(t, err)
	var b *settings.BackendError
	if errors.As(err, &b) {
		t.Errorf("SettingsChanged = %v, want no *settings.BackendError (it maps to unavailable)", err)
	}
}

func TestASaveSettingsWhoseReReadIsCutOffStillAnswersTheRevisionItWrote(t *testing.T) {
	// The write answers; the read that follows it stalls until the method's context ends, and that read is best effort.
	dir, res, err := stalledCall(t, "SaveSettings", saveParams, adapterStallsAfterLoad, adapterWrites)
	if err != nil {
		t.Fatalf("SaveSettings = %T: %v, want the save the adapter took", err, err)
	}
	if got, ok := res.(settings.Result); !ok || got.Revision != 2 {
		t.Errorf("SaveSettings = %#v, want a settings.Result at revision 2, the one the adapter wrote", res)
	}
	awaitAdapterGone(t, dir)
}

func TestASaveSettingsConflictIsStillAConflictWhenTheReReadItStartsIsCutOff(t *testing.T) {
	// The adapter refuses the write as a conflict; Core reads again (best effort) and that read stalls.
	dir, _, err := stalledCall(t, "SaveSettings", saveParams, adapterStallsAfterLoad, adapterConflicts)
	var e *apiError
	if !errors.As(err, &e) || e.Code != codeConflict {
		t.Errorf("SaveSettings = %T: %v, want the %s *apiError the adapter's refusal maps to", err, err, codeConflict)
	}
	awaitAdapterGone(t, dir)
}
