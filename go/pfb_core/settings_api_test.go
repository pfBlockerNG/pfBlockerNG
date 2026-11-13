package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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
