package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// The read-only ingest projection (issue #3975) over the API: the settings methods never show its proxy password and never
// change it. Only code inside Core's process reads the password, through Store.GetClear.

const ingestSecret = "hunter2-the-proxy-password"

// startIngest serves the settings methods over a store whose file backend holds a proxy with a password.
func startIngest(t *testing.T) (*harness, *settings.Store) {
	t.Helper()
	dir := t.TempDir()
	doc := `{"format":1,"revision":1,"projections":{"ingest":{"values":{"proxyUrl":"http://proxy.example.com:3128","proxyUser":"alice","proxyPassword":"` + ingestSecret + `"}}}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := settings.Open(dir, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	return start(t, func(o *options) {
		for name, m := range settingsMethods(st) {
			o.methods[name] = m
		}
	}, nil), st
}

func TestNoSettingsMethodShowsTheProxyPasswordOnlyThatItIsSet(t *testing.T) {
	h, st := startIngest(t)

	for _, body := range []string{`{}`, `{"projectionIds":["ingest"]}`} {
		got := h.post("/v1/GetSettings", body)
		if got.status != http.StatusOK || bytes.Contains(got.body, []byte(ingestSecret)) {
			t.Errorf("GetSettings %s = %d %s, want 200 without the password", body, got.status, got.body)
		}
		if !bytes.Contains(got.body, []byte(`"proxyPassword":{"present":true}`)) || !bytes.Contains(got.body, []byte(`"proxyUser":"alice"`)) {
			t.Errorf("GetSettings %s = %s, want the password as presence only beside the user", body, got.body)
		}
	}
	if got := h.post("/v1/SettingsChanged", `{}`); got.status != http.StatusOK || bytes.Contains(got.body, []byte(ingestSecret)) {
		t.Errorf("SettingsChanged = %d %s, want the snapshot GetSettings gives, without the password", got.status, got.body)
	}
	if plain, err := st.GetClear("ingest"); err != nil || plain["proxyPassword"] != ingestSecret {
		t.Errorf("GetClear proxyPassword = %v, %v, want the password for code in the process", plain["proxyPassword"], err)
	}
}

func TestTheSettingsMethodsRefuseAChangeToIngestAndAnInitializeThatNamesIt(t *testing.T) {
	h := startSettings(t)
	wantError(t, h.post("/v1/InitializeSettings", `{"requestId":"i0","settings":{"ingest":{"suppression":false}}}`),
		http.StatusBadRequest, codeInvalidArgument, "settings.ingest")
	if got := h.post("/v1/GetSettings", `{}`); !bytes.Contains(got.body, []byte(`"initialized":false`)) {
		t.Fatalf("the refused Initialize initialized the settings: %s", got.body)
	}
	if got := h.post("/v1/InitializeSettings", `{"requestId":"i1","settings":{}}`); got.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", got.status, got.body)
	}

	wantError(t, h.post("/v1/SaveSettings", `{"requestId":"s1","expectedRevision":1,"changes":{"ingest":{"suppression":false}}}`),
		http.StatusBadRequest, codeInvalidArgument, "changes.ingest")
	wantError(t, h.post("/v1/ValidateSettings", `{"changes":{"ingest":{"suppression":false}}}`),
		http.StatusBadRequest, codeInvalidArgument, "changes.ingest")
	if got := h.post("/v1/GetSettings", `{"projectionIds":["ingest"]}`); !bytes.Contains(got.body, []byte(`"suppression":true`)) || !bytes.Contains(got.body, []byte(`"revision":1`)) {
		t.Errorf("GetSettings after the refused changes = %s, want ingest as it was at revision 1", got.body)
	}
}

func TestGetSettingsSchemaPublishesIngestAsReadOnly(t *testing.T) {
	h := startSettings(t)
	got := h.post("/v1/GetSettingsSchema", `{}`)
	if got.status != http.StatusOK || !bytes.Contains(got.body, []byte(`"id":"ingest","readOnly":true,"fields":[`)) {
		t.Errorf("GetSettingsSchema = %d %s, want settings/ingest published readOnly", got.status, got.body)
	}
	if bytes.Count(got.body, []byte(`"readOnly"`)) != 1 {
		t.Errorf("GetSettingsSchema publishes readOnly %d times, want only for ingest", bytes.Count(got.body, []byte(`"readOnly"`)))
	}
}
