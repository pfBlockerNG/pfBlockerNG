package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// fieldErrorsOf is the fieldErrors array of an error reply, as JSON text.
func fieldErrorsOf(t *testing.T, r reply) string {
	t.Helper()
	var env struct {
		Error struct {
			FieldErrors json.RawMessage `json:"fieldErrors"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.body, &env); err != nil {
		t.Fatalf("not an error reply: %v\n%s", err, r.body)
	}
	return string(env.Error.FieldErrors)
}

func TestValidateSettingsIsADryRunOfSaveSettings(t *testing.T) {
	h := startSettings(t)
	h.post("/v1/InitializeSettings", `{"requestId":"i1","settings":{"dns":{"decisionCacheMax":500}}}`)
	before := h.post("/v1/GetSettings", `{}`)

	cases := []struct {
		name, changes string
		invalid       bool
		field         string
	}{
		{"cache over the maximum", `{"dns":{"decisionCacheMax":5000001}}`, true, "changes.dns.decisionCacheMax"},
		{"cache negative", `{"dns":{"decisionCacheMax":-1}}`, true, "changes.dns.decisionCacheMax"},
		{"cache a string", `{"dns":{"decisionCacheMax":"abc"}}`, true, "changes.dns.decisionCacheMax"},
		{"cache a fraction", `{"dns":{"decisionCacheMax":1.5}}`, true, "changes.dns.decisionCacheMax"},
		{"cache null is the default", `{"dns":{"decisionCacheMax":null}}`, false, ""},
		{"idnMode outside the enum", `{"dns":{"idnMode":"all"}}`, true, "changes.dns.idnMode"},
		{"idnMode empty", `{"dns":{"idnMode":""}}`, true, "changes.dns.idnMode"},
		{"unknown field", `{"dns":{"nosuch":1}}`, true, "changes.dns.nosuch"},
		{"unknown projection", `{"nosuch":{}}`, true, "changes.nosuch"},
		{"controlLegacy over a held control", `{"dns":{"controlLegacy":true}}`, false, ""},
		{"valid", `{"dns":{"control":true,"decisionCacheMax":700}}`, false, ""},
		{"empty", `{}`, false, ""},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := h.post("/v1/ValidateSettings", `{"changes":`+c.changes+`}`)
			if !c.invalid {
				wantJSON(t, got, http.StatusOK, `{}`)
				return
			}
			wantError(t, got, http.StatusBadRequest, codeInvalidArgument, c.field)
			// The same changes through SaveSettings (at the revision the store holds) give the same field errors.
			save := h.post("/v1/SaveSettings", `{"requestId":"s`+strconv.Itoa(i)+`","expectedRevision":1,"changes":`+c.changes+`}`)
			wantError(t, save, http.StatusBadRequest, codeInvalidArgument, c.field)
			if v, s := fieldErrorsOf(t, got), fieldErrorsOf(t, save); v != s {
				t.Errorf("ValidateSettings fieldErrors %s, SaveSettings %s, want them equal", v, s)
			}
		})
	}

	if after := h.post("/v1/GetSettings", `{}`); !bytes.Equal(after.body, before.body) {
		t.Errorf("GetSettings changed:\n before %s\n after  %s", before.body, after.body)
	}
}

func TestValidateSettingsWritesNothingWhenValid(t *testing.T) {
	h := startSettings(t)
	h.post("/v1/InitializeSettings", `{"requestId":"i1","settings":{}}`)
	before := h.post("/v1/GetSettings", `{}`)

	wantJSON(t, h.post("/v1/ValidateSettings", `{"changes":{"dns":{"control":true}}}`), http.StatusOK, `{}`)

	if after := h.post("/v1/GetSettings", `{}`); !bytes.Equal(after.body, before.body) {
		t.Errorf("GetSettings changed:\n before %s\n after  %s", before.body, after.body)
	}
}

func TestValidateSettingsBeforeInitializationChecksTheDefaultsAndLeavesCoreUninitialized(t *testing.T) {
	h := startSettings(t)
	wantJSON(t, h.post("/v1/ValidateSettings", `{"changes":{"dns":{"control":true}}}`), http.StatusOK, `{}`)
	wantError(t, h.post("/v1/ValidateSettings", `{"changes":{"dns":{"decisionCacheMax":5000001}}}`),
		http.StatusBadRequest, codeInvalidArgument, "changes.dns.decisionCacheMax")
	wantJSON(t, h.post("/v1/GetSettings", `{}`), http.StatusOK, `{"initialized":false,"revision":0,"projections":[]}`)
}

func TestValidateSettingsTakesNoRequestID(t *testing.T) {
	h := startSettings(t)
	wantError(t, h.post("/v1/ValidateSettings", `{"requestId":"x","changes":{}}`),
		http.StatusBadRequest, codeInvalidArgument, "requestId")
	wantError(t, h.post("/v1/ValidateSettings", `{"expectedRevision":1,"changes":{}}`),
		http.StatusBadRequest, codeInvalidArgument, "expectedRevision")
}

func TestValidateSettingsRefusesChangesThatAreNotAProjectionMap(t *testing.T) {
	h := startSettings(t)
	wantError(t, h.post("/v1/ValidateSettings", `{"changes":[]}`), http.StatusBadRequest, codeInvalidArgument, "changes")
	wantError(t, h.post("/v1/ValidateSettings", `{"changes":"x"}`), http.StatusBadRequest, codeInvalidArgument, "changes")
	wantError(t, h.post("/v1/ValidateSettings", `{"changes":{"dns":[]}}`), http.StatusBadRequest, codeInvalidArgument, "changes.dns")
}
