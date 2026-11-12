package main

import (
	"bytes"
	"net/http"
	"testing"
)

// A repeated InitializeSettings (same requestId, same body) replays its first result instead of answering a conflict.
func TestARepeatedInitializeSettingsReplaysTheFirstResult(t *testing.T) {
	h := startSettings(t)
	body := `{"requestId":"init-1","settings":{"dns":{"control":true}}}`
	first := h.post("/v1/InitializeSettings", body)
	if first.status != http.StatusOK {
		t.Fatalf("InitializeSettings = %d %s", first.status, first.body)
	}
	if again := h.post("/v1/InitializeSettings", body); again.status != first.status || !bytes.Equal(again.body, first.body) {
		t.Errorf("the repeat got %d %s, want the first result %d %s", again.status, again.body, first.status, first.body)
	}
}
