package settings

import (
	"testing"
)

func TestScheduleCategoryProviderKeepsConfiguredTitle(t *testing.T) {
	backend := newRefreshBackend(1, map[string]map[string]any{
		"schedule": {
			"categoryProviders": []any{map[string]any{
				"id": "work", "title": "Work", "selected": true, "categories": "adult",
			}},
		},
	})
	store, err := Load(backend, Production())
	if err != nil {
		t.Fatalf("load provider title: %v", err)
	}
	schedule, err := store.GetClear("schedule")
	if err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	providers, ok := schedule["categoryProviders"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("categoryProviders = %#v, want one provider", schedule["categoryProviders"])
	}
	provider, ok := providers[0].(map[string]any)
	if !ok || provider["title"] != "Work" {
		t.Fatalf("category provider = %#v, want read-only title Work", providers[0])
	}
}
