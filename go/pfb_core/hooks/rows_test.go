package hooks_test

import (
	"reflect"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
)

// Rows reads the settings/hooks projection as Store.GetClear("hooks") answers it: every row, disabled ones too, in list
// order. Selecting the fire point's enabled rows is the runner's.
func TestRowsReadTheHooksProjectionInListOrder(t *testing.T) {
	value := map[string]any{"rows": []any{
		map[string]any{"id": "0", "when": "pre", "script": "hook_pre_a.sh", "description": "First", "timeout": int64(30),
			"enabled": true},
		map[string]any{"id": "2", "when": "post", "script": "hook_post_b.py", "description": "", "timeout": int64(60),
			"enabled": false},
	}}
	want := []hooks.Hook{
		{When: "pre", Script: "hook_pre_a.sh", Description: "First", Timeout: 30, Enabled: true},
		{When: "post", Script: "hook_post_b.py", Timeout: 60},
	}
	if got := hooks.Rows(value); !reflect.DeepEqual(got, want) {
		t.Errorf("Rows = %+v; want %+v", got, want)
	}
	if got := hooks.Rows(map[string]any{"rows": []any{}}); len(got) != 0 {
		t.Errorf("Rows of no rows = %+v; want none", got)
	}
}
