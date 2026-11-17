package settings

import "strings"

// hooksProjection is settings/hooks (issue #4031): the Update hook rows, in list order, as the Outpost's Hooks page stores
// them. It is read-only: the Outpost owns the rows. A script is a file name of the hook directory named for its row's fire
// point; whether the file exists is checked where the hook runs. tests/core/fixtures/settings_hooks_parity.json is the parity
// fixture.
func hooksProjection() Projection {
	return Projection{ID: "hooks", ReadOnly: true, Fields: []Field{
		{Name: "rows", Type: TypeList, Default: []any{}, Key: "id", Check: checkHook, Items: []Field{
			{Name: "id", Type: TypeString, Default: "", Pattern: `^(?:0|[1-9][0-9]*)$`}, // the row's index in the stored list
			{Name: "when", Type: TypeEnum, Default: "pre", Enum: []string{"pre", "post"}},
			{Name: "script", Type: TypeString, Default: "", Pattern: `^hook_(?:pre|post)_[^/\p{C}]*\.(?:sh|py)$`},
			{Name: "description", Type: TypeString, Default: "", Pattern: `^[^\p{C}]*$`},
			{Name: "timeout", Type: TypeInt, Default: int64(60), Min: new(int64(1))}, // seconds
			{Name: "enabled", Type: TypeBool, Default: false},
		}},
	}}
}

// checkHook holds a row's script to its fire point: hook_pre_* runs at pre, hook_post_* at post.
func checkHook(item map[string]any) []FieldError {
	if !strings.HasPrefix(item["script"].(string), "hook_"+item["when"].(string)+"_") {
		return []FieldError{{Field: "script", Message: "must be named for the row's fire point: hook_<when>_"}}
	}
	return nil
}
