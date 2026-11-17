package settings

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestTheHooksProjectionIsReadOnlyWithOneListOfRowsKeyedById(t *testing.T) {
	p := productionProjection(t, "hooks")
	if !p.ReadOnly {
		t.Error("hooks is writable, want read-only: the Outpost's Hooks page owns the rows")
	}
	if len(p.Fields) != 1 || p.Fields[0].Name != "rows" || p.Fields[0].Type != TypeList || p.Fields[0].Key != "id" {
		t.Fatalf("hooks fields = %+v, want the one list rows keyed by id", p.Fields)
	}
	var names []string
	for _, f := range p.Fields[0].Items {
		names = append(names, f.Name)
	}
	if want := []string{"id", "when", "script", "description", "timeout", "enabled"}; !slices.Equal(names, want) {
		t.Errorf("a row's fields = %v, want %v", names, want)
	}
}

func TestTheHooksProjectionMatchesItsParityFixture(t *testing.T) {
	checkParity(t, "settings_hooks_parity.json", "hooks", "value")
}

// The rows are the Outpost's: a change set that names hooks is refused whole, whatever it holds, and nothing is written.
func TestAChangeSetThatNamesHooksIsRefusedWholeAndWritesNothing(t *testing.T) {
	for name, body := range map[string]string{
		"a valid row":     `{"hooks": {"rows": [{"id": "0", "when": "pre", "script": "hook_pre_a.sh", "description": "", "timeout": 60, "enabled": true}]}}`,
		"an empty object": `{"hooks": {}}`,
		"null":            `{"hooks": null}`,
		"beside a change": `{"dns": {"control": true}, "hooks": {"rows": []}}`,
	} {
		t.Run(name, func(t *testing.T) {
			b := ingestBackend(t, nil)
			st := storeOver(t, b)
			refused := func(method string, err error) {
				t.Helper()
				var v *ValidationError
				if !errors.As(err, &v) || len(v.Fields) != 1 || v.Fields[0].Field != "hooks" || !strings.Contains(v.Fields[0].Message, "read-only") {
					t.Errorf("%s = %v, want one ValidationError naming hooks as read-only", method, err)
				}
			}
			refused("Validate", st.Validate(changes(t, body)))
			_, err := st.Save(t.Context(), 1, changes(t, body))
			refused("Save", err)
			if b.writes != 0 || controlOf(t, st) != false {
				t.Errorf("a refused Save wrote %d times and left control %v, want nothing changed", b.writes, controlOf(t, st))
			}
		})
	}
}
