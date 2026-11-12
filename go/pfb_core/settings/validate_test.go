package settings

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// validationErr is err's fields; a nil error is nil, anything but a *ValidationError fails the test.
func validationErr(t *testing.T, what string, err error) []FieldError {
	t.Helper()
	if err == nil {
		return nil
	}
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("%s = %v, want nil or a *ValidationError", what, err)
	}
	return v.Fields
}

// storeBytes is the store file as it stands.
func storeBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, storeFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateAcceptsAValidChangeAndWritesNothing(t *testing.T) {
	st, dir := initialized(t)
	before := get(t, st)
	file := storeBytes(t, dir)

	if err := st.Validate(changes(t, `{"dns": {"control": true, "decisionCacheMax": 700}}`)); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}

	after := get(t, st)
	if jsonOf(t, after) != jsonOf(t, before) {
		t.Errorf("Get after Validate:\n have %s\n want %s", jsonOf(t, after), jsonOf(t, before))
	}
	dns := projection(t, after, "dns")
	if after.Revision != 1 || dns.Generation != 1 || dns.Value["control"] != false || dns.Value["decisionCacheMax"] != int64(500) {
		t.Errorf("after Validate: revision %d, dns %+v, want revision 1, generation 1, control off, cap 500", after.Revision, dns)
	}
	if !bytes.Equal(storeBytes(t, dir), file) {
		t.Error("Validate changed settings.json")
	}
	if _, err := os.Stat(filepath.Join(dir, storeFile+".tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Validate left settings.json.tmp: %v", err)
	}
}

// Every case is checked against what Save gives for the same changes on an identical store.
func TestValidateSaysWhatSaveWouldSay(t *testing.T) {
	cases := []struct {
		name    string
		changes string
		invalid bool
	}{
		{"cache over the maximum", `{"dns": {"decisionCacheMax": 5000001}}`, true},
		{"cache negative", `{"dns": {"decisionCacheMax": -1}}`, true},
		{"cache a string", `{"dns": {"decisionCacheMax": "abc"}}`, true},
		{"cache a fraction", `{"dns": {"decisionCacheMax": 1.5}}`, true},
		{"cache null is the default", `{"dns": {"decisionCacheMax": null}}`, false},
		{"cache at the maximum", `{"dns": {"decisionCacheMax": 5000000}}`, false},
		{"idnMode outside the enum", `{"dns": {"idnMode": "all"}}`, true},
		{"idnMode empty", `{"dns": {"idnMode": ""}}`, true},
		{"idnMode in the enum", `{"dns": {"idnMode": "on"}}`, false},
		{"a bool that is a string", `{"dns": {"control": "yes"}}`, true},
		{"unknown projection", `{"nosuch": {"a": 1}}`, true},
		{"unknown field", `{"dns": {"nosuch": 1}}`, true},
		{"unknown projection and field and value", `{"nosuch": {}, "dns": {"nosuch": 1, "decisionCacheMax": -1}}`, true},
		{"controlLegacy over a held control", `{"dns": {"controlLegacy": true}}`, false},
		{"nothing", `{}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, dir := initialized(t)
			file := storeBytes(t, dir)
			ch := changes(t, c.changes)

			vFields := validationErr(t, "Validate", st.Validate(ch))
			if (vFields != nil) != c.invalid {
				t.Fatalf("Validate fields = %v, want invalid: %v", vFields, c.invalid)
			}
			if !bytes.Equal(storeBytes(t, dir), file) || get(t, st).Revision != 1 {
				t.Fatal("Validate changed the store")
			}

			_, saveErr := st.Save(1, ch)
			if sFields := validationErr(t, "Save", saveErr); !reflect.DeepEqual(vFields, sFields) {
				t.Errorf("Validate fields %v, Save fields %v, want them equal", vFields, sFields)
			}
		})
	}
}

func TestValidateNamesUnknownProjectionsAndFieldsLikeSave(t *testing.T) {
	st, _ := initialized(t)
	got := validationErr(t, "Validate", st.Validate(changes(t, `{"nosuch": {"a": 1}, "dns": {"nosuch": 1}}`)))
	want := []FieldError{{Field: "dns.nosuch", Message: "no such field"}, {Field: "nosuch", Message: "no such projection"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Validate fields = %v, want %v", got, want)
	}
}

func TestValidateOnAnUninitializedStoreChecksAgainstTheDefaultsAndStaysUninitialized(t *testing.T) {
	dir := t.TempDir()
	st := open(t, dir)

	if err := st.Validate(changes(t, `{"dns": {"control": true, "controlLegacy": true}}`)); err != nil {
		t.Fatalf("Validate of a valid change = %v, want nil", err)
	}
	bad := changes(t, `{"dns": {"decisionCacheMax": 5000001}, "nosuch": {}}`)
	got := validationErr(t, "Validate", st.Validate(bad))
	if len(got) != 2 {
		t.Errorf("Validate of an invalid change: fields %v, want decisionCacheMax and nosuch", got)
	}

	if snap := get(t, st); snap.Initialized || snap.Revision != 0 || len(snap.Projections) != 0 {
		t.Errorf("Get after Validate = %s, want still uninitialized", jsonOf(t, snap))
	}
	if _, err := os.Stat(filepath.Join(dir, storeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Validate made settings.json: %v", err)
	}

	other := open(t, t.TempDir())
	_, initErr := other.Initialize(bad)
	if want := validationErr(t, "Initialize", initErr); !reflect.DeepEqual(got, want) {
		t.Errorf("Validate fields %v, Initialize fields %v, want them equal", got, want)
	}
}

func TestValidateOfARequiresRuleHoldsTheFieldAndWritesNothing(t *testing.T) {
	st, dir := initialized(t)
	file := storeBytes(t, dir)

	if err := st.Validate(changes(t, `{"dns": {"controlLegacy": true}}`)); err != nil {
		t.Fatalf("Validate = %v, want nil (controlLegacy is held false while control is off)", err)
	}

	if dns := projection(t, get(t, st), "dns"); dns.Value["controlLegacy"] != false || dns.Generation != 1 {
		t.Errorf("dns after Validate = %+v, want controlLegacy false at generation 1", dns)
	}
	if !bytes.Equal(storeBytes(t, dir), file) {
		t.Error("Validate changed settings.json")
	}
}
