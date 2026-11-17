package settings

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// parityFixture is a parity fixture of one projection (tests/core/fixtures/settings_<name>_parity.json), frozen against today's
// PHP by its PHPUnit test. A case's value (over the fixture's defaults) is what the adapter reads from its config.xml: Core
// accepts it and reads it back as it is. A refused row is a value Core refuses to read, naming `field`: Core does not trust
// what the backend answers.
type parityFixture struct {
	Schema     int                          `json:"schema"`
	Projection string                       `json:"projection"`
	Defaults   map[string]any               `json:"defaults"`
	Cases      []map[string]json.RawMessage `json:"cases"`
	Refused    []map[string]json.RawMessage `json:"refused"`
}

// loadParityFixture reads the fixture of projection id from file.
func loadParityFixture(t *testing.T, file, id string) parityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc parityFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != id || len(doc.Defaults) == 0 || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, %d defaults, %d cases, %d refused", doc.Schema, doc.Projection, len(doc.Defaults), len(doc.Cases), len(doc.Refused))
	}
	return doc
}

// over is the fixture's defaults with the row's member key laid on them: the whole value a backend answers.
func (d parityFixture) over(t *testing.T, row map[string]json.RawMessage, key string) map[string]any {
	t.Helper()
	values := maps.Clone(d.Defaults)
	var given map[string]any
	if err := json.Unmarshal(row[key], &given); err != nil {
		t.Fatalf("row %s: its %s does not read: %v", row["id"], key, err)
	}
	maps.Copy(values, given)
	return values
}

// text is the row's string member key.
func text(t *testing.T, row map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(row[key], &s); err != nil {
		t.Fatalf("row member %s does not read: %v", key, err)
	}
	return s
}

// productionProjection is the projection id of the production schema, failing the test when the schema has none.
func productionProjection(t *testing.T, id string) Projection {
	t.Helper()
	for _, p := range Production().Projections {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("the production schema has no projection %s", id)
	return Projection{}
}

// checkParity runs Core against the fixture of projection id, whose rows carry the value in member key.
func checkParity(t *testing.T, file, id, key string) {
	doc := loadParityFixture(t, file, id)
	t.Run("defaults", func(t *testing.T) {
		have := map[string]any{}
		for _, f := range productionProjection(t, id).Fields {
			have[f.Name] = f.Default
		}
		if jsonOf(t, have) != jsonOf(t, doc.Defaults) {
			t.Errorf("the schema's defaults\n %s\n the fixture's defaults\n %s", jsonOf(t, have), jsonOf(t, doc.Defaults))
		}
	})
	for _, c := range doc.Cases {
		t.Run("case/"+text(t, c, "id"), func(t *testing.T) {
			want := doc.over(t, c, key)
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{id: want}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", text(t, c, "description"), err)
			}
			got, err := st.GetClear(id)
			if err != nil {
				t.Fatal(err)
			}
			if jsonOf(t, got) != jsonOf(t, want) {
				t.Errorf("%s\nread  %s\nwant  %s", text(t, c, "description"), jsonOf(t, got), jsonOf(t, want))
			}
		})
	}
	for _, c := range doc.Refused {
		t.Run("refused/"+text(t, c, "id"), func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{id: doc.over(t, c, key)}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", text(t, c, "description"), c[key])
			}
			if field := text(t, c, "field"); st != nil || !strings.Contains(err.Error(), id+"."+field+":") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming %s.%s", text(t, c, "description"), st, err, id, field)
			}
		})
	}
}

func TestTheExtrasProjectionIsWritableWithTheFixturesFieldsInOrderAndThreeSecrets(t *testing.T) {
	p := productionProjection(t, "extras")
	if p.ReadOnly {
		t.Error("extras is read-only, want writable: Core changes the credentials")
	}
	var names, secrets []string
	for _, f := range p.Fields {
		names = append(names, f.Name)
		if f.Secret {
			secrets = append(secrets, f.Name)
		}
	}
	if want := []string{"maxmindAccount", "maxmindKey", "maxmindLocale", "maxmindCsvDisabled", "ipinfoToken", "top1mProvider", "top1mToken"}; !slices.Equal(names, want) {
		t.Errorf("extras fields = %v, want %v", names, want)
	}
	if want := []string{"maxmindKey", "ipinfoToken", "top1mToken"}; !slices.Equal(secrets, want) {
		t.Errorf("extras secrets = %v, want %v", secrets, want)
	}
}

func TestTheExtrasProjectionMatchesItsParityFixture(t *testing.T) {
	checkParity(t, "settings_extras_parity.json", "extras", "extras")
}

// Secrets are write-only on the API: a read shows whether each is set, and only code inside Core's process gets the value.
func TestAReadOfExtrasShowsEachSecretAsItsPresenceAndNeverItsValue(t *testing.T) {
	set := map[string]any{"maxmindAccount": "424242", "maxmindKey": "Key_SECRET_1", "ipinfoToken": "ipi-SECRET-2", "top1mToken": "t1m.SECRET.3"}
	for name, stored := range map[string]map[string]any{"set": set, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"extras": stored}), Production())
			if err != nil {
				t.Fatal(err)
			}
			snap, err := st.Get([]string{"extras"})
			if err != nil {
				t.Fatal(err)
			}
			shown := jsonOf(t, snap)
			for _, secret := range []string{"maxmindKey", "ipinfoToken", "top1mToken"} {
				if want := `"` + secret + `":{"present":` + map[bool]string{true: "true", false: "false"}[stored[secret] != nil] + `}`; !strings.Contains(shown, want) {
					t.Errorf("the read does not show %s; it shows\n%s", want, shown)
				}
			}
			if strings.Contains(shown, "SECRET") {
				t.Errorf("the read shows a secret's value:\n%s", shown)
			}
			clear, err := st.GetClear("extras")
			if err != nil {
				t.Fatal(err)
			}
			for secret, value := range stored {
				if clear[secret] != value {
					t.Errorf("GetClear %s = %v, want %v: code inside Core reads the value", secret, clear[secret], value)
				}
			}
		})
	}
}
