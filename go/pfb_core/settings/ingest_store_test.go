package settings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ingestBackend is a backend at revision 1 that holds the defaults of every projection and, of ingest, over laid on them.
func ingestBackend(t *testing.T, over map[string]any) *refreshBackend {
	t.Helper()
	values := map[string]map[string]any{"ingest": loadIngestFixture(t).ingestOver(over)}
	for _, p := range Production().Projections {
		if p.ID != "ingest" {
			values[p.ID] = defaults(p)
		}
	}
	return newRefreshBackend(1, values)
}

func TestOnlyTheIngestProjectionIsPublishedReadOnly(t *testing.T) {
	var schema struct {
		Projections []map[string]any `json:"projections"`
	}
	raw := jsonOf(t, Production())
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		t.Fatal(err)
	}
	readOnly := 0
	for _, p := range schema.Projections {
		v, published := p["readOnly"]
		switch {
		case p["id"] == "ingest" && v != true:
			t.Errorf("settings/ingest is published %v, want readOnly true", p)
		case p["id"] != "ingest" && published:
			t.Errorf("settings/%v is published readOnly %v: only ingest is", p["id"], v)
		}
		if published {
			readOnly++
		}
	}
	if readOnly != 1 {
		t.Errorf("%d projections publish readOnly, want only ingest in %s", readOnly, raw)
	}
}

// A change set that names a read-only projection is refused whole, by every method that takes one, whatever it holds: valid
// values, none, null or a field the projection does not have.
func TestAChangeSetThatNamesAReadOnlyProjectionIsRefusedWholeBySaveValidateAndInitialize(t *testing.T) {
	bodies := map[string]string{
		"a valid value":        `{"dns": {"control": true}, "ingest": {"suppression": false}}`,
		"an empty object":      `{"ingest": {}}`,
		"null":                 `{"ingest": null}`,
		"a field it lacks":     `{"ingest": {"nosuchfield": 1}}`,
		"the secret":           `{"ingest": {"proxyPassword": "x"}}`,
		"an invalid value too": `{"ingest": {"suppressionCidrV4": 99}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			refused := func(method string, err error) {
				t.Helper()
				var v *ValidationError
				if !errors.As(err, &v) || len(v.Fields) != 1 || v.Fields[0].Field != "ingest" || !strings.Contains(v.Fields[0].Message, "read-only") {
					t.Errorf("%s = %v, want one ValidationError naming ingest as read-only", method, err)
				}
			}
			b := ingestBackend(t, nil)
			st := storeOver(t, b)
			refused("Validate", st.Validate(changes(t, body)))
			_, err := st.Save(t.Context(), 1, changes(t, body))
			refused("Save", err)
			if b.writes != 0 || controlOf(t, st) != false {
				t.Errorf("a refused Save wrote %d times and left control %v, want nothing changed", b.writes, controlOf(t, st))
			}

			fresh := newRefreshBackend(0, nil)
			uninitialized := storeOver(t, fresh)
			refused("Validate over an uninitialized store", uninitialized.Validate(changes(t, body)))
			_, err = uninitialized.Initialize(t.Context(), changes(t, body))
			refused("Initialize", err)
			if fresh.writes != 0 || get(t, uninitialized).Initialized {
				t.Errorf("a refused Initialize wrote %d times and initialized the store %v, want nothing", fresh.writes, get(t, uninitialized).Initialized)
			}
		})
	}
}

func controlOf(t *testing.T, st *Store) any {
	t.Helper()
	return projection(t, get(t, st, "dns"), "dns").Value["control"]
}

func TestInitializeGivesTheReadOnlyProjectionItsDefaults(t *testing.T) {
	b := newRefreshBackend(0, nil)
	st := storeOver(t, b)
	if _, err := st.Initialize(t.Context(), changes(t, `{"dns": {"control": true}}`)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	got, err := st.GetClear("ingest")
	if err != nil {
		t.Fatal(err)
	}
	if want := jsonOf(t, loadIngestFixture(t).Defaults); jsonOf(t, got) != want {
		t.Errorf("ingest after Initialize = %s, want its defaults %s", jsonOf(t, got), want)
	}
	if b.values["ingest"] == nil {
		t.Error("the backend was not given the ingest projection to store")
	}
}

func TestAProxyPasswordIsShownAsPresenceOnlyWhileGetClearGivesTheValue(t *testing.T) {
	const secret = "hunter2-the-proxy-password"
	st := storeOver(t, ingestBackend(t, map[string]any{"proxyUrl": "http://proxy.example.com:3128", "proxyUser": "alice", "proxyPassword": secret}))

	shown := get(t, st, "ingest")
	if raw := jsonOf(t, shown); strings.Contains(raw, secret) {
		t.Fatalf("GetSettings shows the secret: %s", raw)
	}
	value := projection(t, shown, "ingest").Value
	if got := jsonOf(t, value["proxyPassword"]); got != `{"present":true}` {
		t.Errorf("proxyPassword shown as %s, want {\"present\":true}", got)
	}
	if value["proxyUser"] != "alice" || value["proxyUrl"] != "http://proxy.example.com:3128" {
		t.Errorf("the other proxy fields are shown as %v, want them as they are", value)
	}
	plain, err := st.GetClear("ingest")
	if err != nil || plain["proxyPassword"] != secret {
		t.Errorf("GetClear proxyPassword = %v, %v, want the value", plain["proxyPassword"], err)
	}

	other := storeOver(t, ingestBackend(t, map[string]any{"proxyUrl": "http://proxy.example.com:3128", "proxyUser": "alice", "proxyPassword": "another"}))
	if a, b := projection(t, shown, "ingest").Generation, projection(t, get(t, other, "ingest"), "ingest").Generation; a != b {
		t.Errorf("generations %d and %d differ for two passwords: a secret counts only by its presence", a, b)
	}
	none := storeOver(t, ingestBackend(t, nil))
	if got := jsonOf(t, projection(t, get(t, none, "ingest"), "ingest").Value["proxyPassword"]); got != `{"present":false}` {
		t.Errorf("an empty proxyPassword is shown as %s, want {\"present\":false}", got)
	}
}

func TestGetClearGivesTheSecretsOfListItemsToo(t *testing.T) {
	b := ingestBackend(t, nil)
	b.values["feeds/ipv4"] = map[string]any{"groups": []any{map[string]any{"name": "A", "action": "Deny_Inbound", "feeds": []any{
		map[string]any{"header": "A_f", "url": "https://example.org/f.txt", "credentials": "user:pw"}}}}}
	st := storeOver(t, b)

	if raw := jsonOf(t, get(t, st, "feeds/ipv4")); strings.Contains(raw, "user:pw") {
		t.Fatalf("GetSettings shows a feed's credentials: %s", raw)
	}
	plain, err := st.GetClear("feeds/ipv4")
	if err != nil {
		t.Fatal(err)
	}
	feed := plain["groups"].([]any)[0].(map[string]any)["feeds"].([]any)[0].(map[string]any)
	if feed["credentials"] != "user:pw" {
		t.Errorf("GetClear feed = %v, want the credentials in clear", feed)
	}
}

func TestGetClearHandsOutACopyAndRefusesWhatGetCannotAnswer(t *testing.T) {
	st := storeOver(t, ingestBackend(t, map[string]any{"selfAddresses": []any{map[string]any{"address": "192.0.2.1"}}}))
	first, err := st.GetClear("ingest")
	if err != nil {
		t.Fatal(err)
	}
	want := jsonOf(t, first)
	first["selfAddresses"].([]any)[0].(map[string]any)["address"] = "198.51.100.9"
	first["suppression"] = !first["suppression"].(bool)
	if again, _ := st.GetClear("ingest"); jsonOf(t, again) != want {
		t.Errorf("GetClear after its caller changed a result = %s, want the store's own %s", jsonOf(t, again), want)
	}

	var v *ValidationError
	if _, err := st.GetClear("no/such"); !errors.As(err, &v) {
		t.Errorf("GetClear of an unknown projection = %v, want a *ValidationError", err)
	}
	var c *ConflictError
	if _, err := storeOver(t, newRefreshBackend(0, nil)).GetClear("ingest"); !errors.As(err, &c) {
		t.Errorf("GetClear while uninitialized = %v, want a *ConflictError", err)
	}
}
