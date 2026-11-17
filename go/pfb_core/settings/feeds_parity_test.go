package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The parity fixture of the feed projections (issue #3937): tests/core/fixtures/settings_feeds_parity.json, frozen against
// today's PHP by tests/php/CoreSettingsFeedsParityTest.php. A stored case's native group (what the adapter reads from
// config.xml) is saved as the projection's only group: Core accepts it and reads it back with credentials hidden. A
// posted case's input (the Groups editor's form, natively) gets the page's verdict, and a script name PHP's.
func TestTheFeedProjectionsMatchTodaysPhpOnEveryFixtureCase(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_feeds_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      int      `json:"schema"`
		Projections []string `json:"projections"`
		ScriptNames []struct {
			Name  string `json:"name"`
			Valid bool   `json:"valid"`
		} `json:"scriptNames"`
		ListClasses []struct {
			ID          string         `json:"id"`
			Description string         `json:"description"`
			Stored      map[string]any `json:"stored"`
			ListClass   string         `json:"listClass"`
			Folder      *string        `json:"folder"`
		} `json:"listClasses"`
		Cases []struct {
			ID          string          `json:"id"`
			Description string          `json:"description"`
			Projection  string          `json:"projection"`
			Source      string          `json:"source"`
			Stored      json.RawMessage `json:"stored"`
			Posted      json.RawMessage `json:"posted"`
			Input       json.RawMessage `json:"input"`
			Valid       bool            `json:"valid"`
			Native      json.RawMessage `json:"native"`
		} `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || len(doc.Cases) == 0 || len(doc.ScriptNames) == 0 || len(doc.ListClasses) == 0 {
		t.Fatalf("fixture schema %d with %d cases, %d script names and %d list classes", doc.Schema, len(doc.Cases), len(doc.ScriptNames), len(doc.ListClasses))
	}
	// A list class (issue #4031) is derived from the Outpost's stored keys: Core holds each of the fixture's classes on an IP group, and no DNSBL group has one.
	for _, row := range doc.ListClasses {
		for _, id := range []string{"feeds/ipv4", "feeds/ipv6"} {
			st := open(t, t.TempDir())
			if _, err := st.Initialize(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			group := jsonOf(t, map[string]string{"name": "G", "listClass": row.ListClass})
			if _, err := st.Save(t.Context(), 1, map[string]map[string]json.RawMessage{id: {"groups": json.RawMessage("[" + group + "]")}}); err != nil {
				t.Fatalf("%s %s: Core refuses the list class %s: %v", id, row.ID, row.ListClass, err)
			}
			groups, _ := projection(t, get(t, st, id), id).Value["groups"].([]any)
			if len(groups) != 1 || groups[0].(map[string]any)["listClass"] != row.ListClass {
				t.Errorf("%s %s: read %s, want the list class %s", id, row.ID, jsonOf(t, groups), row.ListClass)
			}
		}
	}
	for _, id := range doc.Projections {
		if _, ok := open(t, t.TempDir()).projection(id); !ok {
			t.Errorf("the schema has no projection %s", id)
		}
	}
	// A hostile script name gets PHP's verdict in every projection, as preScript and as postScript.
	for _, n := range doc.ScriptNames {
		for _, id := range doc.Projections {
			for _, field := range []string{"preScript", "postScript"} {
				st := open(t, t.TempDir())
				if _, err := st.Initialize(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				group := jsonOf(t, map[string]string{"name": "G", field: n.Name})
				_, err := st.Save(t.Context(), 1, map[string]map[string]json.RawMessage{id: {"groups": json.RawMessage("[" + group + "]")}})
				if accepted := err == nil; accepted != n.Valid {
					t.Errorf("Core's verdict on %s %q in %s: accepted %v (%v), PHP's %v", field, n.Name, id, accepted, err, n.Valid)
				}
			}
		}
	}
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			input := c.Input
			if c.Source == "stored" {
				if string(c.Native) == "null" {
					return // the adapter leaves the group out: nothing reaches Core
				}
				input = c.Native
			}
			st := open(t, t.TempDir())
			if _, err := st.Initialize(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			_, err := st.Save(t.Context(), 1, map[string]map[string]json.RawMessage{c.Projection: {"groups": json.RawMessage("[" + string(input) + "]")}})
			if accepted := err == nil; accepted != c.Valid {
				t.Fatalf("%s\nCore's verdict on %s: accepted %v (%v), PHP's %v", c.Description, input, accepted, err, c.Valid)
			}
			if !c.Valid || c.Source != "stored" {
				return
			}
			groups, _ := projection(t, get(t, st, c.Projection), c.Projection).Value["groups"].([]any)
			if len(groups) != 1 {
				t.Fatalf("%s: read %d groups, want 1", c.Projection, len(groups))
			}
			if have, want := jsonOf(t, groups[0]), hideCredentials(t, c.Native); have != want {
				t.Errorf("%s\nread  %s\nwant  %s", c.Description, have, want)
			}
		})
	}
}

// hideCredentials is a native group as a read shows it: each feed's credentials as their presence, keys sorted.
func hideCredentials(t *testing.T, native json.RawMessage) string {
	t.Helper()
	var group map[string]any
	if err := json.Unmarshal(native, &group); err != nil {
		t.Fatal(err)
	}
	for _, f := range group["feeds"].([]any) {
		feed := f.(map[string]any)
		feed["credentials"] = map[string]bool{"present": feed["credentials"] != ""}
	}
	return jsonOf(t, group)
}

// A secret inside a list item never appears in a read, Get's or Save's, and its presence follows the value.
func TestFeedCredentialsAreWriteOnly(t *testing.T) {
	st := open(t, t.TempDir())
	if _, err := st.Initialize(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	res, err := st.Save(t.Context(), 1, changes(t, `{"feeds/dnsbl": {"groups": [{"name": "G", "feeds": [
		{"header": "A", "url": "https://example.org/a", "credentials": "user:s3cret"},
		{"header": "B", "url": "https://example.org/b"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, read := range []string{jsonOf(t, res), jsonOf(t, get(t, st))} {
		if strings.Contains(read, "s3cret") {
			t.Fatalf("a read shows the credentials: %s", read)
		}
		if !strings.Contains(read, `"credentials":{"present":true}`) || !strings.Contains(read, `"credentials":{"present":false}`) {
			t.Errorf("a read does not show each feed's credentials as their presence: %s", read)
		}
	}
}

// Rows have identities: a group name and a feed header are required and unique within their list. The same rows with
// distinct keys are accepted, so each refusal is the key's.
func TestListKeysAreRequiredAndUnique(t *testing.T) {
	st := open(t, t.TempDir())
	if _, err := st.Initialize(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	valid := `{"feeds/ipv4": {"groups": [{"name": "A"}, {"name": "B"}]},
		"feeds/dnsbl": {"groups": [{"name": "A", "feeds": [{"header": "F", "state": "disabled"}, {"header": "G", "state": "disabled"}]}]}}`
	if _, err := st.Save(t.Context(), 1, changes(t, valid)); err != nil {
		t.Fatalf("Save refused rows with distinct keys: %v", err)
	}
	for name, text := range map[string]string{
		"duplicate group": `{"feeds/ipv4": {"groups": [{"name": "A"}, {"name": "A"}]}}`,
		"empty group":     `{"feeds/ipv4": {"groups": [{"name": ""}]}}`,
		"missing group":   `{"feeds/ipv4": {"groups": [{"action": "Disabled"}]}}`,
		"duplicate feed":  `{"feeds/dnsbl": {"groups": [{"name": "A", "feeds": [{"header": "F", "state": "disabled"}, {"header": "F", "state": "disabled"}]}]}}`,
		"unknown field":   `{"feeds/dnsbl": {"groups": [{"name": "A", "bogus": 1}]}}`,
		"not a list":      `{"feeds/dnsbl": {"groups": {"name": "A"}}}`,
		"not an object":   `{"feeds/dnsbl": {"groups": ["A"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := st.Validate(changes(t, text)); err == nil {
				t.Fatalf("Validate accepted %s", text)
			}
		})
	}
}

// The list class is part of an IP group only, and one of five tokens; it is the Outpost's to derive, so Core's value is what it was read as.
func TestOnlyIpGroupsHaveAListClassOfFiveTokens(t *testing.T) {
	for _, p := range Production().Projections {
		if !strings.HasPrefix(p.ID, "feeds/") || p.ID == "feeds/geoip" {
			continue
		}
		var group []Field
		for _, f := range p.Fields {
			if f.Name == "groups" {
				group = f.Items
			}
		}
		i := slices.IndexFunc(group, func(f Field) bool { return f.Name == "listClass" })
		if p.ID == "feeds/dnsbl" {
			if i >= 0 {
				t.Errorf("%s has a listClass field: a DNSBL group has no IP list", p.ID)
			}
			continue
		}
		if i < 0 {
			t.Errorf("%s has no listClass field", p.ID)
			continue
		}
		f := group[i]
		if f.Type != TypeEnum || f.Default != "none" || !slices.Equal(f.Enum, []string{"none", "deny", "permit", "match", "native"}) {
			t.Errorf("%s listClass = %+v, want an enum of none deny permit match native, default none", p.ID, f)
		}
		if after := slices.IndexFunc(group, func(f Field) bool { return f.Name == "whoisConvert" }); i != after+1 {
			t.Errorf("%s listClass is field %d, want right after whoisConvert (%d)", p.ID, i, after)
		}
	}
	for id, text := range map[string]string{
		"feeds/ipv4":  `{"feeds/ipv4": {"groups": [{"name": "G", "listClass": "block"}]}}`,
		"feeds/ipv6":  `{"feeds/ipv6": {"groups": [{"name": "G", "listClass": ""}]}}`,
		"feeds/dnsbl": `{"feeds/dnsbl": {"groups": [{"name": "G", "listClass": "deny"}]}}`,
	} {
		st, _ := initialized(t)
		err := st.Validate(changes(t, text))
		var invalid *ValidationError
		if !errors.As(err, &invalid) || len(invalid.Fields) == 0 || invalid.Fields[0].Field != id+".groups[0].listClass" {
			t.Errorf("%s: Validate(%s) = %v, want a validation error naming %s.groups[0].listClass", id, text, err, id)
		}
	}
}
