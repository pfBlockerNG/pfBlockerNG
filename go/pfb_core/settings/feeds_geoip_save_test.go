package settings

import (
	"encoding/json"
	"errors"
	"testing"
)

// groupsWith is the nine default continents as a Save value with the changes laid on the group of each name.
func groupsWith(t *testing.T, over map[string]map[string]any) map[string]map[string]json.RawMessage {
	t.Helper()
	groups := loadFeedsGeoipFixture(t).valueOver(over)
	return map[string]map[string]json.RawMessage{"feeds/geoip": {"groups": json.RawMessage(jsonOf(t, groups["groups"]))}}
}

// A client's change to feeds/geoip is held to the same rules as what the adapter reads (issue #4031): an edit is stored and read back,
// a value that is not the nine continents of valid fields is refused naming its field and leaves the stored values as they were.
func TestSavingFeedsGeoipStoresAnEditAndReadsItBack(t *testing.T) {
	st, _ := initialized(t)
	before := get(t, st)

	res, err := st.Save(t.Context(), before.Revision, groupsWith(t, map[string]map[string]any{
		"pfB_Europe": {"action": "Deny_Both", "countriesV4": []any{map[string]any{"code": "DE"}, map[string]any{"code": "A1_US_rep"}}},
	}))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(res.Projections) != 1 || res.Projections[0].ResourceID != "settings/feeds/geoip" {
		t.Fatalf("Save changed %s, want only settings/feeds/geoip", jsonOf(t, res.Projections))
	}
	groups := projection(t, get(t, st, "feeds/geoip"), "feeds/geoip").Value["groups"].([]any)
	europe := groups[4].(map[string]any)
	if europe["name"] != "pfB_Europe" || europe["action"] != "Deny_Both" || jsonOf(t, europe["countriesV4"]) != `[{"code":"DE"},{"code":"A1_US_rep"}]` || len(groups) != 9 {
		t.Errorf("feeds/geoip after Save = %s, want Europe Deny_Both with its two countries among nine groups", jsonOf(t, groups))
	}
}

func TestSavingFeedsGeoipRefusesAValueThatIsNotTheNineContinentsOnceNamingItsFieldAndKeepsTheStoredValues(t *testing.T) {
	for name, tc := range map[string]struct {
		change map[string]map[string]any
		field  string
	}{
		"an unknown continent":     {map[string]map[string]any{"pfB_Top": {"name": "pfB_Mars"}}, "feeds/geoip.groups[0].name"},
		"a country in lower case":  {map[string]map[string]any{"pfB_Asia": {"countriesV6": []any{map[string]any{"code": "jp"}}}}, "feeds/geoip.groups[3].countriesV6[0].code"},
		"an action off its tokens": {map[string]map[string]any{"pfB_Asia": {"action": "unbound"}}, "feeds/geoip.groups[3].action"},
		"a repeated continent":     {map[string]map[string]any{"pfB_PS": {"name": "pfB_Top"}}, "feeds/geoip.groups[8].name"},
	} {
		t.Run(name, func(t *testing.T) {
			st, _ := initialized(t)
			before := get(t, st)

			_, err := st.Save(t.Context(), before.Revision, groupsWith(t, tc.change))

			var invalid *ValidationError
			if !errors.As(err, &invalid) || len(invalid.Fields) == 0 || invalid.Fields[0].Field != tc.field {
				t.Fatalf("Save = %v, want a validation error naming %s", err, tc.field)
			}
			if after := get(t, st); jsonOf(t, after) != jsonOf(t, before) {
				t.Errorf("the refused Save changed the settings\nbefore %s\nafter  %s", jsonOf(t, before), jsonOf(t, after))
			}
		})
	}
}

func TestSavingFeedsGeoipWithoutOneContinentIsRefusedNamingTheList(t *testing.T) {
	st, _ := initialized(t)
	before := get(t, st)
	nine := loadFeedsGeoipFixture(t).valueOver(nil)["groups"].([]any)

	_, err := st.Save(t.Context(), before.Revision, map[string]map[string]json.RawMessage{"feeds/geoip": {"groups": json.RawMessage(jsonOf(t, nine[:8]))}})

	var invalid *ValidationError
	if !errors.As(err, &invalid) || len(invalid.Fields) != 1 || invalid.Fields[0].Field != "feeds/geoip.groups" {
		t.Fatalf("Save = %v, want one validation error naming feeds/geoip.groups", err)
	}
}
