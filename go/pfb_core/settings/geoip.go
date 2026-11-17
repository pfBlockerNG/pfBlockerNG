package settings

import (
	"fmt"
	"slices"
)

// geoipContinents are the continents the Outpost keeps a GeoIP group for, in its order: Core changes their lists, never their number.
var geoipContinents = []string{"pfB_Top", "pfB_Africa", "pfB_Antarctica", "pfB_Asia", "pfB_Europe", "pfB_NAmerica", "pfB_Oceania", "pfB_SAmerica", "pfB_PS"}

// listClass is the list class of an IP group or a GeoIP continent: where the Outpost keeps its list. It is derived from the group's
// action and its inversions, which only the Outpost stores: the Outpost answers it and ignores what a client sends back.
func listClass() Field {
	return Field{Name: "listClass", Type: TypeEnum, Default: "none", Enum: []string{"none", "deny", "permit", "match", "native"}}
}

// feedsGeoipProjection is settings/feeds/geoip (issue #4031): the action and the countries of each GeoIP continent, as the Outpost reads
// them from its configuration. tests/core/fixtures/settings_feeds_geoip_parity.json is the parity fixture.
func feedsGeoipProjection() Projection {
	countries := func(name string) Field {
		return Field{Name: name, Type: TypeList, Default: []any{}, Key: "code",
			Items: []Field{{Name: "code", Type: TypeString, Default: "", Pattern: `^(?:A[12]_)?[A-Z][A-Z0-9](?:_rep)?$`}}}
	}
	defaults := make([]any, 0, len(geoipContinents))
	for _, name := range geoipContinents {
		defaults = append(defaults, map[string]any{"name": name, "action": "Disabled", "listClass": "none", "countriesV4": []any{}, "countriesV6": []any{}})
	}
	return Projection{ID: "feeds/geoip", Fields: []Field{{Name: "groups", Type: TypeList, Default: defaults, Key: "name", CheckList: eachContinent,
		Items: []Field{
			{Name: "name", Type: TypeEnum, Default: "", Enum: geoipContinents},
			{Name: "action", Type: TypeEnum, Default: "Disabled", Enum: ipActions},
			listClass(),
			countries("countriesV4"),
			countries("countriesV6"),
		}}}}
}

// eachContinent holds the groups to one of each continent: the Outpost has no others and does not drop one.
func eachContinent(groups []any) []FieldError {
	have := make([]string, 0, len(groups))
	for _, g := range groups {
		have = append(have, g.(map[string]any)["name"].(string))
	}
	slices.Sort(have)
	if want := slices.Sorted(slices.Values(geoipContinents)); !slices.Equal(have, want) {
		return []FieldError{{Message: fmt.Sprintf("must hold each of the %d continents once", len(want))}}
	}
	return nil
}
