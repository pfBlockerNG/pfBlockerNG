// The country a reply row shows for a GeoLite2 record: the shapes MaxMind's own test databases do not hold.
package decider

import "testing"

func TestGeoRecordCodeFollowsPythonsLookupOrder(t *testing.T) {
	gb, eu, empty := "GB", "EU", ""
	for _, c := range []struct {
		name   string
		record geoRecord
		want   string
	}{
		{"a country with its code", geoRecord{Country: &struct {
			IsoCode *string `maxminddb:"iso_code"`
		}{&gb}}, "GB"},
		{"a country with its code and a continent", geoRecord{Country: &struct {
			IsoCode *string `maxminddb:"iso_code"`
		}{&gb}, Continent: &struct {
			Code *string `maxminddb:"code"`
		}{&eu}}, "GB"},
		{"a country without a code is unk, whatever its continent says", geoRecord{Country: &struct {
			IsoCode *string `maxminddb:"iso_code"`
		}{}, Continent: &struct {
			Code *string `maxminddb:"code"`
		}{&eu}}, "unk"},
		{"a continent alone", geoRecord{Continent: &struct {
			Code *string `maxminddb:"code"`
		}{&eu}}, "EU"},
		{"a continent without a code", geoRecord{Continent: &struct {
			Code *string `maxminddb:"code"`
		}{}}, "unk"},
		{"neither (a registered_country or traits record, or no record)", geoRecord{}, "unk"},
		{"an empty code is the code", geoRecord{Country: &struct {
			IsoCode *string `maxminddb:"iso_code"`
		}{&empty}}, ""},
	} {
		if got := c.record.code(); got != c.want {
			t.Errorf("%s: code() = %q, want %q", c.name, got, c.want)
		}
	}
}
