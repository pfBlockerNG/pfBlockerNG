package settings

import (
	"errors"
	"testing"
)

// A client's change to policy/ip is held to the same rules as what the adapter reads (issue #4031): an edit is stored and read back,
// a hostile value is refused naming its field and leaves the stored values as they were.
func TestSavingPolicyIpStoresAnEditAndReadsItBack(t *testing.T) {
	st, _ := initialized(t)
	before := get(t, st)

	res, err := st.Save(t.Context(), before.Revision, changes(t, `{"policy/ip": {"dedup": true, "maxLimit": 25, "countryBlacklistAction": "block",
		"countryWhitelist": [{"code": "US"}, {"code": "DE"}], "suppressionV6": [{"cidr": "2001:db8::/32"}]}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(res.Projections) != 1 || res.Projections[0].ResourceID != "settings/policy/ip" {
		t.Fatalf("Save changed %s, want only settings/policy/ip", jsonOf(t, res.Projections))
	}
	got := projection(t, get(t, st, "policy/ip"), "policy/ip").Value
	if got["dedup"] != true || got["maxLimit"] != int64(25) || got["countryBlacklistAction"] != "block" || got["aggregate"] != false ||
		jsonOf(t, got["countryWhitelist"]) != `[{"code":"US"},{"code":"DE"}]` || jsonOf(t, got["suppressionV6"]) != `[{"cidr":"2001:db8::/32"}]` {
		t.Errorf("policy/ip after Save = %s, want the edit over the defaults", jsonOf(t, got))
	}
}

func TestSavingPolicyIpRefusesAHostileValueNamingItsFieldAndKeepsTheStoredValues(t *testing.T) {
	for name, tc := range map[string]struct{ change, field string }{
		"a limit above the range":       {`{"policy/ip": {"dMaxLimit": 51}}`, "policy/ip.dMaxLimit"},
		"a country in lower case":       {`{"policy/ip": {"countryWhitelist": [{"code": "us"}]}}`, "policy/ip.countryWhitelist[0].code"},
		"an IPv6 CIDR in the IPv4 list": {`{"policy/ip": {"suppressionV4": [{"cidr": "2001:db8::/32"}]}}`, "policy/ip.suppressionV4[0].cidr"},
		"an IPv4 mask below /8":         {`{"policy/ip": {"suppressionV4": [{"cidr": "10.0.0.0/7"}]}}`, "policy/ip.suppressionV4[0].cidr"},
		"an action off its tokens":      {`{"policy/ip": {"countryWhitelistAction": "none"}}`, "policy/ip.countryWhitelistAction"},
	} {
		t.Run(name, func(t *testing.T) {
			st, _ := initialized(t)
			before := get(t, st)

			_, err := st.Save(t.Context(), before.Revision, changes(t, tc.change))

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
