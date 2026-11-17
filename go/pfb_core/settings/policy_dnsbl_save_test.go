package settings

import (
	"errors"
	"testing"
)

// A client's change to policy/dnsbl is held to the same rules as what the adapter reads (issue #4031): an edit is stored and read
// back, a hostile value is refused naming its field and leaves the stored values as they were.
func TestSavingPolicyDnsblStoresAnEditAndReadsItBack(t *testing.T) {
	st, _ := initialized(t)
	before := get(t, st)

	res, err := st.Save(t.Context(), before.Revision, changes(t, `{"policy/dnsbl": {"enabled": true, "top1mCount": 500, "safeSearchYoutube": "Strict",
		"whitelist": [{"domain": "example.com"}, {"domain": ".example.org"}], "regexList": [{"pattern": "^Ads\\. # trailing"}],
		"tldAllowGtld": [{"tld": "arpa"}, {"tld": "com"}], "dnsblIpAction": "Deny_Both"}}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(res.Projections) != 1 || res.Projections[0].ResourceID != "settings/policy/dnsbl" {
		t.Fatalf("Save changed %s, want only settings/policy/dnsbl", jsonOf(t, res.Projections))
	}
	got := projection(t, get(t, st, "policy/dnsbl"), "policy/dnsbl").Value
	if got["enabled"] != true || got["top1mCount"] != int64(500) || got["safeSearchYoutube"] != "Strict" || got["regex"] != false || got["dnsblIpAction"] != "Deny_Both" ||
		jsonOf(t, got["whitelist"]) != `[{"domain":"example.com"},{"domain":".example.org"}]` || jsonOf(t, got["regexList"]) != `[{"pattern":"^Ads\\. # trailing"}]` ||
		jsonOf(t, got["tldAllowGtld"]) != `[{"tld":"arpa"},{"tld":"com"}]` {
		t.Errorf("policy/dnsbl after Save = %s, want the edit over the defaults", jsonOf(t, got))
	}
}

func TestSavingPolicyDnsblRefusesAHostileValueNamingItsFieldAndKeepsTheStoredValues(t *testing.T) {
	for name, tc := range map[string]struct{ change, field string }{
		"a whitelist entry with a line break":   {`{"policy/dnsbl": {"whitelist": [{"domain": "a.example\nb.example"}]}}`, "policy/dnsbl.whitelist[0].domain"},
		"a whitelist entry with no dot":         {`{"policy/dnsbl": {"whitelist": [{"domain": "nodots"}]}}`, "policy/dnsbl.whitelist[0].domain"},
		"a whitelist entry with an empty label": {`{"policy/dnsbl": {"whitelist": [{"domain": "a..example"}]}}`, "policy/dnsbl.whitelist[0].domain"},
		"a regex entry that is a comment":       {`{"policy/dnsbl": {"regexList": [{"pattern": "#a"}]}}`, "policy/dnsbl.regexList[0].pattern"},
		"a count of zero":                       {`{"policy/dnsbl": {"top1mCount": 0}}`, "policy/dnsbl.top1mCount"},
		"a TLD with a comma":                    {`{"policy/dnsbl": {"tldAllowCctld": [{"tld": "a,b"}]}}`, "policy/dnsbl.tldAllowCctld[0].tld"},
		"a mechanism off its tokens":            {`{"policy/dnsbl": {"logging": "default"}}`, "policy/dnsbl.logging"},
		"a repeated group":                      {`{"policy/dnsbl": {"groups": [{"name": "g"}, {"name": "g"}]}}`, "policy/dnsbl.groups[1].name"},
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
