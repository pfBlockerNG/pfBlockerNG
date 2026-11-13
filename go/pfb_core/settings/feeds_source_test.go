package settings

import "testing"

// The Outpost stores a feed's url and credentials as one source (pfSense: the URL's userinfo, a local path for
// file:///). Core refuses a pair that would not read back as written, so it never accepts what the adapter refuses
// (issue #3937): credentials beside a url that is not scheme://, userinfo inside the url, a bare local path, and
// credentials holding a character that ends the userinfo.
func TestAFeedSourceMustReadBackAsWritten(t *testing.T) {
	for name, c := range map[string]struct {
		feed  string
		valid bool
	}{
		"credentials on https":         {`{"header": "F", "url": "https://example.org/a", "credentials": "u:p@ss"}`, true},
		"file url":                     {`{"header": "F", "url": "file:///var/db/pfblockerng/a.txt"}`, true},
		"geoip token":                  {`{"header": "F", "format": "geoip", "url": "US United States"}`, true},
		"credentials on a token":       {`{"header": "F", "format": "asn", "url": "AS13335", "credentials": "u:p"}`, false},
		"credentials on host::module":  {`{"header": "F", "format": "rsync", "url": "example.org::feeds", "credentials": "u:p"}`, false},
		"userinfo inside the url":      {`{"header": "F", "url": "https://u:p@example.org/a"}`, false},
		"a bare local path":            {`{"header": "F", "url": "/var/db/pfblockerng/a.txt"}`, false},
		"credentials holding a slash":  {`{"header": "F", "url": "https://example.org/a", "credentials": "u:p/q"}`, false},
		"credentials holding a ? or #": {`{"header": "F", "url": "https://example.org/a", "credentials": "u:p?#"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			st := open(t, t.TempDir())
			text := `{"feeds/ipv4": {"groups": [{"name": "G", "feeds": [` + c.feed + `]}]}}`
			if err := st.Validate(changes(t, text)); (err == nil) != c.valid {
				t.Errorf("Validate(%s) = %v, want valid %v", text, err, c.valid)
			}
		})
	}
}
