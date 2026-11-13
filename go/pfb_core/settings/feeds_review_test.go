package settings

import (
	"strings"
	"testing"
)

// Issue #3937 (CodeRabbit on PR #3942): a header names one file in its type's directory, so it is unique across every
// group of the projection, not only within its group.
func TestAFeedHeaderIsUniqueAcrossTheGroupsOfAType(t *testing.T) {
	st := open(t, t.TempDir())
	distinct := `{"feeds/dnsbl": {"groups": [{"name": "A", "feeds": [{"header": "F", "state": "disabled"}]}, {"name": "B", "feeds": [{"header": "G", "state": "disabled"}]}]}}`
	if err := st.Validate(changes(t, distinct)); err != nil {
		t.Fatalf("Validate refused distinct headers: %v", err)
	}
	repeated := strings.Replace(distinct, `"G"`, `"F"`, 1)
	err := st.Validate(changes(t, repeated))
	if err == nil || !strings.Contains(err.Error(), "feeds/dnsbl.groups[1].feeds[0].header") {
		t.Fatalf("Validate(%s) = %v, want the second group's header refused", repeated, err)
	}
}

// A client never sees a feed's credentials, so a save that lists the feed without them keeps them (the item with the same
// key is the base of an edited item); an explicit "" or null clears them.
func TestAnEditedFeedKeepsItsCredentialsUnlessTheSaveClearsThem(t *testing.T) {
	st := open(t, t.TempDir())
	if _, err := st.Initialize(nil); err != nil {
		t.Fatal(err)
	}
	saved := func(revision uint64, feed string) string {
		t.Helper()
		if _, err := st.Save(revision, changes(t, `{"feeds/ipv4": {"groups": [{"name": "G", "feeds": [`+feed+`]}]}}`)); err != nil {
			t.Fatal(err)
		}
		return jsonOf(t, st.values["feeds/ipv4"])
	}
	saved(1, `{"header": "F", "url": "https://example.org/f", "credentials": "u:s3cret"}`)
	if v := saved(2, `{"header": "F", "url": "https://example.org/g"}`); !strings.Contains(v, `"credentials":"u:s3cret"`) || !strings.Contains(v, "example.org/g") {
		t.Errorf("after an edit without credentials: %s, want the new url and the credentials kept", v)
	}
	if v := saved(3, `{"header": "F", "url": "https://example.org/g", "credentials": ""}`); !strings.Contains(v, `"credentials":""`) {
		t.Errorf("after an explicit empty credentials: %s, want them cleared", v)
	}
	saved(4, `{"header": "F", "url": "https://example.org/g", "credentials": "u:again"}`)
	if v := saved(5, `{"header": "F", "url": "https://example.org/g", "credentials": null}`); !strings.Contains(v, `"credentials":""`) {
		t.Errorf("after credentials null: %s, want them reset to the default", v)
	}
	if v := saved(6, `{"header": "H", "url": "https://example.org/h"}`); strings.Contains(v, "s3cret") || strings.Contains(v, "again") {
		t.Errorf("a feed under another header inherited credentials: %s", v)
	}
}
