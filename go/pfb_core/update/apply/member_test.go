package apply_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// tests/core/fixtures/ip_members.json: the members Core publishes, agreed with the Outpost's member check
// (tests/php/IpMembersFixtureTest.php runs the same rows through pfb_outpost_ip_member_valid()).
const membersFixture = "../../../../tests/core/fixtures/ip_members.json"

type memberRow struct {
	Member    string  `json:"member"`
	Family    string  `json:"family"`
	Outpost   bool    `json:"outpost"`
	Canonical *string `json:"canonical"`
	Note      string  `json:"note"`
}

func readMembers(t *testing.T) []memberRow {
	t.Helper()
	raw, err := os.ReadFile(membersFixture)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema   int               `json:"schema"`
		Contract string            `json:"contract"`
		Members  []memberRow       `json:"members"`
		Rest     []json.RawMessage `json:"ipset_departures"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Contract != "ip-set-members" || len(doc.Members) < 50 {
		t.Fatalf("not the member fixture: schema %d, %q, %d rows", doc.Schema, doc.Contract, len(doc.Members))
	}
	return doc.Members
}

// WHEN each member of the fixture is published THEN Core writes the row's canonical spelling, or leaves the row out; what it
// writes is its own canonical spelling, a member the store holds (never "#" first, no control character), and Core never
// publishes a row the Outpost's check refuses.
func TestCorePublishesEachMemberInOneSpelling(t *testing.T) {
	for _, row := range readMembers(t) {
		got, err := apply.Member(row.Member, row.Family)
		switch {
		case row.Canonical == nil && err == nil:
			t.Errorf("%q (%s): Core publishes %q, the row says it is left out (%s)", row.Member, row.Family, got, row.Note)
		case row.Canonical != nil && (err != nil || got != *row.Canonical):
			t.Errorf("%q (%s): Core publishes %q (%v), the row says %q (%s)", row.Member, row.Family, got, err, *row.Canonical, row.Note)
		case !row.Outpost && row.Canonical != nil:
			t.Errorf("%q: the row publishes a member the Outpost's check refuses", row.Member)
		}
		if err != nil {
			continue
		}
		if again, err := apply.Member(got, row.Family); err != nil || again != got {
			t.Errorf("%q: Core's spelling %q is published again as %q (%v)", row.Member, got, again, err)
		}
		if _, err := resources.Canonical([]string{got}); err != nil || got[0] == '#' || !printable([]byte(got)) || bytes.ContainsRune([]byte(got), ' ') {
			t.Errorf("%q: Core publishes %q, which the store or the Outpost cannot hold: %v", row.Member, got, err)
		}
	}
}
