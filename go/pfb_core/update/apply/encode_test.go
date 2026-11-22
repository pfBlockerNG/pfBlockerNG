package apply_test

import (
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// WHEN a DNSBL without groups is written THEN groups is an empty list: the apply refuses null or an absent list.
func TestADNSBLWithoutGroupsIsWrittenWithAnEmptyList(t *testing.T) {
	b, err := apply.Encode(apply.Request{Trigger: "manual", Scope: "dnsbl", DNSBL: &apply.DNSBL{Generation: 1}})
	if err != nil || !strings.Contains(string(b), `"dnsbl":{"generation":"1","groups":[]}`) {
		t.Errorf("Core writes %s (%v)", b, err)
	}
}
