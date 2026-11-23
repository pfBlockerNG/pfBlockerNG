package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parity fixture of the pfB-DNS switch (issue #4038, sub-slice 9g): tests/core/fixtures/settings_pfb_dns_parity.json,
// frozen against today's PHP by tests/php/CoreSettingsPfbDnsParityTest.php. A case's pfbDnsEnabled is what the adapter answers
// in dns for a stored dns/pfb_dns, and php today's reader as pfb_dnsbl_active() compares it; Core reads it back as it is.
type pfbDNSFixture struct {
	Schema      int    `json:"schema"`
	Projection  string `json:"projection"`
	Field       string `json:"field"`
	Description string `json:"description"`
	Cases       []struct {
		ID            string          `json:"id"`
		Description   string          `json:"description"`
		Stored        json.RawMessage `json:"stored"`
		PHP           bool            `json:"php"`
		PfbDNSEnabled bool            `json:"pfbDnsEnabled"`
	} `json:"cases"`
	Refused []struct {
		ID            string `json:"id"`
		Description   string `json:"description"`
		PfbDNSEnabled any    `json:"pfbDnsEnabled"`
	} `json:"refused"`
}

func loadPfbDNSFixture(t *testing.T) pfbDNSFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "settings_pfb_dns_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc pfbDNSFixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the fixture does not read: %v", err)
	}
	if doc.Schema != 1 || doc.Projection != "dns" || doc.Field != "pfbDnsEnabled" || len(doc.Cases) == 0 || len(doc.Refused) == 0 {
		t.Fatalf("fixture schema %d, projection %q, field %q, %d cases, %d refused", doc.Schema, doc.Projection, doc.Field, len(doc.Cases), len(doc.Refused))
	}
	return doc
}

func TestCoreReadsTheAdaptersPfbDNSSwitchBackAsTodaysReaderTakesIt(t *testing.T) {
	for _, c := range loadPfbDNSFixture(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.PfbDNSEnabled != c.PHP {
				t.Fatalf("%s\nthe adapter answers %v where today's reader gives %v", c.Description, c.PfbDNSEnabled, c.PHP)
			}
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"dns": {"pfbDnsEnabled": c.PfbDNSEnabled}}), Production())
			if err != nil {
				t.Fatalf("%s\nCore refuses what the adapter reads: %v", c.Description, err)
			}
			dns, err := st.GetClear("dns")
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := dns["pfbDnsEnabled"].(bool); !ok || got != c.PHP {
				t.Errorf("%s\nread %v, want %v (today's reader on %s)", c.Description, dns["pfbDnsEnabled"], c.PHP, c.Stored)
			}
		})
	}
}

func TestCoreRefusesAPfbDNSSwitchThatIsNoBooleanNamingTheField(t *testing.T) {
	for _, c := range loadPfbDNSFixture(t).Refused {
		t.Run(c.ID, func(t *testing.T) {
			st, err := Load(newRefreshBackend(1, map[string]map[string]any{"dns": {"pfbDnsEnabled": c.PfbDNSEnabled}}), Production())
			if err == nil {
				t.Fatalf("%s\nCore read %s without a refusal", c.Description, jsonOf(t, c.PfbDNSEnabled))
			}
			if st != nil || !strings.Contains(err.Error(), "dns.pfbDnsEnabled:") {
				t.Errorf("%s\nLoad = %v, %v, want no store and an error naming dns.pfbDnsEnabled", c.Description, st, err)
			}
		})
	}
}

func TestThePfbDNSSwitchDefaultsToOff(t *testing.T) {
	st, err := Load(newRefreshBackend(1, map[string]map[string]any{}), Production())
	if err != nil {
		t.Fatal(err)
	}
	dns, err := st.GetClear("dns")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := dns["pfbDnsEnabled"]; !ok || v != false {
		t.Errorf("dns.pfbDnsEnabled with nothing answered = %v (present %v), want false", v, ok)
	}
}
