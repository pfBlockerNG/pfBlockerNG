package coreinput

import (
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// A string value with a line break would end its ini line and start another: it is refused.
func TestSettingsIniRefusesALineBreakInAString(t *testing.T) {
	for _, field := range []string{"idnMode", "pslFeedPrivatePolicy", "pslFeedIcannPolicy"} {
		dns, policy := coretest.Settings()
		dns[field] = "honor\npython_enable = off"
		if text, err := settingsIni(dns, policy); err == nil {
			t.Errorf("%s: settingsIni = %q, want an error", field, text)
		}
	}
}
