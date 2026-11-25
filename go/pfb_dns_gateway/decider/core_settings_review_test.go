// Review round 1 of sub-slice 7e's settings (issue #4036).
package decider

import (
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// pslData is Core's data with a PSL that makes co.uk an ICANN suffix, and a feed that blocks co.uk and name.
func pslData(gen, name string) map[string]coretest.Resource {
	psl := coretest.Lines([]string{`{"section":"icann","rule":"uk"}`, `{"section":"icann","rule":"co.uk"}`})
	return coreDataWith(gen, map[string]coretest.Resource{"dnsbl/psl": {Generation: gen, Body: psl}}, "co.uk", name)
}

// A data change after a settings change builds with the settings Core gave, not the ones the module started with.
func TestOnCoreADataChangeBuildsWithTheSettingsSwappedIn(t *testing.T) {
	srv := coretest.Start(t, pslData("1", "a.example"))
	srv.SetSettings(coretest.Settings())
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	if !serves(m, "co.uk") {
		t.Fatal("a feed rule at a public suffix is not honored by default")
	}

	srv.SetSettings(coreSettings(map[string]any{"pslFeedIcannPolicy": "ignore"}))
	ticks.settle()
	if serves(m, "co.uk") {
		t.Fatal("the settings swap did not apply the ICANN policy")
	}

	srv.Set(pslData("2", "b.example"))
	ticks.settle()
	if !serves(m, "b.example") {
		t.Fatal("the new data is not served")
	}
	if serves(m, "co.uk") {
		t.Error("the data swap built with the policy the module started with")
	}
}

// A settings change that turns client metrics or the control channel off takes effect at once, even when no swap can
// build: a swap the RAM gate declines.
func TestOnCoreAnOptOutTakesEffectWithoutASwap(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true, "control": true}))
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	m.metricsPrivacyEpochs.Store(&map[int]string{dbResolver: "e1"})
	if m.controlStop == nil {
		t.Fatal("the control reader does not run")
	}

	m.totalRAM = func() (uint64, bool) { return 1, true } // every swap is declined
	srv.SetSettings(coretest.Settings())
	ticks.settle()
	if ip, epoch := m.metricClient(dbResolver, "192.0.2.1"); ip != "" || epoch != "" {
		t.Errorf("metricClient = %q, %q after client metrics were turned off", ip, epoch)
	}
	if m.controlStop != nil {
		t.Error("the control reader still runs after control was turned off")
	}
}

// Before Core has given settings, the DNSBL is reported lost for that reason, not for a broken ini.
func TestOnCoreNoSettingsYetIsTheReasonGiven(t *testing.T) {
	m, _ := bootOnCore(t, t.TempDir(), deadSocket(t))
	if got := m.snapshot.Load().dnsblUnbuilt; !strings.Contains(got, "No settings from Core yet") {
		t.Errorf("dnsblUnbuilt = %q", got)
	}
}
