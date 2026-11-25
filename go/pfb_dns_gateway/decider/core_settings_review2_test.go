// Review round 2 (light) of sub-slice 7e's settings (issue #4036).
package decider

import (
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// Client metrics turned off and on again while no swap can build are on once the swap lands: the authority the opt-out
// dropped is captured again from the database.
func TestOnCoreClientMetricsOffAndOnBeforeASwapAreOn(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true}))
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	sqlExec(t, m.pfb.pfbPyResolver, "UPDATE dns_metric_settings SET client_ip=1, epoch='e1' WHERE row=0")

	m.totalRAM = func() (uint64, bool) { return 1, true } // every swap is declined
	srv.SetSettings(coretest.Settings())
	ticks.settle()
	if ip, _ := m.metricClient(dbResolver, "192.0.2.1"); ip != "" {
		t.Fatal("client metrics still counted after they were turned off")
	}
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true}))
	ticks.settle()

	m.totalRAM = nil
	ticks.settle()
	if !m.snapshot.Load().settings.metricsClientIp {
		t.Fatal("the settings swap did not land")
	}
	if ip, epoch := m.metricClient(dbResolver, "192.0.2.1"); ip == "" || epoch != "e1" {
		t.Errorf("metricClient = %q, %q; want the client counted under e1", ip, epoch)
	}
}

// A smaller decision cache bound evicts the least recently used entries past it at once.
func TestDecisionCacheShrinksToItsNewBound(t *testing.T) {
	c := newLruCache[int](10)
	for i, k := range []string{"a", "b", "c", "d"} {
		c.set(k, i)
	}
	c.get("a")
	c.resize(2)
	if c.len() != 2 || !c.contains("a") || !c.contains("d") {
		t.Errorf("len %d, a %v, d %v; want the two most recently used", c.len(), c.contains("a"), c.contains("d"))
	}
}
