// CodeRabbit's review of sub-slice 7e's settings (issue #4036).
package decider

import (
	"os"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// On the Core input an ini that is not pfB-DNS's own is never read, also when the start could not remove it.
func TestOnCoreAnUntrustedIniLeftInPlaceIsNotRead(t *testing.T) {
	m, _ := bootOnCore(t, t.TempDir(), deadSocket(t))
	if err := os.WriteFile(m.pfb.pfbUnboundIni, []byte("[MAIN]\npython_enable = on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(m.pfb.pfbUnboundIni, 0o666); err != nil {
		t.Fatal(err)
	}
	if config := m.loadIniConfig(); config != nil {
		t.Error("the world-writable ini is read")
	}
}

// Every settings swap with client metrics on captures the authority of each open database, as a start does: a database
// that granted none before gets its own.
func TestOnCoreASettingsSwapCapturesEachDatabase(t *testing.T) {
	srv := coretest.Start(t, coreData("1"))
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true}))
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	sqlExec(t, m.pfb.pfbPyResolver, "UPDATE dns_metric_settings SET client_ip=1, epoch='r1' WHERE row=0")
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true, "cnameValidation": true}))
	ticks.settle()
	if _, epoch := m.metricClient(dbResolver, "192.0.2.1"); epoch != "r1" {
		t.Fatalf("resolver epoch %q, want r1", epoch)
	}

	// The DNSBL database opens with a swap that wants statistics, and grants client addresses afterwards.
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true, "idnMode": "confusable"}))
	ticks.settle()
	if !m.sqlite3DnsblCon.Load() {
		t.Fatal("the DNSBL database did not open")
	}
	sqlExec(t, m.pfb.pfbPyDnsbl, "UPDATE dns_metric_settings SET client_ip=1, epoch='d1' WHERE row=0")
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true, "idnMode": "confusable", "cnameValidation": true}))
	ticks.settle()
	if _, epoch := m.metricClient(dbDnsbl, "192.0.2.1"); epoch != "d1" {
		t.Errorf("DNSBL epoch %q, want d1", epoch)
	}
}
