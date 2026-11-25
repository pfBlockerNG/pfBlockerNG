// pfB-DNS's settings on the Core input (issue #4036, sub-slice 7e): it takes settings/dns and settings/policy/dnsbl through
// its poll, keeps them in its private cache for a start without Core, and applies a change through the snapshot swap, with
// no restart.
package decider

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// coreSettings is Core's settings with the dns fields of set changed.
func coreSettings(set map[string]any) (dns, policy map[string]any) {
	dns, policy = coretest.Settings()
	for k, v := range set {
		dns[k] = v
	}
	return dns, policy
}

// onlyNoAAAA is whether name is the one entry of the noAAAA table.
func onlyNoAAAA(snap *snapshot, name string) bool {
	_, ok := snap.noAAAADB[name]
	return ok && len(snap.noAAAADB) == 1
}

func cacheSize(m *pfbUnbound) int {
	m.decisionDB.mu.Lock()
	defer m.decisionDB.mu.Unlock()
	return m.decisionDB.maxsize
}

func TestOnCoreASettingsChangeIsSwappedInWithoutARestart(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{
		"noAaaa": true, "noAaaaList": []any{map[string]any{"domain": "v6.example"}}, "control": true, "decisionCacheMax": 5,
		"idnMode": "confusable",
	}))
	// No ini and no cache: the module starts without settings and takes them, with the data, from the first poll.
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	if m.snapshot.Load().settings.pythonEnable {
		t.Fatal("settings before the first poll")
	}
	ticks.settle()
	snap := m.snapshot.Load()
	switch {
	case !serves(m, "a.example"):
		t.Error("the data is not served")
	case !snap.settings.pythonEnable || !snap.settings.noAAAADB || !onlyNoAAAA(snap, "v6.example"):
		t.Errorf("noAAAA not applied: flag %v, table %v", snap.settings.noAAAADB, snap.noAAAADB)
	case snap.settings.idnMode != IdnModeConfusable:
		t.Errorf("idnMode = %q, want confusable", snap.settings.idnMode)
	case !snap.settings.pythonControl || m.controlStop == nil:
		t.Errorf("control: setting %v, reader running %v", snap.settings.pythonControl, m.controlStop != nil)
	case cacheSize(m) != 5:
		t.Errorf("decision cache holds %d, want 5", cacheSize(m))
	case !m.sqlite3ResolverCon.Load():
		t.Error("the resolver database init skipped is not opened")
	}

	srv.SetSettings(coreSettings(map[string]any{"decisionCacheMax": 7}))
	ticks.settle()
	snap = m.snapshot.Load()
	switch {
	case !serves(m, "a.example"):
		t.Error("the data is not served after the settings changed")
	case snap.settings.noAAAADB || len(snap.noAAAADB) != 0:
		t.Errorf("noAAAA still applied: flag %v, table %v", snap.settings.noAAAADB, snap.noAAAADB)
	case snap.settings.idnMode != IdnModeOff:
		t.Errorf("idnMode = %q, want off", snap.settings.idnMode)
	case snap.settings.pythonControl || m.controlStop != nil:
		t.Errorf("control: setting %v, reader running %v", snap.settings.pythonControl, m.controlStop != nil)
	case cacheSize(m) != 7:
		t.Errorf("decision cache holds %d, want 7", cacheSize(m))
	}
}

// iniTables is the noAAAA and bypass tables the module loads from an ini's text, with the entries that hold white space
// left out (such a name matches no query) and the bypass networks as a set (a network listed twice matches the same
// clients).
func iniTables(t *testing.T, text string) (noAAAA bool, names map[string]bool, bypass bool, hosts map[string]int, nets map[netip.Prefix]bool) {
	t.Helper()
	config := newConfigParser()
	if err := config.readString(text, "pfb_unbound.ini"); err != nil {
		t.Fatalf("ini: %v", err)
	}
	set, scratch := newModuleSettings(t.TempDir()), newSnapshot()
	if err := (&pfbUnbound{}).loadIniSettings(config, &set, scratch); err != nil {
		t.Fatalf("loadIniSettings: %v", err)
	}
	names = map[string]bool{}
	for name, wildcard := range scratch.noAAAADB {
		if !strings.ContainsFunc(name, unicode.IsSpace) {
			names[name] = wildcard
		}
	}
	nets = map[netip.Prefix]bool{}
	for _, network := range scratch.gpNetDB {
		nets[network] = true
	}
	return set.noAAAADB, names, set.gpListDB, scratch.gpListDB, nets
}

// pfB-DNS builds the same noAAAA and Group Policy bypass tables from the ini Core's settings give as from the sections
// today's writer gives for the same stored values (the fixture sub-slice 7c froze), but the recorded departures: a '%'
// entry, which makes today's ini fail whole, and the netmask and zone forms the DNSBL page never saves.
func TestOnCoreTheNoAAAAAndBypassTablesAreTheIniWritersOwn(t *testing.T) {
	data, err := os.ReadFile("../../../tests/core/fixtures/settings_dns_parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID     string
			Native map[string]any
			Ini    map[string]*string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	departures := map[string]bool{"lists-noaaaa-percent": true, "lists-gp-forms-not-held": true}
	srv := coretest.Start(t, nil)
	checked := 0
	for _, c := range fixture.Cases {
		if c.Ini == nil || departures[c.ID] {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			today := "[MAIN]\npython_enable = on\n"
			for _, name := range []string{"noAAAA", "GP_Bypass_List"} {
				if c.Ini[name] != nil {
					today += "\n[" + name + "]\n" + *c.Ini[name]
				}
			}
			srv.SetSettings(coreSettings(c.Native))
			dir := t.TempDir()
			if _, err := coreinput.SyncSettings(context.Background(), coreinput.New(srv.Socket), dir); err != nil {
				t.Fatalf("SyncSettings: %v", err)
			}
			fromCore, err := os.ReadFile(filepath.Join(dir, "pfb_unbound.ini"))
			if err != nil {
				t.Fatal(err)
			}
			n1, names1, b1, hosts1, nets1 := iniTables(t, today)
			n2, names2, b2, hosts2, nets2 := iniTables(t, string(fromCore))
			if n1 != n2 || !reflect.DeepEqual(names1, names2) {
				t.Errorf("noAAAA from Core %v %v, today %v %v", n2, names2, n1, names1)
			}
			if b1 != b2 || !reflect.DeepEqual(hosts1, hosts2) || !reflect.DeepEqual(nets1, nets2) {
				t.Errorf("bypass from Core %v %v %v, today %v %v %v", b2, hosts2, nets2, b1, hosts1, nets1)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("the fixture holds no case with ini sections")
	}
}

// The settings Core last gave are in the private cache: a start while Core is down applies them.
func TestOnCoreTheCachedSettingsAreAppliedAtAStartWithoutCore(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{"noAaaa": true, "noAaaaList": []any{map[string]any{"domain": "v6.example"}}}))
	_, ticks := bootOnCore(t, dir, srv.Socket)
	ticks.settle()

	m, _ := bootOnCore(t, dir, deadSocket(t))
	snap := m.snapshot.Load()
	if !serves(m, "a.example") || !snap.settings.noAAAADB || !onlyNoAAAA(snap, "v6.example") {
		t.Errorf("the cache is not served: data %v, noAAAA %v %v", serves(m, "a.example"), snap.settings.noAAAADB, snap.noAAAADB)
	}
}

// A new generation of the data keeps the settings and a bypass a control command added, as a reload does; a settings
// change starts from Core's settings, as a restart does.
func TestOnCoreOnlyASettingsChangeDropsAControlEdit(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{"control": true}))
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	if applied, msg := m.pfbApplyControlCommand([]string{"python_control", "addbypass", "10.9.9.9"}); !applied {
		t.Fatalf("addbypass: %s", msg)
	}

	srv.Set(coreData("2", "b.example"))
	ticks.settle()
	snap := m.snapshot.Load()
	if !serves(m, "b.example") || !snap.settings.gpListDB || len(snap.gpListDB) != 1 {
		t.Fatalf("after a data change: served %v, bypass %v %v", serves(m, "b.example"), snap.settings.gpListDB, snap.gpListDB)
	}

	srv.SetSettings(coreSettings(map[string]any{"control": true, "cnameValidation": true}))
	ticks.settle()
	snap = m.snapshot.Load()
	if !snap.settings.pythonCname || snap.settings.gpListDB || len(snap.gpListDB) != 0 {
		t.Errorf("after a settings change: cname %v, bypass %v %v", snap.settings.pythonCname, snap.settings.gpListDB, snap.gpListDB)
	}
}

// forwarding is whether pfB-DNS was started with --observer: the observer reports only arrive then, so no setting holds it.
func TestOnCoreForwardingIsTheObserverFlag(t *testing.T) {
	for _, observer := range []bool{false, true} {
		srv := coretest.Start(t, coreData("1", "a.example"))
		srv.SetSettings(coretest.Settings())
		ticks := make(coreTicks)
		m, err := bootCore(t.TempDir(), testLogDir, srv.Socket, observer, ticks.source)
		if err != nil {
			t.Fatalf("bootCore: %v", err)
		}
		stopModule(t, m)
		ticks.settle()
		if got := m.snapshot.Load().settings.forwarding; got != observer {
			t.Errorf("observer %v: forwarding = %v", observer, got)
		}
	}
}

// Client metrics turned off stop counting client addresses at once; turned on, they count only from then.
func TestOnCoreClientMetricsTurnedOffStopCountingClients(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coreSettings(map[string]any{"metricsClientIp": true}))
	m, ticks := bootOnCore(t, t.TempDir(), srv.Socket)
	ticks.settle()
	m.metricsPrivacyEpochs.Store(&map[int]string{dbResolver: "e1"})
	if ip, _ := m.metricClient(dbResolver, "192.0.2.1"); ip == "" {
		t.Fatal("no client address counted with the authority granted")
	}

	srv.SetSettings(coretest.Settings())
	ticks.settle()
	if ip, epoch := m.metricClient(dbResolver, "192.0.2.1"); ip != "" || epoch != "" {
		t.Errorf("metricClient = %q, %q after client metrics were turned off", ip, epoch)
	}
}
