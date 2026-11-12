// issue #3848: a decider that has lost a part of its work keeps serving and says what it lost. Frontend.Degraded lists the
// parts, named as the gateway's control-socket status names them (dnsbl, dnsbl_settings, statistics, observer), in that order,
// each with the message the module already logs.
package decider

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// requireDegraded fails unless f serves without exactly the parts in want, in that order.
func requireDegraded(t *testing.T, f *Frontend, when string, want ...string) []DegradedPart {
	t.Helper()
	got := f.Degraded()
	names := make([]string, len(got))
	for i, p := range got {
		names[i] = p.Part
	}
	if !reflect.DeepEqual(names, append([]string{}, want...)) {
		t.Fatalf("%s: serves without %q, want %q; rows: %+v", when, names, want, got)
	}
	return got
}

func manifestPath(dir string) string { return filepath.Join(dir, "pfb_py_sources.json") }

// A module that booted with no DNSBL build blocks nothing: the status must say so, with the reason the ledger carries.
func TestAModuleWithNoManifestReportsTheDNSBLAsLost(t *testing.T) {
	modCaptureLog(t)
	dir := modIniDir(t, "[MAIN]\npython_enable = true\n")
	f := newFrontend(modMust(t, dir))
	got := requireDegraded(t, f, "no manifest", "dnsbl")
	if want := "DNSBL manifest absent: " + manifestPath(dir) + " -- DNSBL not loaded"; got[0].Reason != want {
		t.Errorf("reason = %q, want %q", got[0].Reason, want)
	}
}

// issue #3870: a module that booted with no pfb_unbound.ini leaves python_enable off and blocks nothing: the status must say so.
func TestAModuleWithNoIniReportsTheDNSBLAsLost(t *testing.T) {
	modCaptureLog(t)
	got := requireDegraded(t, newFrontend(modMust(t, t.TempDir())), "no ini", "dnsbl")
	if want := "Failed to load ini configuration. Ini file missing."; got[0].Reason != want {
		t.Errorf("reason = %q, want %q", got[0].Reason, want)
	}
}

func TestAModuleWhoseManifestCannotBeReadOrBuiltReportsTheDNSBLAsLostWithTheLoadError(t *testing.T) {
	for name, tc := range map[string]struct{ manifest, reasonPrefix string }{
		"corrupt JSON":          {"{not json", "Failed to load DNSBL manifest '%s': "},
		"JSON that is no build": {"[]", "Failed to build DNSBL structures from raw: "},
	} {
		t.Run(name, func(t *testing.T) {
			modCaptureLog(t)
			dir := opManifestModule(t, nil, nil)
			if err := os.WriteFile(manifestPath(dir), []byte(tc.manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			f := newFrontend(modMust(t, dir))
			got := requireDegraded(t, f, name, "dnsbl")
			if want := strings.ReplaceAll(tc.reasonPrefix, "%s", manifestPath(dir)); !strings.HasPrefix(got[0].Reason, want) {
				t.Errorf("reason = %q, want it to start with %q", got[0].Reason, want)
			}
		})
	}
}

// A zero-downtime reload that swaps in a built snapshot ends the loss; the state before it is asserted, so that the flip is the
// reload's.
func TestAReloadThatBuildsTheDNSBLEndsTheLoss(t *testing.T) {
	m, dir := rlManifestModule(t, nil, nil)
	f := newFrontend(m)
	requireDegraded(t, f, "init with no manifest", "dnsbl")
	rlWriteFeeds(t, dir, map[string][]string{"feed.txt": {"a.example"}})
	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatal("the reload with a good manifest did not swap")
	}
	requireDegraded(t, f, "after a reload that built the DNSBL")
}

// The last good snapshot keeps blocking when a later reload cannot build: nothing is lost, so nothing is reported.
func TestAFailedReloadAfterAGoodBuildKeepsTheLastGoodSnapshotAndReportsNothing(t *testing.T) {
	m, dir := rlManifestModule(t, nil, map[string][]string{"feed.txt": {"a.example"}})
	f := newFrontend(m)
	requireDegraded(t, f, "init with a good manifest")
	live := m.snapshot.Load()
	if err := os.WriteFile(manifestPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatal("a reload of a corrupt manifest swapped")
	}
	if m.snapshot.Load() != live {
		t.Fatal("the failed reload replaced the live snapshot")
	}
	requireDegraded(t, f, "after a failed reload")
}

// pfb_unbound.ini that cannot be parsed is read as far as it goes (DNSBL runs with that): the settings are what is lost.
func TestAnIniThatCannotBeParsedReportsTheSettingsAsLost(t *testing.T) {
	for name, tc := range map[string]struct {
		ini  string
		lost bool
	}{
		"parses":           {"[MAIN]\na = 1\n", false},
		"non-UTF-8 bytes":  {"[MAIN]\na = \xff\n", true},
		"a duplicate name": {"[MAIN]\na = 1\na = 2\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			modCaptureLog(t)
			f := newFrontend(modMust(t, modIniDir(t, tc.ini)))
			if !tc.lost {
				requireDegraded(t, f, name)
				return
			}
			got := requireDegraded(t, f, name, "dnsbl_settings")
			if !strings.HasPrefix(got[0].Reason, "Failed to load ini configuration: ") {
				t.Errorf("reason = %q, want the load failure the module logs", got[0].Reason)
			}
		})
	}
}

// A statistics database that cannot be opened turns the counters off, not DNS: the status says so.
func TestAStatisticsDatabaseThatCannotBeOpenedReportsTheStatisticsAsLost(t *testing.T) {
	f := newFrontend(statsOutageModule(t))
	got := requireDegraded(t, f, "both databases unopenable", "statistics")
	if !strings.Contains(got[0].Reason, "Failed to open pfb_py_resolver.sqlite database") {
		t.Errorf("reason = %q, want the first failure the module logs", got[0].Reason)
	}
}

// A database that opens on a later try ends its loss.
func TestAStatisticsDatabaseThatOpensLaterEndsTheLoss(t *testing.T) {
	r := newSqlRig(t, "", nil)
	f := newFrontend(r.m)
	for _, p := range f.Degraded() {
		if p.Part == "statistics" {
			t.Fatalf("a healthy module reports the statistics as lost: %+v", p)
		}
	}
	blocked := r.path(dbDnsbl)
	if err := os.MkdirAll(filepath.Join(blocked, "keep"), 0o755); err != nil { // neither openable nor removable
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep", "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wanted := &pfbSettings{pythonBlacklist: true}
	r.m.openDnsblStatsDbIfWanted(wanted)
	got := f.Degraded()
	if len(got) != 2 || got[1].Part != "statistics" || !strings.Contains(got[1].Reason, "Failed to open pfb_py_dnsbl.sqlite database") {
		t.Fatalf("after the failed open: %+v, want the dnsbl manifest loss and the statistics", got)
	}
	if err := os.RemoveAll(blocked); err != nil {
		t.Fatal(err)
	}
	r.m.openDnsblStatsDbIfWanted(wanted)
	if got := f.Degraded(); len(got) != 1 || got[0].Part != "dnsbl" {
		t.Fatalf("after the database opened: %+v, want only the dnsbl manifest loss", got)
	}
}

// An observer socket that cannot be bound costs upstream-block detection, not DNS.
func TestAnObserverSocketThatCannotBeBoundReportsTheObserverAsLost(t *testing.T) {
	rlQuietLog(t)
	dir := shortDir(t) // its ini turns the DNSBL on, which would lose its manifest: this test is about the observer
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	healthy := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	requireDegraded(t, healthy, "an observer that bound")
	healthy.Close() // frees the path for the next bind
	if err := os.WriteFile(observerPath(dir), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	got := requireDegraded(t, f, "an observer path held by a file", "observer")
	if want := "upstream-block detection is off: cannot listen on pfb_upstream.sock: pfb_upstream.sock exists and is not a socket"; got[0].Reason != want {
		t.Errorf("reason = %q, want %q", got[0].Reason, want)
	}
}

func TestADeciderWithNoModuleReportsNothingLost(t *testing.T) {
	requireDegraded(t, openOK(t, Options{LogDir: testLogDir, NoModule: true}), "no module")
}

// The gateway merges the decider's parts into its own list in one fixed order, so the decider's own order is that order too.
func TestADeciderThatLostEverythingReportsTheDNSBLSettingsStatisticsAndObserverInContractOrder(t *testing.T) {
	rlQuietLog(t)
	previous := dbRetrySleep
	dbRetrySleep = func(time.Duration) {}
	t.Cleanup(func() { dbRetrySleep = previous })
	dir := shortDir(t)
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\npython_enable = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range sqlFileNames {
		if err := os.MkdirAll(filepath.Join(dir, name, "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "keep", "file"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(observerPath(dir), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	requireDegraded(t, f, "everything lost", "dnsbl", "dnsbl_settings", "statistics", "observer")
}
