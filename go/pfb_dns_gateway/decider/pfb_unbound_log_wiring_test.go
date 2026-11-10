// What init_standard wires for the DNS Reply log: the GeoIP reader (opened only when DNS Reply Logging is on and the
// GeoLite2 database is installed) and the log writer.
package decider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// geoModule boots a module whose ini says python_reply = `reply`, with the GeoIP database path set to `database`.
func geoModule(t *testing.T, reply string, database string) (*pfbUnbound, string) {
	t.Helper()
	logs := modCaptureLog(t)
	previous := maxmindDBPath
	maxmindDBPath = database
	t.Cleanup(func() { maxmindDBPath = previous })
	dir := modIniDir(t, "[MAIN]\npython_enable = true\npython_reply = "+reply+"\n")
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), []byte(`{"version":1,"config":{},"feeds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := boot(dir)
	if err != nil {
		t.Fatal(err)
	}
	stopModule(t, m)
	return m, logs.String()
}

func TestInitOpensTheGeoIPReaderWhenRepliesAreLoggedAndTheDatabaseIsInstalled(t *testing.T) {
	m, logs := geoModule(t, "true", filepath.Join("testdata", "GeoLite2-Country-Test.mmdb"))
	if !m.snapshot.Load().settings.pythonMaxmind || m.maxmind == nil {
		t.Errorf("python_maxmind = %v, reader = %v, want both on: DNS Reply Logging is on and the database exists", m.snapshot.Load().settings.pythonMaxmind, m.maxmind)
	}
	if logs != "" {
		t.Errorf("log = %q, want nothing", logs)
	}
	m.closeMaxmind()
	if m.maxmind != nil {
		t.Errorf("reader = %v after close, want none: deinit closes it", m.maxmind)
	}
}

func TestInitLeavesGeoIPOffWhenRepliesAreNotLogged(t *testing.T) {
	m, _ := geoModule(t, "false", filepath.Join("testdata", "GeoLite2-Country-Test.mmdb"))
	if m.snapshot.Load().settings.pythonMaxmind || m.maxmind != nil {
		t.Error("the GeoIP reader is open with DNS Reply Logging off: it is opened for the reply rows only")
	}
}

func TestInitLeavesGeoIPOffWithoutTheDatabase(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{"absent": filepath.Join(dir, "absent.mmdb"), "a directory": dir} {
		m, logs := geoModule(t, "true", path)
		if m.snapshot.Load().settings.pythonMaxmind || m.maxmind != nil {
			t.Errorf("%s: the GeoIP reader is open, want it off: os.path.isfile is false", name)
		}
		if logs != "" {
			t.Errorf("%s: log = %q, want nothing for a database that is not installed", name, logs)
		}
	}
}

func TestInitReportsAGeoIPDatabaseItCannotOpenAndBootsWithoutIt(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	if err := os.WriteFile(bad, []byte("this is not a MaxMind DB"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, logs := geoModule(t, "true", bad)
	if m.snapshot.Load().settings.pythonMaxmind || m.maxmind != nil {
		t.Error("python_maxmind is on for a database that did not open")
	}
	if !strings.Contains(logs, "[pfBlockerNG]: Failed to open MaxMind DB: ") {
		t.Errorf("log = %q, want the open failure reported", logs)
	}
}

func TestEveryBootStartsALogWriterThatStopLoggingEnds(t *testing.T) {
	m, _ := geoModule(t, "false", filepath.Join(t.TempDir(), "absent.mmdb"))
	if m.logs == nil {
		t.Fatal("no log writer after init_standard: pfb_setup_logging runs at its end")
	}
	m.stopLogging()
	if m.logs != nil {
		t.Error("the log writer is still set after stopLogging: deinit sets pfb[\"log_listener\"] False")
	}
	m.stopLogging() // a second stop is not an error
}
