package decider

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Close is called while a query may still be inside Resolve (the gateway closes the decider after its drain bound, whatever
// the query is doing). A query that outlives Close must find a module that is closed, not one half torn down: it writes no
// row, and it reads the log writer and the GeoIP reader without racing their close.

// closingModule boots a module whose log directory is its own, with DNS Reply logging and the GeoIP test database on.
func closingModule(t *testing.T) (m *pfbUnbound, logDir string) {
	t.Helper()
	_ = modCaptureLog(t)
	previous := maxmindDBPath
	maxmindDBPath = filepath.Join("testdata", "GeoLite2-Country-Test.mmdb")
	t.Cleanup(func() { maxmindDBPath = previous })
	dir := modIniDir(t, "[MAIN]\npython_enable = true\npython_reply = true\n")
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), []byte(`{"version":1,"config":{},"feeds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	logDir = t.TempDir()
	m, err := boot(dir, logDir)
	if err != nil {
		t.Fatal(err)
	}
	if m.logs == nil || m.maxmind == nil {
		t.Fatalf("the module booted without its log writer (%v) or GeoIP reader (%v)", m.logs != nil, m.maxmind != nil)
	}
	return m, logDir
}

// A row of a query that outlives Close is not written: once the module is closed nothing is appended to its logs, as
// nothing else is written after Close (the retired guards of the watchers, the markers and the databases).
func TestARowOfAQueryThatOutlivesCloseIsNotWritten(t *testing.T) {
	m, logDir := closingModule(t)
	m.deinit()

	m.pfbLog(dnsblLogName, "late,row")
	m.pfbLog(dnsReplyLogName, "late,row")

	for _, name := range []string{dnsblLogName, dnsReplyLogName} {
		if data, err := os.ReadFile(filepath.Join(logDir, name)); err == nil {
			t.Errorf("%s holds %q after Close, want nothing written", name, data)
		}
	}
}

// A query reading the log writer and the GeoIP reader while Close closes them is not a data race: run under -race this is
// the check; without it the test still proves the module answers "unk" and writes nothing once closed.
func TestAQueryRunningWhileCloseClosesTheModuleDoesNotRace(t *testing.T) {
	m, _ := closingModule(t)
	settings := m.snapshot.Load().settings

	started, stop := make(chan struct{}), make(chan struct{})
	var queries sync.WaitGroup
	queries.Add(1)
	go func() {
		defer queries.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.geoIPCode(settings, "8.8.8.8")
			m.pfbLog(dnsReplyLogName, "row")
		}
	}()
	<-started
	m.deinit()
	close(stop)
	queries.Wait()

	if got := m.geoIPCode(settings, "8.8.8.8"); got != "unk" {
		t.Errorf("geoIPCode after Close = %q, want unk: the reader is closed", got)
	}
}
