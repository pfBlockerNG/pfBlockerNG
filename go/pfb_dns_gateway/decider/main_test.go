// Every module this package boots starts the log writer and opens the GeoIP reader named by its settings, so the run
// points both at places of its own: no test writes under /var/log/pfblockerng or reads the host's GeoIP database.
package decider

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// stopModule ends what init_standard started for a module booted by a test (deinit's stop of the reload watcher, the log
// writer, close of the GeoIP reader and close of the stats databases) when the test ends, so no test leaks a goroutine or
// a descriptor.
func stopModule(t *testing.T, m *pfbUnbound) {
	t.Helper()
	t.Cleanup(m.closeMaxmind)
	t.Cleanup(m.stopLogging)
	t.Cleanup(m.closeDb) // a module holds its stats databases open: a test that leaves them lets the descriptors add up
	t.Cleanup(m.stopQueryWatcher)
	t.Cleanup(m.stopReloadWatcher) // registered last, it runs first: a watcher mid-build must not meet a closed database
}

// testLogDir is where every module of these tests writes its logs: a directory of its own, never /var/log/pfblockerng.
var testLogDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pfblogs")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	testLogDir = dir
	maxmindDBPath = filepath.Join(dir, "no-GeoLite2-Country.mmdb")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
