// Every module this package boots starts the log writer and opens the GeoIP reader named by its settings, so the run
// points both at places of its own: no test writes under /var/log/pfblockerng or reads the host's GeoIP database.
package decider

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pfblogs")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pfbLogDir = dir
	maxmindDBPath = filepath.Join(dir, "no-GeoLite2-Country.mmdb")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
