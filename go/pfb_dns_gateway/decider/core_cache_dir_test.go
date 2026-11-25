package decider

// On the Core input pfB-DNS keeps what it fetched in a folder of its own, which the RAM-disk archive takes whole (issue
// #4251, owner 2026-11-25). The module directory keeps what PHP reads and writes there: the counts, the status ledger,
// the databases, the reload and control markers, and the ini PHP still writes.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

func TestOnCoreWhatPfbDnsFetchedIsKeptInAFolderOfItsOwn(t *testing.T) {
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coretest.Settings())
	dir := t.TempDir()
	m, ticks := bootOnCore(t, dir, srv.Socket)
	ticks.settle()
	if !serves(m, "a.example") {
		t.Fatal("before: the generation is not served")
	}

	cache := filepath.Join(dir, "pfb_dns")
	for _, name := range []string{"pfb_py_core.json", "pfb_py_sources.json", "pfb_py_raw", "pfb_unbound.ini"} {
		if _, err := os.Lstat(filepath.Join(cache, name)); err != nil {
			t.Errorf("%s is not in the cache folder: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is in the module directory, beside what PHP writes there", name)
		}
	}
	if info, err := os.Stat(cache); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the cache folder is %v (%v), want pfB-DNS's alone (0700)", info, err)
	}
}

func TestOnCoreTheCacheFolderIsServedWhileCoreIsDown(t *testing.T) {
	dir := t.TempDir()
	cacheFrom(t, filepath.Join(dir, "pfb_dns"), coreData("1", "a.example"))
	m, _ := bootOnCore(t, dir, deadSocket(t))
	if !serves(m, "a.example") {
		t.Error("the cache folder's generation is not served while Core is down")
	}
}
