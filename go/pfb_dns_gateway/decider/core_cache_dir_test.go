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

	cache := filepath.Join(dir, "pfb_dns") // the name pfblockerng.sh archives, spelled out: not CORE_CACHE_DIR
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

// What stands at the cache folder's name is made pfB-DNS's own folder before anything is written there: a looser folder is
// tightened to 0700, and a link or a file is replaced by a folder, so nothing is written through a link.
func TestOnCoreTheCacheFolderIsMadePfbDnsOwnBeforeUse(t *testing.T) {
	for name, plant := range map[string]func(cache, elsewhere string) error{
		"a folder open to others": func(cache, _ string) error { return os.Mkdir(cache, 0o755) },
		"a link to a folder":      func(cache, elsewhere string) error { return os.Symlink(elsewhere, cache) },
		"a file":                  func(cache, _ string) error { return os.WriteFile(cache, []byte("x"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := coretest.Start(t, coreData("1", "a.example"))
			srv.SetSettings(coretest.Settings())
			dir, elsewhere := t.TempDir(), t.TempDir()
			cache := filepath.Join(dir, "pfb_dns")
			if err := plant(cache, elsewhere); err != nil {
				t.Fatal(err)
			}
			m, ticks := bootOnCore(t, dir, srv.Socket)
			ticks.settle()
			info, err := os.Lstat(cache)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
				t.Fatalf("the cache folder is %v (%v), want a folder of pfB-DNS's alone (0700)", info, err)
			}
			if !serves(m, "a.example") {
				t.Error("the generation is not served from the folder")
			}
			if left, _ := os.ReadDir(elsewhere); len(left) != 0 {
				t.Errorf("%d entries were written through the link", len(left))
			}
		})
	}
}

// A cache folder pfB-DNS cannot make its own is not written: the poller fetches nothing into a folder another user
// controls, and nothing is served from it.
func TestOnCoreACacheFolderOfAnotherUserIsNotWritten(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the folder to another user")
	}
	srv := coretest.Start(t, coreData("1", "a.example"))
	srv.SetSettings(coretest.Settings())
	dir := t.TempDir()
	cache := filepath.Join(dir, "pfb_dns")
	if err := os.Mkdir(cache, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(cache, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	m, ticks := bootOnCore(t, dir, srv.Socket)
	ticks.settle()
	if left, _ := os.ReadDir(cache); len(left) != 0 {
		t.Errorf("%d entries were written into a folder of another user", len(left))
	}
	if serves(m, "a.example") {
		t.Error("a generation fetched into a folder of another user is served")
	}
}

// Nor are settings read from it: an ini that would be trusted on its own, in a cache folder pfB-DNS cannot make its own,
// gives the module nothing.
func TestOnCoreTheSettingsOfACacheFolderOfAnotherUserAreNotRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the folder to another user")
	}
	dir := t.TempDir()
	cache := filepath.Join(dir, "pfb_dns")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	ini := "[MAIN]\npython_enable = on\n[noAAAA]\n0 = v6.example,0\n"
	if err := os.WriteFile(filepath.Join(cache, "pfb_unbound.ini"), []byte(ini), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(cache, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	m, _ := bootOnCore(t, dir, deadSocket(t))
	if got := m.snapshot.Load().noAAAADB; len(got) != 0 {
		t.Errorf("the noAAAA table of an ini in a folder of another user was loaded: %v", got)
	}
}
