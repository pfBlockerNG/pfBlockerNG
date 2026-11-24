package coreinput_test

// What Load and Sync do with a module directory that is not what the last Sync left: an interrupted Sync, a file gone or
// changed, a state file lost, and Core's data gone.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// synced is dir after a good Sync of generation 7, its state, and the server.
func synced(t *testing.T) (string, coreinput.State, *coretest.Server, *coreinput.Client) {
	t.Helper()
	dir := t.TempDir()
	srv := coretest.Start(t, data("7", "a.example"))
	c := coreinput.New(srv.Socket)
	state, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.State{})
	if err != nil {
		t.Fatal(err)
	}
	return dir, state, srv, c
}

func TestAnInterruptedSyncLeavesNoStateToTrust(t *testing.T) {
	dir, state, srv, c := synced(t)
	// The manifest's rename fails: a folder stands where it goes.
	sources := filepath.Join(dir, "pfb_py_sources.json")
	if err := os.Remove(sources); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sources, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	srv.Set(data("8", "b.example"))
	if _, _, err := coreinput.Sync(context.Background(), c, dir, state); err == nil {
		t.Fatal("Sync over a manifest it cannot replace succeeded")
	}
	if err := os.RemoveAll(sources); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sources, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
		t.Fatalf("Load after an interrupted Sync = %+v, want no state", got)
	}
	if _, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil || !changed {
		t.Fatalf("Sync after an interrupted one: changed %v, %v", changed, err)
	}
	if got := tree(t, dir)[rawOf(t, dir)]; got != "b.example\n" {
		t.Errorf("the feed = %q, want generation 8's", got)
	}
}

func TestAFileGoneOrChangedIsFetchedAgain(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(dir string) error
	}{
		{"the feed folder gone", func(dir string) error { return os.RemoveAll(filepath.Dir(filepath.Join(dir, rawOfDir(dir)))) }},
		{"a feed changed", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, rawOfDir(dir)), []byte("evil.example\n"), 0o600)
		}},
		{"TOP1M changed", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "pfb_py_top1m.txt"), []byte("x\n"), 0o600)
		}},
		{"SafeSearch gone", func(dir string) error { return os.Remove(filepath.Join(dir, "pfb_py_ss.txt")) }},
		{"the PSL gone", func(dir string) error { return os.Remove(filepath.Join(dir, "dnsbl_psl")) }},
		{"the state file gone", func(dir string) error { return os.Remove(filepath.Join(dir, "pfb_py_core.json")) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, _, _, cl := synced(t)
			want := tree(t, dir)
			if err := c.break_(dir); err != nil {
				t.Fatal(err)
			}
			if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
				t.Fatalf("Load = %+v, want no state", got)
			}
			if _, changed, err := coreinput.Sync(context.Background(), cl, dir, coreinput.Load(dir)); err != nil || !changed {
				t.Fatalf("Sync: changed %v, %v", changed, err)
			}
			got := tree(t, dir)
			for name, content := range map[string]string{"pfb_py_top1m.txt": want["pfb_py_top1m.txt"], "pfb_py_ss.txt": want["pfb_py_ss.txt"],
				"dnsbl_psl": want["dnsbl_psl"], rawOf(t, dir): "a.example\n"} {
				if got[name] != content {
					t.Errorf("%s = %q, want %q", name, got[name], content)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, rawOf(t, dir))); err != nil {
				t.Errorf("the folder the manifest names: %v", err)
			}
		})
	}
}

// rawOfDir is rawOf for a fixture step that has no test to fail: "" when the manifest names no feed.
func rawOfDir(dir string) string {
	var doc struct{ Feeds []struct{ Raw string } }
	data, _ := os.ReadFile(filepath.Join(dir, "pfb_py_sources.json"))
	if json.Unmarshal(data, &doc) != nil || len(doc.Feeds) == 0 {
		return ""
	}
	return doc.Feeds[0].Raw
}

func TestCoreDataGoneRemovesTheCoreFiles(t *testing.T) {
	dir, state, srv, c := synced(t)
	srv.Set(map[string]coretest.Resource{})
	_, changed, err := coreinput.Sync(context.Background(), c, dir, state)
	if !errors.Is(err, coreinput.ErrNoData) || !changed {
		t.Fatalf("Sync = changed %v, %v; want ErrNoData and a change", changed, err)
	}
	if got := tree(t, dir); len(got) != 0 {
		t.Errorf("dir still holds %q", got)
	}
	if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
		t.Errorf("Load = %+v, want no state", got)
	}
}
