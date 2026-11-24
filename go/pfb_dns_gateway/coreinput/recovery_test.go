package coreinput_test

// What Load and Sync do with a module directory that is not what the last Sync left: an interrupted Sync, a file gone or
// changed, a state file lost, and Core's data gone.

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
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
		{"the manifest gone", func(dir string) error { return os.Remove(filepath.Join(dir, "pfb_py_sources.json")) }},
		{"the manifest a link", func(dir string) error {
			path := filepath.Join(dir, "pfb_py_sources.json")
			if err := os.Rename(path, path+".real"); err != nil {
				return err
			}
			return os.Symlink(path+".real", path)
		}},
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

// Core answering not_found for the manifest is also a store not rebuilt yet (a RAM disk after a reboot), when the cache is
// what keeps DNSBL up: DNSBL switched off reaches pfB-DNS through its settings, so Sync keeps every file.
func TestCoreDataGoneKeepsTheCache(t *testing.T) {
	dir, state, srv, c := synced(t)
	want := tree(t, dir)
	srv.Set(map[string]coretest.Resource{})
	got, changed, err := coreinput.Sync(context.Background(), c, dir, state)
	if !errors.Is(err, coreinput.ErrNoData) || changed || got.Manifest != state.Manifest {
		t.Fatalf("Sync = %+v, changed %v, %v; want ErrNoData, no change, the state kept", got, changed, err)
	}
	if after := tree(t, dir); !maps.Equal(after, want) {
		t.Errorf("files = %q, want %q", after, want)
	}
	if loaded := coreinput.Load(dir); loaded.Manifest != state.Manifest {
		t.Errorf("Load = %+v, want the state kept", loaded)
	}
}

// The folder the manifest on disk names stays through the next Sync even when Load trusts nothing: a build may read it.
func TestTheFolderTheManifestNamesOutlivesALostState(t *testing.T) {
	dir, _, srv, c := synced(t)
	g7 := rawOf(t, dir)
	if err := os.Remove(filepath.Join(dir, "pfb_py_core.json")); err != nil {
		t.Fatal(err)
	}
	srv.Set(data("8", "b.example"))
	if _, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil || !changed {
		t.Fatalf("Sync: changed %v, %v", changed, err)
	}
	if got := tree(t, dir)[g7]; got != "a.example\n" {
		t.Errorf("%s = %q, want it kept", g7, got)
	}
}

func TestAnEmptySafeSearchBodyIsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, memberWith("dnsbl/safesearch", 4, ""))
	res := memberWith("dnsbl/safesearch", 4, "")
	res["dnsbl/safesearch"] = coretest.Resource{Generation: "9", Body: []byte{}}
	m := rows(res["dnsbl/manifest"].Body)
	m[4] = `{"kind":"member","resource":"dnsbl/safesearch","generation":"9","digest":"` + coretest.Digest(nil) + `","entries":0}`
	res["dnsbl/manifest"] = coretest.Resource{Generation: "9", Body: coretest.Lines(m)}
	srv.Set(res)
	state, _, err := coreinput.Sync(context.Background(), coreinput.New(srv.Socket), dir, coreinput.State{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := tree(t, dir)["pfb_py_ss.txt"]; !ok || got != "" {
		t.Errorf("pfb_py_ss.txt = %q (present %v), want an empty file", got, ok)
	}
	if loaded := coreinput.Load(dir); loaded.Manifest != state.Manifest {
		t.Errorf("Load = %+v, want %+v", loaded, state.Manifest)
	}
}

func TestSyncRemovesTheTemporaryFilesAnInterruptedWriteLeft(t *testing.T) {
	dir, _, srv, c := synced(t)
	for _, name := range []string{".pfb_py_ss.txt.123", ".pfb_py_sources.json.9", ".pfb_py_core.json.1", ".dnsbl_psl.5"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.Set(data("8", "b.example"))
	if _, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil {
		t.Fatal(err)
	}
	got := tree(t, dir)
	for _, name := range []string{".pfb_py_ss.txt.123", ".pfb_py_sources.json.9", ".pfb_py_core.json.1", ".dnsbl_psl.5"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s is still there", name)
		}
	}
	if _, ok := got["pfb_unbound.ini"]; !ok {
		t.Error("a file Sync does not write is gone")
	}
}

// A cache file another user could have written, or that is not the file itself, is not trusted (issue #4036's hostile
// cache rows): Load answers no state, so that pfB-DNS does not build from it and the next Sync fetches everything.
func TestACacheFileAnotherUserCouldWriteIsNotTrusted(t *testing.T) {
	chmod := func(rel func(t *testing.T, dir string) string, mode os.FileMode) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, rel(t, dir)), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	chown := func(rel func(t *testing.T, dir string) string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if os.Geteuid() != 0 {
				t.Skip("changing a file's owner needs root")
			}
			if err := os.Lchown(filepath.Join(dir, rel(t, dir)), 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}
	}
	named := func(name string) func(*testing.T, string) string {
		return func(*testing.T, string) string { return name }
	}
	for name, spoil := range map[string]func(t *testing.T, dir string){
		"the state file is world-writable":       chmod(named("pfb_py_core.json"), 0o606),
		"the manifest is group-writable":         chmod(named("pfb_py_sources.json"), 0o620),
		"a feed file is world-writable":          chmod(rawOf, 0o602),
		"the TOP1M file is group-writable":       chmod(named("pfb_py_top1m.txt"), 0o660),
		"the PSL file is world-writable":         chmod(named("dnsbl_psl"), 0o606),
		"the state file belongs to another user": chown(named("pfb_py_core.json")),
		"a feed file belongs to another user":    chown(rawOf),
		"the SafeSearch file belongs to another": chown(named("pfb_py_ss.txt")),
		"the state file is a symbolic link": func(t *testing.T, dir string) {
			state := filepath.Join(dir, "pfb_py_core.json")
			if err := os.Rename(state, state+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(state+".real", state); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, state, _, _ := synced(t)
			if got := coreinput.Load(dir); got.Manifest != state.Manifest {
				t.Fatalf("Load before the change = %+v, want %+v", got.Manifest, state.Manifest)
			}
			spoil(t, dir)
			if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
				t.Errorf("Load = %+v, want no state", got)
			}
		})
	}
}

// The SafeSearch and PSL files are written converted, not as Core sent them: Load checks them against what the Sync
// wrote, so a truncated or emptied one is not trusted either.
func TestATruncatedSafeSearchOrPSLFileIsNotTrusted(t *testing.T) {
	for name, content := range map[string]string{"pfb_py_ss.txt": "www.goo", "dnsbl_psl": ""} {
		t.Run(name, func(t *testing.T) {
			dir, _, _, _ := synced(t)
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
				t.Errorf("Load = %+v, want no state", got.Manifest)
			}
		})
	}
}

// A state file of another version, or of none (a cache an older binary wrote), is not trusted.
func TestAStateOfAnotherVersionIsNotTrusted(t *testing.T) {
	for name, version := range map[string]any{"none": nil, "a later one": 2} {
		t.Run(name, func(t *testing.T) {
			dir, _, _, _ := synced(t)
			path := filepath.Join(dir, "pfb_py_core.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if _, ok := doc["version"]; !ok {
				t.Fatalf("the state file has no version: %s", data)
			}
			if version == nil {
				delete(doc, "version")
			} else {
				doc["version"] = version
			}
			if data, err = json.Marshal(doc); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := coreinput.Load(dir); got.Manifest != (coreinput.Cursor{}) {
				t.Errorf("Load = %+v, want no state", got.Manifest)
			}
		})
	}
}

// A generation lower than the one cached (a store Core rebuilt) is taken as a full manifest whose bodies all verify
// (#4036, 2026-11-21).
func TestALowerGenerationIsTakenWhenItsBodiesVerify(t *testing.T) {
	dir, _, _, _ := synced(t)
	rebuilt := coretest.Start(t, data("5", "b.example"))
	got, changed, err := coreinput.Sync(context.Background(), coreinput.New(rebuilt.Socket), dir, coreinput.Load(dir))
	if err != nil || !changed || got.Manifest.Generation != "5" {
		t.Fatalf("Sync of the rebuilt store: %+v, changed %v, %v", got.Manifest, changed, err)
	}
	if feed := tree(t, dir)[rawOf(t, dir)]; feed != "b.example\n" {
		t.Errorf("the feed = %q", feed)
	}
}
