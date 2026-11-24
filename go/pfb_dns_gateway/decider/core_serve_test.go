// pfB-DNS on the Core input (issue #4036, sub-slice 7e): it boots from the cache the last Sync left, never waiting for
// Core, polls Core in place of the reload sentinel, swaps in each new generation, and reports what it serves.
//
// The poller's tick is the test's: a send returns once the drain before it has finished and starts the next one, so
// sending twice waits for one whole drain after a change. A drain with nothing new does nothing, which keeps the
// assertions made while the next one runs stable.
package decider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// coreData is one generation of Core's DNSBL data: a manifest and one deny feed that blocks the names given.
func coreData(gen string, blocked ...string) map[string]coretest.Resource {
	feed := coretest.Lines(blocked)
	manifest := coretest.Lines([]string{
		`{"kind":"config","builtinLogFlag":"0","top1mEnabled":false}`,
		fmt.Sprintf(`{"kind":"feed","position":1,"feed":"F","group":"G","logFlag":"1","provenance":"feed","mode":"deny",`+
			`"top1m":false,"resource":"dnsbl/feed-F","generation":%q,"digest":%q,"entries":%d}`, gen, coretest.Digest(feed), len(blocked)),
	})
	return map[string]coretest.Resource{"dnsbl/manifest": {Generation: gen, Body: manifest}, "dnsbl/feed-F": {Generation: gen, Body: feed}}
}

// cursors is what a report names for data.
func cursors(data map[string]coretest.Resource) map[string]coretest.Cursor {
	out := map[string]coretest.Cursor{}
	for id, r := range data {
		out[id] = coretest.Cursor{Generation: r.Generation, Digest: coretest.Digest(r.Body)}
	}
	return out
}

// coreModuleDir is a module directory with an ini that turns DNSBL on, and nothing else.
func coreModuleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// cacheFrom leaves in dir what a Sync of data writes.
func cacheFrom(t *testing.T, dir string, data map[string]coretest.Resource) {
	t.Helper()
	srv := coretest.Start(t, data)
	if _, _, err := coreinput.Sync(context.Background(), coreinput.New(srv.Socket), dir, coreinput.State{}); err != nil {
		t.Fatal(err)
	}
}

// deadSocket is a socket path nothing listens on: Core is down.
func deadSocket(t *testing.T) string { return filepath.Join(t.TempDir(), "api.sock") }

type coreTicks chan time.Time

func (c coreTicks) source() (<-chan time.Time, func()) { return c, func() {} }

// settle waits for the drain running now, then for the one it starts.
func (c coreTicks) settle() {
	c <- time.Time{}
	c <- time.Time{}
}

// bootOnCore boots a module in dir on the Core at socket, with a poller the test ticks.
func bootOnCore(t *testing.T, dir, socket string) (*pfbUnbound, coreTicks) {
	t.Helper()
	ticks := make(coreTicks)
	m, err := bootCore(dir, testLogDir, socket, ticks.source)
	if err != nil {
		t.Fatalf("bootCore: %v", err)
	}
	stopModule(t, m)
	return m, ticks
}

func serves(m *pfbUnbound, name string) bool {
	_, ok := m.snapshot.Load().dataDB[name]
	return ok
}

func TestOnCoreTheCacheIsServedWhileCoreIsDown(t *testing.T) {
	dir := coreModuleDir(t)
	cacheFrom(t, dir, coreData("1", "a.example"))
	f, err := Open(Options{ModuleDir: dir, LogDir: testLogDir, CoreSocket: deadSocket(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(f.Close)
	if !serves(f.module, "a.example") {
		t.Error("the cached generation is not served")
	}
	if parts := f.Degraded(); len(parts) != 0 {
		t.Errorf("Degraded = %v, want nothing lost", parts)
	}
	// The sentinel watcher does not run: Core's input has no reload sentinel and no applied marker.
	if _, err := os.Stat(filepath.Join(dir, "pfb_py_reload.applied")); !os.IsNotExist(err) {
		t.Errorf("pfb_py_reload.applied: %v, want none written", err)
	}
}

func TestOnCoreWithoutACacheNothingIsBlockedAndDNSBLIsDegraded(t *testing.T) {
	m, _ := bootOnCore(t, coreModuleDir(t), deadSocket(t))
	if len(m.snapshot.Load().dataDB) != 0 {
		t.Error("something is blocked without data")
	}
	if parts := newFrontend(m).Degraded(); len(parts) != 1 || parts[0].Part != partDNSBL {
		t.Errorf("Degraded = %v, want the DNSBL lost", parts)
	}
}

// The files of a cache whose state is lost, or that another user could have written, are not built from, though they
// are there: a degraded start, until Core answers.
func TestOnCoreAnUntrustedCacheIsNotServed(t *testing.T) {
	for name, spoil := range map[string]func(dir string) error{
		"the state file is gone":   func(dir string) error { return os.Remove(filepath.Join(dir, "pfb_py_core.json")) },
		"the manifest is writable": func(dir string) error { return os.Chmod(filepath.Join(dir, "pfb_py_sources.json"), 0o666) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := coreModuleDir(t)
			cacheFrom(t, dir, coreData("1", "a.example"))
			if err := spoil(dir); err != nil {
				t.Fatal(err)
			}
			m, _ := bootOnCore(t, dir, deadSocket(t))
			if serves(m, "a.example") {
				t.Error("the untrusted cache is served")
			}
			if parts := newFrontend(m).Degraded(); len(parts) != 1 || parts[0].Part != partDNSBL {
				t.Errorf("Degraded = %v, want the DNSBL lost", parts)
			}
		})
	}
}

// Core up with no data yet, then publishing: the first generation is served after the next poll, the degraded row goes,
// and the generation is reported.
func TestOnCoreANewGenerationIsServedAfterThePollAndReported(t *testing.T) {
	srv := coretest.Start(t, map[string]coretest.Resource{})
	m, ticks := bootOnCore(t, coreModuleDir(t), srv.Socket)
	ticks.settle()
	if len(m.snapshot.Load().dataDB) != 0 {
		t.Fatal("something is blocked before Core has data")
	}
	if got := srv.Applied(); !reflect.DeepEqual(got, []map[string]coretest.Cursor{{}}) {
		t.Errorf("reports before Core has data = %v, want one of nothing served", got)
	}

	gen1 := coreData("1", "a.example")
	srv.Set(gen1)
	ticks.settle()
	if !serves(m, "a.example") {
		t.Fatal("generation 1 is not served after the poll")
	}
	if parts := newFrontend(m).Degraded(); len(parts) != 0 {
		t.Errorf("Degraded = %v, want nothing lost once Core's data is served", parts)
	}

	gen2 := coreData("2", "b.example")
	srv.Set(gen2)
	ticks.settle()
	if !serves(m, "b.example") || serves(m, "a.example") {
		t.Fatal("generation 2 is not what is served after the poll")
	}
	want := []map[string]coretest.Cursor{{}, cursors(gen1), cursors(gen2)}
	if got := srv.Applied(); !reflect.DeepEqual(got, want) {
		t.Errorf("reports = %v, want %v", got, want)
	}
}

// The cache served at start is reported once, though Core has nothing new.
func TestOnCoreTheCacheServedIsReportedOnceAtStart(t *testing.T) {
	dir := coreModuleDir(t)
	gen1 := coreData("1", "a.example")
	cacheFrom(t, dir, gen1)
	srv := coretest.Start(t, gen1)
	_, ticks := bootOnCore(t, dir, srv.Socket)
	ticks.settle()
	ticks.settle()
	if got := srv.Applied(); !reflect.DeepEqual(got, []map[string]coretest.Cursor{cursors(gen1)}) {
		t.Errorf("reports = %v, want one of generation 1", got)
	}
}

// What Core answers that cannot be served leaves the snapshot and the report as they were: a body whose digest is not
// the manifest's, and Core's data gone.
func TestOnCoreAHostileReplyLeavesTheSnapshotUnchanged(t *testing.T) {
	for name, change := range map[string]func(srv *coretest.Server){
		"a delta and a body that are not their digest's": func(srv *coretest.Server) {
			srv.Set(coreData("2", "b.example"))
			hostile := func(id string, w http.ResponseWriter) bool {
				if id != "dnsbl/feed-F" {
					return false
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Write([]byte("c.example\n"))
				return true
			}
			srv.SetBody(hostile)
			srv.SetPart(func(id, _ string, w http.ResponseWriter) bool { return hostile(id, w) })
		},
		"Core's data gone": func(srv *coretest.Server) { srv.Set(map[string]coretest.Resource{}) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := coreModuleDir(t)
			gen1 := coreData("1", "a.example")
			cacheFrom(t, dir, gen1)
			srv := coretest.Start(t, gen1)
			m, ticks := bootOnCore(t, dir, srv.Socket)
			ticks.settle()
			change(srv)
			ticks.settle()
			if !serves(m, "a.example") || serves(m, "b.example") || serves(m, "c.example") {
				t.Error("the snapshot changed")
			}
			if got := srv.Applied(); !reflect.DeepEqual(got, []map[string]coretest.Cursor{cursors(gen1)}) {
				t.Errorf("reports = %v, want only generation 1's", got)
			}
		})
	}
}
