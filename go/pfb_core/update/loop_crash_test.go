package update

// Crash safety of the Core Updater loop (issue #4038, sub-slice 9j-2): the worker is killed at every stage boundary of an
// Update, through the loop's boundary seam, with the replay's fixtures, feed server and stand-in apply (e2e_replay_test.go).
// Run it under the race detector: go test -race -run TestAKilledUpdate ./update/

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// e2eKillAt makes the worker kill itself with SIGKILL at the boundary the file kill of the replay folder names. It wraps
// the recorder e2eWorkerStages installs, which it reads to be initialized after it, so the boundary is recorded first.
var e2eKillAt = func() bool {
	if !e2eWorkerStages {
		return false
	}
	dir, record := os.Getenv(e2eEnv), boundary
	boundary = func(name string) {
		record(name)
		if b, _ := os.ReadFile(filepath.Join(dir, "kill")); strings.TrimSpace(string(b)) == name {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			time.Sleep(time.Hour) // the signal ends the process before this returns
		}
	}
	return true
}()

// e2eSandbox is one box of the replay: a feed server, the settings adapter's and the stand-in apply's folder, the
// sandbox root the Loop's folders live under, and the Update log of its state directory.
type e2eSandbox struct {
	dir, root, self string
	feeds           *e2eFeeds
	server          *httptest.Server
	loop            *Loop
	store           *resources.Store
	log             *os.File
}

func newE2ESandbox(t *testing.T, c e2eCase) *e2eSandbox {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sb := &e2eSandbox{dir: t.TempDir(), root: t.TempDir(), self: self, feeds: &e2eFeeds{bodies: map[string]e2eBody{}}}
	sb.feeds.set(c.Serve)
	sb.server = httptest.NewServer(sb.feeds)
	t.Cleanup(sb.server.Close)
	t.Setenv(e2eEnv, sb.dir)
	sb.loop = e2eLoop(t, sb.root, self)
	sb.store = resources.Open(filepath.Join(sb.root, "core/resources"))
	sb.log = independentLog(t)
	return sb
}

// run runs step i of c as the replay does, and returns what Run returned.
func (sb *e2eSandbox) run(t *testing.T, c e2eCase, i int) error {
	t.Helper()
	sb.feeds.set(c.Steps[i].Serve)
	reply := strings.ReplaceAll(string(c.Expect[i].Snapshot), "{{FEEDS}}", sb.server.URL)
	reply = strings.ReplaceAll(reply, "192.168.89.0/24", "127.0.0.0/8")
	if err := os.WriteFile(filepath.Join(sb.dir, "reply"), []byte(reply), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"stages", "requests"} {
		if err := os.Remove(filepath.Join(sb.dir, f)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	_, err := runCmd(t, &Command{Path: sb.self, Loop: sb.loop}, c.Steps[i].Request, sb.log)
	return err
}

// published is what a client of the store is served: the desired sets by alias and the DNSBL data, as JSON.
func (sb *e2eSandbox) published(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(struct {
		Sets  map[string][]string
		DNSBL *e2eDNSBLData
	}{e2eSets(t, sb.store), e2eDNSBL(t, sb.store)})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// baselines is the applied baseline of every resource the index records: the generation the client applied.
func (sb *e2eSandbox) baselines(t *testing.T) map[string]uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sb.root, "core/resources/index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Resources map[string]struct {
			Applied *struct {
				Generation uint64 `json:"generation,string"`
			}
		}
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for id, e := range idx.Resources {
		if e.Applied != nil {
			out[id] = e.Applied.Generation
		}
	}
	return out
}

// whole fails the test for every resource the store serves that cannot be read whole, and for every body dnsbl/manifest
// names that the store does not hold: the store keeps a body's current generation and its applied baseline (package
// dnsbl), so a row may name either, never a generation it dropped.
func (sb *e2eSandbox) whole(t *testing.T) {
	t.Helper()
	ids, err := sb.store.IDs("")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, id := range ids {
		r, err := sb.store.Get(id, nil)
		if err != nil {
			t.Errorf("the store serves %s, which cannot be read: %v", id, err)
			continue
		}
		f, _, err := sb.store.Body(id, r.Generation, resources.PartMembers, 0)
		if err != nil {
			t.Errorf("%s generation %d: %v", id, r.Generation, err)
			continue
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(f)
		f.Close()
		if n := bytes.Count(buf.Bytes(), []byte("\n")); n != r.Entries {
			t.Errorf("%s generation %d holds %d lines, its index %d", id, r.Generation, n, r.Entries)
		}
	}
	for _, line := range body(t, sb.store, dnsbl.ManifestID) {
		var row struct {
			Resource   string
			Generation uint64 `json:",string"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("manifest row %q: %v", line, err)
		}
		if row.Resource == "" {
			continue
		}
		f, _, err := sb.store.Body(row.Resource, row.Generation, resources.PartMembers, 0)
		if err != nil {
			t.Errorf("dnsbl/manifest names %s generation %d, which the store does not hold: %v", row.Resource, row.Generation, err)
			continue
		}
		f.Close()
	}
}

func e2eCaseNamed(t *testing.T, id string) e2eCase {
	t.Helper()
	raw, err := os.ReadFile(e2eCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Cases []e2eCase }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("the corpus has no case %s", id)
	return e2eCase{}
}

// TestAKilledUpdateLeavesTheStoreWholeAndTheNextConverges kills the worker at each stage boundary of an Update that
// changes an IP feed after a first Update has published and applied everything. After the kill the store serves only
// whole resources, the manifest names only bodies the store holds, and every applied baseline is still held; the next
// Update, the same request again, publishes what one uninterrupted Update does.
func TestAKilledUpdateLeavesTheStoreWholeAndTheNextConverges(t *testing.T) {
	c := e2eCaseNamed(t, "both_first_run_then_unchanged_then_changed")
	const first, changed = 0, 2 // the first Update; the Update that changes ipv4:E2E1A_v4
	var want string
	t.Run("uninterrupted", func(t *testing.T) {
		sb := newE2ESandbox(t, c)
		for _, i := range []int{first, changed} {
			if err := sb.run(t, c, i); err != nil {
				t.Fatalf("step %d: %v\n%s", i, err, logText(t, sb.log))
			}
		}
		want = sb.published(t)
	})
	if want == "" {
		t.Fatal("the uninterrupted Update did not run")
	}
	var names []string
	for _, s := range stages {
		names = append(names, s.name)
	}
	for _, at := range append(names, "end") {
		t.Run(at, func(t *testing.T) {
			sb := newE2ESandbox(t, c)
			if err := sb.run(t, c, first); err != nil {
				t.Fatalf("the first Update: %v\n%s", err, logText(t, sb.log))
			}
			before := sb.baselines(t)
			if len(before) == 0 {
				t.Fatal("the first Update left no applied baseline: the kill would prove nothing about one")
			}
			if err := os.WriteFile(filepath.Join(sb.dir, "kill"), []byte(at), 0o600); err != nil {
				t.Fatal(err)
			}
			err := sb.run(t, c, changed)
			if reached := e2eLines(t, filepath.Join(sb.dir, "stages")); err == nil || len(reached) == 0 || reached[len(reached)-1] != at {
				t.Fatalf("the worker was not killed at %s: Run = %v, boundaries reached %q", at, err, reached)
			}
			if err := os.Remove(filepath.Join(sb.dir, "kill")); err != nil {
				t.Fatal(err)
			}
			sb.whole(t)
			after := sb.baselines(t)
			for id, g := range before {
				if a, ok := after[id]; !ok || a < g {
					t.Errorf("%s lost its applied baseline: generation %d before the kill, %d (held %v) after", id, g, a, ok)
					continue
				}
				f, _, err := sb.store.Body(id, after[id], resources.PartMembers, 0)
				if err != nil {
					t.Errorf("%s: its applied baseline %d cannot be read: %v", id, after[id], err)
					continue
				}
				f.Close()
			}
			if err := sb.run(t, c, changed); err != nil {
				t.Fatalf("the next Update: %v\n%s", err, logText(t, sb.log))
			}
			sb.whole(t)
			if got := sb.published(t); got != want {
				t.Errorf("the next Update did not converge on what one uninterrupted Update publishes:\n have %s\n want %s", got, want)
			}
		})
	}
}
