package coreinput_test

// What a Sync fetches of a new generation (owner, 2026-11-24): a body the last one already had is not fetched again, and
// a changed feed or TOP1M body that Core holds a delta for arrives as that delta, merged into the cached body. A delta
// that does not turn the cached body into the one the manifest names is dropped for the full body.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coreinput"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// withTop1m is data with the TOP1M body holding top and the manifest's row for it to match, at generation gen.
func withTop1m(res map[string]coretest.Resource, gen string, top ...string) map[string]coretest.Resource {
	body := coretest.Lines(top)
	res["dnsbl/top1m"] = coretest.Resource{Generation: gen, Body: body}
	m := rows(res["dnsbl/manifest"].Body)
	m[3] = fmt.Sprintf(`{"kind":"member","resource":"dnsbl/top1m","generation":%q,"digest":%q,"entries":%d}`, gen,
		coretest.Digest(body), len(top))
	res["dnsbl/manifest"] = coretest.Resource{Generation: res["dnsbl/manifest"].Generation, Body: coretest.Lines(m)}
	return res
}

// bodyCalls is the GetResourceBody calls among calls.
func bodyCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "GetResourceBody ") {
			out = append(out, c)
		}
	}
	return out
}

func TestABodyTheLastGenerationHadIsNotFetchedAgain(t *testing.T) {
	dir, state, srv, c := synced(t)
	next := data("7", "a.example")
	m := rows(next["dnsbl/manifest"].Body)
	m[1] = `{"kind":"whitelist","domain":"other.example"}`
	next["dnsbl/manifest"] = coretest.Resource{Generation: "8", Body: coretest.Lines(m)}
	srv.Set(next)
	before := len(srv.Calls())
	got, changed, err := coreinput.Sync(context.Background(), c, dir, state)
	if err != nil || !changed {
		t.Fatalf("Sync: changed %v, %v", changed, err)
	}
	if calls := bodyCalls(srv.Calls()[before:]); !slices.Equal(calls, []string{"GetResourceBody dnsbl/manifest members"}) {
		t.Errorf("bodies fetched = %q, want the manifest's only", calls)
	}
	files := tree(t, dir)
	if files[rawOf(t, dir)] != "a.example\n" || files["pfb_py_top1m.txt"] != "top.example\n" ||
		!strings.Contains(files["pfb_py_ss.txt"], "www.google.com") || !strings.Contains(files["dnsbl_psl"], "blogspot.com") {
		t.Errorf("files after the Sync = %q", files)
	}
	if loaded := coreinput.Load(dir); loaded.Manifest != got.Manifest {
		t.Errorf("Load = %+v, want the Sync's state", loaded.Manifest)
	}
}

func TestAChangedFeedArrivesAsADelta(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, withTop1m(data("7", "a.example", "b.example"), "7", "t1.example", "t2.example"))
	c := coreinput.New(srv.Socket)
	state, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.State{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Set(withTop1m(data("8", "b.example", "c.example"), "8", "t2.example", "t3.example"))
	before := len(srv.Calls())
	got, changed, err := coreinput.Sync(context.Background(), c, dir, state)
	if err != nil || !changed {
		t.Fatalf("Sync: changed %v, %v", changed, err)
	}
	for _, call := range bodyCalls(srv.Calls()[before:]) {
		if call == "GetResourceBody dnsbl/feed-F members" || call == "GetResourceBody dnsbl/top1m members" {
			t.Errorf("%s: the full body was fetched", call)
		}
	}
	files := tree(t, dir)
	if files[rawOf(t, dir)] != "b.example\nc.example\n" || files["pfb_py_top1m.txt"] != "t2.example\nt3.example\n" {
		t.Errorf("feed %q, TOP1M %q after the delta", files[rawOf(t, dir)], files["pfb_py_top1m.txt"])
	}
	if loaded := coreinput.Load(dir); loaded.Manifest != got.Manifest {
		t.Errorf("Load = %+v, want the Sync's state", loaded.Manifest)
	}
}

// A delta part that does not merge into the cached body, or that Core no longer holds, is dropped: the full body is
// fetched and the Sync succeeds.
func TestADeltaThatDoesNotApplyIsReplacedByTheFullBody(t *testing.T) {
	plain := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(body))
	}
	for name, add := range map[string]func(w http.ResponseWriter){
		"adds a member the body has": func(w http.ResponseWriter) { plain(w, "b.example\n") },
		"out of byte order":          func(w http.ResponseWriter) { plain(w, "d.example\nc.example\n") },
		"a line repeated":            func(w http.ResponseWriter) { plain(w, "c.example\nc.example\n") },
		"another line count":         func(w http.ResponseWriter) { plain(w, "c.example\nd.example\n") },
		"not plain text": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("c.example\n"))
		},
		"a merge that is not the body": func(w http.ResponseWriter) { plain(w, "d.example\n") },
		"pruned": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			w.Write([]byte(`{"error":{"code":"not_found","message":"not found"}}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			srv := coretest.Start(t, data("7", "a.example", "b.example"))
			c := coreinput.New(srv.Socket)
			state, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.State{})
			if err != nil {
				t.Fatal(err)
			}
			srv.Set(data("8", "b.example", "c.example"))
			srv.SetPart(func(id, part string, w http.ResponseWriter) bool {
				if id != "dnsbl/feed-F" || part != "add" {
					return false
				}
				add(w)
				return true
			})
			before := len(srv.Calls())
			if _, changed, err := coreinput.Sync(context.Background(), c, dir, state); err != nil || !changed {
				t.Fatalf("Sync: changed %v, %v", changed, err)
			}
			if !slices.Contains(srv.Calls()[before:], "GetResourceBody dnsbl/feed-F members") {
				t.Error("the full body was not fetched")
			}
			if got := tree(t, dir)[rawOf(t, dir)]; got != "b.example\nc.example\n" {
				t.Errorf("the feed = %q", got)
			}
		})
	}
}

// A remove part naming a member the cached body has not is no delta of it either.
func TestARemovePartForAMemberNotThereIsReplacedByTheFullBody(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, data("7", "a.example", "b.example"))
	c := coreinput.New(srv.Socket)
	state, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.State{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Set(data("8", "b.example", "c.example"))
	srv.SetPart(func(id, part string, w http.ResponseWriter) bool {
		if id != "dnsbl/feed-F" || part != "remove" {
			return false
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("z.example\n"))
		return true
	})
	if _, _, err := coreinput.Sync(context.Background(), c, dir, state); err != nil {
		t.Fatal(err)
	}
	if got := tree(t, dir)[rawOf(t, dir)]; got != "b.example\nc.example\n" {
		t.Errorf("the feed = %q", got)
	}
}

// The cached body a delta merges into is the one the last Sync left; one changed under it since is not trusted by Load,
// so the next Sync starts from no state and fetches everything whole.
func TestADeltaIsNotMergedIntoACachedBodyThatChanged(t *testing.T) {
	dir, _, srv, c := synced(t)
	if err := os.WriteFile(filepath.Join(dir, rawOf(t, dir)), []byte("x.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.Set(data("8", "b.example"))
	before := len(srv.Calls())
	if _, _, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(srv.Calls()[before:], "GetResourceBody dnsbl/feed-F members") {
		t.Error("the full body was not fetched")
	}
	if got := tree(t, dir)[rawOf(t, dir)]; got != "b.example\n" {
		t.Errorf("the feed = %q", got)
	}
}
