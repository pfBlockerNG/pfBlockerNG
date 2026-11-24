package coreinput_test

// What Sync does with what Core answers (issue #4036, sub-slice 7d): a hostile reply leaves the module directory as it
// was, an unchanged manifest fetches nothing, and a new generation replaces the files and the folder of the last.

import (
	"context"
	"encoding/json"
	"errors"
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

// data is a dnsbl/* set: a feed, TOP1M, SafeSearch and the PSL, with the manifest naming them at gen.
func data(gen string, feedRows ...string) map[string]coretest.Resource {
	feed := coretest.Lines(feedRows)
	top1m := coretest.Lines([]string{"top.example"})
	ss := coretest.Lines([]string{`{"host":"www.google.com","a":"forcesafesearch.google.com","aaaa":"forcesafesearch.google.com"}`})
	psl := coretest.Lines([]string{`{"section":"icann","rule":"com"}`, `{"section":"private","rule":"blogspot.com"}`})
	row := func(kind, id string, body []byte, extra string) string {
		return fmt.Sprintf(`{"kind":%q,%s"resource":%q,"generation":%q,"digest":%q,"entries":%d}`, kind, extra, id, gen,
			coretest.Digest(body), strings.Count(string(body), "\n"))
	}
	manifest := []string{
		`{"kind":"config","builtinLogFlag":"0","top1mEnabled":true}`,
		`{"kind":"whitelist","domain":"allowed.example"}`,
		row("feed", "dnsbl/feed-F", feed, `"position":1,"feed":"F","group":"G","logFlag":"1","provenance":"feed","mode":"deny","top1m":false,`),
		row("member", "dnsbl/top1m", top1m, ""),
		row("member", "dnsbl/safesearch", ss, ""),
		row("member", "dnsbl/psl", psl, ""),
	}
	return map[string]coretest.Resource{
		"dnsbl/manifest": {Generation: gen, Body: coretest.Lines(manifest)}, "dnsbl/feed-F": {Generation: gen, Body: feed},
		"dnsbl/top1m": {Generation: gen, Body: top1m}, "dnsbl/safesearch": {Generation: gen, Body: ss},
		"dnsbl/psl": {Generation: gen, Body: psl},
	}
}

// pslWith is generation 9 with the PSL body of row alone.
func pslWith(row string) map[string]coretest.Resource { return memberWith("dnsbl/psl", 5, row) }

// ssWith is generation 9 with the SafeSearch body of row alone.
func ssWith(row string) map[string]coretest.Resource { return memberWith("dnsbl/safesearch", 4, row) }

func memberWith(id string, at int, row string) map[string]coretest.Resource {
	res := data("9", "x.example")
	body := coretest.Lines([]string{row})
	res[id] = coretest.Resource{Generation: "9", Body: body}
	m := rows(res["dnsbl/manifest"].Body)
	m[at] = fmt.Sprintf(`{"kind":"member","resource":%q,"generation":"9","digest":%q,"entries":1}`, id, coretest.Digest(body))
	res["dnsbl/manifest"] = coretest.Resource{Generation: "9", Body: coretest.Lines(m)}
	return res
}

// tree is every file under dir with its content.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(dir, path)
			out[rel] = string(b)
		}
		return nil
	})
	return out
}

func TestSyncWritesTheModuleFilesAndReplacesTheLastGeneration(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, data("7", "a.example", "b.example"))
	c := coreinput.New(srv.Socket)
	state, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir))
	if err != nil || !changed {
		t.Fatalf("Sync: changed %v, %v", changed, err)
	}
	got := tree(t, dir)
	g7 := rawOf(t, dir)
	if !strings.HasPrefix(g7, "pfb_py_raw/g7.") || !strings.HasSuffix(g7, "/feed-F.txt") {
		t.Errorf("the feed's raw = %q, want pfb_py_raw/g7.<unique>/feed-F.txt", g7)
	}
	want := map[string]string{
		g7:                 "a.example\nb.example\n",
		"pfb_py_top1m.txt": "top.example\n",
		"pfb_py_ss.txt":    "www.google.com,forcesafesearch.google.com,forcesafesearch.google.com\n",
		"dnsbl_psl": "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n" +
			"// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n",
		"pfb_py_sources.json": `{"config":{"builtin_log_flag":"0","tld_wildcard_blacklist":[],"tld_wildcard_exclusion":[],` +
			`"top1m_enabled":true,"user_unlock":[],"user_whitelist":["allowed.example"]},"feeds":[{"feed":"F",` +
			`"group":"G","log_flag":"1","mode":"deny","provenance":"feed","raw":"` + g7 + `","top1m":false}],"version":1}`,
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("%s = %q, want %q", name, got[name], content)
		}
	}
	if len(state.Resources) != 5 || state.Manifest.Generation != "7" || state.Resources["dnsbl/feed-F"].Generation != "7" {
		t.Errorf("state = %+v, want the manifest and its four bodies at 7", state)
	}
	if loaded := coreinput.Load(dir); loaded.Manifest != state.Manifest || len(loaded.Resources) != 5 {
		t.Errorf("Load = %+v, want %+v", loaded, state)
	}

	// The same manifest again: nothing fetched but its cursor, nothing changed.
	before := len(srv.Calls())
	if _, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil || changed {
		t.Fatalf("Sync over an unchanged manifest: changed %v, %v", changed, err)
	}
	if calls := srv.Calls()[before:]; !slices.Equal(calls, []string{"GetResources dnsbl/manifest"}) {
		t.Errorf("calls over an unchanged manifest = %q", calls)
	}

	// A new generation without TOP1M, SafeSearch or PSL removes their files; the last feed folder stays for a build that
	// may still read it, until the Sync after.
	next := data("8", "c.example")
	m := rows(next["dnsbl/manifest"].Body)
	m[0] = `{"kind":"config","builtinLogFlag":"0","top1mEnabled":false}`
	next["dnsbl/manifest"] = coretest.Resource{Generation: "8", Body: coretest.Lines(m[:3])}
	srv.Set(next)
	if _, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil || !changed {
		t.Fatalf("Sync of generation 8: changed %v, %v", changed, err)
	}
	got = tree(t, dir)
	for _, gone := range []string{"pfb_py_top1m.txt", "pfb_py_ss.txt", "dnsbl_psl"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%s is still there", gone)
		}
	}
	g8 := rawOf(t, dir)
	if got[g8] != "c.example\n" || got[g7] != "a.example\nb.example\n" {
		t.Errorf("after generation 8: its feed %q = %q, the last one %q = %q", g8, got[g8], g7, got[g7])
	}
	srv.Set(data("9", "d.example"))
	if _, changed, err := coreinput.Sync(context.Background(), c, dir, coreinput.Load(dir)); err != nil || !changed {
		t.Fatalf("Sync of generation 9: changed %v, %v", changed, err)
	}
	got = tree(t, dir)
	if _, ok := got[g7]; ok {
		t.Errorf("%s is still there two generations on", g7)
	}
	if _, ok := got[g8]; !ok {
		t.Errorf("%s, the last generation's feed, is gone", g8)
	}
}

// rawOf is the raw path of the first feed pfb_py_sources.json names.
func rawOf(t *testing.T, dir string) string {
	t.Helper()
	var doc struct{ Feeds []struct{ Raw string } }
	data, err := os.ReadFile(filepath.Join(dir, "pfb_py_sources.json"))
	if err != nil || json.Unmarshal(data, &doc) != nil || len(doc.Feeds) == 0 {
		t.Fatalf("pfb_py_sources.json names no feed: %v", err)
	}
	return doc.Feeds[0].Raw
}

// rows is a body's lines.
func rows(body []byte) []string { return strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") }

func TestSyncWithoutDataChangesNothing(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, map[string]coretest.Resource{})
	if _, changed, err := coreinput.Sync(context.Background(), coreinput.New(srv.Socket), dir, coreinput.State{}); !errors.Is(err, coreinput.ErrNoData) || changed {
		t.Fatalf("Sync = changed %v, %v; want ErrNoData", changed, err)
	}
	if got := tree(t, dir); len(got) != 0 {
		t.Errorf("dir holds %q", got)
	}
}

// TestAHostileReplyLeavesTheModuleAsItWas serves a good generation, then a hostile one: Sync fails and every file stays.
func TestAHostileReplyLeavesTheModuleAsItWas(t *testing.T) {
	manifestWith := func(edit func(rows []string) []string) map[string]coretest.Resource {
		res := data("9", "x.example")
		res["dnsbl/manifest"] = coretest.Resource{Generation: "9", Body: coretest.Lines(edit(rows(res["dnsbl/manifest"].Body)))}
		return res
	}
	body := func(id string, reply func(w http.ResponseWriter)) func(string, http.ResponseWriter) bool {
		return func(got string, w http.ResponseWriter) bool {
			if got != id {
				return false
			}
			reply(w)
			return true
		}
	}
	plain := func(text string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte(text))
		}
	}
	for _, c := range []struct {
		name string
		res  map[string]coretest.Resource
		body func(string, http.ResponseWriter) bool
		want error
	}{
		{"a truncated feed body", data("9", "x.example", "y.example"), body("dnsbl/feed-F", plain("x.example\n")), nil},
		{"a feed body that is not the digest's", data("9", "x.example"), body("dnsbl/feed-F", plain("z.example\n")), nil},
		{"a body over its bound", data("9", "x.example"), body("dnsbl/feed-F", plain(strings.Repeat("a", 1<<20+2)+"\n")), nil},
		{"a body that is not plain text", data("9", "x.example"), body("dnsbl/feed-F", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("x.example\n"))
		}), nil},
		{"a body that moved on", data("9", "x.example"), body("dnsbl/feed-F", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			w.Write([]byte(`{"error":{"code":"not_found","message":"gone"}}`))
		}), coreinput.ErrMoved},
		{"an unknown row kind", manifestWith(func(r []string) []string { return append(r, `{"kind":"surprise"}`) }), nil, nil},
		{"a second config", manifestWith(func(r []string) []string { return append(r, r[0]) }), nil, nil},
		{"no config", manifestWith(func(r []string) []string { return r[1:] }), nil, nil},
		{"a builtinLogFlag outside 0 to 6", manifestWith(func(r []string) []string {
			r[0] = `{"kind":"config","builtinLogFlag":"7","top1mEnabled":true}`
			return r
		}), nil, nil},
		{"TOP1M on without its body", manifestWith(func(r []string) []string { return slices.Delete(r, 3, 4) }), nil, nil},
		{"a feed named twice at two positions with two bodies", manifestWith(func(r []string) []string {
			return append(r, strings.Replace(strings.Replace(r[2], `"position":1`, `"position":2`, 1), `"entries":1`, `"entries":2`, 1))
		}), nil, nil},
		{"a feed position missing", manifestWith(func(r []string) []string {
			r[2] = strings.Replace(r[2], `"position":1`, `"position":2`, 1)
			return r
		}), nil, nil},
		{"a feed name that is not a word", manifestWith(func(r []string) []string {
			r[2] = strings.Replace(strings.Replace(r[2], `"feed":"F"`, `"feed":"../F"`, 1), `dnsbl/feed-F`, `dnsbl/feed-../F`, 1)
			return r
		}), nil, nil},
		{"a feed whose resource is a member's", manifestWith(func(r []string) []string {
			r[2] = strings.Replace(r[2], `"resource":"dnsbl/feed-F"`, `"resource":"dnsbl/top1m"`, 1)
			return r
		}), nil, nil},
		{"a generation that is not decimal", manifestWith(func(r []string) []string {
			r[2] = strings.Replace(r[2], `"generation":"9"`, `"generation":"-9"`, 1)
			return r
		}), nil, nil},
		{"a PSL rule holding a line break", func() map[string]coretest.Resource {
			res := data("9", "x.example")
			psl := coretest.Lines([]string{`{"section":"icann","rule":"com\n// ===END ICANN DOMAINS==="}`})
			res["dnsbl/psl"] = coretest.Resource{Generation: "9", Body: psl}
			m := rows(res["dnsbl/manifest"].Body)
			m[5] = fmt.Sprintf(`{"kind":"member","resource":"dnsbl/psl","generation":"9","digest":%q,"entries":1}`, coretest.Digest(psl))
			res["dnsbl/manifest"] = coretest.Resource{Generation: "9", Body: coretest.Lines(m)}
			return res
		}(), nil, nil},
		// Each case below fails one guard alone: its body is the one its row names, but for the guard's own fault.
		{"an oversized body whose digest and count are right", data("9", strings.Repeat("a", 1<<20+1)), nil, nil},
		{"a row whose count is not its body's", manifestWith(func(r []string) []string {
			r[2] = strings.Replace(r[2], `"entries":1`, `"entries":2`, 1)
			return r
		}), nil, nil},
		{"a feed name that is not a word, served", func() map[string]coretest.Resource {
			res := data("9", "x.example")
			res["dnsbl/feed-F-x"] = res["dnsbl/feed-F"]
			m := rows(res["dnsbl/manifest"].Body)
			m[2] = strings.Replace(strings.Replace(m[2], `"feed":"F"`, `"feed":"F-x"`, 1), `dnsbl/feed-F"`, `dnsbl/feed-F-x"`, 1)
			res["dnsbl/manifest"] = coretest.Resource{Generation: "9", Body: coretest.Lines(m)}
			return res
		}(), nil, nil},
		{"a member named twice", manifestWith(func(r []string) []string { return append(r, r[3]) }), nil, nil},
		{"a PSL rule that is a section marker", pslWith(`{"section":"icann","rule":"// ===END ICANN DOMAINS==="}`), nil, nil},
		{"a PSL rule padded with spaces", pslWith(`{"section":"icann","rule":" com"}`), nil, nil},
		{"a SafeSearch value that needs quoting", ssWith(`{"host":"a,b.example","a":"x.example","aaaa":"x.example"}`), nil, nil},
		{"a SafeSearch value padded with a space", ssWith(`{"host":"www.example","a":" x.example","aaaa":"x.example"}`), nil, nil},
		{"a SafeSearch row without a host", ssWith(`{"host":"","a":"x.example","aaaa":"x.example"}`), nil, nil},
		{"a PSL rule that is a comment", pslWith(`{"section":"icann","rule":"# com"}`), nil, nil},
		{"a PSL rule holding a carriage return", pslWith(`{"section":"icann","rule":"com\rnet"}`), nil, nil},
		{"an empty PSL rule", pslWith(`{"section":"icann","rule":""}`), nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			srv := coretest.Start(t, data("8", "good.example"))
			cl := coreinput.New(srv.Socket)
			if _, _, err := coreinput.Sync(context.Background(), cl, dir, coreinput.State{}); err != nil {
				t.Fatalf("Sync of the good generation: %v", err)
			}
			before := tree(t, dir)
			srv.Set(c.res)
			srv.SetBody(c.body)
			state, changed, err := coreinput.Sync(context.Background(), cl, dir, coreinput.Load(dir))
			if err == nil || changed || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("Sync = changed %v, %v; want a refusal %v", changed, err, c.want)
			}
			if state.Manifest.Generation != "8" {
				t.Errorf("state = %+v, want generation 8 kept", state)
			}
			after := tree(t, dir)
			if len(after) != len(before) {
				t.Errorf("files = %d, want %d", len(after), len(before))
			}
			for name, content := range before {
				if after[name] != content {
					t.Errorf("%s changed", name)
				}
			}
		})
	}
}
