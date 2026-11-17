package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// GetResources serves the resource store read-only (docs/misc/core-api-protocol.md, "Resources"). The store is written here
// through package resources, as the Core Updater will write it.

// resRig is a Core started with --resource-dir naming a store the test writes into.
type resRig struct {
	t     *testing.T
	dir   string // the store directory
	store *resources.Store
	core  *runningCore
}

func newResRig(t *testing.T) *resRig {
	t.Helper()
	dir := scratchDir(t)
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	return &resRig{t: t, dir: store, store: resources.Open(store), core: startCore(t, dir, "--resource-dir", store)}
}

// pub publishes members under id and returns the generation.
func (r *resRig) pub(id string, meta map[string]any, members ...string) uint64 {
	r.t.Helper()
	g, err := r.store.Publish(id, slices.Clone(members), meta)
	if err != nil {
		r.t.Fatalf("publish %s: %v", id, err)
	}
	return g
}

func (r *resRig) applied(id string, g uint64) {
	r.t.Helper()
	if err := r.store.Applied(id, g); err != nil {
		r.t.Fatalf("applied %s %d: %v", id, g, err)
	}
}

// digest is the digest of id's current body.
func (r *resRig) digest(id string) string {
	r.t.Helper()
	got, err := r.store.Get(id, nil)
	if err != nil {
		r.t.Fatalf("get %s: %v", id, err)
	}
	return got.Digest
}

// call posts GetResources with the cursors (id to raw JSON cursor) and returns the reply's "resources" object, error
// messages replaced by "msg" (the contract is that a message is present, not its wording).
func (r *resRig) call(req map[string]string) map[string]any {
	r.t.Helper()
	raw := map[string]json.RawMessage{}
	for id, c := range req {
		raw[id] = json.RawMessage(c)
	}
	body, err := json.Marshal(map[string]any{"resources": raw})
	if err != nil {
		r.t.Fatal(err)
	}
	return r.decode(r.core.post("GetResources", string(body)))
}

func (r *resRig) decode(rep reply) map[string]any {
	r.t.Helper()
	if rep.status != 200 {
		r.t.Fatalf("status = %d, want 200 (body %s)", rep.status, rep.body)
	}
	var env map[string]map[string]any
	if err := json.Unmarshal(rep.body, &env); err != nil || len(env) != 1 || env["resources"] == nil {
		r.t.Fatalf("reply is not exactly {\"resources\":{...}}: %v\n%s", err, rep.body)
	}
	for _, item := range env["resources"] {
		if e, ok := item.(map[string]any)["error"].(map[string]any); ok {
			if m, _ := e["message"].(string); m != "" {
				e["message"] = "msg"
			}
		}
	}
	return env["resources"]
}

// resJSONEqual fails the test unless got and want marshal to the same JSON (null and [] differ).
func resJSONEqual(t *testing.T, got, want any) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		t.Errorf("reply:\n got  %s\n want %s", g, w)
	}
}

func cur(g uint64, d string) string { return fmt.Sprintf(`{"generation":"%d","digest":%q}`, g, d) }

func full(g string, members []string, d string, entries int, meta map[string]any) map[string]any {
	return map[string]any{"kind": "full", "generation": g, "members": members, "digest": d, "entries": entries, "metadata": meta}
}

func delta(g, from string, add, remove []string, d string, entries int, meta map[string]any) map[string]any {
	return map[string]any{"kind": "delta", "generation": g, "from": from, "add": add, "remove": remove, "digest": d, "entries": entries, "metadata": meta}
}

func unchanged(g string) map[string]any { return map[string]any{"kind": "unchanged", "generation": g} }

func errItem(code string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": "msg"}}
}

func TestGetResourcesWireShape(t *testing.T) {
	r := newResRig(t)
	meta := map[string]any{"action": "deny", "direction": "inbound"}
	r.pub("ip-set/Full/ipv4", meta, "10.0.0.0/8", "1.1.1.1")
	fd := r.digest("ip-set/Full/ipv4")
	r.pub("ip-set/Delta/ipv4", meta, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	r.applied("ip-set/Delta/ipv4", 1)
	d1 := r.digest("ip-set/Delta/ipv4")
	r.pub("ip-set/Delta/ipv4", meta, "10.0.0.2", "10.0.0.3", "10.0.0.4")
	d2 := r.digest("ip-set/Delta/ipv4")
	m1, m2 := map[string]any{"action": "deny"}, map[string]any{"action": "permit", "direction": "outbound"}
	r.pub("ip-set/Meta/ipv6", m1, "::1")
	r.applied("ip-set/Meta/ipv6", 1)
	md := r.digest("ip-set/Meta/ipv6")
	r.pub("ip-set/Meta/ipv6", m2, "::1")
	r.pub("dnsbl/empty", nil)
	ed := r.digest("dnsbl/empty")

	for name, tc := range map[string]struct {
		req  map[string]string
		want map[string]any
	}{
		"full without a cursor": {map[string]string{"ip-set/Full/ipv4": `{}`},
			map[string]any{"ip-set/Full/ipv4": full("1", []string{"1.1.1.1", "10.0.0.0/8"}, fd, 2, meta)}},
		"unchanged": {map[string]string{"ip-set/Full/ipv4": cur(1, fd)},
			map[string]any{"ip-set/Full/ipv4": unchanged("1")}},
		"delta": {map[string]string{"ip-set/Delta/ipv4": cur(1, d1)},
			map[string]any{"ip-set/Delta/ipv4": delta("2", "1", []string{"10.0.0.4"}, []string{"10.0.0.1"}, d2, 3, meta)}},
		"delta after a metadata-only change": {map[string]string{"ip-set/Meta/ipv6": cur(1, md)},
			map[string]any{"ip-set/Meta/ipv6": delta("2", "1", []string{}, []string{}, md, 1, m2)}},
		"full of an empty set": {map[string]string{"dnsbl/empty": `{}`},
			map[string]any{"dnsbl/empty": full("1", []string{}, ed, 0, map[string]any{})}},
		"a good id and a never published one": {map[string]string{"ip-set/Full/ipv4": `{}`, "ip-set/Never/ipv4": `{}`},
			map[string]any{"ip-set/Full/ipv4": full("1", []string{"1.1.1.1", "10.0.0.0/8"}, fd, 2, meta), "ip-set/Never/ipv4": errItem("not_found")}},
	} {
		t.Run(name, func(t *testing.T) { resJSONEqual(t, r.call(tc.req), tc.want) })
	}
}

// The issue's matrix of cursor against current generation and applied baseline.
func TestGetResourcesCursorMatrix(t *testing.T) {
	r := newResRig(t)
	const id = "ip-set/M/ipv4"
	r.pub(id, nil, "10.0.0.1")
	r.applied(id, 1)
	d1 := r.digest(id)
	r.pub(id, nil, "10.0.0.1", "10.0.0.2")
	d2 := r.digest(id)
	whole := full("2", []string{"10.0.0.1", "10.0.0.2"}, d2, 2, map[string]any{})
	for name, tc := range map[string]struct {
		cursor string
		want   map[string]any
	}{
		"no cursor":                       {`{}`, whole},
		"current and its digest":          {cur(2, d2), unchanged("2")},
		"current, another digest":         {cur(2, d1), whole},
		"baseline and its digest":         {cur(1, d1), delta("2", "1", []string{"10.0.0.2"}, []string{}, d2, 2, map[string]any{})},
		"baseline, another digest":        {cur(1, d2), whole},
		"a generation the store lacks":    {cur(7, d1), whole},
		"generation zero":                 {cur(0, d1), whole},
		"newer than current, digest held": {cur(3, d2), whole},
	} {
		t.Run(name, func(t *testing.T) {
			resJSONEqual(t, r.call(map[string]string{id: tc.cursor}), map[string]any{id: tc.want})
		})
	}
}

// A store directory removed and republished restarts at generation 1: a cursor from before it is newer, and gets the full body.
func TestGetResourcesCursorNewerThanCurrentAfterTheStoreWasRebuilt(t *testing.T) {
	r := newResRig(t)
	const id = "dnsbl/main"
	r.pub(id, nil, "a.example")
	r.pub(id, nil, "a.example", "b.example")
	old := r.digest(id)
	if err := os.RemoveAll(r.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if g := r.pub(id, nil, "c.example"); g != 1 {
		t.Fatalf("republished generation = %d, want 1", g)
	}
	resJSONEqual(t, r.call(map[string]string{id: cur(2, old)}),
		map[string]any{id: full("1", []string{"c.example"}, r.digest(id), 1, map[string]any{})})
}

func TestGetResourcesServesEveryKindOfID(t *testing.T) {
	r := newResRig(t)
	ids := []string{"ip-set/Abuse/ipv4", "ip-set/Abuse/ipv6", "ip-aggregate/deny/ipv4", "geo-catalog", "dnsbl/main"}
	req, want := map[string]string{}, map[string]any{}
	for _, id := range ids {
		r.pub(id, nil, "member-of-"+strings.ReplaceAll(id, "/", "_"))
		req[id] = `{}`
		want[id] = full("1", []string{"member-of-" + strings.ReplaceAll(id, "/", "_")}, r.digest(id), 1, map[string]any{})
	}
	resJSONEqual(t, r.call(req), want)
	// 128 bytes is a valid id, only not published
	long := "dnsbl/" + strings.Repeat("a", 122)
	resJSONEqual(t, r.call(map[string]string{long: `{}`}), map[string]any{long: errItem("not_found")})
}

func TestGetResourcesAnEmptyRequestAnswersAnEmptyObject(t *testing.T) {
	r := newResRig(t)
	for _, body := range []string{`{}`, `{"resources":{}}`, `{"resources":null}`, ``} {
		wantJSON(t, r.core.post("GetResources", body), 200, `{"resources":{}}`)
	}
}

func TestGetResourcesAnUnreadableStoreAnswersUnavailablePerResource(t *testing.T) {
	const bad, ok = "ip-set/U/ipv4", "dnsbl/ok"
	body := "ip-set~U~ipv4.1.body"
	for name, tc := range map[string]struct {
		damage func(t *testing.T, r *resRig)
		both   bool // the index is damaged: no resource can be served
	}{
		"index truncated": {both: true, damage: func(t *testing.T, r *resRig) {
			raw, err := os.ReadFile(filepath.Join(r.dir, "index.json"))
			if err == nil {
				err = os.WriteFile(filepath.Join(r.dir, "index.json"), raw[:len(raw)/2], 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
		}},
		"index not JSON": {both: true, damage: func(t *testing.T, r *resRig) {
			if err := os.WriteFile(filepath.Join(r.dir, "index.json"), []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		"current body missing": {damage: func(t *testing.T, r *resRig) {
			if err := os.Remove(filepath.Join(r.dir, body)); err != nil {
				t.Fatal(err)
			}
		}},
		"body shorter than recorded": {damage: func(t *testing.T, r *resRig) {
			if err := os.Truncate(filepath.Join(r.dir, body), 3); err != nil {
				t.Fatal(err)
			}
		}},
		"body replaced by a symlink": {damage: func(t *testing.T, r *resRig) {
			raw, err := os.ReadFile(filepath.Join(r.dir, body))
			target := filepath.Join(filepath.Dir(r.dir), "elsewhere")
			if err == nil {
				err = os.WriteFile(target, raw, 0o600)
			}
			if err == nil {
				err = os.Remove(filepath.Join(r.dir, body))
			}
			if err == nil {
				err = os.Symlink(target, filepath.Join(r.dir, body))
			}
			if err != nil {
				t.Fatal(err)
			}
		}},
		"body replaced by a directory": {damage: func(t *testing.T, r *resRig) {
			if err := os.Remove(filepath.Join(r.dir, body)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(r.dir, body), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newResRig(t)
			r.pub(bad, nil, "10.0.0.1", "10.0.0.2")
			r.pub(ok, nil, "ok.example")
			okDigest := r.digest(ok)
			tc.damage(t, r)
			want := map[string]any{bad: errItem("unavailable"), ok: full("1", []string{"ok.example"}, okDigest, 1, map[string]any{})}
			if tc.both {
				want[ok] = errItem("unavailable")
			}
			resJSONEqual(t, r.call(map[string]string{bad: `{}`, ok: `{}`}), want)
		})
	}
}

func TestGetResourcesARemovedResourceIsNotFound(t *testing.T) {
	r := newResRig(t)
	r.pub("dnsbl/gone", nil, "a.example")
	if err := r.store.Remove("dnsbl/gone"); err != nil {
		t.Fatal(err)
	}
	resJSONEqual(t, r.call(map[string]string{"dnsbl/gone": `{}`}), map[string]any{"dnsbl/gone": errItem("not_found")})
}

func TestGetResourcesRefusesAHostileRequestNamingTheField(t *testing.T) {
	r := newResRig(t)
	r.pub("dnsbl/main", nil, "a.example")
	before := snapshotDir(t, r.dir)
	dg := strings.Repeat("a", 32)
	one := func(id, cursor string) string { return `{"resources":{` + id + `:` + cursor + `}}` }
	gen := func(g string) string { return `{"generation":` + g + `,"digest":"` + dg + `"}` }
	dig := func(d string) string { return `{"generation":"1","digest":"` + d + `"}` }
	cases := map[string][2]string{ // name: body, field
		"traversal":                   {one(`"ip-set/../ipv4"`, `{}`), "resources"},
		"too many segments":           {one(`"ip-set/a/b/ipv4"`, `{}`), "resources"},
		"empty segment":               {one(`"ip-set//ipv4"`, `{}`), "resources"},
		"NUL":                         {one(`"dnsbl/a\u0000"`, `{}`), "resources"},
		"newline":                     {one(`"dnsbl/a\nb"`, `{}`), "resources"},
		"a settings id":               {one(`"settings/dns"`, `{}`), "resources"},
		"empty id":                    {one(`""`, `{}`), "resources"},
		"129 bytes":                   {one(`"dnsbl/`+strings.Repeat("a", 123)+`"`, `{}`), "resources"},
		"17 ids":                      {`{"resources":{` + manyIDs(17) + `}}`, "resources"},
		"generation abc":              {one(`"dnsbl/main"`, gen(`"abc"`)), "resources.dnsbl/main.generation"},
		"generation -1":               {one(`"dnsbl/main"`, gen(`"-1"`)), "resources.dnsbl/main.generation"},
		"generation +1":               {one(`"dnsbl/main"`, gen(`"+1"`)), "resources.dnsbl/main.generation"},
		"generation 1.5":              {one(`"dnsbl/main"`, gen(`"1.5"`)), "resources.dnsbl/main.generation"},
		"generation empty":            {one(`"dnsbl/main"`, gen(`""`)), "resources.dnsbl/main.generation"},
		"generation space":            {one(`"dnsbl/main"`, gen(`" 1"`)), "resources.dnsbl/main.generation"},
		"generation hex":              {one(`"dnsbl/main"`, gen(`"0x10"`)), "resources.dnsbl/main.generation"},
		"generation 2^64":             {one(`"dnsbl/main"`, gen(`"18446744073709551616"`)), "resources.dnsbl/main.generation"},
		"generation a number":         {one(`"geo-catalog"`, gen(`41`)), "resources.geo-catalog.generation"},
		"generation a bool":           {one(`"geo-catalog"`, gen(`true`)), "resources.geo-catalog.generation"},
		"slashed generation a number": {one(`"dnsbl/main"`, gen(`41`)), "resources.dnsbl/main.generation"},
		"slashed digest a number":     {one(`"dnsbl/main"`, `{"generation":"1","digest":5}`), "resources.dnsbl/main.digest"},
		"slashed cursor a string":     {one(`"ip-set/a/ipv4"`, `"x"`), "resources.ip-set/a/ipv4"},
		"digest 31 characters":        {one(`"dnsbl/main"`, dig(dg[:31])), "resources.dnsbl/main.digest"},
		"digest 33 characters":        {one(`"dnsbl/main"`, dig(dg+"a")), "resources.dnsbl/main.digest"},
		"digest with g":               {one(`"dnsbl/main"`, dig(dg[:31]+"g")), "resources.dnsbl/main.digest"},
		"digest upper case":           {one(`"dnsbl/main"`, dig(strings.ToUpper(strings.Repeat("abcdef01", 4)))), "resources.dnsbl/main.digest"},
		"only generation":             {one(`"dnsbl/main"`, `{"generation":"1"}`), "resources.dnsbl/main.digest"},
		"only digest":                 {one(`"dnsbl/main"`, `{"digest":"`+dg+`"}`), "resources.dnsbl/main.generation"},
		"unknown cursor key":          {one(`"dnsbl/main"`, `{"generation":"1","digest":"`+dg+`","extra":1}`), "extra"},
		"cursor a string":             {one(`"geo-catalog"`, `"x"`), "resources.geo-catalog"},
		"cursor an array":             {one(`"geo-catalog"`, `[]`), "resources.geo-catalog"},
		"cursor a number":             {one(`"geo-catalog"`, `5`), "resources.geo-catalog"},
		"cursor null":                 {one(`"geo-catalog"`, `null`), "resources"},
		"resources an array":          {`{"resources":[]}`, "resources"},
		"resources a string":          {`{"resources":"x"}`, "resources"},
		"resources a number":          {`{"resources":5}`, "resources"},
		"unknown parameter":           {`{"resources":{},"bogus":1}`, "bogus"},
		"unknown parameter with ~1":   {`{"resources":{},"a~1b":1}`, "a~1b"},
		"unknown cursor key with ~0":  {one(`"dnsbl/main"`, `{"generation":"1","digest":"`+dg+`","x~0y":1}`), "x~0y"},
	}
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		t.Run(name, func(t *testing.T) {
			wantError(t, r.core.post("GetResources", cases[name][0]), 400, "invalid_argument", cases[name][1])
		})
	}
	t.Run("a body over 1 MiB", func(t *testing.T) {
		big := `{"resources":{},"pad":"` + strings.Repeat("x", 1<<20) + `"}`
		wantError(t, r.core.post("GetResources", big), 413, "payload_too_large")
	})
	t.Run("16 ids are accepted", func(t *testing.T) {
		rep := r.core.post("GetResources", `{"resources":{`+manyIDs(16)+`}}`)
		if got := r.decode(rep); len(got) != 16 {
			t.Errorf("answered %d items, want 16", len(got))
		}
	})
	if after := snapshotDir(t, r.dir); !maps.EqualFunc(before, after, bytes.Equal) {
		t.Errorf("the store changed under hostile requests:\n before %v\n after %v", before, after)
	}
}

func manyIDs(n int) string {
	var parts []string
	for i := range n {
		parts = append(parts, fmt.Sprintf(`"dnsbl/a%02d":{}`, i))
	}
	return strings.Join(parts, ",")
}

func TestGetResourcesTakesTheEdgeCursors(t *testing.T) {
	r := newResRig(t)
	const id = "geo-catalog"
	r.pub(id, nil, "XX")
	d := r.digest(id)
	want := map[string]any{id: full("1", []string{"XX"}, d, 1, map[string]any{})}
	zero := strings.Repeat("0", 32)
	for name, cursor := range map[string]string{
		"null generation and digest": `{"generation":null,"digest":null}`,
		"largest generation":         `{"generation":"18446744073709551615","digest":"` + zero + `"}`,
		"leading zeros":              `{"generation":"007","digest":"` + zero + `"}`,
	} {
		t.Run(name, func(t *testing.T) { resJSONEqual(t, r.call(map[string]string{id: cursor}), want) })
	}
}

// A generation above 2^53 is exact: it is a string, never a JSON number.
func TestGetResourcesAGenerationAbove2To53IsExact(t *testing.T) {
	r := newResRig(t)
	const id, big = "ip-set/Big/ipv4", "9007199254740993"
	r.pub(id, nil, "10.0.0.1")
	d := r.digest(id)
	raw, err := os.ReadFile(filepath.Join(r.dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx map[string]any
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	idx["resources"].(map[string]any)[id].(map[string]any)["current"].(map[string]any)["generation"] = big
	raw, _ = json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(r.dir, "index.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(r.dir, "ip-set~Big~ipv4.1.body"), filepath.Join(r.dir, "ip-set~Big~ipv4."+big+".body")); err != nil {
		t.Fatal(err)
	}
	resJSONEqual(t, r.call(map[string]string{id: `{}`}), map[string]any{id: full(big, []string{"10.0.0.1"}, d, 1, map[string]any{})})
	resJSONEqual(t, r.call(map[string]string{id: `{"generation":"` + big + `","digest":"` + d + `"}`}), map[string]any{id: unchanged(big)})
}

// snapshotDir is every entry of dir with its kind, mode, modification time and bytes (a symlink: its target).
func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		desc := fmt.Sprintf("%v %d|", info.Mode(), info.ModTime().UnixNano())
		var data []byte
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			data = []byte(target)
			if err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if data, err = os.ReadFile(path); err != nil {
				return err
			}
		}
		out[path] = append([]byte(desc), data...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGetResourcesNeverWritesTheStore(t *testing.T) {
	r := newResRig(t)
	r.pub("ip-set/R/ipv4", map[string]any{"action": "deny"}, "10.0.0.1")
	r.applied("ip-set/R/ipv4", 1)
	d1 := r.digest("ip-set/R/ipv4")
	r.pub("ip-set/R/ipv4", map[string]any{"action": "deny"}, "10.0.0.1", "10.0.0.2")
	r.pub("dnsbl/R", nil, "a.example")
	r.pub("dnsbl/Gone", nil, "b.example")
	if err := r.store.Remove("dnsbl/Gone"); err != nil {
		t.Fatal(err)
	}
	r.pub("dnsbl/Short", nil, "c.example")
	if err := os.Truncate(filepath.Join(r.dir, "dnsbl~Short.1.body"), 2); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, r.dir)
	r.call(map[string]string{"ip-set/R/ipv4": `{}`, "dnsbl/R": `{}`, "dnsbl/Gone": `{}`, "dnsbl/Short": `{}`, "geo-catalog": `{}`})
	r.call(map[string]string{"ip-set/R/ipv4": cur(1, d1)})
	r.call(map[string]string{"ip-set/R/ipv4": cur(2, r.digest("ip-set/R/ipv4"))})
	r.core.post("GetResources", `{"resources":{"settings/dns":{}}}`)
	r.core.post("GetResources", `{"resources":{"dnsbl/R":{"generation":"x","digest":"y"}}}`)
	if after := snapshotDir(t, r.dir); !maps.EqualFunc(before, after, bytes.Equal) {
		t.Errorf("the store changed under GetResources:\n before %v\n after %v", before, after)
	}
}

func TestResourceDirThatDoesNotExistAnswersNotFoundAndIsNotCreated(t *testing.T) {
	dir := scratchDir(t)
	store := filepath.Join(dir, "absent", "store")
	r := &resRig{t: t, dir: store, core: startCore(t, dir, "--resource-dir", store)}
	resJSONEqual(t, r.call(map[string]string{"dnsbl/main": `{}`, "geo-catalog": cur(3, strings.Repeat("a", 32))}), map[string]any{"dnsbl/main": errItem("not_found"), "geo-catalog": errItem("not_found")})
	for _, p := range []string{store, filepath.Dir(store)} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s exists after GetResources (stat error %v), the Core API never creates the store", p, err)
		}
	}
}

func TestResourceDirAbsentAnswersUnavailable(t *testing.T) {
	c := startCore(t, scratchDir(t))
	wantError(t, c.post("GetResources", `{"resources":{"dnsbl/main":{}}}`), 503, "unavailable")
	wantError(t, c.post("GetResources", `{}`), 503, "unavailable")
}

func TestResourceDirMustBeAbsolute(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	dir := scratchDir(t)
	var stderr bytes.Buffer
	if code := run(stopped, coreArgs(dir, "run", "--resource-dir", "relative/store"), &stderr); code != 2 {
		t.Errorf("run with a relative --resource-dir = %d, want 2; stderr %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "resource-dir") || !strings.Contains(stderr.String(), "is not an absolute path") {
		t.Errorf("stderr %q does not name the flag and say the path is not absolute", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); err == nil {
		t.Error("run made the state directory before it refused the flag")
	}
}

func TestResourceDirUsageNamesTheFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--resource-dir PATH") {
		t.Errorf("the usage text does not name --resource-dir PATH: %q", stderr.String())
	}
}
