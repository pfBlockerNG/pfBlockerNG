package resources_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

const id = "dnsbl/x"

func body(members []string) []byte {
	var b strings.Builder
	for _, m := range members {
		b.WriteString(m + "\n")
	}
	return []byte(b.String())
}

func dg(members ...string) string { return digest.Bytes(body(members)) }

func bn(id string, g int) string {
	return fmt.Sprintf("%s.%d.body", strings.ReplaceAll(id, "/", "~"), g)
}

func newStore(t *testing.T) (*resources.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	return resources.Open(dir), dir
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range ents {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func wantNames(t *testing.T, dir string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := names(t, dir); !slices.Equal(got, want) {
		t.Fatalf("files in the store:\n got %v\nwant %v", got, want)
	}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out[n] = string(b)
	}
	return out
}

func publish(t *testing.T, s *resources.Store, id string, want uint64, meta map[string]any, members ...string) {
	t.Helper()
	g, err := s.Publish(id, slices.Clone(members), meta)
	if err != nil || g != want {
		t.Fatalf("Publish(%s, %v) = %d, %v; want generation %d", id, members, g, err, want)
	}
}

func applied(t *testing.T, s *resources.Store, id string, g uint64) {
	t.Helper()
	if err := s.Applied(id, g); err != nil {
		t.Fatalf("Applied(%s, %d): %v", id, g, err)
	}
}

func mustGet(t *testing.T, s *resources.Store, id string, c *resources.Cursor) resources.Reply {
	t.Helper()
	r, err := s.Get(id, c)
	if err != nil {
		t.Fatalf("Get(%s, %v): %v", id, c, err)
	}
	return r
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: error = %v; want %v", what, err, want)
	}
}

func readIndex(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestGetReplyKindByCursorAndStoreState(t *testing.T) {
	const aid = "ip-set/a/ipv4"
	v1, v2 := []string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "3.3.3.3"}
	// applied1: v1 applied, then v2 published: current 2, baseline 1.
	applied1 := func(t *testing.T, s *resources.Store, _ string) {
		publish(t, s, aid, 1, nil, v1...)
		applied(t, s, aid, 1)
		publish(t, s, aid, 2, nil, v2...)
	}
	tests := []struct {
		name   string
		setup  func(t *testing.T, s *resources.Store, dir string)
		cursor *resources.Cursor
		kind   string
		err    error
	}{
		{"A1 no cursor", applied1, nil, resources.KindFull, nil},
		{"A2 current generation and digest", applied1, &resources.Cursor{2, dg(v2...)}, resources.KindUnchanged, nil},
		{"A3 current generation, digest differs", applied1, &resources.Cursor{2, "bad"}, resources.KindFull, nil},
		{"A4 held baseline, digest matches", applied1, &resources.Cursor{1, dg(v1...)}, resources.KindDelta, nil},
		{"A5 held baseline, digest differs", applied1, &resources.Cursor{1, "bad"}, resources.KindFull, nil},
		{"A6 older generation, no baseline", func(t *testing.T, s *resources.Store, _ string) {
			publish(t, s, aid, 1, nil, v1...)
			publish(t, s, aid, 2, nil, v2...)
		}, &resources.Cursor{1, dg(v1...)}, resources.KindFull, nil},
		{"A6 older generation, baseline is another generation", func(t *testing.T, s *resources.Store, _ string) {
			publish(t, s, aid, 1, nil, "1.1.1.1")
			publish(t, s, aid, 2, nil, "2.2.2.2")
			applied(t, s, aid, 2)
			publish(t, s, aid, 3, nil, "3.3.3.3")
		}, &resources.Cursor{1, dg("1.1.1.1")}, resources.KindFull, nil},
		{"A7 newer than current after a rebuild", func(t *testing.T, s *resources.Store, dir string) {
			publish(t, s, aid, 1, nil, "1.1.1.1")
			publish(t, s, aid, 2, nil, "2.2.2.2")
			publish(t, s, aid, 3, nil, "3.3.3.3")
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			publish(t, s, aid, 1, nil, v1...)
		}, &resources.Cursor{3, dg("3.3.3.3")}, resources.KindFull, nil},
		{"A8 newer than current, baseline holds that number", func(t *testing.T, s *resources.Store, dir string) {
			publish(t, s, aid, 1, nil, v1...)
			idx := readIndex(t, dir)
			ent := idx["resources"].(map[string]any)[aid].(map[string]any)
			base := []string{"9.9.9.9"}
			ent["applied"] = map[string]any{"generation": "3", "digest": dg(base...), "length": len(body(base)), "entries": 1, "metadata": map[string]any{}}
			raw, _ := json.Marshal(idx)
			if err := os.WriteFile(filepath.Join(dir, "index.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, bn(aid, 3)), body(base), 0o600); err != nil {
				t.Fatal(err)
			}
		}, &resources.Cursor{3, "other"}, resources.KindFull, nil},
		{"A9 never had the id", func(t *testing.T, s *resources.Store, _ string) { publish(t, s, aid, 1, nil, v1...) },
			&resources.Cursor{1, "x"}, "", resources.ErrNotFound},
		{"A9 removed id", func(t *testing.T, s *resources.Store, _ string) {
			publish(t, s, aid, 1, nil, v1...)
			if err := s.Remove(aid); err != nil {
				t.Fatal(err)
			}
		}, &resources.Cursor{1, dg(v1...)}, "", resources.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := newStore(t)
			tc.setup(t, s, dir)
			getID := aid
			if tc.err != nil && strings.Contains(tc.name, "never") {
				getID = "ip-set/other/ipv4"
			}
			r, err := s.Get(getID, tc.cursor)
			if tc.err != nil {
				wantErr(t, "Get", err, tc.err)
				return
			}
			if err != nil || r.Kind != tc.kind {
				t.Fatalf("Get kind = %q, %v; want %q", r.Kind, err, tc.kind)
			}
			if tc.kind == resources.KindDelta && (!slices.Equal(r.Add, []string{"3.3.3.3"}) || !slices.Equal(r.Remove, []string{"1.1.1.1"}) || r.From != 1) {
				t.Fatalf("delta = from %d add %v remove %v", r.From, r.Add, r.Remove)
			}
			if tc.kind == resources.KindFull && (r.Members == nil || r.Digest != dg(r.Members...)) {
				t.Fatalf("full = %v digest %s", r.Members, r.Digest)
			}
		})
	}
}

func TestLifecycleForEveryResourceKind(t *testing.T) {
	for _, rid := range []string{"ip-set/Abuse/ipv4", "ip-set/Abuse/ipv6", "ip-aggregate/deny/ipv4", "geo-catalog", "dnsbl/main"} {
		t.Run(rid, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, rid, 1, map[string]any{"k": "v"}, "b", "a")
			if r := mustGet(t, s, rid, nil); r.Kind != resources.KindFull || !slices.Equal(r.Members, []string{"a", "b"}) || r.Generation != 1 {
				t.Fatalf("full = %+v", r)
			}
			applied(t, s, rid, 1)
			publish(t, s, rid, 2, map[string]any{"k": "v"}, "b", "c")
			r := mustGet(t, s, rid, &resources.Cursor{1, dg("a", "b")})
			if r.Kind != resources.KindDelta || !slices.Equal(r.Add, []string{"c"}) || !slices.Equal(r.Remove, []string{"a"}) {
				t.Fatalf("delta = %+v", r)
			}
			if err := s.Remove(rid); err != nil {
				t.Fatal(err)
			}
			_, err := s.Get(rid, nil)
			wantErr(t, "Get after Remove", err, resources.ErrNotFound)
			if err := s.RemovalApplied(rid); err != nil {
				t.Fatal(err)
			}
			wantNames(t, dir, "index.json")
		})
	}
}

func TestRetentionTransitions(t *testing.T) {
	two := func(t *testing.T) (*resources.Store, string) { // generation 1 applied, generation 2 current
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		applied(t, s, id, 1)
		publish(t, s, id, 2, nil, "2")
		wantNames(t, dir, "index.json", bn(id, 1), bn(id, 2))
		return s, dir
	}
	t.Run("C1 first publish", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		wantNames(t, dir, "index.json", bn(id, 1))
	})
	t.Run("C2 publish again before any apply", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		wantNames(t, dir, "index.json", bn(id, 1))
		publish(t, s, id, 2, nil, "2")
		wantNames(t, dir, "index.json", bn(id, 2))
	})
	t.Run("C3 applied current then publish", func(t *testing.T) { two(t) })
	t.Run("C4 applied current with an older baseline", func(t *testing.T) {
		s, dir := two(t)
		applied(t, s, id, 2)
		wantNames(t, dir, "index.json", bn(id, 2))
	})
	t.Run("C5 applied report of the held baseline", func(t *testing.T) {
		s, dir := two(t)
		applied(t, s, id, 1)
		wantNames(t, dir, "index.json", bn(id, 1), bn(id, 2))
		if r := mustGet(t, s, id, &resources.Cursor{1, dg("1")}); r.Kind != resources.KindDelta {
			t.Fatalf("baseline lost: %+v", r)
		}
	})
	t.Run("C6 applied older than the baseline", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		applied(t, s, id, 1)
		publish(t, s, id, 2, nil, "2")
		applied(t, s, id, 2)
		publish(t, s, id, 3, nil, "3")
		wantNames(t, dir, "index.json", bn(id, 2), bn(id, 3))
		applied(t, s, id, 1)
		wantNames(t, dir, "index.json", bn(id, 3))
	})
	t.Run("C6 applied newer than current", func(t *testing.T) {
		s, dir := two(t)
		applied(t, s, id, 9)
		wantNames(t, dir, "index.json", bn(id, 2))
	})
	t.Run("C7 remove then removal applied", func(t *testing.T) {
		s, dir := two(t)
		if err := s.Remove(id); err != nil {
			t.Fatal(err)
		}
		wantNames(t, dir, "index.json", bn(id, 1), bn(id, 2))
		if err := s.RemovalApplied(id); err != nil {
			t.Fatal(err)
		}
		wantNames(t, dir, "index.json")
		if got := readIndex(t, dir)["resources"].(map[string]any); len(got) != 0 {
			t.Fatalf("index still holds %v", got)
		}
	})
	late := func(t *testing.T, s *resources.Store, dir string, want uint64, members ...string) {
		t.Helper()
		if err := s.Remove(id); err != nil {
			t.Fatal(err)
		}
		publish(t, s, id, want, nil, members...)
		before := snapshot(t, dir)
		if err := s.RemovalApplied(id); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
			t.Fatalf("late RemovalApplied changed the store: %v -> %v", before, snapshot(t, dir))
		}
		if r := mustGet(t, s, id, nil); r.Generation != want {
			t.Fatalf("Get generation = %d; want %d", r.Generation, want)
		}
	}
	t.Run("C8 republished same content keeps its generation", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		late(t, s, dir, 1, "1")
	})
	t.Run("C8 republished changed content continues counting", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		late(t, s, dir, 2, "2")
		wantNames(t, dir, "index.json", bn(id, 2))
	})
	t.Run("C9 store directory lost", func(t *testing.T) {
		s, dir := two(t)
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		_, err := s.Get(id, nil)
		wantErr(t, "Get", err, resources.ErrNotFound)
		publish(t, s, id, 1, nil, "x")
		wantNames(t, dir, "index.json", bn(id, 1))
	})
	t.Run("C10 identical publish changes nothing", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, map[string]any{"a": 1}, "b", "a")
		before := snapshot(t, dir)
		publish(t, s, id, 1, map[string]any{"a": 1}, "a", "b", "a")
		if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
			t.Fatalf("store changed: %v -> %v", before, snapshot(t, dir))
		}
	})
	t.Run("C11 metadata only", func(t *testing.T) {
		s, _ := newStore(t)
		publish(t, s, id, 1, map[string]any{"action": "deny", "direction": "ingress"}, "1")
		applied(t, s, id, 1)
		publish(t, s, id, 2, map[string]any{"action": "permit", "direction": "ingress"}, "1")
		r := mustGet(t, s, id, &resources.Cursor{1, dg("1")})
		if r.Kind != resources.KindDelta || r.Add == nil || r.Remove == nil || len(r.Add)+len(r.Remove) != 0 {
			t.Fatalf("reply = %+v; want a delta with empty non-nil add and remove", r)
		}
		if string(r.Metadata) != `{"action":"permit","direction":"ingress"}` {
			t.Fatalf("metadata = %s", r.Metadata)
		}
	})
	t.Run("C13 pruning one id leaves a sibling whose escaped name it prefixes", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, "dnsbl/x", 1, nil, "1")
		publish(t, s, "dnsbl/xy", 1, nil, "1")
		publish(t, s, "dnsbl/x", 2, nil, "2")
		wantNames(t, dir, "index.json", "dnsbl~x.2.body", "dnsbl~xy.1.body")
		if r := mustGet(t, s, "dnsbl/xy", nil); !slices.Equal(r.Members, []string{"1"}) {
			t.Fatalf("sibling reply = %+v", r)
		}
		if err := s.Remove("dnsbl/x"); err != nil {
			t.Fatal(err)
		}
		if err := s.RemovalApplied("dnsbl/x"); err != nil {
			t.Fatal(err)
		}
		wantNames(t, dir, "index.json", "dnsbl~xy.1.body")
	})
	t.Run("C12 empty body is a generation", func(t *testing.T) {
		s, _ := newStore(t)
		publish(t, s, id, 1, nil, "1")
		publish(t, s, id, 2, nil)
		r := mustGet(t, s, id, nil)
		if r.Kind != resources.KindFull || r.Members == nil || len(r.Members) != 0 || r.Entries != 0 || r.Digest != dg() || string(r.Metadata) != "{}" {
			t.Fatalf("reply = %+v", r)
		}
	})
}

func TestInvalidIDsTouchNothing(t *testing.T) {
	bad := []string{"ip-set/../ipv4", "ip-set/a/b/ipv4", "ip-set/a/ipv4/x", "ip-set//ipv4", "ip-set/a/", "ip-set/a/ipv5", "ip-set/a",
		"geo-catalog/x", "dnsbl/", "dnsbl/a/b", "dnsbl/a\nb", "dnsbl/a\x00", "dnsbl/a b", "dnsbl/a~b", "dnsbl/a.b", "settings/dns",
		"", "/", "IP-SET/a/ipv4", "dnsbl/" + strings.Repeat("a", 123)}
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "1")
	before := snapshot(t, dir)
	for _, bid := range bad {
		_, err := s.Publish(bid, []string{"1"}, nil)
		wantErr(t, fmt.Sprintf("Publish(%q)", bid), err, resources.ErrInvalidID)
		_, err = s.Get(bid, nil)
		wantErr(t, fmt.Sprintf("Get(%q)", bid), err, resources.ErrInvalidID)
		wantErr(t, fmt.Sprintf("Applied(%q)", bid), s.Applied(bid, 1), resources.ErrInvalidID)
		wantErr(t, fmt.Sprintf("Remove(%q)", bid), s.Remove(bid), resources.ErrInvalidID)
		wantErr(t, fmt.Sprintf("RemovalApplied(%q)", bid), s.RemovalApplied(bid), resources.ErrInvalidID)
	}
	if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
		t.Fatalf("store changed by invalid ids: %v -> %v", before, snapshot(t, dir))
	}
	longest := "dnsbl/" + strings.Repeat("a", 122)
	if len(longest) != resources.MaxIDLength || !resources.ValidID(longest) || resources.ValidID(longest+"a") {
		t.Fatalf("length bound: %d bytes valid=%v, one more valid=%v", len(longest), resources.ValidID(longest), resources.ValidID(longest+"a"))
	}
}

func TestInvalidMembersAreRefused(t *testing.T) {
	for _, m := range []string{"", "1.2.3.4\n5.6.7.8", "a\rb", "a\tb", "a\x00b", "\xff\xfe", "a\u0085b", "a\x7fb", "#x", "#"} {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "1")
		before := snapshot(t, dir)
		if _, err := s.Publish(id, []string{"ok", m}, nil); err == nil {
			t.Fatalf("Publish accepted member %q", m)
		}
		if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
			t.Fatalf("store changed by member %q", m)
		}
	}
	s, _ := newStore(t)
	if g, err := s.Publish(id, []string{"a#b", "b"}, nil); err != nil || g != 1 {
		t.Fatalf("a member with # past its first byte: %d, %v", g, err)
	}
	if _, err := s.Publish(id, []string{"a"}, map[string]any{"f": func() {}}); err == nil {
		t.Fatal("Publish accepted metadata that cannot be marshalled")
	}
}

func TestCorruptIndex(t *testing.T) {
	const other = "dnsbl/y"
	tests := map[string]func(t *testing.T, path string){
		"truncated": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, b[:len(b)/2], 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"not JSON":      func(t *testing.T, p string) { os.WriteFile(p, []byte("garbage"), 0o600) },
		"array":         func(t *testing.T, p string) { os.WriteFile(p, []byte("[]"), 0o600) },
		"other version": func(t *testing.T, p string) { os.WriteFile(p, []byte(`{"version":2,"resources":{}}`), 0o600) },
		"symlink to a valid index": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			real := filepath.Join(t.TempDir(), "real")
			os.WriteFile(real, b, 0o600)
			os.Remove(p)
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, p string) {
			os.Remove(p)
			if err := os.MkdirAll(filepath.Join(p, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "1")
			corrupt(t, filepath.Join(dir, "index.json"))
			os.WriteFile(filepath.Join(dir, "stray.tmp"), []byte("x"), 0o600)
			_, err := s.Get(id, nil)
			wantErr(t, "Get", err, resources.ErrUnavailable)
			publish(t, s, other, 1, nil, "2")
			wantNames(t, dir, "index.json", bn(other, 1))
			if r := mustGet(t, s, other, nil); !slices.Equal(r.Members, []string{"2"}) {
				t.Fatalf("members = %v", r.Members)
			}
		})
	}
}

func TestBrokenBodiesNeverServed(t *testing.T) {
	tests := map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, p string) { os.Remove(p) },
		"shorter": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)-1], 0o600)
		},
		"longer": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, '\n'), 0o600)
		},
		"one byte changed": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			b[0] ^= 1
			os.WriteFile(p, b, 0o600)
		},
		"symlink to the right content": func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			real := filepath.Join(t.TempDir(), "real")
			os.WriteFile(real, b, 0o600)
			os.Remove(p)
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, p string) {
			os.Remove(p)
			os.Mkdir(p, 0o700)
		},
	}
	for name, corrupt := range tests {
		t.Run("current "+name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			corrupt(t, filepath.Join(dir, bn(id, 1)))
			r, err := s.Get(id, nil)
			wantErr(t, fmt.Sprintf("Get (reply %+v)", r), err, resources.ErrUnavailable)
		})
		t.Run("baseline "+name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			applied(t, s, id, 1)
			publish(t, s, id, 2, nil, "20", "30")
			corrupt(t, filepath.Join(dir, bn(id, 1)))
			r := mustGet(t, s, id, &resources.Cursor{1, dg("10", "20")})
			if r.Kind != resources.KindFull || !slices.Equal(r.Members, []string{"20", "30"}) {
				t.Fatalf("reply = %+v; want the full current body", r)
			}
		})
	}
}

func TestInconsistentIndexNeverServed(t *testing.T) {
	edits := map[string]func(g map[string]any){
		"negative length":  func(g map[string]any) { g["length"] = -1 },
		"entries one more": func(g map[string]any) { g["entries"] = g["entries"].(float64) + 1 },
		"entries negative": func(g map[string]any) { g["entries"] = -1 },
	}
	edit := func(t *testing.T, dir, which string, f func(map[string]any)) {
		t.Helper()
		idx := readIndex(t, dir)
		f(idx["resources"].(map[string]any)[id].(map[string]any)[which].(map[string]any))
		b, err := json.Marshal(idx)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The reply's metadata is the current generation's: it must be the JSON object the writer stored.
	for name, f := range map[string]func(g map[string]any){
		"metadata an array": func(g map[string]any) { g["metadata"] = []any{} },
		"metadata null":     func(g map[string]any) { g["metadata"] = nil },
		"metadata a number": func(g map[string]any) { g["metadata"] = 5 },
		"metadata a string": func(g map[string]any) { g["metadata"] = "{}" },
		"metadata missing":  func(g map[string]any) { delete(g, "metadata") },
	} {
		t.Run("current "+name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, map[string]any{"action": "deny"}, "10", "20")
			edit(t, dir, "current", f)
			r, err := s.Get(id, nil)
			wantErr(t, fmt.Sprintf("Get (reply %+v)", r), err, resources.ErrUnavailable)
			r, err = s.Get(id, &resources.Cursor{1, dg("10", "20")})
			wantErr(t, fmt.Sprintf("Get at the current cursor (reply %+v)", r), err, resources.ErrUnavailable)
		})
	}
	for name, f := range edits {
		t.Run("current "+name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			edit(t, dir, "current", f)
			r, err := s.Get(id, nil)
			wantErr(t, fmt.Sprintf("Get (reply %+v)", r), err, resources.ErrUnavailable)
		})
		t.Run("baseline "+name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			applied(t, s, id, 1)
			publish(t, s, id, 2, nil, "20", "30")
			edit(t, dir, "applied", f)
			r := mustGet(t, s, id, &resources.Cursor{1, dg("10", "20")})
			if r.Kind != resources.KindFull || !slices.Equal(r.Members, []string{"20", "30"}) {
				t.Fatalf("reply = %+v; want the full current body", r)
			}
		})
	}
}

// A removal killed between the index write and the deletion leaves the bodies behind with no entry: reporting the removal
// applied again clears them, and only them.
func TestARepeatedRemovalAppliedClearsTheBodiesAKilledOneLeft(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, "dnsbl/xy", 1, nil, "a")
	for _, left := range []string{bn("dnsbl/x", 2), bn("dnsbl/x", 3)} {
		if err := os.WriteFile(filepath.Join(dir, left), []byte("gone\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wantNames(t, dir, bn("dnsbl/x", 2), bn("dnsbl/x", 3), bn("dnsbl/xy", 1), "index.json")
	if err := s.RemovalApplied("dnsbl/x"); err != nil {
		t.Fatalf("RemovalApplied: %v", err)
	}
	wantNames(t, dir, bn("dnsbl/xy", 1), "index.json")
}

func TestFIFOBodyNeverServed(t *testing.T) {
	fifo := func(t *testing.T, p string) {
		os.Remove(p)
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("current", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil)
		fifo(t, filepath.Join(dir, bn(id, 1)))
		_, err := s.Get(id, nil)
		wantErr(t, "Get", err, resources.ErrUnavailable)
	})
	t.Run("baseline", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil)
		applied(t, s, id, 1)
		publish(t, s, id, 2, nil, "20")
		fifo(t, filepath.Join(dir, bn(id, 1)))
		if r := mustGet(t, s, id, &resources.Cursor{1, dg()}); r.Kind != resources.KindFull || !slices.Equal(r.Members, []string{"20"}) {
			t.Fatalf("reply = %+v; want the full current body", r)
		}
	})
}

func TestWriterKeepsTheStoreOnReadErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := resources.Open(filepath.Join(file, "sub")) // ENOTDIR: not a content problem
	if _, err := s.Publish(id, []string{"1"}, nil); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("Publish error = %v; want ENOTDIR", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "x" {
		t.Fatalf("file changed: %q", b)
	}
}

func TestPublishRefusesGenerationOverflow(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "1")
	idx := readIndex(t, dir)
	idx["resources"].(map[string]any)[id].(map[string]any)["current"].(map[string]any)["generation"] = "18446744073709551615"
	raw, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	if g, err := s.Publish(id, []string{"2"}, nil); err == nil {
		t.Fatalf("Publish = %d, nil; want an error", g)
	}
	if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
		t.Fatalf("store changed: %v -> %v", before, snapshot(t, dir))
	}
}

func TestIdenticalPublishHealsALostBody(t *testing.T) {
	lose := map[string]func(t *testing.T, p string){
		"deleted":   func(t *testing.T, p string) { os.Remove(p) },
		"truncated": func(t *testing.T, p string) { os.Truncate(p, 3) },
		"same size, one byte changed": func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("10\n29\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, f := range lose {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			index := snapshot(t, dir)["index.json"]
			f(t, filepath.Join(dir, bn(id, 1)))
			publish(t, s, id, 1, nil, "10", "20")
			if r := mustGet(t, s, id, nil); r.Kind != resources.KindFull || !slices.Equal(r.Members, []string{"10", "20"}) {
				t.Fatalf("reply = %+v", r)
			}
			if got := snapshot(t, dir); got["index.json"] != index || len(got) != 2 {
				t.Fatalf("store after heal: %v; index was %q", got, index)
			}
		})
	}
	t.Run("intact body is not rewritten", func(t *testing.T) {
		s, dir := newStore(t)
		publish(t, s, id, 1, nil, "10", "20")
		p := filepath.Join(dir, bn(id, 1))
		before, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		publish(t, s, id, 1, nil, "10", "20")
		if after, err := os.Lstat(p); err != nil || !os.SameFile(before, after) {
			t.Fatalf("body file was replaced: %v", err)
		}
	})
}

func TestCanonicalFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Cases []struct {
			Name        string
			Input, Want []string
		}
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) < 6 {
		t.Fatalf("fixture has %d cases", len(fx.Cases))
	}
	for _, c := range fx.Cases {
		got, err := resources.Canonical(slices.Clone(c.Input))
		if err != nil || !slices.Equal(got, c.Want) {
			t.Errorf("%s: Canonical(%q) = %q, %v; want %q", c.Name, c.Input, got, err, c.Want)
		}
	}
}

func TestDeltaRebuildsTheNewBodyExactly(t *testing.T) {
	pick := func(r *rand.Rand, n, universe int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("10.%d.%d.0/24", r.IntN(universe)/256, r.IntN(universe)%256)
		}
		return out
	}
	for seed := range uint64(200) {
		r := rand.New(rand.NewPCG(seed, 7))
		a := pick(r, r.IntN(300), 400)
		b := pick(r, r.IntN(300), 400)
		switch seed % 5 {
		case 0:
			b = slices.Clone(a)
		case 1:
			a = nil
		case 2:
			b = nil
		case 3:
			b = append(slices.Clone(a), pick(r, 3, 400)...)
		}
		a, _ = resources.Canonical(a)
		b, _ = resources.Canonical(b)
		s, _ := newStore(t)
		publish(t, s, id, 1, nil, a...)
		applied(t, s, id, 1)
		want := uint64(2)
		if slices.Equal(a, b) {
			want = 1
		}
		publish(t, s, id, want, nil, b...)
		rep := mustGet(t, s, id, &resources.Cursor{1, dg(a...)})
		if slices.Equal(a, b) {
			if rep.Kind != resources.KindUnchanged {
				t.Fatalf("seed %d: kind %q for equal sets", seed, rep.Kind)
			}
			continue
		}
		if rep.Kind != resources.KindDelta {
			t.Fatalf("seed %d: kind %q", seed, rep.Kind)
		}
		for _, l := range [][]string{rep.Add, rep.Remove} {
			if l == nil || !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != len(l) {
				t.Fatalf("seed %d: add/remove not sorted unique non-nil: %v", seed, l)
			}
		}
		for _, m := range rep.Add {
			if slices.Contains(rep.Remove, m) {
				t.Fatalf("seed %d: %q in add and remove", seed, m)
			}
		}
		set := map[string]bool{}
		for _, m := range a {
			set[m] = true
		}
		for _, m := range rep.Remove {
			delete(set, m)
		}
		for _, m := range rep.Add {
			set[m] = true
		}
		got := []string{}
		for m := range set {
			got = append(got, m)
		}
		slices.Sort(got)
		if string(body(got)) != string(body(b)) || digest.Bytes(body(got)) != rep.Digest || rep.Digest != dg(b...) || rep.Entries != len(b) {
			t.Fatalf("seed %d: rebuilt body differs from the published one (%d vs %d members)", seed, len(got), len(b))
		}
	}
}

// It exercises the reader's restart on a raced publish as often as the scheduler interleaves them, and asserts only that
// no torn reply is ever seen.
func TestReadersNeverSeeATornPublish(t *testing.T) {
	var x, y []string
	for i := range 2000 {
		x = append(x, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		y = append(y, fmt.Sprintf("11.0.%d.%d", i/256, i%256))
	}
	slices.Sort(x)
	slices.Sort(y)
	w, dir := newStore(t)
	publish(t, w, id, 1, nil, x...)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rd := resources.Open(dir)
			for {
				select {
				case <-done:
					return
				default:
				}
				r, err := rd.Get(id, nil)
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				if r.Kind != resources.KindFull || !(slices.Equal(r.Members, x) && r.Digest == dg(x...) || slices.Equal(r.Members, y) && r.Digest == dg(y...)) {
					t.Errorf("reply is neither body: kind %s, %d members, digest %s", r.Kind, len(r.Members), r.Digest)
					return
				}
			}
		}()
	}
	for i := range 300 {
		next := y
		if i%2 == 1 {
			next = x
		}
		if _, err := w.Publish(id, slices.Clone(next), nil); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	wg.Wait()
}
