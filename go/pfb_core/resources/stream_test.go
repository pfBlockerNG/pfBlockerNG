package resources_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// dn is the file name of a delta part of id's generation g from generation from.
func dn(id string, g, from int, part string) string {
	return fmt.Sprintf("%s.%d.%d.%s", strings.ReplaceAll(id, "/", "~"), g, from, part)
}

// read is the bytes the store serves for a part, and their lines.
func read(t *testing.T, s *resources.Store, id string, g uint64, part string, from uint64) []string {
	t.Helper()
	f, size, err := s.Body(id, g, part, from)
	if err != nil {
		t.Fatalf("Body(%s, %d, %s, %d): %v", id, g, part, from, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil || int64(len(b)) != size {
		t.Fatalf("Body(%s, %d, %s, %d) read %d bytes of %d: %v", id, g, part, from, len(b), size, err)
	}
	if len(b) == 0 {
		return []string{}
	}
	if b[len(b)-1] != '\n' {
		t.Fatalf("Body(%s, %d, %s, %d) does not end in a newline: %q", id, g, part, from, b)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// members is the full body of r's generation.
func members(t *testing.T, s *resources.Store, id string, r resources.Reply) []string {
	t.Helper()
	return read(t, s, id, r.Generation, resources.PartMembers, 0)
}

// delta is r's add and remove lines, which must match the reply's counts.
func delta(t *testing.T, s *resources.Store, id string, r resources.Reply) (add, remove []string) {
	t.Helper()
	add = read(t, s, id, r.Generation, resources.PartAdd, r.From)
	remove = read(t, s, id, r.Generation, resources.PartRemove, r.From)
	if len(add) != r.Adds || len(remove) != r.Removes {
		t.Fatalf("delta of %d adds and %d removes; the reply says %d and %d", len(add), len(remove), r.Adds, r.Removes)
	}
	return add, remove
}

// diff is the in-memory oracle of a delta: what turns base into cur, both canonical.
func diff(base, cur []string) (add, remove []string) {
	add, remove = []string{}, []string{}
	for _, m := range cur {
		if _, ok := slices.BinarySearch(base, m); !ok {
			add = append(add, m)
		}
	}
	for _, m := range base {
		if _, ok := slices.BinarySearch(cur, m); !ok {
			remove = append(remove, m)
		}
	}
	return add, remove
}

// lazy yields n canonical members, "m<i>" zero-padded, one line at a time, skipping each i that skip names; it never
// holds more than one line, in one buffer it reuses.
type lazy struct {
	i, n int
	skip func(int) bool
	buf  []byte
	rest []byte // the unread part of buf
}

func (l *lazy) Read(p []byte) (int, error) {
	for len(l.rest) == 0 {
		if l.i >= l.n {
			return 0, io.EOF
		}
		i := l.i
		l.i++
		if l.skip == nil || !l.skip(i) {
			l.buf = append(l.buf[:0], "m000000000\n"...) // formatted by hand: fmt would box i, an allocation a line
			for j, v := 9, i; v > 0; j, v = j-1, v/10 {
				l.buf[j] = byte('0' + v%10)
			}
			l.rest = l.buf
		}
	}
	n := copy(p, l.rest)
	l.rest = l.rest[n:]
	return n, nil
}

func TestPublishFromStoresTheBodyPublishStores(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, map[string]any{"k": 1}, "b", "a", "c")
	want, err := os.ReadFile(filepath.Join(dir, bn(id, 1)))
	if err != nil {
		t.Fatal(err)
	}
	s2, dir2 := newStore(t)
	g, err := s2.PublishFrom(id, strings.NewReader("a\nb\nc\n"), map[string]any{"k": 1})
	if err != nil || g != 1 {
		t.Fatalf("PublishFrom = %d, %v", g, err)
	}
	got, err := os.ReadFile(filepath.Join(dir2, bn(id, 1)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("body = %q, %v; want %q", got, err, want)
	}
	if r1, r2 := mustGet(t, s, id, nil), mustGet(t, s2, id, nil); r1.Digest != r2.Digest || r1.Entries != r2.Entries ||
		string(r1.Metadata) != string(r2.Metadata) {
		t.Fatalf("replies differ: %+v and %+v", r1, r2)
	}
	if g, err := s2.PublishFrom(id, strings.NewReader("a\nb\nc"), map[string]any{"k": 1}); err != nil || g != 1 {
		t.Fatalf("the same body without its last newline = generation %d, %v; want 1, the same body", g, err)
	}
}

func TestPublishFromRefusesABodyThatIsNotCanonical(t *testing.T) {
	for name, in := range map[string]string{
		"unsorted":            "b\na\n",
		"duplicate":           "a\na\n",
		"empty line":          "a\n\nb\n",
		"comment":             "#a\n",
		"control character":   "a\tb\n",
		"invalid UTF-8":       "a\xff\n",
		"carriage return":     "a\r\n",
		"line over the limit": strings.Repeat("a", 1<<20+1) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "x")
			before := snapshot(t, dir)
			if g, err := s.PublishFrom(id, strings.NewReader(in), nil); err == nil {
				t.Fatalf("PublishFrom(%.40q) = %d; want a refusal", in, g)
			}
			if fmt.Sprint(snapshot(t, dir)) != fmt.Sprint(before) {
				t.Fatalf("a refused publish changed the store: %v", names(t, dir))
			}
		})
	}
}

// The add and remove files written at publish are the in-memory diff of the two bodies, over a randomized corpus.
func TestDeltaFilesAreTheDiffOfTheTwoBodies(t *testing.T) {
	r := rand.New(rand.NewPCG(4049, 1))
	set := func() []string {
		m := []string{}
		for i := range 200 {
			if r.IntN(3) > 0 {
				m = append(m, fmt.Sprintf("10.%d.%d.0/24", i/50, r.IntN(4)+i))
			}
		}
		slices.Sort(m)
		return slices.Compact(m)
	}
	for round := range 50 {
		s, dir := newStore(t)
		base, cur := set(), set()
		if round == 0 {
			base = []string{}
		}
		if round == 1 {
			cur = []string{}
		}
		publish(t, s, id, 1, nil, base...)
		applied(t, s, id, 1)
		publish(t, s, id, 2, nil, cur...)
		rep := mustGet(t, s, id, &resources.Cursor{1, dg(base...)})
		if rep.Kind != resources.KindDelta || rep.From != 1 {
			t.Fatalf("round %d: reply %+v; want a delta from 1", round, rep)
		}
		add, remove := delta(t, s, id, rep)
		wantAdd, wantRemove := diff(base, cur)
		if !slices.Equal(add, wantAdd) || !slices.Equal(remove, wantRemove) {
			t.Fatalf("round %d: delta add %v remove %v; want %v and %v", round, add, remove, wantAdd, wantRemove)
		}
		wantNames(t, dir, "index.json", bn(id, 1), bn(id, 2), dn(id, 2, 1, "add"), dn(id, 2, 1, "remove"))
	}
}

func TestBodyServesOnlyWhatTheStoreHolds(t *testing.T) {
	s, _ := newStore(t)
	publish(t, s, id, 1, nil, "1")
	applied(t, s, id, 1)
	publish(t, s, id, 2, nil, "2")
	if got := read(t, s, id, 1, resources.PartMembers, 0); !slices.Equal(got, []string{"1"}) {
		t.Fatalf("applied baseline = %v", got)
	}
	if got := read(t, s, id, 2, resources.PartMembers, 0); !slices.Equal(got, []string{"2"}) {
		t.Fatalf("current = %v", got)
	}
	for _, c := range []struct {
		g    uint64
		part string
		from uint64
	}{
		{3, resources.PartMembers, 0}, {2, resources.PartAdd, 0}, {1, resources.PartAdd, 0}, {2, resources.PartRemove, 3},
	} {
		_, _, err := s.Body(id, c.g, c.part, c.from)
		wantErr(t, fmt.Sprintf("Body(%d, %s, %d)", c.g, c.part, c.from), err, resources.ErrNotFound)
	}
	// Pruned: generation 1 and the delta from it are gone once 2 is applied and 3 published.
	applied(t, s, id, 2)
	publish(t, s, id, 3, nil, "3")
	_, _, err := s.Body(id, 1, resources.PartMembers, 0)
	wantErr(t, "Body of a pruned generation", err, resources.ErrNotFound)
	_, _, err = s.Body(id, 2, resources.PartAdd, 1)
	wantErr(t, "Body of a pruned delta", err, resources.ErrNotFound)
	if r := mustGet(t, s, id, &resources.Cursor{1, dg("1")}); r.Kind != resources.KindFull {
		t.Fatalf("a pruned cursor = %+v; want full", r)
	}
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Body(id, 3, resources.PartMembers, 0)
	wantErr(t, "Body of a removed resource", err, resources.ErrNotFound)
	_, _, err = s.Body("dnsbl/other", 1, resources.PartMembers, 0)
	wantErr(t, "Body of an unknown resource", err, resources.ErrNotFound)
	_, _, err = s.Body("not an id", 1, resources.PartMembers, 0)
	wantErr(t, "Body of an invalid id", err, resources.ErrInvalidID)
	_, _, err = s.Body(id, 3, "body", 0)
	wantErr(t, "Body of an unknown part", err, resources.ErrInvalidPart)
}

// A part whose bytes differ from what the index recorded is never served, whatever its size; GetResources then answers
// full for a delta, and the body read refuses the body itself.
func TestBodyVerifiesTheBytesItServes(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "10", "20")
	applied(t, s, id, 1)
	publish(t, s, id, 2, nil, "20", "30")
	for _, name := range []string{bn(id, 2), dn(id, 2, 1, "add")} {
		p := filepath.Join(dir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[0] ^= 1
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := s.Body(id, 2, resources.PartMembers, 0)
	wantErr(t, "Body of a damaged body", err, resources.ErrUnavailable)
	_, _, err = s.Body(id, 2, resources.PartAdd, 1)
	wantErr(t, "Body of a damaged delta", err, resources.ErrUnavailable)
	if got := read(t, s, id, 2, resources.PartRemove, 1); !slices.Equal(got, []string{"10"}) {
		t.Fatalf("the intact remove part = %v", got)
	}
	if r, err := s.Get(id, &resources.Cursor{1, dg("10", "20")}); err == nil || r.Kind == resources.KindDelta {
		t.Fatalf("Get with a damaged body and delta = %+v, %v; want unavailable", r, err)
	}
}

// A delta part that is damaged turns the delta into a full reply.
func TestADamagedDeltaPartAnswersFull(t *testing.T) {
	for _, part := range []string{"add", "remove"} {
		t.Run(part, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			applied(t, s, id, 1)
			publish(t, s, id, 2, nil, "20", "30")
			p := filepath.Join(dir, dn(id, 2, 1, part))
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b[0] ^= 1
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if r := mustGet(t, s, id, &resources.Cursor{1, dg("10", "20")}); r.Kind != resources.KindFull {
				t.Fatalf("reply = %+v; want full", r)
			}
		})
	}
}

// A publish that changes nothing writes back a delta that is lost or that an older index never recorded.
func TestAnUnchangedPublishRestoresTheDelta(t *testing.T) {
	for name, lose := range map[string]func(t *testing.T, dir string){
		"part deleted": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, dn(id, 2, 1, "add"))); err != nil {
				t.Fatal(err)
			}
		},
		"index without a delta": func(t *testing.T, dir string) {
			idx := readIndex(t, dir)
			delete(idx["resources"].(map[string]any)[id].(map[string]any), "delta")
			raw, _ := json.Marshal(idx)
			if err := os.WriteFile(filepath.Join(dir, "index.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{"add", "remove"} {
				os.Remove(filepath.Join(dir, dn(id, 2, 1, part)))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			publish(t, s, id, 1, nil, "10", "20")
			applied(t, s, id, 1)
			publish(t, s, id, 2, nil, "20", "30")
			lose(t, dir)
			publish(t, s, id, 2, nil, "20", "30")
			r := mustGet(t, s, id, &resources.Cursor{1, dg("10", "20")})
			if r.Kind != resources.KindDelta {
				t.Fatalf("reply = %+v; want a delta", r)
			}
			if add, remove := delta(t, s, id, r); !slices.Equal(add, []string{"30"}) || !slices.Equal(remove, []string{"10"}) {
				t.Fatalf("delta add %v remove %v", add, remove)
			}
		})
	}
}

// A member of MaxMemberLength bytes is taken; one byte more is refused, by Canonical as by PublishFrom.
func TestTheMemberLengthLimit(t *testing.T) {
	s, _ := newStore(t)
	at := strings.Repeat("a", resources.MaxMemberLength)
	if _, err := s.PublishFrom(id, strings.NewReader(at+"\n"), nil); err != nil {
		t.Fatalf("a member of %d bytes: %v", len(at), err)
	}
	over := at + "a"
	if _, err := resources.Canonical([]string{over}); err == nil || !strings.Contains(err.Error(), "invalid member") {
		t.Fatalf("Canonical of a member of %d bytes = %v; want an invalid member", len(over), err)
	}
	for _, in := range []string{over, over + "\n"} {
		if _, err := s.PublishFrom(id, strings.NewReader(in), nil); err == nil || !strings.Contains(err.Error(), "invalid member") {
			t.Fatalf("PublishFrom of a member of %d bytes = %v; want an invalid member", len(over), err)
		}
	}
}

// A baseline whose body is damaged when a publish runs gets no delta: the merge would read the wrong lines.
func TestADamagedBaselineGetsNoDelta(t *testing.T) {
	s, dir := newStore(t)
	publish(t, s, id, 1, nil, "10", "20")
	applied(t, s, id, 1)
	if err := os.WriteFile(filepath.Join(dir, bn(id, 1)), []byte("10\n29\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	publish(t, s, id, 2, nil, "20", "30")
	wantNames(t, dir, "index.json", bn(id, 1), bn(id, 2))
	if r := mustGet(t, s, id, &resources.Cursor{1, dg("10", "20")}); r.Kind != resources.KindFull {
		t.Fatalf("reply = %+v; want full", r)
	}
}

// The store never holds a body or a delta in memory: publishing and reading a large body allocates a small constant,
// far below the body's size.
func TestPublishAndReadAllocateAConstant(t *testing.T) {
	const n = 300_000 // 3 MB a body
	const budget = 1 << 20
	s, _ := newStore(t)
	allocs := func(what string, f func()) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		if got := after.TotalAlloc - before.TotalAlloc; got > budget {
			t.Errorf("%s allocated %d bytes; want at most %d", what, got, budget)
		}
	}
	allocs("PublishFrom", func() {
		if _, err := s.PublishFrom(id, &lazy{n: n}, nil); err != nil {
			t.Fatal(err)
		}
	})
	applied(t, s, id, 1)
	allocs("PublishFrom with a 1% delta", func() {
		if _, err := s.PublishFrom(id, &lazy{n: n + n/200, skip: func(i int) bool { return i%200 == 0 }}, nil); err != nil {
			t.Fatal(err)
		}
	})
	var r resources.Reply
	allocs("Get", func() {
		var err error
		if r, err = s.Get(id, nil); err != nil {
			t.Fatal(err)
		}
	})
	for _, p := range []struct {
		g    uint64
		part string
		from uint64
	}{{2, resources.PartMembers, 0}, {2, resources.PartAdd, 1}, {2, resources.PartRemove, 1}} {
		allocs("Body "+p.part, func() {
			f, _, err := s.Body(id, p.g, p.part, p.from)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, f); err != nil {
				t.Fatal(err)
			}
			f.Close()
		})
	}
	if r.Entries != n+n/200-(n+n/200+199)/200 {
		t.Fatalf("entries = %d", r.Entries)
	}
}
