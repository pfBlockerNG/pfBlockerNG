package dnsbl_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

const psl = "// comment before\n// ===BEGIN ICANN DOMAINS===\n// a comment\ncom\n\n  *.ck  \n!www.ck\n// ===END ICANN DOMAINS===\noutside.example\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\r\n// ===END PRIVATE DOMAINS===\n"

// body is id's current body as lines, read back from the store.
func body(t *testing.T, store *resources.Store, id string) []string {
	t.Helper()
	reply, err := store.Get(id, nil)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	f, _, err := store.Body(id, reply.Generation, resources.PartMembers, 0)
	if err != nil {
		t.Fatalf("Body(%s): %v", id, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	return lines[:len(lines)-1]
}

// generations is the current generation of every id, ErrNotFound as 0.
func generations(t *testing.T, store *resources.Store, ids []string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, id := range ids {
		reply, err := store.Get(id, nil)
		switch {
		case errors.Is(err, resources.ErrNotFound):
		case err != nil:
			t.Fatalf("Get(%s): %v", id, err)
		default:
			out[id] = reply.Generation
		}
	}
	return out
}

func sampleSet() dnsbl.Set {
	return dnsbl.Set{
		BuiltinLogFlag: "1",
		Top1mEnabled:   true,
		Whitelist:      []string{".example.com", "a.example"},
		Unlock:         []string{"u.example"},
		TLDBlacklist:   []string{"zip"},
		TLDExclusions:  []string{"ok.zip"},
		Feeds: []dnsbl.Feed{
			{Name: "Ads_2", Group: "Ads", LogFlag: "1", Rows: []string{"z.example", "||ad.example^", "a.example", "z.example"}},
			{Name: "Mal", Group: "Malware", LogFlag: "0", Provenance: "user", Rows: []string{"m.example"}},
			{Name: "Ads_1", Group: "Ads", LogFlag: "2", Mode: "permit", Top1m: true, Rows: []string{"b.example", "c.example"}},
		},
		Top1m:      []string{"google.com", "bing.com"},
		SafeSearch: []dnsbl.SafeSearch{{Host: "www.bing.com", A: "cname", AAAA: "strict.bing.com", V4: "204.79.197.220", V6: "::1"}, {Host: "duckduckgo.com", A: "1.2.3.4", AAAA: "nxdomain"}, {Host: "duckduckgo.com", A: "5.6.7.8", AAAA: "nxdomain"}},
		PSL:        []byte(psl),
	}
}

// Scenario: a whole set. The manifest is the commit record: its rows name every body with the generation, digest and
// entries the store holds for it, in byte order, and its metadata counts each group's entries in feed order.
func TestPublishWritesEveryBodyAndAManifestNamingThem(t *testing.T) {
	store := resources.Open(t.TempDir())
	res, err := dnsbl.Publish(store, sampleSet())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{
		"dnsbl/feed-Ads_2": {"a.example", "z.example", "||ad.example^"},
		"dnsbl/feed-Mal":   {"m.example"},
		"dnsbl/feed-Ads_1": {"b.example", "c.example"},
		dnsbl.Top1mID:      {"bing.com", "google.com"},
		dnsbl.SafeSearchID: {
			`{"host":"duckduckgo.com","a":"5.6.7.8","aaaa":"nxdomain"}`,
			`{"host":"www.bing.com","a":"cname","aaaa":"strict.bing.com","v4":"204.79.197.220","v6":"::1"}`,
		},
		dnsbl.PSLID: {
			`{"section":"icann","rule":"!www.ck"}`,
			`{"section":"icann","rule":"*.ck"}`,
			`{"section":"icann","rule":"com"}`,
			`{"section":"private","rule":"github.io"}`,
		},
	}
	described := map[string]resources.Reply{}
	for id, lines := range want {
		if got := body(t, store, id); !slices.Equal(got, lines) {
			t.Errorf("%s body = %q, want %q", id, got, lines)
		}
		described[id], _ = store.Get(id, nil)
	}
	row := func(id string) string {
		r := described[id]
		return fmt.Sprintf(`"resource":%q,"generation":"%d","digest":%q,"entries":%d}`, id, r.Generation, r.Digest, r.Entries)
	}
	wantManifest := []string{
		`{"kind":"config","builtinLogFlag":"1","top1mEnabled":true}`,
		`{"kind":"feed","position":1,"feed":"Ads_2","group":"Ads","logFlag":"1","provenance":"feed","mode":"deny","top1m":false,` + row("dnsbl/feed-Ads_2"),
		`{"kind":"feed","position":2,"feed":"Mal","group":"Malware","logFlag":"0","provenance":"user","mode":"deny","top1m":false,` + row("dnsbl/feed-Mal"),
		`{"kind":"feed","position":3,"feed":"Ads_1","group":"Ads","logFlag":"2","provenance":"feed","mode":"permit","top1m":true,` + row("dnsbl/feed-Ads_1"),
		`{"kind":"member",` + row(dnsbl.PSLID),
		`{"kind":"member",` + row(dnsbl.SafeSearchID),
		`{"kind":"member",` + row(dnsbl.Top1mID),
		`{"kind":"tld_blacklist","tld":"zip"}`,
		`{"kind":"tld_exclusion","domain":"ok.zip"}`,
		`{"kind":"unlock","domain":"u.example"}`,
		`{"kind":"whitelist","domain":".example.com"}`,
		`{"kind":"whitelist","domain":"a.example"}`,
	}
	slices.Sort(wantManifest)
	if got := body(t, store, dnsbl.ManifestID); !slices.Equal(got, wantManifest) {
		t.Errorf("manifest =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantManifest, "\n"))
	}

	reply, err := store.Get(dnsbl.ManifestID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != reply.Generation || res.Generation == 0 {
		t.Errorf("Result.Generation = %d, the store's manifest generation is %d", res.Generation, reply.Generation)
	}
	wantMeta := `{"entries":6,"feeds":3,"groups":[{"name":"Ads","entries":5},{"name":"Malware","entries":1}]}`
	if string(reply.Metadata) != wantMeta {
		t.Errorf("manifest metadata = %s, want %s", reply.Metadata, wantMeta)
	}
	if len(res.Dropped) != 0 || len(res.Refused) != 0 {
		t.Errorf("Dropped %v, Refused %v, want none", res.Dropped, res.Refused)
	}
}

// Scenario: an absent TOP1M, SafeSearch or PSL publishes no body and no member row, and nothing else is named.
func TestPublishLeavesOutTheMembersTheSetDoesNotCarry(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{BuiltinLogFlag: "0", Feeds: []dnsbl.Feed{{Name: "F", Group: "G", LogFlag: "0"}}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{dnsbl.Top1mID, dnsbl.SafeSearchID, dnsbl.PSLID} {
		if _, err := store.Get(id, nil); !errors.Is(err, resources.ErrNotFound) {
			t.Errorf("Get(%s) = %v, want not found", id, err)
		}
	}
	got := body(t, store, dnsbl.ManifestID)
	if len(got) != 2 || !strings.Contains(got[1], `"resource":"dnsbl/feed-F","generation":"1"`) || !strings.Contains(got[1], `"entries":0`) {
		t.Errorf("manifest = %q, want the config row and an empty feed's row", got)
	}
}

// Property: publishing the same set again advances no generation, whatever the set; changing one feed advances that
// feed's body and the manifest only.
func TestPublishingTheSameSetTwiceAdvancesNoGeneration(t *testing.T) {
	r := rand.New(rand.NewPCG(4036, 7))
	word := func() string { return fmt.Sprintf("d%d.example", r.IntN(50)) }
	for trial := range 40 {
		var set dnsbl.Set
		set.BuiltinLogFlag = fmt.Sprint(r.IntN(7))
		set.Top1mEnabled = r.IntN(2) == 0
		for range r.IntN(4) {
			set.Whitelist = append(set.Whitelist, word())
		}
		for f := range 1 + r.IntN(4) {
			feed := dnsbl.Feed{Name: fmt.Sprint("F", f), Group: fmt.Sprint("G", r.IntN(2)), LogFlag: "1"}
			for range r.IntN(20) {
				feed.Rows = append(feed.Rows, word())
			}
			set.Feeds = append(set.Feeds, feed)
		}
		if r.IntN(2) == 0 {
			set.Top1m = []string{word(), word()}
		}
		ids := []string{dnsbl.ManifestID, dnsbl.Top1mID}
		for _, f := range set.Feeds {
			ids = append(ids, dnsbl.FeedPrefix+f.Name)
		}
		clone := func() dnsbl.Set {
			c := set
			c.Feeds = slices.Clone(set.Feeds)
			for i := range c.Feeds {
				c.Feeds[i].Rows = slices.Clone(set.Feeds[i].Rows)
			}
			c.Top1m = slices.Clone(set.Top1m)
			return c
		}

		store := resources.Open(t.TempDir())
		first, err := dnsbl.Publish(store, clone())
		if err != nil {
			t.Fatal(err)
		}
		before := generations(t, store, ids)
		second, err := dnsbl.Publish(store, clone())
		if err != nil {
			t.Fatal(err)
		}
		if after := generations(t, store, ids); !maps.Equal(before, after) || first.Generation != second.Generation {
			t.Fatalf("trial %d: generations %v then %v (manifest %d then %d), want unchanged", trial, before, after, first.Generation, second.Generation)
		}

		changed := clone()
		changed.Feeds[0].Rows = append(changed.Feeds[0].Rows, "new.example")
		if _, err := dnsbl.Publish(store, changed); err != nil {
			t.Fatal(err)
		}
		after := generations(t, store, ids)
		for _, id := range ids {
			advanced := after[id] != before[id]
			if want := id == dnsbl.ManifestID || id == dnsbl.FeedPrefix+set.Feeds[0].Name; advanced != want {
				t.Errorf("trial %d: %s went %d -> %d after one feed changed, want advanced = %v", trial, id, before[id], after[id], want)
			}
		}
	}
}

// Scenario: a feed that left, and a TOP1M list switched off, are removed once the manifest no longer names them; what
// stays keeps its generation.
func TestPublishRemovesWhatTheNewManifestNoLongerNames(t *testing.T) {
	store := resources.Open(t.TempDir())
	set := dnsbl.Set{Feeds: []dnsbl.Feed{{Name: "Stay", Rows: []string{"s.example"}}, {Name: "Leave", Rows: []string{"l.example"}}}, Top1m: []string{"t.example"}}
	if _, err := dnsbl.Publish(store, set); err != nil {
		t.Fatal(err)
	}
	stay, _ := store.Get("dnsbl/feed-Stay", nil)
	if _, err := store.Get("dnsbl/feed-Leave", nil); err != nil {
		t.Fatalf("before: dnsbl/feed-Leave: %v", err)
	}

	if _, err := dnsbl.Publish(store, dnsbl.Set{Feeds: []dnsbl.Feed{{Name: "Stay", Rows: []string{"s.example"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"dnsbl/feed-Leave", dnsbl.Top1mID} {
		if _, err := store.Get(id, nil); !errors.Is(err, resources.ErrNotFound) {
			t.Errorf("after: Get(%s) = %v, want not found", id, err)
		}
	}
	if now, err := store.Get("dnsbl/feed-Stay", nil); err != nil || now.Generation != stay.Generation {
		t.Errorf("after: dnsbl/feed-Stay = %+v, %v; want generation %d kept", now, err, stay.Generation)
	}

	if _, err := dnsbl.Publish(store, set); err != nil {
		t.Fatal(err)
	}
	if got := body(t, store, "dnsbl/feed-Leave"); !slices.Equal(got, []string{"l.example"}) {
		t.Errorf("a feed that came back = %q, want its rows", got)
	}
}

// Hostile rows: a row the store cannot hold (NUL, another control character, a leading "#", empty, over 1 MiB) is left
// out of its body and counted; the rest of the feed is published.
func TestPublishDropsRowsTheStoreCannotHoldAndCountsThem(t *testing.T) {
	store := resources.Open(t.TempDir())
	long := strings.Repeat("a", resources.MaxMemberLength+1)
	res, err := dnsbl.Publish(store, dnsbl.Set{
		Feeds: []dnsbl.Feed{{Name: "F", Rows: []string{"ok.example", "nul\x00.example", "||tab\t.example^", "##.banner", "", long, "del\x7f.example", "ok.example"}}},
		Top1m: []string{"top.example", "#x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"dnsbl/feed-F": 6, dnsbl.Top1mID: 1}; !maps.Equal(res.Dropped, want) {
		t.Errorf("Dropped = %v, want %v", res.Dropped, want)
	}
	if got := body(t, store, "dnsbl/feed-F"); !slices.Equal(got, []string{"ok.example"}) {
		t.Errorf("feed body = %q, want the one storable row", got)
	}
}

// Hostile rows: a feed whose name is not letters, digits and underscores (what today's writer refuses) is left out and
// reported; a feed named twice refuses the whole set before anything is written.
func TestPublishRefusesFeedNamesTodaysWriterRefuses(t *testing.T) {
	store := resources.Open(t.TempDir())
	res, err := dnsbl.Publish(store, dnsbl.Set{Feeds: []dnsbl.Feed{
		{Name: "bad-name"}, {Name: "bad.name"}, {Name: ""}, {Name: "../x"}, {Name: strings.Repeat("a", 120)}, {Name: "Good_1", Rows: []string{"g.example"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bad-name", "bad.name", "", "../x", strings.Repeat("a", 120)}; !slices.Equal(res.Refused, want) {
		t.Errorf("Refused = %q, want %q", res.Refused, want)
	}
	manifest := body(t, store, dnsbl.ManifestID)
	if len(manifest) != 2 || !strings.Contains(manifest[1], `"feed":"Good_1"`) || !strings.Contains(manifest[1], `"position":1`) {
		t.Errorf("manifest = %q, want only Good_1, at position 1", manifest)
	}

	empty := resources.Open(t.TempDir())
	_, err = dnsbl.Publish(empty, dnsbl.Set{Feeds: []dnsbl.Feed{{Name: "Dup", Rows: []string{"a.example"}}, {Name: "Dup", Rows: []string{"b.example"}}}})
	if err == nil || err.Error() != `feed "Dup" is named twice` {
		t.Errorf("a feed named twice: err = %v", err)
	}
	for _, id := range []string{dnsbl.ManifestID, "dnsbl/feed-Dup"} {
		if _, err := empty.Get(id, nil); !errors.Is(err, resources.ErrNotFound) {
			t.Errorf("after a refused set, Get(%s) = %v, want not found", id, err)
		}
	}
}

// Hostile rows: a PSL text without its four markers, once each and in order, or not UTF-8, or holding a NUL, refuses
// the whole set; the previous publication stays as it was.
func TestPublishRefusesAPSLTextWithoutItsMarkers(t *testing.T) {
	store := resources.Open(t.TempDir())
	if _, err := dnsbl.Publish(store, dnsbl.Set{PSL: []byte(psl)}); err != nil {
		t.Fatal(err)
	}
	before := generations(t, store, []string{dnsbl.ManifestID, dnsbl.PSLID})
	for name, text := range map[string]string{
		"no markers":       "com\nnet\n",
		"one missing":      strings.Replace(psl, "// ===END PRIVATE DOMAINS===\n", "", 1),
		"one twice":        psl + "// ===BEGIN ICANN DOMAINS===\n",
		"out of order":     "// ===BEGIN PRIVATE DOMAINS===\nx\n// ===END PRIVATE DOMAINS===\n// ===BEGIN ICANN DOMAINS===\ny\n// ===END ICANN DOMAINS===\n",
		"invalid UTF-8":    psl + "\xff\n",
		"NUL":              psl + "a\x00b\n",
		"marker mid-line":  strings.Replace(psl, "// ===END ICANN DOMAINS===", "x // ===END ICANN DOMAINS===", 1),
		"empty text given": "",
	} {
		if _, err := dnsbl.Publish(store, dnsbl.Set{PSL: []byte(text)}); err == nil {
			t.Errorf("%s: Publish accepted the PSL text", name)
		}
	}
	if after := generations(t, store, []string{dnsbl.ManifestID, dnsbl.PSLID}); !maps.Equal(before, after) {
		t.Errorf("a refused PSL changed the store: %v -> %v", before, after)
	}
}

// Hostile rows: list entries with control characters encoding/json leaves raw become escapes, so the manifest row is
// still a member, and the client reads back the same entry; an entry over 1 MiB refuses the set.
func TestManifestRowsEscapeEveryControlCharacter(t *testing.T) {
	store := resources.Open(t.TempDir())
	entry := "a\x7fb\u0085c\x01d"
	if _, err := dnsbl.Publish(store, dnsbl.Set{Whitelist: []string{entry}}); err != nil {
		t.Fatal(err)
	}
	var row struct{ Kind, Domain string }
	for _, line := range body(t, store, dnsbl.ManifestID) {
		if strings.Contains(line, "whitelist") {
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
		}
	}
	if row.Domain != entry {
		t.Errorf("whitelist row reads back %q, want %q", row.Domain, entry)
	}
	if _, err := dnsbl.Publish(store, dnsbl.Set{Whitelist: []string{strings.Repeat("w", resources.MaxMemberLength)}}); err == nil {
		t.Error("a whitelist entry over 1 MiB as a row was accepted")
	}
}

// ReadStaged takes the rows pfb_dnsbl_ndjson_emit_row() and feedparse write and skips, counting, every other shape, as
// pfb_dnsbl_ndjson_parse_row() skips it: not JSON, not a two-string array, an unknown tag, an empty payload, and the
// legacy object rows Core never writes.
func TestReadStagedTakesCompactRowsOnly(t *testing.T) {
	staged := strings.Join([]string{
		`["d","a.example"]`,
		`["a","||b.example^"]`,
		``,
		`  `,
		`["d","x"`,
		`["x","c.example"]`,
		`["d",""]`,
		`["d","a","b"]`,
		`[1,"a"]`,
		`null`,
		`{"kind":"domain","domain":"old.example","log":"1","feed":"F","group":"G"}`,
		` ["d","spaced.example"] `,
		`["d","last.example"]`, // no newline at the end
	}, "\n")
	rows, invalid, err := dnsbl.ReadStaged(strings.NewReader(staged))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example", "||b.example^", "spaced.example", "last.example"}; !slices.Equal(rows, want) {
		t.Errorf("rows = %q, want %q", rows, want)
	}
	if invalid != 7 {
		t.Errorf("invalid = %d, want 7", invalid)
	}
}

func TestReadStagedReportsAReadError(t *testing.T) {
	failing := io.MultiReader(strings.NewReader(`["d","a.example"]`+"\n"), errReader{})
	if _, _, err := dnsbl.ReadStaged(failing); err == nil || !reflect.DeepEqual(err, errBroken) {
		t.Errorf("err = %v, want %v", err, errBroken)
	}
}

var errBroken = errors.New("broken")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBroken }
