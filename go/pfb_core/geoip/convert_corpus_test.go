package geoip_test

// The GeoIP conversion corpus (#4034), schema 1: JSON scenarios in tests/geoip/fixtures/parity that today's PHP passes
// (tests/php/GeoipConversionCorpusTest.php drives pfblockerng_uc_countries() as the dcc verb calls it) and this package
// passes. A scenario (unknown keys are refused):
//
//	schema       1.
//	description  what the scenario pins.
//	locale       the MaxMind locale (default "en").
//	share_mtime  the Locations file's modification time (RFC 3339), which maxmind_ver reports.
//	share        {name: content}: the MaxMind CSVs in the share folder.
//	seed         {path: content}: files under the root before the run (a previous generation).
//	expect       ok (the conversion's answer), files ({path: content, or null when absent}: only the paths named),
//	             tree (sha256 over every file the run leaves at the root outside share/, as sorted "<path>\0<sha256>\n"
//	             lines, the catalog file cc/.geo_catalog left out) and catalog (the geo-catalog's digest, or null when the
//	             published generation has none; see catalogDigest).
//	old_expect   today's PHP answer where Core deliberately differs (an owner decision): the PHP runner asserts it, this
//	             runner asserts expect and refuses an old_expect equal to it.
//
// Content is a string, {"b64": bytes}, or {"prefix", "repeat", "times", "suffix"} for a long line; a file that is not
// UTF-8 reads as {"b64": bytes}. The root holds share/, cc/ (the country folder), db/geoip.txt (the ISO list) and log/
// (maxmind_ver). A continent file's "# Generated from MaxMind Inc. on: <time>" line reads "{now}" on both sides.
//
// Paths are today's layout. Core publishes each generation in a folder of its own that cc links to, with the ISO list
// inside as .geoip_isos and the publication lock beside the link (#4140): this runner seeds cc/ and db/geoip.txt as that
// previous generation, and reads the result back through the link, as today's paths name it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/geoip"
)

const conversionCorpusDir = "../../../tests/geoip/fixtures/parity"

type corpusContent struct {
	text   *string
	B64    *string `json:"b64"`
	Prefix string  `json:"prefix"`
	Repeat string  `json:"repeat"`
	Times  int     `json:"times"`
	Suffix string  `json:"suffix"`
}

func (c *corpusContent) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &c.text)
	}
	type plain corpusContent
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}

func (c corpusContent) bytes(t *testing.T) []byte {
	switch {
	case c.text != nil:
		return []byte(*c.text)
	case c.B64 != nil:
		b, err := base64.StdEncoding.DecodeString(*c.B64)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return []byte(c.Prefix + strings.Repeat(c.Repeat, c.Times) + c.Suffix)
}

type conversionExpect struct {
	OK      bool                      `json:"ok"`
	Files   map[string]*corpusContent `json:"files"`
	Tree    string                    `json:"tree"`
	Catalog *string                   `json:"catalog"`
}

type conversionCase struct {
	Schema      int                      `json:"schema"`
	Description string                   `json:"description"`
	Locale      string                   `json:"locale"`
	ShareMtime  string                   `json:"share_mtime"`
	Share       map[string]corpusContent `json:"share"`
	Seed        map[string]corpusContent `json:"seed"`
	Expect      conversionExpect         `json:"expect"`
	OldExpect   *conversionExpect        `json:"old_expect"`
}

var generatedLine = regexp.MustCompile(`(?m)^# Generated from MaxMind Inc\. on: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d$`)

func normalized(b []byte) []byte {
	return generatedLine.ReplaceAll(b, []byte("# Generated from MaxMind Inc. on: {now}"))
}

// shown is a file's content as the corpus spells it.
func shown(b []byte) any {
	if utf8.Valid(b) {
		return string(b)
	}
	return map[string]string{"b64": base64.StdEncoding.EncodeToString(b)}
}

func TestConversionCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(conversionCorpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus under %s: %v", conversionCorpusDir, err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var c conversionCase
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if err := d.Decode(&c); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if c.Schema != 1 {
				t.Fatalf("schema %d", c.Schema)
			}
			if c.OldExpect != nil && reflect.DeepEqual(*c.OldExpect, c.Expect) {
				t.Fatalf("%s: old_expect equals expect; drop it", file)
			}
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "share"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, seededGeneration), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(seededGeneration, filepath.Join(root, "cc")); err != nil {
				t.Fatal(err)
			}
			write := func(rel string, content []byte) {
				path := filepath.Join(root, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for name, content := range c.Share {
				write("share/"+name, content.bytes(t))
			}
			locale := c.Locale
			if locale == "" {
				locale = "en"
			}
			if c.ShareMtime != "" {
				mtime, err := time.Parse(time.RFC3339, c.ShareMtime)
				if err != nil {
					t.Fatal(err)
				}
				locations := filepath.Join(root, "share", "GeoLite2-Country-Locations-"+locale+".csv")
				if _, err := os.Stat(locations); err == nil {
					if err := os.Chtimes(locations, mtime, mtime); err != nil {
						t.Fatal(err)
					}
				}
			}
			for rel, content := range c.Seed {
				write(seeded(rel), content.bytes(t))
			}

			conv := geoip.Conversion{
				Share:  filepath.Join(root, "share"),
				CCDir:  filepath.Join(root, "cc"),
				LogDir: filepath.Join(root, "log"),
				Locale: locale,
				Now:    time.Date(2026, 11, 20, 9, 15, 0, 0, time.Local),
				Log:    io.Discard,
			}
			got := map[string]any{"ok": conv.Run(context.Background())}

			published := todays(t, root)
			gotFiles := map[string]any{}
			for rel := range c.Expect.Files {
				if b, ok := published[rel]; ok {
					gotFiles[rel] = shown(normalized(b))
				} else {
					gotFiles[rel] = nil
				}
			}
			got["files"] = gotFiles
			catalog, ok := published["cc/.geo_catalog"]
			delete(published, "cc/.geo_catalog")
			sums, listing := tree(published)
			got["tree"] = sums
			got["catalog"] = nil
			if ok {
				got["catalog"] = catalogDigest(t, catalog)
			}

			wantFiles := map[string]any{}
			for rel, content := range c.Expect.Files {
				if content == nil {
					wantFiles[rel] = nil
					continue
				}
				wantFiles[rel] = shown(content.bytes(t))
			}
			want := map[string]any{"ok": c.Expect.OK, "files": wantFiles, "tree": c.Expect.Tree, "catalog": nil}
			if c.Expect.Catalog != nil {
				want["catalog"] = *c.Expect.Catalog
			}
			if !reflect.DeepEqual(got, want) {
				gj, _ := json.MarshalIndent(got, "", "  ")
				wj, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("%s\n got: %.4000s\nwant: %.4000s\ntree:\n%s", c.Description, gj, wj, listing)
			}
		})
	}
}

// seededGeneration is the previous generation a row's seed fills.
const seededGeneration = ".cc.1.00000000"

// seeded is where a seed path of today's layout lies in Core's: the country folder and the ISO list are the previous
// generation's.
func seeded(rel string) string {
	switch {
	case strings.HasPrefix(rel, "cc/"):
		return seededGeneration + "/" + strings.TrimPrefix(rel, "cc/")
	case rel == "db/geoip.txt" || strings.HasPrefix(rel, "db/geoip.txt/"):
		return seededGeneration + "/.geoip_isos" + strings.TrimPrefix(rel, "db/geoip.txt")
	}
	return rel
}

// todays is every file the run leaves under root outside share/, by its path in today's layout: the generation cc links
// to is cc/ (its .geoip_isos is db/geoip.txt), the lock beside the link is cc/.pfb_generation.lock, and the other
// generations are not published.
func todays(t *testing.T, root string) map[string][]byte {
	t.Helper()
	gen, err := os.Readlink(filepath.Join(root, "cc"))
	if err != nil {
		t.Fatalf("cc is not a link: %v", err)
	}
	files := map[string][]byte{}
	err = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		top, rest, _ := strings.Cut(rel, "/")
		if e.IsDir() {
			if rel == "share" || rest == "" && strings.HasPrefix(rel, ".cc.") && rel != gen {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		switch {
		case top == gen && (rest == ".geoip_isos" || strings.HasPrefix(rest, ".geoip_isos/")):
			rel = "db/geoip.txt" + strings.TrimPrefix(rest, ".geoip_isos")
		case top == gen:
			rel = "cc/" + rest
		case rel == ".cc.lock":
			rel = "cc/.pfb_generation.lock"
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	generations, _ := filepath.Glob(filepath.Join(root, ".cc.*.*"))
	for _, g := range generations {
		if name := filepath.Base(g); name != gen && name != seededGeneration {
			t.Errorf("left beside cc: %s", name) // a leaked or extra generation, which the digest no longer sees
		}
	}
	return files
}

// catalogDigest is the corpus digest of a catalog file, which must be a canonical resource body (JSON Lines, unique and
// in byte order, each line ending in a newline): the sha256 of its rows' lines
// "<kind>\0<page>\0<continent>\0<family>\0<position>\0<iso>\0<country>\0<networks>\n" (a field a row lacks is
// empty) in byte order, as tests/php/GeoipConversionCorpusTest.php reads the same rows back from the pages, whatever
// each side's JSON encoder spells.
func catalogDigest(t *testing.T, body []byte) string {
	t.Helper()
	if len(body) > 0 && body[len(body)-1] != '\n' {
		t.Fatalf("catalog does not end in a newline")
	}
	members := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(body) == 0 {
		members = nil
	}
	var lines []string
	for i, m := range members {
		if i > 0 && m <= members[i-1] {
			t.Fatalf("catalog line %d is not after the line before it in byte order: %q", i+1, m)
		}
		var row struct {
			Kind, Page, Continent, ISO, Country string
			Family, Position, Networks          *int
		}
		d := json.NewDecoder(strings.NewReader(m))
		d.DisallowUnknownFields()
		if err := d.Decode(&row); err != nil || !errors.Is(d.Decode(&struct{}{}), io.EOF) { // nothing after the row
			t.Fatalf("catalog line %d is not one row: %q: %v", i+1, m, err)
		}
		n := func(p *int) string {
			if p == nil {
				return ""
			}
			return strconv.Itoa(*p)
		}
		lines = append(lines, strings.Join([]string{row.Kind, row.Page, row.Continent, n(row.Family), n(row.Position),
			row.ISO, row.Country, n(row.Networks)}, "\x00")+"\n")
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

// tree is the corpus digest of the files, and their listing for a failure message.
func tree(files map[string][]byte) (string, string) {
	var lines, listing strings.Builder
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		sum := sha256.Sum256(normalized(files[rel]))
		h := hex.EncodeToString(sum[:])
		lines.WriteString(rel + "\x00" + h + "\n")
		listing.WriteString(h + "  " + rel + "\n")
	}
	sum := sha256.Sum256([]byte(lines.String()))
	return hex.EncodeToString(sum[:]), listing.String()
}
