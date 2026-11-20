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
//	expect       ok (the conversion's answer), files ({path: content, or null when absent}: only the paths named) and
//	             tree (sha256 over every file the run leaves at the root outside share/, as sorted "<path>\0<sha256>\n"
//	             lines).
//	old_expect   today's PHP answer where Core deliberately differs (an owner decision); only the PHP runner reads it.
//
// Content is a string, {"b64": bytes}, or {"prefix", "repeat", "times", "suffix"} for a long line; a file that is not
// UTF-8 reads as {"b64": bytes}. The root holds share/, cc/ (the country folder), db/geoip.txt (the ISO list) and log/
// (maxmind_ver). A continent file's "# Generated from MaxMind Inc. on: <time>" line reads "{now}" on both sides.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
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
	OK    bool                      `json:"ok"`
	Files map[string]*corpusContent `json:"files"`
	Tree  string                    `json:"tree"`
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
			root := t.TempDir()
			for _, dir := range []string{"share", "cc", "db", "log"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
					t.Fatal(err)
				}
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
				write(rel, content.bytes(t))
			}

			conv := geoip.Conversion{
				Share:  filepath.Join(root, "share"),
				CCDir:  filepath.Join(root, "cc"),
				ISOs:   filepath.Join(root, "db", "geoip.txt"),
				LogDir: filepath.Join(root, "log"),
				Locale: locale,
				Now:    time.Date(2026, 11, 20, 9, 15, 0, 0, time.Local),
				Log:    io.Discard,
			}
			got := map[string]any{"ok": conv.Run(context.Background())}

			gotFiles := map[string]any{}
			for rel := range c.Expect.Files {
				b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
				if err != nil {
					gotFiles[rel] = nil
					continue
				}
				gotFiles[rel] = shown(normalized(b))
			}
			got["files"] = gotFiles
			sums, listing := tree(t, root)
			got["tree"] = sums

			wantFiles := map[string]any{}
			for rel, content := range c.Expect.Files {
				if content == nil {
					wantFiles[rel] = nil
					continue
				}
				wantFiles[rel] = shown(content.bytes(t))
			}
			want := map[string]any{"ok": c.Expect.OK, "files": wantFiles, "tree": c.Expect.Tree}
			if !reflect.DeepEqual(got, want) {
				gj, _ := json.MarshalIndent(got, "", "  ")
				wj, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("%s\n got: %.4000s\nwant: %.4000s\ntree:\n%s", c.Description, gj, wj, listing)
			}
		})
	}
}

// tree is the corpus digest of every file under root outside share/, and its listing for a failure message.
func tree(t *testing.T, root string) (string, string) {
	var rels []string
	sums := map[string]string{}
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if e.IsDir() {
			if rel == "share" {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(normalized(b))
		sums[rel] = hex.EncodeToString(sum[:])
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(rels)
	var lines, listing strings.Builder
	for _, rel := range rels {
		lines.WriteString(rel + "\x00" + sums[rel] + "\n")
		listing.WriteString(sums[rel] + "  " + rel + "\n")
	}
	sum := sha256.Sum256([]byte(lines.String()))
	return hex.EncodeToString(sum[:]), listing.String()
}
