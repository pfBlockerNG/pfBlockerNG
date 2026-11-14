package feedparse

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Replays testdata/normcache.json (schema: testdata/README.md): the storage half of pfb_feed_normalize() through NormalizeFile.
// The PHP runner (tests/php/FeedParseNormCacheCorpusTest.php) replays the same file through the production function with the
// converter off, which is the path Core takes.

type ncFilesJSON struct {
	Orig    *string `json:"orig"`
	OrigHex *string `json:"orig_hex"`
	Norm    *string `json:"norm"`
	NormHex *string `json:"norm_hex"`
	XXH128  *string `json:"xxhash128"`
	MD5     *string `json:"md5"`
}

type ncCaseJSON struct {
	ID          *string      `json:"id"`
	Description *string      `json:"description"`
	Setup       *ncFilesJSON `json:"setup"`
	Expect      *struct {
		Path       *string      `json:"path"`
		Changed    *bool        `json:"changed"`
		Normalized *bool        `json:"normalized"`
		Files      *ncFilesJSON `json:"files"`
	} `json:"expect"`
}

// ncSuffix is the suffix after the feed name of each file the corpus names.
var ncSuffix = map[string]string{"orig": ".orig", "norm": ".norm", "xxhash128": ".norm.src.xxhash128", "md5": ".norm.src.md5"}

type ncCase struct {
	id                  string
	setup, files        map[string]string
	path                string
	changed, normalized bool
}

func (f *ncFilesJSON) state(id string) (map[string]string, error) {
	out := map[string]string{}
	for key, pair := range map[string][2]*string{"orig": {f.Orig, f.OrigHex}, "norm": {f.Norm, f.NormHex}} {
		b, err := corpusBytes(id, key, pair[0], pair[1], false)
		if err != nil {
			return nil, err
		}
		if pair[0] != nil || pair[1] != nil {
			out[key] = string(b)
		}
	}
	for key, v := range map[string]*string{"xxhash128": f.XXH128, "md5": f.MD5} {
		if v != nil {
			out[key] = *v
		}
	}
	return out, nil
}

func loadNormCache(data []byte) ([]ncCase, error) {
	var file struct {
		Schema *int         `json:"schema"`
		Cases  []ncCaseJSON `json:"cases"`
	}
	if err := decodeCorpus(data, &file); err != nil {
		return nil, err
	}
	if file.Schema == nil || *file.Schema != 1 || len(file.Cases) == 0 {
		return nil, errors.New(`normcache.json must be {"schema": 1, "cases": [non-empty list]}`)
	}
	ids := corpusIDs{}
	var out []ncCase
	for i, c := range file.Cases {
		if err := ids.add(c.ID, c.Description); err != nil {
			return nil, fmt.Errorf("case #%d: %w", i, err)
		}
		e := c.Expect
		if c.Setup == nil || e == nil || e.Path == nil || e.Changed == nil || e.Normalized == nil || e.Files == nil {
			return nil, fmt.Errorf("case %s: setup and expect need every key", *c.ID)
		}
		if *e.Path != "norm" && *e.Path != "orig" {
			return nil, fmt.Errorf("case %s: path is norm or orig", *c.ID)
		}
		want := ncCase{id: *c.ID, path: *e.Path, changed: *e.Changed, normalized: *e.Normalized}
		var err error
		if want.setup, err = c.Setup.state(want.id); err != nil {
			return nil, err
		}
		if want.files, err = e.Files.state(want.id); err != nil {
			return nil, err
		}
		out = append(out, want)
	}
	return out, nil
}

func TestNormCacheCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/normcache.json")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := loadNormCache(data)
	if err != nil {
		t.Fatalf("normcache.json: %v", err)
	}
	byName := map[string]string{}
	for key, suffix := range ncSuffix {
		byName["feed"+suffix] = key
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			dir := t.TempDir()
			for key, content := range c.setup {
				if err := os.WriteFile(filepath.Join(dir, "feed"+ncSuffix[key]), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := NormalizeFile(dir, "feed")
			path := got.Path
			switch path {
			case filepath.Join(dir, "feed.norm"):
				path = "norm"
			case filepath.Join(dir, "feed.orig"):
				path = "orig"
			}
			if path != c.path || got.Changed != c.changed || got.Normalized != c.normalized {
				t.Errorf("Path, Changed, Normalized = %s, %v, %v; want %s, %v, %v", path, got.Changed, got.Normalized, c.path, c.changed, c.normalized)
			}
			// Every file of the directory, a stray temporary one included, by the name the corpus gives it.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]string{}
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				name := e.Name()
				if key, ok := byName[name]; ok {
					name = key
				}
				files[name] = string(b)
			}
			for name, want := range c.files {
				if g, ok := files[name]; !ok || g != want {
					t.Errorf("file %s\n  expected: %s\n  actual:   %s", name, visible(want), shown(g, ok))
				}
			}
			for name, g := range files {
				if _, ok := c.files[name]; !ok {
					t.Errorf("file %s should not exist, holds %s", name, visible(g))
				}
			}
		})
	}
}

func shown(s string, present bool) string {
	if !present {
		return "(absent)"
	}
	return visible(s)
}

func TestNormCacheLoaderIsStrict(t *testing.T) {
	const ok = `{"id": "a", "description": "d", "setup": {"orig": "a.example\n"}, "expect": {"path": "norm", "changed": true, "normalized": true, "files": {"orig": "a.example\n", "norm": "a.example\n", "xxhash128": "00000000000000000000000000000000"}}}`
	doc := func(c string) string { return `{"schema": 1, "cases": [` + c + `]}` }
	if _, err := loadNormCache([]byte(doc(ok))); err != nil {
		t.Fatalf("the well-formed document is refused: %v", err)
	}
	rep := func(old, new string) string { return doc(replaceOnce(t, ok, old, new)) }
	bad := map[string]string{
		"unknown top key":      replaceOnce(t, doc(ok), `"schema": 1`, `"schema": 1, "x": 1`),
		"unknown case key":     rep(`"description": "d",`, `"description": "d", "x": 1,`),
		"unknown setup key":    rep(`"setup": {"orig"`, `"setup": {"x": "y", "orig"`),
		"orig and orig_hex":    rep(`"setup": {"orig": "a.example\n"}`, `"setup": {"orig": "a", "orig_hex": "ff"}`),
		"orig_hex is UTF-8":    rep(`"setup": {"orig": "a.example\n"}`, `"setup": {"orig_hex": "61"}`),
		"sidecar not a string": rep(`"xxhash128": "00000000000000000000000000000000"`, `"xxhash128": 0`),
		"bad path":             rep(`"path": "norm"`, `"path": "x"`),
		"changed not a bool":   rep(`"changed": true`, `"changed": 1`),
		"missing files":        rep(`, "files": {"orig": "a.example\n", "norm": "a.example\n", "xxhash128": "00000000000000000000000000000000"}`, ``),
		"duplicate id":         `{"schema": 1, "cases": [` + ok + `,` + ok + `]}`,
		"empty cases":          `{"schema": 1, "cases": []}`,
	}
	for name, text := range bad {
		if _, err := loadNormCache([]byte(text)); err == nil {
			t.Errorf("%s: the malformed document is accepted", name)
		}
	}
}
