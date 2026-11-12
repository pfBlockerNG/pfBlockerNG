package feedparse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Replays testdata/normalize.json (schema: testdata/README.md) through Normalize. The PHP runner replays the same file
// through the old path; `converter`, `appliance` and `old_expect` are its concern, Core's result is `expect` for every case.

type normalizeCase struct {
	ID           *string `json:"id"`
	Description  *string `json:"description"`
	Converter    *bool   `json:"converter"`
	Appliance    *bool   `json:"appliance"`
	Input        *string `json:"input"`
	InputHex     *string `json:"input_hex"`
	Expect       *string `json:"expect"`
	ExpectHex    *string `json:"expect_hex"`
	OldExpect    *string `json:"old_expect"`
	OldExpectHex *string `json:"old_expect_hex"`
}

type normalizeCorpus struct {
	Schema *int            `json:"schema"`
	Cases  []normalizeCase `json:"cases"`
}

// corpusBytes returns the bytes held by the text key or the hex key of one case; hex is only for bytes that are not valid UTF-8.
func corpusBytes(id, key string, text, hexForm *string, required bool) ([]byte, error) {
	switch {
	case text != nil && hexForm != nil:
		return nil, fmt.Errorf("case %s holds both %s and %s_hex", id, key, key)
	case text != nil:
		return []byte(*text), nil
	case hexForm != nil:
		b, err := hex.DecodeString(*hexForm)
		if err != nil || hex.EncodeToString(b) != *hexForm {
			return nil, fmt.Errorf("case %s: %s_hex is not lower-case hex", id, key)
		}
		if utf8.Valid(b) {
			return nil, fmt.Errorf("case %s: %s_hex is valid UTF-8, write it as text", id, key)
		}
		return b, nil
	case required:
		return nil, fmt.Errorf("case %s lacks %s", id, key)
	}
	return nil, nil
}

func loadNormalizeCorpus(t *testing.T) (ids []string, inputs, expects [][]byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/normalize.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var corpus normalizeCorpus
	if err := dec.Decode(&corpus); err != nil {
		t.Fatalf("normalize.json: %v", err)
	}
	if corpus.Schema == nil || *corpus.Schema != 1 || len(corpus.Cases) == 0 {
		t.Fatal(`normalize.json must be {"schema": 1, "cases": [non-empty list]}`)
	}
	seen := map[string]bool{}
	for i, c := range corpus.Cases {
		if c.ID == nil || *c.ID == "" || c.Description == nil || *c.Description == "" || c.Converter == nil {
			t.Fatalf("normalize.json: case #%d needs a non-empty id, a non-empty description and a bool converter", i)
		}
		id := *c.ID
		if seen[id] {
			t.Fatalf("normalize.json: duplicate id %s", id)
		}
		seen[id] = true
		in, err := corpusBytes(id, "input", c.Input, c.InputHex, true)
		if err != nil {
			t.Fatal(err)
		}
		want, err := corpusBytes(id, "expect", c.Expect, c.ExpectHex, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := corpusBytes(id, "old_expect", c.OldExpect, c.OldExpectHex, false); err != nil {
			t.Fatal(err)
		}
		ids, inputs, expects = append(ids, id), append(inputs, in), append(expects, want)
	}
	return ids, inputs, expects
}

func visible(line string) string {
	cut := len(line) > 160
	if cut {
		line = line[:160]
	}
	q := strconv.QuoteToASCII(line)
	if cut {
		q += "..."
	}
	return q
}

func lineDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "expected %d bytes, got %d\n", len(want), len(got))
	shown := 0
	for i := 0; i < max(len(w), len(g)) && shown < 20; i++ {
		var a, c string
		okA, okC := i < len(w), i < len(g)
		if okA {
			a = w[i]
		}
		if okC {
			c = g[i]
		}
		if okA == okC && a == c {
			continue
		}
		show := func(ok bool, s string) string {
			if !ok {
				return "(no such line)"
			}
			return visible(s)
		}
		fmt.Fprintf(&b, "line %d\n  expected: %s\n  actual:   %s\n", i+1, show(okA, a), show(okC, c))
		shown++
	}
	return b.String()
}

func TestNormalizeCorpus(t *testing.T) {
	ids, inputs, expects := loadNormalizeCorpus(t)
	for i, id := range ids {
		t.Run(id, func(t *testing.T) {
			if got := Normalize(inputs[i]); !bytes.Equal(got, expects[i]) {
				t.Errorf("Normalize differs from the corpus\n%s", lineDiff(expects[i], got))
			}
		})
	}
}
