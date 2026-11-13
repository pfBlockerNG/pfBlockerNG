package feedparse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// The per-feed corpus files (feed.json, normcache.json, prescript.json; schema in testdata/README.md) are read by these helpers
// and the three runners that use them. An unknown or missing key, a duplicate id, a byte field in the wrong form: every one is
// an error of the test, never a skip. The PHP runners (tests/php/FeedParse*CorpusTest.php) hold the same rules.

var lowerHexRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)

// readCorpus decodes testdata/<file> into v, refusing unknown keys and anything after the document.
func readCorpus(file string, v any) error {
	data, err := os.ReadFile("testdata/" + file)
	if err != nil {
		return err
	}
	return decodeCorpus(data, v)
}

func decodeCorpus(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the document")
	}
	return nil
}

// hexBytes is the bytes of a hex field: lower-case hex of bytes that are not valid UTF-8.
func hexBytes(where, s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if !lowerHexRE.MatchString(s) || err != nil || utf8.Valid(b) {
		return nil, fmt.Errorf("%s must be lower-case hex of bytes that are not valid UTF-8", where)
	}
	return b, nil
}

// corpusItem is a list element holding bytes: a JSON string, or {"hex": "..."} for bytes that are not valid UTF-8.
func corpusItem(where string, raw json.RawMessage) (string, error) {
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		err := json.Unmarshal(raw, &s)
		return s, err
	}
	var o struct {
		Hex *string `json:"hex"`
	}
	if err := decodeCorpus(raw, &o); err != nil || o.Hex == nil {
		return "", fmt.Errorf("%s must be a string or {\"hex\": ...}", where)
	}
	b, err := hexBytes(where+" hex", *o.Hex)
	return string(b), err
}

// feedInput is the feed bytes of a case: `input`, `input_hex`, or `input_parts` (strings and {"repeat": text, "count": n}).
type feedInput struct {
	Input      *string           `json:"input"`
	InputHex   *string           `json:"input_hex"`
	InputParts []json.RawMessage `json:"input_parts"`
}

func (in feedInput) bytes(id string) ([]byte, error) {
	if in.InputParts == nil {
		return corpusBytes(id, "input", in.Input, in.InputHex, true)
	}
	if in.Input != nil || in.InputHex != nil {
		return nil, fmt.Errorf("case %s: input_parts is the only input form", id)
	}
	var out []byte
	for i, raw := range in.InputParts {
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, err
			}
			out = append(out, s...)
			continue
		}
		var part struct {
			Repeat *string `json:"repeat"`
			Count  *int    `json:"count"`
		}
		if err := decodeCorpus(raw, &part); err != nil || part.Repeat == nil || *part.Repeat == "" || part.Count == nil || *part.Count < 1 {
			return nil, fmt.Errorf("case %s input_parts #%d: a string, or {repeat: non-empty string, count: positive int}", id, i)
		}
		out = append(out, strings.Repeat(*part.Repeat, *part.Count)...)
	}
	return out, nil
}

// corpusIDs accumulates the ids of a file: every one must be non-empty and unique.
type corpusIDs map[string]bool

func (ids corpusIDs) add(id, description *string) error {
	if id == nil || *id == "" || description == nil || *description == "" {
		return errors.New("a case needs a non-empty id and a non-empty description")
	}
	if ids[*id] {
		return fmt.Errorf("duplicate id %s", *id)
	}
	ids[*id] = true
	return nil
}

// failJSON is one parse-error record of an expectation.
type failJSON struct {
	LineNo *int            `json:"line_no"`
	Line   json.RawMessage `json:"line"`
	Raw    json.RawMessage `json:"raw"`
}

// failRecords reads the records of an expectation: line numbers positive and never decreasing.
func failRecords(where string, list *[]failJSON) ([]FailRecord, error) {
	if list == nil {
		return nil, fmt.Errorf("%s: missing", where)
	}
	var out []FailRecord
	last := 0
	for i, f := range *list {
		w := fmt.Sprintf("%s #%d", where, i)
		if f.LineNo == nil || *f.LineNo < 1 || *f.LineNo < last || f.Line == nil || f.Raw == nil {
			return nil, fmt.Errorf("%s: line_no (a positive int, never smaller than the one before), line and raw are required", w)
		}
		last = *f.LineNo
		line, err := corpusItem(w+" line", f.Line)
		if err != nil {
			return nil, err
		}
		raw, err := corpusItem(w+" raw", f.Raw)
		if err != nil {
			return nil, err
		}
		out = append(out, FailRecord{LineNo: *f.LineNo, Line: line, Raw: raw})
	}
	return out, nil
}

// sameRecords compares record lists, nil and empty alike.
func sameRecords(a, b []FailRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// replaceOnce replaces the one occurrence of old in s: a mutation that changes nothing would test nothing.
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if strings.Count(s, old) < 1 {
		t.Fatalf("test fixture drifted: %q not found", old)
	}
	return strings.Replace(s, old, new, 1)
}
