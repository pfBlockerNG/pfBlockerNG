// Package applied is the applied report pfB-DNS makes through ReportApplied (docs/misc/core-api-protocol.md): its
// cursors, the record Core keeps of it in its state directory, and the one reader of that record, which the Core API
// (at start) and the Core Updater (each fold, issue #4038) share.
package applied

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

const (
	File         = "applied.json" // the record, in Core's state directory
	Prefix       = "dnsbl/"       // the resources pfB-DNS reads and reports
	MaxResources = 4096
	MaxBytes     = 1 << 20 // a record re-encodes a request's resources, so it is never larger than a request body
)

// FieldError is one field a report or a cursor gets wrong.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Cursor is a cursor as the API carries it: a generation as a decimal string and a digest; a null field is absent.
type Cursor struct {
	Generation *string `json:"generation"`
	Digest     *string `json:"digest"`
}

// Record is File's content.
type Record struct {
	Format    int                `json:"format"`
	Resources map[string]*Cursor `json:"resources"`
}

// ParseCursor is id's cursor (nil: none) or the field errors of the id or the cursor. A field name carries the id as
// given, which passed resources.ValidID or was reported as "a key is not a resource id" alone.
func ParseCursor(id string, c *Cursor) (*resources.Cursor, []FieldError) {
	field := "resources." + id + "."
	switch {
	case !resources.ValidID(id): // never quoted: a key may be as long as the body
		return nil, []FieldError{{Field: "resources", Message: "a key is not a resource id"}}
	case c == nil:
		return nil, []FieldError{{Field: "resources", Message: fmt.Sprintf("the cursor of %q must be a JSON object", id)}}
	case c.Generation == nil && c.Digest == nil:
		return nil, nil
	case c.Generation == nil:
		return nil, []FieldError{{Field: field + "generation", Message: "required with digest"}}
	case c.Digest == nil:
		return nil, []FieldError{{Field: field + "digest", Message: "required with generation"}}
	}
	var bad []FieldError
	g, err := strconv.ParseUint(*c.Generation, 10, 64)
	if err != nil {
		bad = append(bad, FieldError{Field: field + "generation", Message: "must be a string of decimal digits that fits 64 bits"})
	}
	if d := *c.Digest; len(d) != 32 || strings.Trim(d, "0123456789abcdef") != "" {
		bad = append(bad, FieldError{Field: field + "digest", Message: "must be 32 lower-case hexadecimal characters"})
	}
	if bad != nil {
		return nil, bad
	}
	return &resources.Cursor{Generation: g, Digest: *c.Digest}, nil
}

// Parse is a report's cursors by id, or its field errors: at most MaxResources dnsbl/* ids, each with a generation and a
// digest.
func Parse(entries map[string]*Cursor) (map[string]resources.Cursor, []FieldError) {
	switch {
	case entries == nil:
		return nil, []FieldError{{Field: "resources", Message: "required"}}
	case len(entries) > MaxResources:
		return nil, []FieldError{{Field: "resources", Message: fmt.Sprintf("at most %d resources per report", MaxResources)}}
	}
	report, bad, badKey := make(map[string]resources.Cursor, len(entries)), []FieldError(nil), false
	for _, id := range slices.Sorted(maps.Keys(entries)) {
		switch {
		case !resources.ValidID(id): // never quoted: a key may be as long as the body
			if !badKey { // once per request, however many keys fail
				bad, badKey = append(bad, FieldError{Field: "resources", Message: "a key is not a resource id"}), true
			}
			continue
		case !strings.HasPrefix(id, Prefix):
			bad = append(bad, FieldError{Field: "resources", Message: fmt.Sprintf("%q is not a dnsbl/* resource id", id)})
			continue
		}
		c, errs := ParseCursor(id, entries[id])
		if c == nil && errs == nil { // a cursor without either field: a report names both
			errs = []FieldError{{Field: "resources." + id + ".generation", Message: "required"},
				{Field: "resources." + id + ".digest", Message: "required"}}
		}
		if errs != nil {
			bad = append(bad, errs...)
			continue
		}
		report[id] = *c
	}
	return report, bad
}

// Read is the report File in stateDir records: nil without the file, an empty map for a report of nothing. A file that
// is not a regular file (a symlink is not followed), is larger than MaxBytes, holds anything after its record, or is not a
// report Parse accepts is an error, and nothing of it is used.
func Read(stateDir string) (map[string]resources.Cursor, error) {
	f, err := os.OpenFile(filepath.Join(stateDir, File), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxBytes)
	}
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after its record")
	}
	if rec.Format != 1 {
		return nil, fmt.Errorf("format %d is not one this Core reads", rec.Format)
	}
	report, bad := Parse(rec.Resources)
	if bad != nil {
		return nil, fmt.Errorf("%s: %s", bad[0].Field, bad[0].Message)
	}
	return report, nil
}
