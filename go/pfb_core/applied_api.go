package main

import (
	"bytes"
	"context"
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

// ReportApplied (docs/misc/core-api-protocol.md, "ReportApplied"): pfb-dns reports the generation of each dnsbl/* resource
// it serves. Core records the report in its state directory and never writes the resource store: the Core Updater, its one
// writer, folds the record into the applied baselines (resources.Store.FoldApplied).

const (
	appliedFile         = "applied.json"
	dnsblPrefix         = "dnsbl/" // the resources pfb-dns reads and reports, and all a further local client may read
	maxAppliedResources = 4096
	maxAppliedFile      = defaultMaxBody // a record re-encodes a request's resources, so it is never larger than its body
)

// appliedRecord is appliedFile's content.
type appliedRecord struct {
	Format    int                        `json:"format"`
	Resources map[string]*resourceCursor `json:"resources"`
}

// appliedMethods is ReportApplied, recording into stateDir.
func appliedMethods(stateDir string) map[string]method {
	return map[string]method{"ReportApplied": {mutating: true, client: true, call: func(_ context.Context, params []byte) (any, error) {
		var p struct {
			RequestID string                     `json:"requestId"`
			Resources map[string]*resourceCursor `json:"resources"`
		}
		if err := decodeResourceParams(params, &p); err != nil {
			return nil, err
		}
		report, bad := parseApplied(p.Resources)
		if bad != nil {
			return nil, newError(codeInvalidArgument, "the report is not valid; nothing was recorded", bad...)
		}
		return struct{}{}, writeApplied(stateDir, report)
	}}}
}

// parseApplied is a report's cursors by id, or its field errors: at most maxAppliedResources dnsbl/* ids, each with a
// generation and a digest.
func parseApplied(entries map[string]*resourceCursor) (map[string]resources.Cursor, []fieldError) {
	switch {
	case entries == nil:
		return nil, []fieldError{{Field: "resources", Message: "required"}}
	case len(entries) > maxAppliedResources:
		return nil, []fieldError{{Field: "resources", Message: fmt.Sprintf("at most %d resources per report", maxAppliedResources)}}
	}
	report, bad := make(map[string]resources.Cursor, len(entries)), []fieldError(nil)
	for _, id := range slices.Sorted(maps.Keys(entries)) {
		if !strings.HasPrefix(id, dnsblPrefix) {
			bad = append(bad, fieldError{Field: "resources", Message: fmt.Sprintf("%q is not a dnsbl/* resource id", id)})
			continue
		}
		c, errs := parseResourceCursor(id, entries[id])
		if c == nil && errs == nil { // a cursor without either field: a report names both
			errs = []fieldError{{Field: "resources." + id + ".generation", Message: "required"},
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

// readApplied is the report appliedFile in stateDir records: nil without the file, an empty map for a report of nothing.
// A file that is not a regular file (a symlink is not followed), is larger than maxAppliedFile, or is not a report
// ReportApplied accepts is an error, and nothing of it is used.
func readApplied(stateDir string) (map[string]resources.Cursor, error) {
	f, err := os.OpenFile(filepath.Join(stateDir, appliedFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	raw, err := io.ReadAll(io.LimitReader(f, maxAppliedFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAppliedFile {
		return nil, fmt.Errorf("larger than %d bytes", maxAppliedFile)
	}
	var rec appliedRecord
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
	report, bad := parseApplied(rec.Resources)
	if bad != nil {
		return nil, fmt.Errorf("%s: %s", bad[0].Field, bad[0].Message)
	}
	return report, nil
}

// writeApplied replaces appliedFile in stateDir with report: written whole and synced under a temporary name of its own,
// renamed over the old file (a symlink there is replaced, never followed), then the directory synced. Two reports never
// share a temporary file, so they need no lock: the later rename wins whole.
func writeApplied(stateDir string, report map[string]resources.Cursor) error {
	rec := appliedRecord{Format: 1, Resources: make(map[string]*resourceCursor, len(report))}
	for id, c := range report {
		g, d := strconv.FormatUint(c.Generation, 10), c.Digest
		rec.Resources[id] = &resourceCursor{Generation: &g, Digest: &d}
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// A new file, never an existing one: CreateTemp makes it 0600, where reusing a file would keep that file's mode.
	tmp, err := os.CreateTemp(stateDir, appliedFile+".*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(stateDir, appliedFile))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
