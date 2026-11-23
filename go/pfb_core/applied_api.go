package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/applied"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// ReportApplied (docs/misc/core-api-protocol.md, "ReportApplied"): pfb-dns reports the generation of each dnsbl/* resource
// it serves. Core records the report in its state directory and never writes the resource store: the Core Updater, its one
// writer, folds the record into the applied baselines (resources.Store.FoldApplied).

const (
	appliedFile         = applied.File
	dnsblPrefix         = applied.Prefix // the resources pfb-dns reads and reports, and all a further local client may read
	maxAppliedFile      = applied.MaxBytes
	maxAppliedResources = applied.MaxResources
)

// appliedRecord is appliedFile's content.
type appliedRecord = applied.Record

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
		report, bad := applied.Parse(p.Resources)
		if bad != nil {
			return nil, newError(codeInvalidArgument, "the report is not valid; nothing was recorded", bad...)
		}
		return struct{}{}, writeApplied(stateDir, report)
	}}}
}

// readApplied is the report appliedFile in stateDir records (applied.Read, the Core Updater's reader too).
func readApplied(stateDir string) (map[string]resources.Cursor, error) { return applied.Read(stateDir) }

// appliedMu holds one report's write from its open to its rename: reports land in the order they take it, and share the
// one temporary name.
var appliedMu sync.Mutex

// writeApplied replaces appliedFile in stateDir with report: written whole and synced under one temporary name (whatever
// sits there is removed first and the name is created exclusively, never a symlink followed), renamed over the old file
// (a symlink there is replaced, never followed), then the directory synced.
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
	path := filepath.Join(stateDir, appliedFile)
	appliedMu.Lock()
	defer appliedMu.Unlock()
	_ = os.Remove(path + ".tmp") // whatever a crash or another user left there: a file, a link, a FIFO, an empty directory
	tmp, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
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
		if info, lerr := os.Lstat(path); lerr == nil && info.IsDir() {
			_ = os.Remove(path) // rename cannot replace a directory; Remove takes an empty one only
		}
		err = os.Rename(path+".tmp", path)
	}
	if err != nil {
		_ = os.Remove(path + ".tmp")
		return err
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
