package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// storeFile, in the state directory, holds a FileBackend's whole configuration. A write goes to storeFile+".tmp", is synced
// and renamed over storeFile, so a crash leaves the previous document whole; a leftover .tmp is ignored and overwritten by
// the next write.
const storeFile = "settings.json"

// beforeRename runs between writing the new document and renaming it into place: a test kills the process there.
var beforeRename func()

// syncDir syncs the state directory after the rename (a test makes it fail).
var syncDir = (*os.File).Sync

// FileBackend keeps the configuration in the state directory dir, for a Core that has no other store. The directory is the
// caller's alone (Core holds core.lock on it): no other writer changes the file between two calls.
type FileBackend struct {
	dir      string
	revision uint64 // of the document last read or written; 0 while there is none
}

func NewFileBackend(dir string) *FileBackend { return &FileBackend{dir: dir} }

type projectionDoc struct {
	Values map[string]any `json:"values"`
}

// document is storeFile's content; absent until the first write. A generation is not stored: the Store derives it.
type document struct {
	Format      int                      `json:"format"`
	Revision    uint64                   `json:"revision"`
	Projections map[string]projectionDoc `json:"projections"`
}

// Read returns the stored document; no file is an uninitialized backend, a file that does not read whole is an error, never
// an uninitialized one.
func (f *FileBackend) Read() (Stored, error) {
	raw, err := os.ReadFile(filepath.Join(f.dir, storeFile))
	if errors.Is(err, fs.ErrNotExist) {
		f.revision = 0
		return Stored{}, nil
	}
	if err != nil {
		return Stored{}, err
	}
	var stored struct {
		Format      int    `json:"format"`
		Revision    uint64 `json:"revision"`
		Projections map[string]struct {
			Generation json.RawMessage            `json:"generation"` // an older Core stored it; it is derived now, so ignored
			Values     map[string]json.RawMessage `json:"values"`
		} `json:"projections"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stored); err != nil {
		return Stored{}, fmt.Errorf("%s: %w", storeFile, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Stored{}, fmt.Errorf("%s: data after its document", storeFile)
	}
	if stored.Format != 1 || stored.Revision == 0 {
		return Stored{}, fmt.Errorf("%s: format %d, revision %d: not a store this Core reads", storeFile, stored.Format, stored.Revision)
	}
	projections := make(map[string]map[string]json.RawMessage, len(stored.Projections))
	for id, p := range stored.Projections {
		projections[id] = p.Values
	}
	f.revision = stored.Revision
	return Stored{Initialized: true, Revision: stored.Revision, Projections: projections}, nil
}

// Write stores values as revision expected+1 when the file is at expected (0: there is none): the new file whole and synced,
// then renamed over the old one, then the directory synced. From the rename on, the new revision is the store, so it is
// returned even when the directory sync then fails.
func (f *FileBackend) Write(expected uint64, values map[string]map[string]any) (uint64, error) {
	if expected != f.revision {
		return 0, &ConflictError{Field: "expectedRevision",
			Message: fmt.Sprintf("%s is at revision %d, not %d", storeFile, f.revision, expected)}
	}
	doc := document{Format: 1, Revision: expected + 1, Projections: make(map[string]projectionDoc, len(values))}
	for id, v := range values {
		doc.Projections[id] = projectionDoc{Values: v}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return 0, err
	}
	path := filepath.Join(f.dir, storeFile)
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if beforeRename != nil {
		beforeRename()
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return 0, err
	}
	f.revision = doc.Revision
	d, err := os.Open(f.dir)
	if err != nil {
		return doc.Revision, err
	}
	defer d.Close()
	return doc.Revision, syncDir(d)
}
