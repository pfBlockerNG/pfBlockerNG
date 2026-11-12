package settings

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
	"sync"
)

// storeFile, in the state directory, holds the whole store. A save writes storeFile+".tmp", syncs it and renames it over
// storeFile, so a crash leaves the previous document whole; a leftover .tmp is ignored and overwritten by the next save.
const storeFile = "settings.json"

// beforeRename runs between writing the new document and renaming it into place: a test kills the process there.
var beforeRename func()

// syncDir syncs the state directory after the rename (a test makes it fail).
var syncDir = (*os.File).Sync

// FieldError names one field at fault: "<projection>.<field>", a projection id, or a parameter.
type FieldError struct {
	Field   string
	Message string
}

// ValidationError rejects a change set or request whole: nothing was changed.
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%d invalid settings, first %v", len(e.Fields), e.Fields[0])
}

// ConflictError refuses a call the store's state does not allow: a stale expectedRevision (Field "expectedRevision"),
// a second initialization, or a save before the first.
type ConflictError struct {
	Field   string
	Message string
}

func (e *ConflictError) Error() string { return e.Message }

// ProjectionValue is one projection as a read shows it: a secret field is {"present": bool}, never its value.
type ProjectionValue struct {
	ResourceID string         `json:"resourceId"`
	Generation uint64         `json:"generation"`
	Value      map[string]any `json:"value"`
}

// Snapshot is what GetSettings answers.
type Snapshot struct {
	Initialized bool              `json:"initialized"`
	Revision    uint64            `json:"revision"`
	Projections []ProjectionValue `json:"projections"`
}

// Result is what an accepted Initialize (every projection) or Save (the projections whose value changed) answers.
type Result struct {
	Revision    uint64            `json:"revision"`
	Projections []ProjectionValue `json:"projections"`
}

type projectionState struct {
	Generation uint64         `json:"generation"`
	Values     map[string]any `json:"values"`
}

// document is storeFile's content; absent until initialization.
type document struct {
	Format      int                         `json:"format"`
	Revision    uint64                      `json:"revision"`
	Projections map[string]*projectionState `json:"projections"`
}

// Store is safe for concurrent use; every call sees one whole revision.
type Store struct {
	mu     sync.Mutex
	dir    string
	schema Schema
	doc    *document // nil: not initialized
}

// Open reads the store in dir, which the caller made private. No store file is an uninitialized Core; a file that does
// not read whole under schema is an error, never an uninitialized Core.
func Open(dir string, schema Schema) (*Store, error) {
	s := &Store{dir: dir, schema: schema}
	raw, err := os.ReadFile(filepath.Join(dir, storeFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var stored struct {
		Format      int    `json:"format"`
		Revision    uint64 `json:"revision"`
		Projections map[string]struct {
			Generation uint64                     `json:"generation"`
			Values     map[string]json.RawMessage `json:"values"`
		} `json:"projections"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stored); err != nil {
		return nil, fmt.Errorf("%s: %w", storeFile, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: data after its document", storeFile)
	}
	if stored.Format != 1 || stored.Revision == 0 {
		return nil, fmt.Errorf("%s: format %d, revision %d: not a store this Core reads", storeFile, stored.Format, stored.Revision)
	}
	doc := &document{Format: 1, Revision: stored.Revision, Projections: map[string]*projectionState{}}
	// A projection or field the store does not hold yet (the schema grew) is its default; one this schema does not
	// know (it shrank) refuses the start, since dropping a stored setting needs a migration.
	for _, p := range schema.Projections {
		sp, ok := stored.Projections[p.ID]
		if !ok {
			sp.Generation = 1
		}
		if sp.Generation == 0 {
			return nil, fmt.Errorf("%s: projection %s has generation 0", storeFile, p.ID)
		}
		values, errs := apply(p, defaults(p), sp.Values, p.ID)
		if errs != nil {
			return nil, fmt.Errorf("%s: %v", storeFile, errs[0])
		}
		doc.Projections[p.ID] = &projectionState{Generation: sp.Generation, Values: values}
	}
	for id := range stored.Projections {
		if _, ok := doc.Projections[id]; !ok {
			return nil, fmt.Errorf("%s: it holds projection %s, which this Core does not know", storeFile, id)
		}
	}
	s.doc = doc
	return s, nil
}

// Schema is the store's schema.
func (s *Store) Schema() Schema { return s.schema }

func (s *Store) projection(id string) (Projection, bool) {
	for _, p := range s.schema.Projections {
		if p.ID == id {
			return p, true
		}
	}
	return Projection{}, false
}

// Get reads the named projections, every one when ids is empty. An uninitialized store holds none.
func (s *Store) Get(ids []string) (Snapshot, error) {
	var errs []FieldError
	for i, id := range ids {
		if _, ok := s.projection(id); !ok {
			errs = append(errs, FieldError{Field: fmt.Sprintf("projectionIds[%d]", i), Message: "no such projection"})
		}
	}
	if errs != nil {
		return Snapshot{}, &ValidationError{Fields: errs}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{Projections: []ProjectionValue{}}
	if s.doc == nil {
		return snap, nil
	}
	snap.Initialized, snap.Revision = true, s.doc.Revision
	for _, p := range s.schema.Projections {
		if len(ids) == 0 || slices.Contains(ids, p.ID) {
			snap.Projections = append(snap.Projections, s.read(p))
		}
	}
	return snap, nil
}

// read shows a projection's values with every secret as its presence.
func (s *Store) read(p Projection) ProjectionValue {
	ps := s.doc.Projections[p.ID]
	value := maps.Clone(ps.Values)
	for _, f := range p.Fields {
		if f.Secret {
			value[f.Name] = map[string]bool{"present": ps.Values[f.Name] != f.Default}
		}
	}
	return ProjectionValue{ResourceID: "settings/" + p.ID, Generation: ps.Generation, Value: value}
}

// Initialize accepts the first settings: every projection is its defaults with the given values over them, at revision 1
// and generation 1. An initialized store refuses it.
func (s *Store) Initialize(settings map[string]map[string]json.RawMessage) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doc != nil {
		return Result{}, &ConflictError{Message: "the settings are already initialized"}
	}
	doc := &document{Format: 1, Revision: 1, Projections: map[string]*projectionState{}}
	var errs []FieldError
	for _, p := range s.schema.Projections {
		values, perr := apply(p, defaults(p), settings[p.ID], p.ID)
		errs = append(errs, perr...)
		doc.Projections[p.ID] = &projectionState{Generation: 1, Values: values}
	}
	errs = append(errs, unknownProjections(s, settings)...)
	if errs != nil {
		return Result{}, &ValidationError{Fields: errs}
	}
	if err := s.commit(doc); err != nil {
		return Result{}, err
	}
	res := Result{Revision: 1}
	for _, p := range s.schema.Projections {
		res.Projections = append(res.Projections, s.read(p))
	}
	return res, nil
}

// Save applies changes (projection → field → value; null resets a field to its default) to the configuration at
// expected. The whole result is validated before anything is written: any error rejects it all. An accepted save
// advances the revision; a projection's generation advances only when its value changed.
func (s *Store) Save(expected uint64, changes map[string]map[string]json.RawMessage) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doc == nil {
		return Result{}, &ConflictError{Message: "the settings are not initialized yet"}
	}
	if expected != s.doc.Revision {
		return Result{}, &ConflictError{Field: "expectedRevision",
			Message: fmt.Sprintf("the settings are at revision %d, not %d", s.doc.Revision, expected)}
	}
	doc := &document{Format: 1, Revision: s.doc.Revision + 1, Projections: map[string]*projectionState{}}
	var errs []FieldError
	var changed []Projection
	for _, p := range s.schema.Projections {
		old := s.doc.Projections[p.ID]
		values, perr := apply(p, old.Values, changes[p.ID], p.ID)
		errs = append(errs, perr...)
		ps := &projectionState{Generation: old.Generation, Values: values}
		if !maps.Equal(values, old.Values) {
			ps.Generation++
			changed = append(changed, p)
		}
		doc.Projections[p.ID] = ps
	}
	errs = append(errs, unknownProjections(s, changes)...)
	if errs != nil {
		return Result{}, &ValidationError{Fields: errs}
	}
	if err := s.commit(doc); err != nil {
		return Result{}, err
	}
	res := Result{Revision: doc.Revision, Projections: []ProjectionValue{}}
	for _, p := range changed {
		res.Projections = append(res.Projections, s.read(p))
	}
	return res, nil
}

func unknownProjections(s *Store, given map[string]map[string]json.RawMessage) []FieldError {
	var errs []FieldError
	for _, id := range slices.Sorted(maps.Keys(given)) {
		if _, ok := s.projection(id); !ok {
			errs = append(errs, FieldError{Field: id, Message: "no such projection"})
		}
	}
	return errs
}

func defaults(p Projection) map[string]any {
	values := make(map[string]any, len(p.Fields))
	for _, f := range p.Fields {
		values[f.Name] = f.Default
	}
	return values
}

// apply returns base with given over it, validated, and with each Requires rule enforced; base is not modified.
func apply(p Projection, base map[string]any, given map[string]json.RawMessage, prefix string) (map[string]any, []FieldError) {
	values := maps.Clone(base)
	var errs []FieldError
	for _, name := range slices.Sorted(maps.Keys(given)) {
		i := slices.IndexFunc(p.Fields, func(f Field) bool { return f.Name == name })
		if i < 0 {
			errs = append(errs, FieldError{Field: prefix + "." + name, Message: "no such field"})
			continue
		}
		f := p.Fields[i]
		v, err := decode(f, given[name])
		if err != nil {
			errs = append(errs, FieldError{Field: prefix + "." + name, Message: err.Error()})
			continue
		}
		values[name] = v
	}
	for _, f := range p.Fields {
		if f.Requires != "" && values[f.Requires] == false {
			values[f.Name] = false
		}
	}
	return values, errs
}

// decode reads one value as f's type and checks its constraints; JSON null is f's default.
func decode(f Field, raw json.RawMessage) (any, error) {
	if string(bytes.TrimSpace(raw)) == "null" {
		return f.Default, nil
	}
	switch f.Type {
	case TypeBool:
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	case TypeInt:
		var n int64
		if json.Unmarshal(raw, &n) != nil {
			return nil, errors.New("must be a whole number")
		}
		if f.Min != nil && n < *f.Min {
			return nil, fmt.Errorf("must be at least %d", *f.Min)
		}
		if f.Max != nil && n > *f.Max {
			return nil, fmt.Errorf("must be at most %d", *f.Max)
		}
		return n, nil
	case TypeEnum, TypeString:
		var str string
		if json.Unmarshal(raw, &str) != nil {
			return nil, errors.New("must be a string")
		}
		if f.Type == TypeEnum && !slices.Contains(f.Enum, str) {
			return nil, fmt.Errorf("must be one of %v", f.Enum)
		}
		return str, nil
	}
	return nil, fmt.Errorf("field type %q is not supported", f.Type)
}

// commit writes doc as the store: the new file whole and synced, then renamed over the old one, then the directory synced.
// From the rename on, doc is the store, so it is served even when the directory sync then fails (that error is returned).
func (s *Store) commit(doc *document) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, storeFile)
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
	if err != nil {
		return err
	}
	if beforeRename != nil {
		beforeRename()
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	s.doc = doc
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return syncDir(d)
}
