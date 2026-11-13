package settings

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
)

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

// Store is Core's settings in memory, loaded from a Backend; it is safe for concurrent use and every call sees one whole
// revision. Initialize, Save and Reload hold wmu across their backend call and mu only to swap the state in, so a slow
// backend never blocks Get or Validate.
type Store struct {
	wmu         sync.Mutex
	mu          sync.Mutex // guards the state below; it changes only with wmu and mu both held
	backend     Backend
	schema      Schema
	initialized bool
	revision    uint64
	values      map[string]map[string]any // projection → field → value; replaced whole, never changed in place
}

// Load reads b once. An empty FileBackend is an uninitialized Core; a configuration that does not read whole under schema
// is an error, never an uninitialized Core.
func Load(b Backend, schema Schema) (*Store, error) {
	s := &Store{backend: b, schema: schema}
	if err := s.fetch(); err != nil {
		return nil, err
	}
	return s, nil
}

// Open is Load over the FileBackend of the state directory dir.
func Open(dir string, schema Schema) (*Store, error) { return Load(NewFileBackend(dir), schema) }

// fetch replaces the state with what the backend holds now; on any error the state is as it was.
func (s *Store) fetch() error {
	stored, err := s.backend.Read()
	if err != nil {
		return err
	}
	var values map[string]map[string]any
	if stored.Initialized {
		// A projection or field the backend does not hold yet (the schema grew) is its default; one this schema does not
		// know (it shrank) refuses the read, since dropping a stored setting needs a migration.
		values = make(map[string]map[string]any, len(s.schema.Projections))
		for _, p := range s.schema.Projections {
			v, errs := apply(p, defaults(p), stored.Projections[p.ID], p.ID)
			if errs != nil {
				return fmt.Errorf("the stored settings are not valid: %s: %s", errs[0].Field, errs[0].Message)
			}
			values[p.ID] = v
		}
		for _, id := range slices.Sorted(maps.Keys(stored.Projections)) {
			if _, ok := values[id]; !ok {
				return fmt.Errorf("the stored settings hold projection %s, which this Core does not know", id)
			}
		}
	}
	s.set(stored.Initialized, stored.Revision, values)
	return nil
}

func (s *Store) set(initialized bool, revision uint64, values map[string]map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized, s.revision, s.values = initialized, revision, values
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
	if !s.initialized {
		return snap, nil
	}
	snap.Initialized, snap.Revision = true, s.revision
	for _, p := range s.schema.Projections {
		if len(ids) == 0 || slices.Contains(ids, p.ID) {
			snap.Projections = append(snap.Projections, show(p, s.values[p.ID]))
		}
	}
	return snap, nil
}

// show is a projection's values as a read shows them, every secret as its presence.
func show(p Projection, values map[string]any) ProjectionValue {
	value := maps.Clone(values)
	for _, f := range p.Fields {
		if f.Secret {
			value[f.Name] = map[string]bool{"present": values[f.Name] != f.Default}
		}
	}
	return ProjectionValue{ResourceID: "settings/" + p.ID, Generation: generation(values), Value: value}
}

// generation derives a projection's generation from its values (53 bits, exact in a JSON number): equal values give the
// same one in any Core, a change of value moves it, and nothing is stored. Secrets are part of the values, so one set to
// a guessable value would be guessable from the generation; the production schema has none.
func generation(values map[string]any) uint64 {
	raw, _ := json.Marshal(values) // bools, ints and strings: cannot fail; keys are sorted
	sum := sha256.Sum256(raw)
	return binary.BigEndian.Uint64(sum[:8]) >> 11
}

// write has the backend store values at expected. The new values are the state as soon as the backend took them, even when
// it then reports an error, and not before: a refused or failed write changes nothing. The caller holds wmu.
func (s *Store) write(expected uint64, values map[string]map[string]any) (uint64, error) {
	revision, err := s.backend.Write(expected, values)
	if revision != 0 {
		s.set(true, revision, values)
	}
	return revision, err
}

// Initialize accepts the first settings: every projection is its defaults with the given values over them. An initialized
// store, whatever its backend, refuses it.
func (s *Store) Initialize(settings map[string]map[string]json.RawMessage) (Result, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.initialized {
		return Result{}, &ConflictError{Message: "the settings are already initialized"}
	}
	values := make(map[string]map[string]any, len(s.schema.Projections))
	var errs []FieldError
	for _, p := range s.schema.Projections {
		v, perr := apply(p, defaults(p), settings[p.ID], p.ID)
		errs = append(errs, perr...)
		values[p.ID] = v
	}
	errs = append(errs, unknownProjections(s, settings)...)
	if errs != nil {
		return Result{}, &ValidationError{Fields: errs}
	}
	revision, err := s.write(0, values)
	if err != nil {
		return Result{}, err
	}
	res := Result{Revision: revision}
	for _, p := range s.schema.Projections {
		res.Projections = append(res.Projections, show(p, values[p.ID]))
	}
	return res, nil
}

// Save applies changes (projection → field → value; null resets a field to its default) to the configuration at
// expected. The whole result is validated before the backend is asked: any error rejects it all. An accepted save moves
// to the revision the backend answers.
func (s *Store) Save(expected uint64, changes map[string]map[string]json.RawMessage) (Result, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if !s.initialized {
		return Result{}, &ConflictError{Message: "the settings are not initialized yet"}
	}
	if expected != s.revision {
		return Result{}, &ConflictError{Field: "expectedRevision",
			Message: fmt.Sprintf("the settings are at revision %d, not %d", s.revision, expected)}
	}
	values := make(map[string]map[string]any, len(s.schema.Projections))
	var errs []FieldError
	var changed []Projection
	for _, p := range s.schema.Projections {
		v, perr := apply(p, s.values[p.ID], changes[p.ID], p.ID)
		errs = append(errs, perr...)
		values[p.ID] = v
		if !maps.Equal(v, s.values[p.ID]) {
			changed = append(changed, p)
		}
	}
	errs = append(errs, unknownProjections(s, changes)...)
	if errs != nil {
		return Result{}, &ValidationError{Fields: errs}
	}
	revision, err := s.write(expected, values)
	if err != nil {
		return Result{}, err
	}
	res := Result{Revision: revision, Projections: []ProjectionValue{}}
	for _, p := range changed {
		res.Projections = append(res.Projections, show(p, values[p.ID]))
	}
	return res, nil
}

// Reload reads the backend again, as when the configuration was changed behind Core's back, and answers what Get(nil)
// would. A backend that fails, or a configuration that does not validate, is a *BackendError and the last values stay.
func (s *Store) Reload() (Snapshot, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.fetch(); err != nil {
		var b *BackendError
		if !errors.As(err, &b) {
			err = &BackendError{Err: err}
		}
		return Snapshot{}, err
	}
	return s.Get(nil)
}

// Validate is Save's validation without the write: changes are checked over the current settings (the defaults while
// uninitialized), and the store, its revision and its generations stay as they are.
func (s *Store) Validate(changes map[string]map[string]json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []FieldError
	for _, p := range s.schema.Projections {
		base := defaults(p)
		if s.initialized {
			base = s.values[p.ID]
		}
		_, perr := apply(p, base, changes[p.ID], p.ID)
		errs = append(errs, perr...)
	}
	errs = append(errs, unknownProjections(s, changes)...)
	if errs != nil {
		return &ValidationError{Fields: errs}
	}
	return nil
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
