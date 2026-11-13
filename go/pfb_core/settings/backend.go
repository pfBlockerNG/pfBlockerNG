package settings

import "encoding/json"

// Stored is a backend's configuration: Initialized is false only for a FileBackend that holds nothing yet.
type Stored struct {
	Initialized bool
	Revision    uint64
	Projections map[string]map[string]json.RawMessage // projection → field → JSON value, as stored: the Store validates it
}

// Backend is where a Store's settings live. A Store calls it one call at a time.
type Backend interface {
	Read() (Stored, error)
	// Write stores values (every field of every projection, already validated by the Store) if the backend is at expected
	// (0: create the first configuration, FileBackend only) and returns the new revision. A *ConflictError or
	// *ValidationError refuses it: nothing was written. Any other error is a failure; when the new revision took effect
	// before the failure (a directory sync after the rename) it is returned beside the error, else the revision is 0.
	Write(expected uint64, values map[string]map[string]any) (uint64, error)
}

// BackendError reports that a backend could not be read or written: the API's unavailable.
type BackendError struct{ Err error }

func (e *BackendError) Error() string { return e.Err.Error() }

func (e *BackendError) Unwrap() error { return e.Err }
