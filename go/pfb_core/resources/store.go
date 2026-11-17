// Package resources is the resource store of the Core Updater pipeline spec (sections 7 and 8.2): a directory the Core
// Updater (the one writer, one process at a time, no locking) publishes resource bodies into under generations, and any
// number of Core API processes read as unchanged, a delta from a cursor, or a full body. The store holds data and caches,
// never settings or secrets. Per resource it keeps the current generation and the applied baseline, nothing else, at
// every moment after a writer operation returns. Readers re-read the index on every call and never write.
package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// MaxIDLength is the longest resource id, in bytes.
const MaxIDLength = 128

// The Kind of a Reply.
const (
	KindUnchanged = "unchanged"
	KindDelta     = "delta"
	KindFull      = "full"
)

var (
	ErrInvalidID   = errors.New("invalid resource id")
	ErrNotFound    = errors.New("resource not found")
	ErrUnavailable = errors.New("resource store unavailable")
)

// step is a test seam: called after each durable step of Publish. Production never sets it.
var step = func(name string) {}

const (
	indexName    = "index.json"
	indexVersion = 1
	maxRounds    = 8 // reads restarted because a publish raced them
)

// errCorrupt marks an index that was read and cannot be used; any other load error leaves the store untouched.
var errCorrupt = errors.New("corrupt index")

// Store is a resource store directory. Open does no I/O.
type Store struct{ dir string }

func Open(dir string) *Store { return &Store{dir: dir} }

// Cursor is what a consumer applied: the generation and the digest of its body.
type Cursor struct {
	Generation uint64
	Digest     string
}

// Reply answers Get. Add, Remove and Members are non-nil (possibly empty) for the kinds that carry them.
type Reply struct {
	Kind       string
	Generation uint64
	From       uint64 // delta: the cursor's generation
	Add        []string
	Remove     []string
	Members    []string
	Digest     string
	Entries    int
	Metadata   json.RawMessage // a JSON object
}

type gen struct {
	Generation uint64          `json:"generation,string"`
	Digest     string          `json:"digest"`
	Length     int64           `json:"length"`
	Entries    int             `json:"entries"`
	Metadata   json.RawMessage `json:"metadata"`
}

type entry struct {
	Current gen  `json:"current"`
	Applied *gen `json:"applied,omitempty"`
	Removed bool `json:"removed,omitempty"`
}

type index struct {
	Version   int               `json:"version"`
	Resources map[string]*entry `json:"resources"`
}

// ValidID reports whether id is ip-set/<seg>/<family>, ip-aggregate/<seg>/<family>, geo-catalog or dnsbl/<seg>.
func ValidID(id string) bool {
	if len(id) > MaxIDLength {
		return false
	}
	p := strings.Split(id, "/")
	switch p[0] {
	case "geo-catalog":
		return len(p) == 1
	case "dnsbl":
		return len(p) == 2 && validSeg(p[1])
	case "ip-set", "ip-aggregate":
		return len(p) == 3 && validSeg(p[1]) && (p[2] == "ipv4" || p[2] == "ipv6")
	}
	return false
}

func validSeg(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return s != ""
}

// Canonical returns members sorted in byte order without duplicates, the order of PHP's pfb_canonical_alias_set. It sorts
// and compacts members in place, so the input slice is spent. A member that is empty, not UTF-8, holds a control
// character or starts with "#" (PHP drops such a line, so the Outpost could not mirror it) is refused.
func Canonical(members []string) ([]string, error) {
	for _, m := range members {
		if m == "" || m[0] == '#' || !utf8.ValidString(m) || strings.IndexFunc(m, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("invalid member %q", m)
		}
	}
	slices.Sort(members)
	return slices.Compact(members), nil
}

func (s *Store) bodyPath(id string, g uint64) string {
	return filepath.Join(s.dir, escape(id)+"."+strconv.FormatUint(g, 10)+".body")
}

// escape is the file-name prefix of an id: ids hold no ".", so "<escaped>." never prefixes another id's files.
func escape(id string) string { return strings.ReplaceAll(id, "/", "~") }

// Publish stores members (canonicalised) and metadata as id's current body. The generation advances only when the body or
// the metadata bytes change; a removed id is brought back either way.
func (s *Store) Publish(id string, members []string, metadata map[string]any) (uint64, error) {
	if !ValidID(id) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	members, err := Canonical(members)
	if err != nil {
		return 0, err
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("metadata: %w", err)
	}
	body := make([]byte, 0, len(members)*16)
	for _, m := range members {
		body = append(append(body, m...), '\n')
	}
	dg := digest.Bytes(body)
	idx, err := s.loadWriter()
	if err != nil {
		return 0, err
	}
	e := idx.Resources[id]
	if e != nil && e.Current.Generation == math.MaxUint64 {
		return 0, fmt.Errorf("%w: %q generation space is exhausted", ErrUnavailable, id)
	}
	if e != nil && e.Current.Digest == dg && bytes.Equal(e.Current.Metadata, meta) {
		// The index says a body is there that is not: write it back under the same generation, index untouched.
		if fi, err := os.Lstat(s.bodyPath(id, e.Current.Generation)); err != nil || !fi.Mode().IsRegular() || fi.Size() != e.Current.Length {
			path := s.bodyPath(id, e.Current.Generation)
			if err := writeTmp(path, body); err != nil {
				return 0, err
			}
			if err := os.Rename(path+".tmp", path); err != nil {
				return 0, err
			}
			if err := s.syncDir(); err != nil {
				return 0, err
			}
		}
		if e.Removed {
			e.Removed = false
			if err := s.save(idx); err != nil {
				return 0, err
			}
		}
		// A publish killed after its index rename left the old bodies behind: settle them.
		return e.Current.Generation, s.prune(id, e)
	}
	g := uint64(1)
	if e == nil {
		e = &entry{}
		idx.Resources[id] = e
	} else {
		g = e.Current.Generation + 1
	}
	path := s.bodyPath(id, g)
	if err := writeTmp(path, body); err != nil {
		return 0, err
	}
	step("body-written")
	if err := os.Rename(path+".tmp", path); err != nil {
		return 0, err
	}
	if err := s.syncDir(); err != nil {
		return 0, err
	}
	step("body-renamed")
	e.Current = gen{g, dg, int64(len(body)), len(members), meta}
	e.Removed = false
	if err := s.save(idx); err != nil {
		return 0, err
	}
	err = s.prune(id, e)
	step("pruned")
	return g, err
}

// Applied records that the consumer applied generation g of id. A generation the store does not hold clears the baseline.
func (s *Store) Applied(id string, g uint64) error {
	e, idx, err := s.writerEntry(id)
	if err != nil {
		return err
	}
	switch {
	case e == nil:
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	case g == e.Current.Generation:
		a := e.Current
		e.Applied = &a
	case e.Applied != nil && g == e.Applied.Generation:
		return nil
	default:
		e.Applied = nil
	}
	if err := s.save(idx); err != nil {
		return err
	}
	return s.prune(id, e)
}

// Remove marks id as left the configuration. Its bodies stay until RemovalApplied; Get answers ErrNotFound at once.
func (s *Store) Remove(id string) error {
	e, idx, err := s.writerEntry(id)
	if err != nil {
		return err
	}
	if e == nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	e.Removed = true
	return s.save(idx)
}

// RemovalApplied deletes a removed id and all its files. An id that is unknown or was published again is left alone.
func (s *Store) RemovalApplied(id string) error {
	e, idx, err := s.writerEntry(id)
	if err != nil || e == nil || !e.Removed {
		return err
	}
	delete(idx.Resources, id)
	if err := s.save(idx); err != nil {
		return err
	}
	return s.prune(id, &entry{})
}

func (s *Store) writerEntry(id string) (*entry, *index, error) {
	if !ValidID(id) {
		return nil, nil, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	idx, err := s.loadWriter()
	if err != nil {
		return nil, nil, err
	}
	return idx.Resources[id], idx, nil
}

// Get answers id for a consumer at cursor (nil: none). Nothing is written.
func (s *Store) Get(id string, cursor *Cursor) (Reply, error) {
	if !ValidID(id) {
		return Reply{}, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	for range maxRounds {
		idx, err := s.load()
		if errors.Is(err, fs.ErrNotExist) {
			return Reply{}, fmt.Errorf("%w: %q", ErrNotFound, id)
		}
		if err != nil {
			return Reply{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		e := idx.Resources[id]
		if e == nil || e.Removed {
			return Reply{}, fmt.Errorf("%w: %q", ErrNotFound, id)
		}
		cur := e.Current
		if cursor != nil && cursor.Generation == cur.Generation && cursor.Digest == cur.Digest {
			return Reply{Kind: KindUnchanged, Generation: cur.Generation}, nil
		}
		body, err := s.readBody(id, cur)
		if err != nil {
			// A publish between the index read and the body read prunes the generation just read: read again.
			if again, lerr := s.load(); lerr == nil {
				if e2 := again.Resources[id]; e2 == nil || e2.Current.Generation != cur.Generation {
					continue
				}
			}
			return Reply{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		r := Reply{Generation: cur.Generation, Digest: cur.Digest, Entries: cur.Entries, Metadata: cur.Metadata}
		if a := e.Applied; cursor != nil && a != nil && a.Generation == cursor.Generation && a.Digest == cursor.Digest {
			if base, err := s.readBody(id, *a); err == nil {
				r.Kind, r.From = KindDelta, a.Generation
				r.Add, r.Remove = diff(base, body)
				return r, nil
			}
		}
		r.Kind = KindFull
		r.Members = lines(body)
		return r, nil
	}
	return Reply{}, fmt.Errorf("%w: %q kept changing", ErrUnavailable, id)
}

// lines splits a canonical body: one string allocation, the members are substrings of it.
func lines(body []byte) []string {
	if len(body) == 0 {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
}

// diff is one merge pass over two canonical bodies; only the differing lines become strings.
func diff(base, cur []byte) (add, remove []string) {
	add, remove = []string{}, []string{}
	nl := []byte{'\n'}
	for len(base) > 0 || len(cur) > 0 {
		var lb, lc, rb, rc []byte
		if len(base) > 0 {
			lb, rb, _ = bytes.Cut(base, nl)
		}
		if len(cur) > 0 {
			lc, rc, _ = bytes.Cut(cur, nl)
		}
		c := bytes.Compare(lb, lc)
		switch {
		case len(cur) == 0 || len(base) > 0 && c < 0:
			remove, base = append(remove, string(lb)), rb
		case len(base) == 0 || c > 0:
			add, cur = append(add, string(lc)), rc
		default:
			base, cur = rb, rc
		}
	}
	return add, remove
}

func (s *Store) readBody(id string, g gen) ([]byte, error) {
	if g.Length < 0 {
		return nil, errors.New("negative body length in the index")
	}
	b, err := readFile(s.bodyPath(id, g.Generation), g.Length)
	if err == nil && digest.Bytes(b) != g.Digest {
		err = errors.New("body digest differs from the index")
	}
	if err == nil && bytes.Count(b, []byte{'\n'}) != g.Entries {
		err = errors.New("body line count differs from the index")
	}
	return b, err
}

// readFile reads a regular file opened without following a symlink; size >= 0 is the exact size it must have.
func readFile(path string, size int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || size >= 0 && fi.Size() != size {
		return nil, fmt.Errorf("%s: not a regular file of %d bytes", path, size)
	}
	return io.ReadAll(f)
}

func (s *Store) load() (*index, error) {
	path := filepath.Join(s.dir, indexName)
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", errCorrupt, path)
	}
	raw, err := readFile(path, -1)
	if err != nil {
		return nil, err
	}
	idx := &index{}
	if err := json.Unmarshal(raw, idx); err != nil {
		return nil, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	if idx.Version != indexVersion {
		return nil, fmt.Errorf("%w: version %d", errCorrupt, idx.Version)
	}
	if idx.Resources == nil {
		idx.Resources = map[string]*entry{}
	}
	return idx, nil
}

// loadWriter treats a missing index as an empty store and an unusable one as a lost store: every body is dropped.
// A read error says nothing about the content and is returned with the store untouched.
func (s *Store) loadWriter() (*index, error) {
	idx, err := s.load()
	if err == nil {
		return idx, nil
	}
	if !errors.Is(err, errCorrupt) {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	} else {
		files, _ := os.ReadDir(s.dir)
		for _, f := range files {
			if n := f.Name(); strings.HasSuffix(n, ".body") || strings.HasSuffix(n, ".tmp") {
				os.Remove(filepath.Join(s.dir, n))
			}
		}
		if err := os.RemoveAll(filepath.Join(s.dir, indexName)); err != nil {
			return nil, err
		}
	}
	return &index{Version: indexVersion, Resources: map[string]*entry{}}, nil
}

func (s *Store) save(idx *index) error {
	raw, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, indexName)
	if err := writeTmp(path, raw); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	step("index-renamed")
	return s.syncDir()
}

func (s *Store) syncDir() error {
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeTmp writes path+".tmp" whole, synced and closed; the caller renames it. One writer, so the name is fixed.
func writeTmp(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	os.Remove(tmp) // a new file, so its mode is 0600 whatever a leftover had
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// prune deletes every file of id except the bodies of e's current generation and applied baseline.
func (s *Store) prune(id string, e *entry) error {
	keep := map[string]bool{}
	if e.Current.Generation != 0 {
		keep[filepath.Base(s.bodyPath(id, e.Current.Generation))] = true
	}
	if e.Applied != nil {
		keep[filepath.Base(s.bodyPath(id, e.Applied.Generation))] = true
	}
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if n := f.Name(); strings.HasPrefix(n, escape(id)+".") && !keep[n] {
			if err := os.Remove(filepath.Join(s.dir, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
