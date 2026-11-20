// Package resources is the resource store of the Core Updater pipeline spec (sections 7 and 8.2): a directory the Core
// Updater (the one writer, one process at a time, no locking) publishes resource bodies into under generations, and any
// number of Core API processes read as unchanged, a delta from a cursor, or a full body. The store holds data and caches,
// never settings or secrets. Per resource it keeps the current generation, the applied baseline and the delta between
// them, nothing else, at every moment after a writer operation returns. Readers re-read the index on every call and
// never write. Neither side holds a body or a delta in memory: both work a line at a time (issue #4049).
package resources

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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

	"github.com/pfBlockerNG/xxh3"
)

// MaxIDLength is the longest resource id, in bytes.
const MaxIDLength = 128

// The Kind of a Reply.
const (
	KindUnchanged = "unchanged"
	KindDelta     = "delta"
	KindFull      = "full"
)

// The parts of a resource Body serves: a generation's members, or the add or remove lines of the delta to it.
const (
	PartMembers = "members"
	PartAdd     = "add"
	PartRemove  = "remove"
)

var (
	ErrInvalidID   = errors.New("invalid resource id")
	ErrInvalidPart = errors.New("invalid resource part")
	ErrNotFound    = errors.New("resource not found")
	ErrUnavailable = errors.New("resource store unavailable")
)

// MaxMemberLength is the longest member PublishFrom takes, in bytes.
const MaxMemberLength = 1 << 20

// chunk is the buffer every streamed file is read and written through.
const chunk = 64 << 10

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

// Reply answers Get. It carries no members: Body serves them.
type Reply struct {
	Kind       string
	Generation uint64
	From       uint64 // delta: the cursor's generation
	Adds       int    // delta: the lines of its add part
	Removes    int    // delta: the lines of its remove part
	Digest     string
	Entries    int
	Metadata   json.RawMessage // a JSON object
}

// file is what the index records of a body or a delta part, and what a read of it is checked against.
type file struct {
	Digest  string `json:"digest"`
	Length  int64  `json:"length"`
	Entries int    `json:"entries"`
}

type gen struct {
	Generation uint64          `json:"generation,string"`
	Digest     string          `json:"digest"`
	Length     int64           `json:"length"`
	Entries    int             `json:"entries"`
	Metadata   json.RawMessage `json:"metadata"`
}

func (g gen) file() file { return file{g.Digest, g.Length, g.Entries} }

// delta is the add and remove parts that turn the applied baseline's body (From) into the current one, written at publish.
type delta struct {
	From   uint64 `json:"from,string"`
	Add    file   `json:"add"`
	Remove file   `json:"remove"`
}

type entry struct {
	Current gen    `json:"current"`
	Applied *gen   `json:"applied,omitempty"`
	Delta   *delta `json:"delta,omitempty"` // from Applied to Current; nil when there is none
	Removed bool   `json:"removed,omitempty"`
}

// delta is e's delta while it still runs from the applied baseline to the current generation, else nil.
func (e *entry) delta() *delta {
	if e.Delta == nil || e.Applied == nil || e.Delta.From != e.Applied.Generation {
		return nil
	}
	return e.Delta
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

// deltaPath is the file of part (add or remove) of the delta from generation from to generation g.
func (s *Store) deltaPath(id string, g, from uint64, part string) string {
	return filepath.Join(s.dir, escape(id)+"."+strconv.FormatUint(g, 10)+"."+strconv.FormatUint(from, 10)+"."+part)
}

// escape is the file-name prefix of an id: ids hold no ".", so "<escaped>." never prefixes another id's files.
func escape(id string) string { return strings.ReplaceAll(id, "/", "~") }

// Publish stores members (canonicalised) and metadata as id's current body, through PublishFrom. It sorts members in place.
func (s *Store) Publish(id string, members []string, metadata map[string]any) (uint64, error) {
	if !ValidID(id) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	members, err := Canonical(members)
	if err != nil {
		return 0, err
	}
	return s.PublishFrom(id, &memberReader{members: members}, metadata)
}

// memberReader is canonical members read as a body, a line at a time.
type memberReader struct {
	members []string
	line    string
}

func (r *memberReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.line == "" {
			if len(r.members) == 0 {
				break
			}
			r.line, r.members = r.members[0]+"\n", r.members[1:]
		}
		c := copy(p[n:], r.line)
		n, r.line = n+c, r.line[c:]
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// PublishFrom stores body, which must already be canonical (members as Canonical leaves them, one per line, the last
// newline optional), and metadata as id's current body, a line at a time. A body that is not canonical is refused and
// changes nothing. The generation advances only when the body or the metadata bytes change; a removed id is brought back
// either way. When the consumer applied an earlier generation, the delta from it is written here, by one merge pass.
func (s *Store) PublishFrom(id string, body io.Reader, metadata map[string]any) (uint64, error) {
	if !ValidID(id) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("metadata: %w", err)
	}
	idx, err := s.loadWriter()
	if err != nil {
		return 0, err
	}
	e := idx.Resources[id]
	if e != nil && e.Current.Generation == math.MaxUint64 {
		return 0, fmt.Errorf("%w: %q generation space is exhausted", ErrUnavailable, id)
	}
	g := uint64(1)
	if e != nil {
		g = e.Current.Generation + 1
	}
	path := s.bodyPath(id, g)
	written, err := writeBody(path, body)
	if err != nil {
		return 0, err
	}
	step("body-written")
	if e != nil && e.Current.Digest == written.Digest && bytes.Equal(e.Current.Metadata, meta) {
		// The body the index names is lost or damaged: write it back under the same generation, index untouched.
		if f, err := openVerified(s.bodyPath(id, e.Current.Generation), e.Current.file()); err == nil {
			f.Close()
			os.Remove(path + ".tmp")
		} else {
			if err := os.Rename(path+".tmp", s.bodyPath(id, e.Current.Generation)); err != nil {
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
		// A publish killed after its index rename left the old files behind: settle them.
		return e.Current.Generation, s.prune(id, e)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return 0, err
	}
	if err := s.syncDir(); err != nil {
		return 0, err
	}
	step("body-renamed")
	if e == nil {
		e = &entry{}
		idx.Resources[id] = e
	}
	e.Current = gen{g, written.Digest, written.Length, written.Entries, meta}
	e.Delta = nil
	if e.Applied != nil {
		if e.Delta, err = s.writeDelta(id, g, *e.Applied); err != nil {
			return 0, err
		}
	}
	e.Removed = false
	if err := s.save(idx); err != nil {
		return 0, err
	}
	err = s.prune(id, e)
	step("pruned")
	return g, err
}

// writeDelta writes the add and remove parts from the baseline's body to generation g's, by one merge pass over the two
// sorted files. A baseline whose body cannot be read verified gets no delta (nil): the consumer is answered full.
func (s *Store) writeDelta(id string, g uint64, base gen) (*delta, error) {
	fb, err := openVerified(s.bodyPath(id, base.Generation), base.file())
	if err != nil {
		return nil, nil
	}
	defer fb.Close()
	fc, err := os.Open(s.bodyPath(id, g))
	if err != nil {
		return nil, err
	}
	defer fc.Close()
	add, err := createPart(s.deltaPath(id, g, base.Generation, PartAdd))
	if err != nil {
		return nil, err
	}
	defer add.abort()
	remove, err := createPart(s.deltaPath(id, g, base.Generation, PartRemove))
	if err != nil {
		return nil, err
	}
	defer remove.abort()
	b, c := lineScanner(fb), lineScanner(fc)
	hb, hc := b.Scan(), c.Scan()
	for hb || hc {
		cmp := 0
		switch {
		case !hc:
			cmp = -1
		case !hb:
			cmp = 1
		default:
			cmp = bytes.Compare(b.Bytes(), c.Bytes())
		}
		switch {
		case cmp < 0:
			remove.line(b.Bytes())
			hb = b.Scan()
		case cmp > 0:
			add.line(c.Bytes())
			hc = c.Scan()
		default:
			hb, hc = b.Scan(), c.Scan()
		}
	}
	if err := errors.Join(b.Err(), c.Err()); err != nil {
		return nil, err
	}
	d := &delta{From: base.Generation}
	if d.Add, err = add.commit(); err != nil {
		return nil, err
	}
	if d.Remove, err = remove.commit(); err != nil {
		return nil, err
	}
	if err := s.syncDir(); err != nil {
		return nil, err
	}
	step("delta-renamed")
	return d, nil
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

// RemovalApplied deletes a removed id and all its files. An id that was published again is left alone; one with no
// entry has only the files a removal killed before its deletion left, and they go.
func (s *Store) RemovalApplied(id string) error {
	e, idx, err := s.writerEntry(id)
	if err != nil || e != nil && !e.Removed {
		return err
	}
	if e != nil {
		delete(idx.Resources, id)
		if err := s.save(idx); err != nil {
			return err
		}
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

// Get answers id for a consumer at cursor (nil: none): the kind and what describes the current body, never its members.
// Every file the reply relies on is read whole and checked against the index, a chunk at a time. Nothing is written.
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
		if len(cur.Metadata) == 0 || cur.Metadata[0] != '{' {
			return Reply{}, fmt.Errorf("%w: %q metadata in the index is not an object", ErrUnavailable, id)
		}
		if cursor != nil && cursor.Generation == cur.Generation && cursor.Digest == cur.Digest {
			return Reply{Kind: KindUnchanged, Generation: cur.Generation}, nil
		}
		if err := s.check(s.bodyPath(id, cur.Generation), cur.file()); err != nil {
			// A publish between the index read and the body read prunes the generation just read: read again.
			if s.moved(id, cur.Generation) {
				continue
			}
			return Reply{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		r := Reply{Kind: KindFull, Generation: cur.Generation, Digest: cur.Digest, Entries: cur.Entries, Metadata: cur.Metadata}
		a, d := e.Applied, e.delta()
		if cursor != nil && d != nil && a.Generation == cursor.Generation && a.Digest == cursor.Digest &&
			s.check(s.bodyPath(id, a.Generation), a.file()) == nil &&
			s.check(s.deltaPath(id, cur.Generation, d.From, PartAdd), d.Add) == nil &&
			s.check(s.deltaPath(id, cur.Generation, d.From, PartRemove), d.Remove) == nil {
			r.Kind, r.From, r.Adds, r.Removes = KindDelta, d.From, d.Add.Entries, d.Remove.Entries
		}
		return r, nil
	}
	return Reply{}, fmt.Errorf("%w: %q kept changing", ErrUnavailable, id)
}

// moved reports whether id's current generation is no longer g, so a read of g raced a publish.
func (s *Store) moved(id string, g uint64) bool {
	idx, err := s.load()
	if err != nil {
		return false
	}
	e := idx.Resources[id]
	return e == nil || e.Current.Generation != g
}

// Body opens the part of id the store holds: PartMembers of generation g (the current one or the applied baseline), or
// PartAdd or PartRemove of the delta from generation from to the current generation g. The file is checked whole against
// the index first and returned rewound, with its size; the caller closes it. ErrNotFound: the store does not hold it.
func (s *Store) Body(id string, g uint64, part string, from uint64) (*os.File, int64, error) {
	if !ValidID(id) {
		return nil, 0, fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	if part != PartMembers && part != PartAdd && part != PartRemove {
		return nil, 0, fmt.Errorf("%w: %q", ErrInvalidPart, part)
	}
	for range maxRounds {
		path, want, err := s.held(id, g, part, from)
		if err != nil {
			return nil, 0, err
		}
		f, err := openVerified(path, want)
		if err != nil {
			// A publish or an apply report between the index read and the open pruned it: read the index again.
			if again, _, herr := s.held(id, g, part, from); herr != nil || again != path {
				continue
			}
			return nil, 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return f, want.Length, nil
	}
	return nil, 0, fmt.Errorf("%w: %q kept changing", ErrUnavailable, id)
}

// held is the path of the part Body names and what the index records of it, or ErrNotFound when the store does not hold it.
func (s *Store) held(id string, g uint64, part string, from uint64) (string, file, error) {
	idx, err := s.load()
	if errors.Is(err, fs.ErrNotExist) {
		return "", file{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if err != nil {
		return "", file{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	e := idx.Resources[id]
	if e == nil || e.Removed {
		return "", file{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	switch d := e.delta(); {
	case part == PartMembers && g == e.Current.Generation:
		return s.bodyPath(id, g), e.Current.file(), nil
	case part == PartMembers && e.Applied != nil && g == e.Applied.Generation:
		return s.bodyPath(id, g), e.Applied.file(), nil
	case part == PartAdd && d != nil && g == e.Current.Generation && from == d.From:
		return s.deltaPath(id, g, from, part), d.Add, nil
	case part == PartRemove && d != nil && g == e.Current.Generation && from == d.From:
		return s.deltaPath(id, g, from, part), d.Remove, nil
	}
	return "", file{}, fmt.Errorf("%w: %q holds no %s of generation %d from %d", ErrNotFound, id, part, g, from)
}

// check reads path whole against want (openVerified) and closes it.
func (s *Store) check(path string, want file) error {
	f, err := openVerified(path, want)
	if err == nil {
		f.Close()
	}
	return err
}

// openVerified opens a store file without following a symlink and checks it is a regular file of want's length whose
// bytes have want's digest and line count, reading it a chunk at a time. The file is returned rewound.
func openVerified(path string, want file) (*os.File, error) {
	if want.Length < 0 {
		return nil, errors.New("negative length in the index")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	err = func() error {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || fi.Size() != want.Length {
			return fmt.Errorf("%s: not a regular file of %d bytes", path, want.Length)
		}
		h, lines, buf := xxh3.New128(), 0, make([]byte, chunk)
		for {
			n, rerr := f.Read(buf)
			h.Write(buf[:n])
			lines += bytes.Count(buf[:n], []byte{'\n'})
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
		switch {
		case hex.EncodeToString(h.Sum(nil)) != want.Digest:
			return fmt.Errorf("%s: digest differs from the index", path)
		case lines != want.Entries:
			return fmt.Errorf("%s: line count differs from the index", path)
		}
		_, err = f.Seek(0, io.SeekStart)
		return err
	}()
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// lineScanner reads one line at a time, its newline dropped and nothing else: a carriage return stays in the line.
func lineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, chunk), MaxMemberLength+1)
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	return sc
}

// partWriter writes a store file a line at a time to its temporary name, keeping what the index records of it.
type partWriter struct {
	path string
	f    *os.File
	w    *bufio.Writer
	h    hash.Hash
	file file
}

func createPart(path string) (*partWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	os.Remove(tmp) // a new file, so its mode is 0600 whatever a leftover had
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	p := &partWriter{path: path, f: f, h: xxh3.New128()}
	p.w = bufio.NewWriterSize(io.MultiWriter(f, p.h), chunk)
	return p, nil
}

func (p *partWriter) line(m []byte) {
	p.w.Write(m)
	p.w.WriteByte('\n')
	p.file.Entries++
	p.file.Length += int64(len(m)) + 1
}

// finish flushes, syncs and closes the temporary file, removing it on failure.
func (p *partWriter) finish() (file, error) {
	err := p.w.Flush()
	if err == nil {
		err = p.f.Sync()
	}
	if cerr := p.f.Close(); err == nil {
		err = cerr
	}
	p.f = nil
	if err != nil {
		os.Remove(p.path + ".tmp")
		return file{}, err
	}
	p.file.Digest = hex.EncodeToString(p.h.Sum(nil))
	return p.file, nil
}

// commit finishes the file and renames it into place.
func (p *partWriter) commit() (file, error) {
	f, err := p.finish()
	if err == nil {
		err = os.Rename(p.path+".tmp", p.path)
	}
	return f, err
}

// abort removes a temporary file the writer did not finish.
func (p *partWriter) abort() {
	if p.f != nil {
		p.f.Close()
		os.Remove(p.path + ".tmp")
	}
}

// writeBody writes a canonical body read from r to path's temporary name, synced and closed; the caller renames it. A
// member that is empty, not UTF-8, holds a control character, starts with "#" or is longer than MaxMemberLength, or a
// line not strictly after the one before it in byte order, refuses the body and leaves no file.
func writeBody(path string, r io.Reader) (file, error) {
	p, err := createPart(path)
	if err != nil {
		return file{}, err
	}
	defer p.abort()
	sc := lineScanner(r)
	prev := make([]byte, 0, 256)
	for sc.Scan() {
		m := sc.Bytes()
		if len(m) == 0 || m[0] == '#' || !utf8.Valid(m) || bytes.IndexFunc(m, unicode.IsControl) >= 0 {
			return file{}, fmt.Errorf("invalid member %.80q", m)
		}
		if p.file.Entries > 0 && bytes.Compare(prev, m) >= 0 {
			return file{}, fmt.Errorf("the body is not canonical: %.80q follows %.80q", m, prev)
		}
		prev = append(prev[:0], m...)
		p.line(m)
	}
	if err := sc.Err(); err != nil {
		return file{}, fmt.Errorf("the body cannot be read: %w", err)
	}
	return p.finish()
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
			if n := f.Name(); strings.HasSuffix(n, ".body") || strings.HasSuffix(n, ".tmp") ||
				strings.HasSuffix(n, "."+PartAdd) || strings.HasSuffix(n, "."+PartRemove) {
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

// prune deletes every file of id except the bodies of e's current generation and applied baseline and the delta between them.
func (s *Store) prune(id string, e *entry) error {
	keep := map[string]bool{}
	if e.Current.Generation != 0 {
		keep[filepath.Base(s.bodyPath(id, e.Current.Generation))] = true
	}
	if e.Applied != nil {
		keep[filepath.Base(s.bodyPath(id, e.Applied.Generation))] = true
	}
	if d := e.delta(); d != nil {
		for _, part := range []string{PartAdd, PartRemove} {
			keep[filepath.Base(s.deltaPath(id, e.Current.Generation, d.From, part))] = true
		}
	}
	files, err := os.ReadDir(s.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
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
