package apply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const (
	MaxLine      = 524288   // the bytes of one result line, its newline included
	MaxResult    = 1 << 20  // the bytes of result Core reads back from the apply's own file
	ResultSuffix = ".apply" // the apply's result file beside the Update log, its fd 3: the Updater's outcomes keep update.log.result
)

// Result is what the apply reported, the result lines added up.
type Result struct {
	Applied        map[string]uint64 // each resource applied, at the generation the request gave
	Removed        []string          // each removal applied
	ChangedAliases []string          // the alias of every table pushed to pf, each once
	IPChanged      bool
	DNSBLChanged   bool
	ReloadLaunched bool
	Failed         []Failure // each resource not applied
}

type Failure struct {
	ID      string
	Stage   string // "fetch" or "apply"
	Message string
}

// ErrCut is ReadResult's error for a result over MaxResult: the Result it comes with holds the complete lines inside the first
// MaxResult bytes, and what the apply reported after them is unknown. Those lines are settled as read; the ids they do not
// name stay pending, as they do after any error, so a caller that treats ErrCut as any other error settles nothing wrong. The
// Result holds only the lines read: its flags (IPChanged, DNSBLChanged, ReloadLaunched) and ChangedAliases are lower bounds, so
// the caller must assume a change and a possible reload.
var ErrCut = errors.New("the apply's result is over 1 MiB: only its complete lines inside the first 1 MiB are read")

// Exit is what the apply's exit status means for the Update.
type Exit int

const (
	Succeeded Exit = iota // 0
	Deferred              // 75: a lock was held or the Core API did not answer; nothing is settled and the work stays pending
	Refused               // 2: the apply refused the request and ran nothing
	Failed                // anything else
)

// ExitOf is the meaning of the apply's exit status.
func ExitOf(status int) Exit {
	switch status {
	case 0:
		return Succeeded
	case 75:
		return Deferred
	case 2:
		return Refused
	}
	return Failed
}

// Counts reports whether the result lines of an apply that ended so are recorded: complete lines count after a success and
// after a failure, never after a deferral or a refusal.
func (e Exit) Counts() bool { return e == Succeeded || e == Failed }

// flag is a JSON boolean that refuses null, as the apply never writes one.
type flag bool

func (f *flag) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", "false":
		*f = string(b) == "true"
		return nil
	}
	return fmt.Errorf("%s is not a boolean", b)
}

type line struct {
	Version        int               `json:"version"`
	Applied        map[string]string `json:"applied"`
	Removed        []string          `json:"removed"`
	ChangedAliases []string          `json:"changedAliases"`
	IPChanged      flag              `json:"ipChanged"`
	DNSBLChanged   flag              `json:"dnsblChanged"`
	ReloadLaunched flag              `json:"reloadLaunched"`
	Failed         []struct {
		ID      string  `json:"id"`
		Stage   string  `json:"stage"`
		Message *string `json:"message"`
	} `json:"failed"`
}

// ReadResult is what the apply wrote to its result file for req: nothing, or lines of version 2, each one JSON object of
// printable ASCII within MaxLine, holding only ids and aliases of req, an applied id at the generation req gave (1 to 20
// digits, leading zeros allowed: the apply echoes the request's string), each id once across all lines, and a failure message
// without a control character or a line or paragraph separator (the apply writes each as a space: the check covers the
// characters that can break a log line and does not repeat every rule of the writer). The lines add up: applied,
// removed, failed and aliases of every line, and a flag true when any line says so. Keys are matched as encoding/json matches
// them (case-insensitively, the last duplicate winning), which the apply never writes. A line is skipped only when it is empty
// or holds only spaces and is within MaxLine; any other whitespace is refused as a byte that is not printable ASCII.
// A result over MaxResult keeps the complete lines inside the first MaxResult bytes, with ErrCut (the flags and ChangedAliases
// of that Result are lower bounds: assume a change and a possible reload), unless the bytes after the last newline inside
// those MaxResult bytes make a line over MaxLine: a line then broke its bound, and the result is refused whole like a line over
// MaxLine. A line the apply's death cut short is the unterminated last line of the file, shorter than MaxLine, of printable
// ASCII, that is a proper prefix of one JSON object (it opens one, and decoding it ends in io.ErrUnexpectedEOF); only such a
// line leaves the lines before it, with the error. Any other error, of a terminated or an unterminated line, returns a zero Result, so nothing of it is settled.
func ReadResult(f io.ReaderAt, req Request) (Result, error) {
	b, err := readBounded(io.NewSectionReader(f, 0, MaxResult+1))
	if err != nil {
		return Result{}, fmt.Errorf("the apply's result cannot be read: %w", err)
	}
	cut := len(b) > MaxResult
	if cut {
		end := bytes.LastIndexByte(b[:MaxResult], '\n') + 1
		// the dropped tail is itself over the line bound (its newline may be the one byte read past the file bound): the
		// writer broke it, the file is not merely cut
		if len(bytes.TrimSuffix(b[end:], []byte("\n")))+1 > MaxLine {
			return Result{}, fmt.Errorf("the apply's result line is refused: it is over %d bytes", MaxLine)
		}
		b = b[:end]
	}
	r := reader{generation: map[string]uint64{}, removable: map[string]bool{}, aliases: map[string]bool{}, named: map[string]bool{},
		changed: map[string]bool{}}
	for _, res := range req.Resources {
		r.generation[res.ID] = res.Generation
		if a, ok := Alias(res.ID); ok {
			r.aliases[a] = true
		}
	}
	for _, id := range req.Removed {
		r.removable[id] = true
		if a, ok := Alias(id); ok {
			r.aliases[a] = true
		}
	}
	for len(b) > 0 {
		l, rest, terminated := bytes.Cut(b, []byte("\n"))
		b = rest
		if len(bytes.Trim(l, " ")) == 0 && len(l)+1 <= MaxLine { // a blank line over the bound goes to add, which refuses it
			continue
		}
		if err := r.add(l); err != nil {
			if !terminated && len(l) < MaxLine && l[0] == '{' && printableASCII(string(l), 0x20) &&
				errors.Is(json.NewDecoder(bytes.NewReader(l)).Decode(new(json.RawMessage)), io.ErrUnexpectedEOF) {
				return r.res, err
			}
			return Result{}, err
		}
	}
	if cut {
		return r.res, ErrCut
	}
	return r.res, nil
}

// readBounded is all of r, which holds at most MaxResult+1 bytes, in a buffer that doubles from 4 KiB and never passes
// MaxResult+1: an empty file costs 4 KiB, a full one under 3 MiB (io.ReadAll's growth of a full file costs about 5 MiB).
func readBounded(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, 4<<10)
	for {
		if len(b) == cap(b) {
			b = slices.Grow(b[:len(b):len(b)], min(len(b), MaxResult+1-len(b)))
		}
		n, err := r.Read(b[len(b):min(cap(b), MaxResult+1)])
		b = b[:len(b)+n]
		if errors.Is(err, io.EOF) {
			return b, nil
		}
		if err != nil || len(b) > MaxResult {
			return b, err
		}
	}
}

// reader is ReadResult's state: what the request holds, what the lines read so far named, and their Result.
type reader struct {
	generation         map[string]uint64
	removable, aliases map[string]bool
	named, changed     map[string]bool // the ids and the changed aliases of the lines read
	res                Result
}

// add adds one line to r.res, or leaves r as it was and gives the reason the line is refused: the line is checked whole first.
func (r *reader) add(raw []byte) error {
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("the apply's result line is refused: "+format, a...)
	}
	if len(raw)+1 > MaxLine {
		return refuse("it is over %d bytes", MaxLine)
	}
	if !printableASCII(string(raw), 0x20) {
		return refuse("it holds a byte that is not printable ASCII")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var l line
	if err := dec.Decode(&l); err != nil {
		return refuse("it is not one JSON object of the contract: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return refuse("it has data after the object")
	}
	if l.Version != Version {
		return refuse("it speaks version %d, not %d", l.Version, Version)
	}
	if len(l.Applied)+len(l.Removed)+len(l.Failed) > MaxIDs || len(l.ChangedAliases) > MaxIDs {
		return refuse("it names more than %d ids or aliases", MaxIDs)
	}
	onLine := map[string]bool{}
	claim := func(id string) bool {
		if r.named[id] || onLine[id] || !handled(id) {
			return false
		}
		onLine[id] = true
		return true
	}
	for id, g := range l.Applied {
		want, requested := r.generation[id]
		if !requested || !claim(id) {
			return refuse("%q is not an id of the request, named once", id)
		}
		if n, err := strconv.ParseUint(g, 10, 64); len(g) > 20 || err != nil || n != want {
			return refuse("%q at %q is not the generation the request gave", id, g)
		}
	}
	for _, id := range l.Removed {
		if !r.removable[id] || !claim(id) {
			return refuse("%q is not an id of the request, named once", id)
		}
	}
	for _, f := range l.Failed {
		_, requested := r.generation[f.ID]
		switch {
		case !(requested || r.removable[f.ID]) || !claim(f.ID):
			return refuse("the failure of %q is not an id of the request, named once", f.ID)
		case f.Stage != "fetch" && f.Stage != "apply":
			return refuse("the failure of %q has a stage other than fetch or apply", f.ID)
		case f.Message == nil:
			return refuse("the failure of %q has no message", f.ID)
		case strings.ContainsFunc(*f.Message, func(c rune) bool { return unicode.IsControl(c) || c == '\u2028' || c == '\u2029' }):
			return refuse("the failure message of %q holds a control character or a line or paragraph separator", f.ID)
		}
	}
	aliasesOnLine := map[string]bool{}
	for _, a := range l.ChangedAliases {
		if !r.aliases[a] || aliasesOnLine[a] {
			return refuse("the changed alias %q is not an alias of the request's ids, once", a)
		}
		aliasesOnLine[a] = true
	}

	for id := range onLine {
		r.named[id] = true
	}
	for id := range l.Applied {
		if r.res.Applied == nil {
			r.res.Applied = map[string]uint64{}
		}
		r.res.Applied[id] = r.generation[id]
	}
	r.res.Removed = append(r.res.Removed, l.Removed...)
	for _, f := range l.Failed {
		r.res.Failed = append(r.res.Failed, Failure{f.ID, f.Stage, *f.Message})
	}
	for _, a := range l.ChangedAliases {
		if !r.changed[a] {
			r.changed[a] = true
			r.res.ChangedAliases = append(r.res.ChangedAliases, a)
		}
	}
	r.res.IPChanged = r.res.IPChanged || bool(l.IPChanged)
	r.res.DNSBLChanged = r.res.DNSBLChanged || bool(l.DNSBLChanged)
	r.res.ReloadLaunched = r.res.ReloadLaunched || bool(l.ReloadLaunched)
	return nil
}
