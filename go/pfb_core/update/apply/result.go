package apply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
	ID      string `json:"id"`
	Stage   string `json:"stage"` // "fetch" or "apply"
	Message string `json:"message"`
}

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

var aliasName = regexp.MustCompile(`^pfB_[A-Za-z0-9_]{1,27}$`)

// ReadResult is what the apply wrote to its result file for req: nothing, or lines of version 2, each one JSON object of
// printable ASCII within MaxLine, holding only ids and aliases of req, an applied id at the generation req gave (1 to 20
// digits, leading zeros allowed: the apply echoes the request's string), each id once across all lines. The lines add up:
// applied, removed, failed and aliases of every line, and a flag true when any line says so. A bad unterminated last line (one the apply's death cut short) leaves the lines before it, with the error; any other
// error returns a zero Result, so nothing of it is settled.
func ReadResult(f io.ReaderAt, req Request) (Result, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, MaxResult+1))
	switch {
	case err != nil:
		return Result{}, fmt.Errorf("the apply's result cannot be read: %w", err)
	case len(b) > MaxResult:
		return Result{}, errors.New("the apply's result is over 1 MiB")
	}
	generation := map[string]uint64{}
	removable := map[string]bool{}
	aliases := map[string]bool{}
	for _, r := range req.Resources {
		generation[r.ID] = r.Generation
		if a, ok := Alias(r.ID); ok {
			aliases[a] = true
		}
	}
	for _, id := range req.Removed {
		removable[id] = true
		if a, ok := Alias(id); ok {
			aliases[a] = true
		}
	}
	var res Result
	named := map[string]bool{}
	lines := bytes.Split(b, []byte("\n"))
	for i, l := range lines {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		next, err := res.add(l, generation, removable, aliases, named)
		if err != nil {
			if i < len(lines)-1 {
				return Result{}, err
			}
			return res, err
		}
		res = next
	}
	return res, nil
}

// add is res with one line added, or the reason the line is refused.
func (res Result) add(raw []byte, generation map[string]uint64, removable, aliases, named map[string]bool) (Result, error) {
	refuse := func(format string, a ...any) (Result, error) {
		return Result{}, fmt.Errorf("the apply's result line is refused: "+format, a...)
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
	claim := func(id string) bool {
		if named[id] || !handled(id) {
			return false
		}
		named[id] = true
		return true
	}
	// a refused line leaves res as it was: the lines before a cut last line still count
	applied := maps.Clone(res.Applied)
	for id, g := range l.Applied {
		want, requested := generation[id]
		if n, err := strconv.ParseUint(g, 10, 64); !requested || !claim(id) || len(g) > 20 || strings.Trim(g, "0123456789") != "" || err != nil || n != want {
			return refuse("%q at %q is not a resource of the request at its generation, once", id, g)
		}
		if applied == nil {
			applied = map[string]uint64{}
		}
		applied[id] = want
	}
	for _, id := range l.Removed {
		if !removable[id] || !claim(id) {
			return refuse("%q is not a removal of the request, once", id)
		}
	}
	var failed []Failure
	for _, f := range l.Failed {
		_, requested := generation[f.ID]
		if !(requested || removable[f.ID]) || !claim(f.ID) || (f.Stage != "fetch" && f.Stage != "apply") || f.Message == nil {
			return refuse("the failure of %q is not one of the request's ids, once, with a stage of fetch or apply and a message", f.ID)
		}
		failed = append(failed, Failure{f.ID, f.Stage, *f.Message})
	}
	changed := slices.Clip(res.ChangedAliases)
	onLine := map[string]bool{}
	for _, a := range l.ChangedAliases {
		if !aliasName.MatchString(a) || !aliases[a] || onLine[a] {
			return refuse("the changed alias %q is not an alias of the request's ids, once", a)
		}
		onLine[a] = true
		if !slices.Contains(changed, a) {
			changed = append(changed, a)
		}
	}
	return Result{
		Applied:        applied,
		Removed:        append(slices.Clip(res.Removed), l.Removed...),
		ChangedAliases: changed,
		IPChanged:      res.IPChanged || bool(l.IPChanged),
		DNSBLChanged:   res.DNSBLChanged || bool(l.DNSBLChanged),
		ReloadLaunched: res.ReloadLaunched || bool(l.ReloadLaunched),
		Failed:         append(slices.Clip(res.Failed), failed...),
	}, nil
}
